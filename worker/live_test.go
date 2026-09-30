package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func liveTestMetadata(run, system string, attempt int) map[string]any {
	return map[string]any{
		"kind": "stage", "run": run, "attempt": attempt,
		"binding":  map[string]any{"system": system, "request": strings.Repeat("a", 32)},
		"terminal": true, "status": "success", "results": []any{},
	}
}

func collectTestBlobs(t *testing.T, storage *memoryCache) {
	t.Helper()
	storage.mu.Lock()
	defer storage.mu.Unlock()
	keep := map[string]bool{}
	for _, raw := range storage.manifests {
		var manifest Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		keep[manifest.Config.Digest] = true
		for _, layer := range manifest.Layers {
			keep[layer.Digest] = true
		}
	}
	for digest := range storage.objects {
		if !keep[digest] {
			delete(storage.objects, digest)
		}
	}
}

func TestLivePublicationRetainsHistoricalOutputsAndResults(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	retirer := newVersionRetirer(versions.api, storage, cacheTestRepository)
	const system = "x86_64-linux"
	paths := []string{}
	for index, char := range "0123456789ab" {
		run := fmt.Sprint(index + 1)
		base, err := loadPlatform(storage, cacheTestRepository, system, identity)
		if err != nil {
			t.Fatal(err)
		}
		delta := NewSnapshot(storage, cacheTestRepository)
		delta.Metadata = liveTestMetadata(run, system, 1)
		path := cacheRecord(delta, string(char))
		name := "cache/nar/" + strings.Repeat(string(char), 64) + ".nar.zst"
		if err := cacheAdd(delta, name, strings.NewReader("archive "+run), recipients); err != nil {
			t.Fatal(err)
		}
		publisher := &livePublisher{snapshot: base, system: system, run: run, attempt: 1, recipients: recipients, retire: retirer.retire}
		if err := publisher.publish(delta, false); err != nil {
			t.Fatal(err)
		}
		// A new path must be substitutable before its terminal result exists.
		published, err := loadPlatform(storage, cacheTestRepository, system, identity)
		if err != nil || !published.Contains(path) {
			t.Fatal("live output was not visible", err)
		}
		if _, err := LoadResult(storage, cacheTestRepository, run, system, 1, identity); !errors.Is(err, ErrObjectNotFound) {
			t.Fatal("unfinished result appeared", err)
		}
		if index%2 == 0 {
			delta.Metadata["status"] = "failure"
		}
		if err := publisher.publish(delta, true); err != nil {
			t.Fatal(err)
		}
		collectTestBlobs(t, storage)
		paths = append(paths, path)
		current, err := loadPlatform(storage, cacheTestRepository, system, identity)
		if err != nil {
			t.Fatal(err)
		}
		for previous, path := range paths {
			if !current.Contains(path) {
				t.Fatal("historical output disappeared", path)
			}
			result, err := LoadResult(storage, cacheTestRepository, fmt.Sprint(previous+1), system, 1, identity)
			if err != nil || result.Metadata["terminal"] != true {
				t.Fatal("historical result disappeared", err)
			}
		}
		if got := string(cacheRead(t, published, name, identity)); got != "archive "+run {
			t.Fatal("old reader lost its archive", got)
		}
		if len(storage.manifests) != 1 || len(storage.tags) != 2 {
			t.Fatal("versions grew with run count", len(storage.manifests), len(storage.tags))
		}
	}
}

func TestLivePublicationStopsAfterRetirementFailure(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	const system = "aarch64-linux"
	base := NewSnapshot(storage, cacheTestRepository)
	base.Metadata = map[string]any{"kind": "live", "run": "1", "system": system, "attempt": 1, "publication": 1}
	cachePublish(t, base, PlatformTag(system), recipients)
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("2", system, 1)
	path := cacheRecord(delta, "a")
	blocked := errors.New("deletion unavailable")
	publisher := &livePublisher{snapshot: base, system: system, run: "2", attempt: 1, recipients: recipients, retire: func(...string) error { return blocked }}
	if err := publisher.publish(delta, false); !errors.Is(err, blocked) {
		t.Fatal(err)
	}
	count := len(storage.manifests)
	delta.Metadata["status"] = "failure"
	if err := publisher.publish(delta, true); !errors.Is(err, blocked) || len(storage.manifests) != count {
		t.Fatal("publication grew the cleanup backlog", err)
	}
	current, err := loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil || !current.Contains(path) {
		t.Fatal("cleanup failure invalidated published output", err)
	}
}

func TestLivePublicationBatchesPendingOutputsAndForcesFinalHead(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	const system = "x86_64-linux"
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("1", system, 1)
	addOutput := func(char string) string {
		t.Helper()
		path := cacheRecord(delta, char)
		if err := cacheAdd(delta, "cache/nar/"+strings.Repeat(char, 64)+".nar.zst", strings.NewReader("archive "+char), recipients); err != nil {
			t.Fatal(err)
		}
		return path
	}
	first := addOutput("a")
	versions := &registryVersions{storage: storage}
	retirer := newVersionRetirer(versions.api, storage, cacheTestRepository)
	publisher := &livePublisher{snapshot: NewSnapshot(storage, cacheTestRepository), system: system, run: "1", attempt: 1, recipients: recipients, retire: func(digests ...string) error {
		if err := retirer.retire(digests...); err != nil {
			return err
		}
		collectTestBlobs(t, storage)
		return nil
	}}
	publisher.dirty = true
	if current, err := publisher.flush(delta, false); err != nil || !current {
		t.Fatal("first output was not published immediately", current, err)
	}
	previous := publisher.snapshot.Digest
	second := addOutput("b")
	publisher.dirty = true
	if current, err := publisher.flush(delta, false); err != nil || current || publisher.snapshot.Digest != previous {
		t.Fatal("pending output bypassed publication cadence", current, err)
	}
	head, err := loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil || !head.Contains(first) || head.Contains(second) {
		t.Fatal("deferred output changed the durable head", err)
	}
	// A later poll must publish pending records even without a newly built path.
	publisher.lastPublished = time.Now().Add(-2 * publicationInterval)
	if current, err := publisher.flush(delta, false); err != nil || !current {
		t.Fatal("pending output was lost between polls", current, err)
	}
	head, err = loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil || !head.Contains(first) || !head.Contains(second) {
		t.Fatal("batched head lost completed outputs", err)
	}
	for _, char := range []string{"a", "b"} {
		if got := string(cacheRead(t, head, "cache/nar/"+strings.Repeat(char, 64)+".nar.zst", identity)); got != "archive "+char {
			t.Fatal("generation retirement collected a batched archive", got)
		}
	}
	third := addOutput("c")
	publisher.dirty = true
	if current, err := publisher.flush(delta, true); err != nil || !current {
		t.Fatal("forced publication waited for cadence", current, err)
	}
	head, err = loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil || !head.Contains(third) {
		t.Fatal("forced publication omitted pending output", err)
	}
	previous = publisher.snapshot.Digest
	if current, err := publisher.flush(delta, true); err != nil || !current || publisher.snapshot.Digest != previous {
		t.Fatal("unchanged poll published a new generation", current, err)
	}
	addOutput("d")
	publisher.dirty = true
	if err := publisher.publish(delta, true); err != nil {
		t.Fatal("terminal publication waited for cadence", err)
	}
	if publisher.dirty {
		t.Fatal("terminal publication retained pending outputs")
	}
	if _, err := LoadResult(storage, cacheTestRepository, "1", system, 1, identity); err != nil {
		t.Fatal("terminal result was not durable", err)
	}
}

func TestLivePublicationKeepsPendingStateAfterFlushFailure(t *testing.T) {
	_, recipients := cacheKeys(t)
	storage := newMemoryCache()
	const system = "aarch64-linux"
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("1", system, 1)
	cacheRecord(delta, "a")
	publisher := &livePublisher{snapshot: NewSnapshot(storage, cacheTestRepository), system: system, run: "1", attempt: 1, recipients: recipients}
	publisher.dirty = true
	if _, err := publisher.flush(delta, false); err != nil {
		t.Fatal(err)
	}
	previous := publisher.lastPublished
	cacheRecord(delta, "b")
	publisher.dirty = true
	publisher.snapshot.Storage = &failingHeadStorage{Storage: storage, failTag: PlatformTag(system)}
	current, failure := publisher.flush(delta, true)
	if failure == nil || current || !publisher.dirty || publisher.lastPublished != previous {
		t.Fatal("failed flush discarded pending state", current, failure)
	}
	publisher.snapshot.Storage = storage
	if current, err := publisher.flush(delta, true); !errors.Is(err, failure) || current {
		t.Fatal("failed flush allowed later publication", current, err)
	}
}

func TestLoadResultRejectsIdentityBeforeRegistryEffects(t *testing.T) {
	for _, test := range []struct {
		run, system string
		attempt     int
	}{
		{"0", "aarch64-linux", 1}, {"1", "unknown", 1}, {"1", "aarch64-linux", 0},
	} {
		if _, err := LoadResult(nil, cacheTestRepository, test.run, test.system, test.attempt, Secret{}); err == nil {
			t.Fatal("accepted invalid result identity")
		}
	}
}

func TestLoadResultRequiresExactAttemptBinding(t *testing.T) {
	identity, recipients := cacheKeys(t)
	const system = "aarch64-linux"
	for _, attempt := range []any{1, 1.5, json.Number("9223372036854775808")} {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			storage := newMemoryCache()
			snapshot := NewSnapshot(storage, cacheTestRepository)
			metadata := liveTestMetadata("1", system, 1)
			metadata["attempt"] = attempt
			raw, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			name, err := resultFile("1", system, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := cacheAdd(snapshot, name, bytes.NewReader(raw), recipients); err != nil {
				t.Fatal(err)
			}
			cachePublish(t, snapshot, PlatformTag(system), recipients)
			_, err = LoadResult(storage, cacheTestRepository, "1", system, 1, identity)
			if attempt == 1 {
				if err != nil {
					t.Fatal("valid result rejected", err)
				}
			} else if !errors.Is(err, ErrResultBindingMismatch) {
				t.Fatal("invalid attempt accepted", err)
			}
		})
	}
}

func TestEmptyPackageAdmissionThenFirstLivePublication(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	api := func(path, method string) (any, error) {
		if strings.Contains(path, "/versions?") && len(storage.manifests) == 0 {
			return nil, ErrObjectNotFound
		}
		return versions.api(path, method)
	}
	retirer := newVersionRetirer(api, storage, cacheTestRepository)
	var log bytes.Buffer
	if _, err := Prune(api, storage, cacheTestRepository, &log); err != nil {
		t.Fatal("missing package blocked admission cleanup", err)
	}
	const system = "aarch64-linux"
	base, err := loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil {
		t.Fatal(err)
	}
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("1", system, 1)
	path := cacheRecord(delta, "a")
	publisher := &livePublisher{snapshot: base, system: system, run: "1", attempt: 1, recipients: recipients, retire: retirer.retire}
	if err := publisher.publish(delta, false); err != nil {
		t.Fatal("first cache publication failed", err)
	}
	if err := publisher.publish(delta, true); err != nil {
		t.Fatal("new package could not retire its first generation", err)
	}
	collectTestBlobs(t, storage)
	reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, io.Discard)
	current, err := reader.Current(NarinfoKey(path))
	if err != nil || !current.Contains(path) || len(storage.manifests) != 1 {
		t.Fatal("new package did not become a usable cache", err)
	}
}
