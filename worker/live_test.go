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
	const system = "x86_64-linux"
	paths := []string{}
	history := map[string]string{}
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
		publisher := &livePublisher{snapshot: base, system: system, run: run, attempt: 1, recipients: recipients}
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
		history[generationTag(system, run, 1, 1)] = published.Digest
		history[generationTag(system, run, 1, 2)] = publisher.snapshot.Digest
		for tag, digest := range history {
			old, err := LoadSnapshot(storage, cacheTestRepository, tag, identity)
			if err != nil || old.Digest != digest {
				t.Fatal("historical generation changed", tag, err)
			}
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
		if len(storage.manifests) != 2*(index+1) || len(storage.tags) != 2*(index+1)+1 {
			t.Fatal("historical generations were lost", len(storage.manifests), len(storage.tags))
		}
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
	publisher := &livePublisher{snapshot: NewSnapshot(storage, cacheTestRepository), system: system, run: "1", attempt: 1, recipients: recipients}
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
			t.Fatal("publication lost a batched archive", got)
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
	const system = "aarch64-linux"
	base, err := loadPlatform(storage, cacheTestRepository, system, identity)
	if err != nil {
		t.Fatal(err)
	}
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("1", system, 1)
	path := cacheRecord(delta, "a")
	publisher := &livePublisher{snapshot: base, system: system, run: "1", attempt: 1, recipients: recipients}
	if err := publisher.publish(delta, false); err != nil {
		t.Fatal("first cache publication failed", err)
	}
	if err := publisher.publish(delta, true); err != nil {
		t.Fatal("new package could not publish its final generation", err)
	}
	collectTestBlobs(t, storage)
	reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, io.Discard)
	current, err := reader.Current(NarinfoKey(path))
	if err != nil || !current.Contains(path) || len(storage.manifests) != 2 {
		t.Fatal("new package did not become a usable cache", err)
	}
}

type failingHeadStorage struct {
	Storage
	failTag string
}

func (s *failingHeadStorage) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	if tag == s.failTag {
		return "", errors.New("tag upload failed")
	}
	return s.Storage.PutManifest(repository, tag, manifest)
}

func TestLivePublicationFailurePreservesPreviousHead(t *testing.T) {
	for _, failHead := range []bool{false, true} {
		t.Run(fmt.Sprint(failHead), func(t *testing.T) {
			_, recipients := cacheKeys(t)
			storage := newMemoryCache()
			const system = "aarch64-linux"
			base := NewSnapshot(storage, cacheTestRepository)
			base.Metadata = map[string]any{"kind": "live", "system": system, "run": "1", "attempt": 1, "publication": 1}
			previous := cachePublish(t, base, PlatformTag(system), recipients)
			historical := generationTag(system, "2", 1, 1)
			failTag := historical
			if failHead {
				failTag = PlatformTag(system)
			}
			failing := &failingHeadStorage{Storage: storage, failTag: failTag}
			base.Storage = failing
			p := &livePublisher{snapshot: base, system: system, run: "2", attempt: 1, recipients: recipients}
			delta := NewSnapshot(storage, cacheTestRepository)
			delta.Metadata = liveTestMetadata("2", system, 1)
			if err := p.publish(delta, false); err == nil {
				t.Fatal("upload failure ignored")
			}
			if storage.tags[PlatformTag(system)] != previous {
				t.Fatal("failed publication retired or replaced previous head")
			}
			if (storage.tags[historical] != "") != failHead {
				t.Fatal("historical tag was not published first")
			}
		})
	}
}
