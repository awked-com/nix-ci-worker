package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
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
		if len(storage.manifests) != 1 || len(storage.tags) != 1 {
			t.Fatal("versions grew with run count", len(storage.manifests), len(storage.tags))
		}
	}
}

func TestLivePublicationStopsAfterRetirementFailure(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	const system = "aarch64-linux"
	base := NewSnapshot(storage, cacheTestRepository)
	base.Metadata = map[string]any{"kind": "live", "run": "1", "system": system}
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
