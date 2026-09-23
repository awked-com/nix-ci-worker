package worker

import (
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

func TestLegacyMigrationPreservesFailedResultsAndDisplacedFiles(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	retirer := newVersionRetirer(versions.api, storage, cacheTestRepository)
	const system = "aarch64-linux"
	base := NewSnapshot(storage, cacheTestRepository)
	base.Metadata = map[string]any{"kind": "commit", "run": "1"}
	first := cacheRecord(base, "a")
	if err := cacheAdd(base, evaluationFile(system), strings.NewReader("old plan"), recipients); err != nil {
		t.Fatal(err)
	}
	oldPlan := base.Files[evaluationFile(system)]
	legacy := publishV2Fixture(t, base, "nixos-cache-latest", recipients)
	stage := NewSnapshot(storage, cacheTestRepository)
	stage.Metadata = liveTestMetadata("2", system, 1)
	stage.Metadata["status"] = "failure"
	second := cacheRecord(stage, "b", strings.TrimPrefix(first, "/nix/store/"))
	if err := cacheAdd(stage, evaluationFile(system), strings.NewReader("new plan"), recipients); err != nil {
		t.Fatal(err)
	}
	if err := cacheAdd(stage, "legacy-artifact", strings.NewReader("private result"), recipients); err != nil {
		t.Fatal(err)
	}
	newPlan := stage.Files[evaluationFile(system)]
	publishV2Fixture(t, stage, ResultTag("2", system, 1), recipients)
	if err := migrateLegacy(storage, cacheTestRepository, "3", 1, identity, recipients, retirer, io.Discard); err != nil {
		t.Fatal(err)
	}
	collectTestBlobs(t, storage)
	for system := range Systems {
		current, err := loadPlatform(storage, cacheTestRepository, system, identity)
		if err != nil || !current.Contains(first) || !current.Contains(second) {
			t.Fatal("migration lost partial or inherited outputs", err)
		}
		for _, file := range []SnapshotFile{oldPlan, newPlan} {
			if _, exists := storage.objects[file.Blob.Digest]; !exists {
				t.Fatal("migration lost displaced plan")
			}
		}
	}
	result, err := LoadResult(storage, cacheTestRepository, "2", system, 1, identity)
	if err != nil || result.Metadata["status"] != "failure" {
		t.Fatal("failed run result not migrated", err)
	}
	if len(storage.manifests) != len(Systems)+1 || storage.tags["nixos-cache-latest"] != legacy {
		t.Fatal("legacy intermediate was retained or migration base replaced")
	}
	if err := migrateLegacy(storage, cacheTestRepository, "4", 1, identity, recipients, retirer, io.Discard); err != nil || len(storage.manifests) != len(Systems)+1 {
		t.Fatal("migration was not idempotent", err)
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

type interruptedMigrationStorage struct {
	Storage
	publish func() error
}

func (s interruptedMigrationStorage) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	if err := s.publish(); err != nil {
		return "", err
	}
	return s.Storage.PutManifest(repository, tag, manifest)
}

func TestLegacyMigrationResumesAfterPartialPublicationAndRetirement(t *testing.T) {
	for _, interrupted := range []string{"publication", "retirement"} {
		t.Run(interrupted, func(t *testing.T) {
			identity, recipients := cacheKeys(t)
			storage := newMemoryCache()
			versions := &registryVersions{storage: storage}
			const system = "aarch64-linux"
			archives := map[string]string{}
			for index, char := range "abc" {
				run := fmt.Sprint(index + 1)
				seed := NewSnapshot(storage, cacheTestRepository)
				seed.Metadata = liveTestMetadata(run, system, 1)
				tag := ResultTag(run, system, 1)
				if index == 0 {
					seed.Metadata = map[string]any{"kind": "commit", "run": run}
					tag = "nixos-cache-latest"
				}
				cacheRecord(seed, string(char))
				name := "cache/nar/" + strings.Repeat(string(char), 64) + ".nar.zst"
				archives[name] = "retained archive " + run
				if err := cacheAdd(seed, name, strings.NewReader(archives[name]), recipients); err != nil {
					t.Fatal(err)
				}
				publishV2Fixture(t, seed, tag, recipients)
			}
			injected := errors.New("interrupted migration")
			publications, deletions := 0, 0
			faulty := interruptedMigrationStorage{Storage: storage, publish: func() error {
				publications++
				if interrupted == "publication" && publications == 2 {
					return injected
				}
				return nil
			}}
			api := func(path, method string) (any, error) {
				if method == "DELETE" {
					deletions++
					if interrupted == "retirement" && deletions == 2 {
						return nil, injected
					}
				}
				return versions.api(path, method)
			}
			retirer := newVersionRetirer(api, faulty, cacheTestRepository)
			if err := migrateLegacy(faulty, cacheTestRepository, "4", 1, identity, recipients, retirer, io.Discard); !errors.Is(err, injected) {
				t.Fatal("migration did not reach interruption", err)
			}
			if interrupted == "publication" && len(versions.deleted) != 0 {
				t.Fatal("legacy versions retired before all platform heads existed")
			}
			if interrupted == "retirement" && len(versions.deleted) != 1 {
				t.Fatal("fixture did not partially retire legacy versions")
			}
			// A fresh admission reconstructs its state solely from the registry.
			retirer = newVersionRetirer(versions.api, storage, cacheTestRepository)
			if err := migrateLegacy(storage, cacheTestRepository, "5", 1, identity, recipients, retirer, io.Discard); err != nil {
				t.Fatal("migration retry failed", err)
			}
			collectTestBlobs(t, storage)
			for platform := range Systems {
				head, err := loadPlatform(storage, cacheTestRepository, platform, identity)
				if err != nil {
					t.Fatal(err)
				}
				for name, want := range archives {
					if got := string(cacheRead(t, head, name, identity)); got != want {
						t.Fatal("migration recovery lost archive", platform, name, got)
					}
				}
			}
			for _, run := range []string{"2", "3"} {
				if _, err := LoadResult(storage, cacheTestRepository, run, system, 1, identity); err != nil {
					t.Fatal("migration recovery lost terminal result", run, err)
				}
			}
			if len(storage.manifests) != len(Systems)+1 {
				t.Fatal("migration retry retained obsolete versions", len(storage.manifests))
			}
		})
	}
}
