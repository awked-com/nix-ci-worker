package worker

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Registry version deletion and blob collection are deliberately separate: a
// registry may collect orphaned blobs immediately after any manifest deletion.
type registryVersions struct {
	mu      sync.Mutex
	storage *memoryCache
	ids     map[string]int64
	next    int64
	deleted []string
}

func (r *registryVersions) api(path, method string) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path == "users/test" {
		return map[string]any{"type": "User"}, nil
	}
	r.storage.mu.Lock()
	defer r.storage.mu.Unlock()
	if r.ids == nil {
		r.ids = map[string]int64{}
	}
	versions := []Version{}
	for _, digest := range sortedKeys(r.storage.manifests) {
		id := r.ids[digest]
		if id == 0 {
			r.next++
			id, r.ids[digest] = r.next, r.next
		}
		version := Version{ID: id, Name: digest, UpdatedAt: "2026-09-23T00:00:00Z"}
		version.Metadata.Container.Tags = []string{}
		for tag, target := range r.storage.tags {
			if target == digest {
				version.Metadata.Container.Tags = append(version.Metadata.Container.Tags, tag)
			}
		}
		versions = append(versions, version)
	}
	parsed, _ := url.Parse(path)
	if parsed.Query().Has("page") {
		page, _ := strconv.Atoi(parsed.Query().Get("page"))
		start, end := min((page-1)*100, len(versions)), min(page*100, len(versions))
		result := []map[string]any{}
		for _, version := range versions[start:end] {
			result = append(result, versionObject(version))
		}
		return result, nil
	}
	id, _ := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
	for _, version := range versions {
		if version.ID != id {
			continue
		}
		if method == "DELETE" {
			delete(r.storage.manifests, version.Name)
			for _, tag := range Tags(version) {
				delete(r.storage.tags, tag)
			}
			r.deleted = append(r.deleted, version.Name)
			return nil, nil
		}
		return versionObject(version), nil
	}
	return nil, ErrObjectNotFound
}

func TestRollingRetirementKeepsHeadsAndManualPins(t *testing.T) {
	f := newRetentionFixture()
	old := f.add(1, []string{}, map[string]any{"kind": "live", "run": "1", "system": "x86_64-linux"})
	head := f.add(2, []string{PlatformTag("x86_64-linux")}, map[string]any{"kind": "live", "run": "1", "system": "x86_64-linux"})
	result := f.add(3, []string{"nixos-cache-pool-1-1-x86_64-linux-result-1"}, map[string]any{"kind": "pool", "run": "1"})
	pinned := f.add(4, []string{"manual", "nixos-cache-pool-1-1-x86_64-linux-result-2"}, map[string]any{"kind": "pool", "run": "1"})
	r := newVersionRetirer(f.api, retentionStorage{fixture: f}, cacheTestRepository)
	if err := r.retire(old, head, result, pinned); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.deleted, []int64{1, 3}) || f.inventoryCalls != 1 {
		t.Fatal("unexpected deletions or full repeated scan", f.deleted, f.inventoryCalls)
	}
}

func TestRollingRetirementValidatesBeforeDeletionAndRechecksPins(t *testing.T) {
	for _, change := range []string{"invalid", "duplicate", "unowned", "pin", "missing", "delete failure"} {
		t.Run(change, func(t *testing.T) {
			f := newRetentionFixture()
			digest := f.add(1, []string{}, map[string]any{"kind": "pool", "run": "1"})
			digests := []string{digest}
			api := func(path, method string) (any, error) {
				if strings.HasSuffix(path, "/versions/1") && change == "pin" && method == "GET" {
					f.versions[1].Metadata.Container.Tags = []string{"manual"}
				}
				if method == "DELETE" && change == "delete failure" {
					return nil, errors.New("permission denied")
				}
				return f.api(path, method)
			}
			switch change {
			case "invalid":
				digests = append(digests, "invalid")
			case "duplicate":
				digests = append(digests, digest)
			case "unowned":
				delete(f.manifests[digest].Annotations, retentionAnnotation)
			case "missing":
				f.versions = f.versions[:1]
			}
			if err := newVersionRetirer(api, retentionStorage{fixture: f}, cacheTestRepository).retire(digests...); err == nil || len(f.deleted) != 0 {
				t.Fatal("unsafe retirement", err, f.deleted)
			}
		})
	}
}

func TestRollingRetirementBoundsSuccessfulTaskVersions(t *testing.T) {
	_, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	r := newVersionRetirer(versions.api, storage, cacheTestRepository)
	previous := ""
	for sequence := range 60 {
		input := NewSnapshot(storage, cacheTestRepository)
		input.Metadata = map[string]any{"kind": "pool", "run": "1", "sequence": sequence}
		in := cachePublish(t, input, "nixos-cache-pool-1-1-x86_64-linux-inputs-1", recipients)
		result := NewSnapshot(storage, cacheTestRepository)
		result.Metadata = map[string]any{"kind": "pool", "run": "1", "sequence": sequence}
		out := cachePublish(t, result, "nixos-cache-pool-1-1-x86_64-linux-result-1", recipients)
		live := NewSnapshot(storage, cacheTestRepository)
		live.Metadata = map[string]any{"kind": "live", "run": "1", "system": "x86_64-linux", "sequence": sequence}
		current := cachePublish(t, live, PlatformTag("x86_64-linux"), recipients)
		if previous != "" {
			if err := r.retire(previous); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.retire(in, out); err != nil {
			t.Fatal(err)
		}
		if len(storage.manifests) != 1 || len(storage.tags) != 1 {
			t.Fatal("completed tasks accumulated versions", sequence, len(storage.manifests), len(storage.tags))
		}
		previous = current
	}
}

func TestRecoveryRetainsActiveHelpersAndOnlyCurrentPlatformHeads(t *testing.T) {
	f := &retentionFixture{manifests: map[string]Manifest{}}
	f.active = []map[string]any{{"id": "2"}}
	for i, system := range sortedKeys(Systems) {
		f.add(int64(10+i*2), []string{}, map[string]any{"kind": "live", "run": "2", "system": system})
		f.add(int64(11+i*2), []string{PlatformTag(system)}, map[string]any{"kind": "live", "run": "2", "system": system})
	}
	f.add(30, []string{"nixos-cache-pool-2-1-x86_64-linux-inputs-1"}, map[string]any{"kind": "pool", "run": "2"})
	f.add(31, []string{"nixos-cache-pool-1-1-x86_64-linux-inputs-1"}, map[string]any{"kind": "pool", "run": "1"})
	candidates, err := f.plan()
	if err != nil || !slices.Equal(versionIDs(candidates), []int64{10, 12, 14, 31}) {
		t.Fatal(fmt.Sprint(versionIDs(candidates)), err)
	}
}

func TestRollingRetirementRetriesPartialDeletion(t *testing.T) {
	_, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	digests := []string{}
	for runner := 1; runner <= 2; runner++ {
		pool := NewSnapshot(storage, cacheTestRepository)
		pool.Metadata = map[string]any{"kind": "pool", "run": "1", "runner": runner}
		digests = append(digests, cachePublish(t, pool, fmt.Sprintf("nixos-cache-pool-1-1-x86_64-linux-result-%d", runner), recipients))
	}
	deletes := 0
	api := func(path, method string) (any, error) {
		if method == "DELETE" {
			deletes++
			if deletes == 2 {
				return nil, errors.New("temporary package deletion failure")
			}
		}
		return versions.api(path, method)
	}
	r := newVersionRetirer(api, storage, cacheTestRepository)
	if err := r.retire(digests...); err == nil || len(storage.manifests) != 1 {
		t.Fatal("partial deletion was not reported", err, len(storage.manifests))
	}
	if err := r.retire(digests...); err != nil || len(storage.manifests) != 0 {
		t.Fatal("partial retirement retry failed", err, len(storage.manifests))
	}
}
