package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type retentionFixture struct {
	versions        []Version
	manifests       map[string]Manifest
	active          []map[string]any
	deleted         []int64
	inventoryCalls  int
	changeInventory bool
}

type retentionStorage struct {
	Storage
	fixture *retentionFixture
}

func (s retentionStorage) GetManifest(repository, reference string) (Manifest, string, error) {
	manifest, ok := s.fixture.manifests[reference]
	if !ok {
		return Manifest{}, "", ErrObjectNotFound
	}
	return manifest, reference, nil
}

func newRetentionFixture() *retentionFixture {
	f := &retentionFixture{manifests: map[string]Manifest{}}
	f.add(100, []string{PlatformTag("aarch64-linux")}, map[string]any{
		"kind":   "live",
		"run":    "100",
		"system": "aarch64-linux",
	})
	return f
}

func (f *retentionFixture) add(id int64, tags []string, metadata map[string]any) string {
	digest := fmt.Sprintf("sha256:%064x", id)
	version := Version{
		ID:        id,
		Name:      digest,
		CreatedAt: "2026-08-01T00:00:00Z",
		UpdatedAt: "2026-08-01T00:00:00Z",
	}
	version.Metadata.Container.Tags = tags
	f.versions = append(f.versions, version)
	manifest := Manifest{Annotations: map[string]string{
		"org.opencontainers.image.source": "https://github.com/test/infra-ci",
	}}
	if metadata != nil {
		raw, _ := json.Marshal(snapshotRetention(metadata))
		manifest.Annotations[retentionAnnotation] = string(raw)
	}
	if f.manifests == nil {
		f.manifests = map[string]Manifest{}
	}
	f.manifests[digest] = manifest
	return digest
}

func versionObject(version Version) map[string]any {
	raw, _ := json.Marshal(version)
	var result map[string]any
	json.Unmarshal(raw, &result)
	return result
}

func (f *retentionFixture) api(path, method string) (any, error) {
	if method == "DELETE" {
		id, _ := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
		f.deleted = append(f.deleted, id)
		for i, v := range f.versions {
			if v.ID == id {
				f.versions = append(f.versions[:i], f.versions[i+1:]...)
				break
			}
		}

		return nil, nil
	}

	if path == "users/test" {
		return map[string]any{"type": "User"}, nil
	}

	parsed, _ := url.Parse(path)
	query := parsed.Query()
	if query.Get("package_type") == "container" {
		return []map[string]any{}, nil
	}
	if strings.Contains(path, "/packages/") {
		if query.Has("page") {
			f.inventoryCalls++
			if f.changeInventory && f.inventoryCalls > 1 {
				return []map[string]any{}, nil
			}

			page, _ := strconv.Atoi(query.Get("page"))
			start := min((page-1)*100, len(f.versions))
			end := min(start+100, len(f.versions))
			result := []map[string]any{}
			for _, v := range f.versions[start:end] {
				result = append(result, versionObject(v))
			}

			return result, nil
		}

		id, _ := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
		for _, v := range f.versions {
			if v.ID == id {
				return versionObject(v), nil
			}
		}

		return nil, ErrObjectNotFound
	}

	if query.Has("status") {
		runs := []map[string]any{}
		if query.Get("status") == "queued" {
			runs = f.active
		}

		return map[string]any{
			"workflow_runs": runs,
			"total_count":   len(runs),
		}, nil
	}

	return nil, fmt.Errorf("unexpected GitHub request: %s", path)
}

func (f *retentionFixture) plan() ([]Version, error) {
	plan, err := PlanCleanup(f.api, retentionStorage{fixture: f}, cacheTestRepository, nil)
	if err != nil {
		return nil, err
	}
	return plan.versions, nil
}

func versionIDs(versions []Version) []int64 {
	ids := []int64{}
	for _, version := range versions {
		ids = append(ids, version.ID)
	}

	return ids
}

func TestRetentionKeepsActiveHelpersAndManualPins(t *testing.T) {
	for _, tag := range []string{
		"nixos-cache-pool-2-1-aarch64-linux-inputs-1",
		"nixos-cache-pool-2-1-aarch64-linux-result-1",
	} {
		t.Run(tag, func(t *testing.T) {
			f := newRetentionFixture()
			f.add(2, []string{tag}, map[string]any{"kind": "pool", "run": "2"})
			f.add(3, []string{"nixos-cache-pool-3-1-aarch64-darwin-result-1"}, map[string]any{"kind": "pool", "run": "3"})
			f.add(4, []string{"manual"}, map[string]any{"kind": "pool", "run": "4"})
			f.active = []map[string]any{{"id": 2}}
			candidates, err := f.plan()
			if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{3}) {
				t.Fatal(versionIDs(candidates), err)
			}
		})
	}
}

func TestRetentionExpiresOldBuildArtifacts(t *testing.T) {
	f := newRetentionFixture()
	f.add(1, []string{"nixos-cache-pool-1-1-aarch64-linux-inputs-0"}, map[string]any{"kind": "pool", "run": "1"})
	f.add(2, []string{"nixos-cache-pool-2-1-aarch64-linux-result-1"}, map[string]any{"kind": "pool", "run": "2"})
	f.add(3, []string{}, map[string]any{"kind": "pool", "run": "3"})

	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{1, 2, 3}) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionFailsClosedOnMissingAndInvalidRunIDs(t *testing.T) {
	for _, id := range []any{nil, "invalid", 0, -1} {
		f := newRetentionFixture()
		f.active = []map[string]any{{"id": id}}
		if _, err := f.plan(); err == nil {
			t.Fatal(id, err)
		}
	}
}

func TestRetentionInventoryPagination(t *testing.T) {
	f := newRetentionFixture()
	for id := int64(101); id < 13202; id++ {
		f.add(id, []string{}, nil)
	}
	_, versions, err := Inventory(f.api, cacheTestRepository)
	if err != nil || len(versions) != 13102 {
		t.Fatal(len(versions), err)
	}
}

func TestVersionInventoryHandlesAbsentPackagesWithoutHidingErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"missing", ErrObjectNotFound},
		{"forbidden", &githubStatusError{method: "GET", status: 403}},
		{"transport", errors.New("transport failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			versions, err := versionInventory(func(string, string) (any, error) { return nil, test.err }, "versions")
			if test.name == "missing" {
				if err != nil || len(versions) != 0 {
					t.Fatal("absent package did not produce an empty inventory", versions, err)
				}
			} else if !errors.Is(err, test.err) {
				t.Fatal("inventory failure was suppressed", err)
			}
		})
	}
	batch := make([]map[string]any, 100)
	for i := range batch {
		batch[i] = map[string]any{"id": i + 1}
	}
	calls := 0
	_, err := versionInventory(func(string, string) (any, error) {
		calls++
		if calls == 1 {
			return batch, nil
		}
		return nil, ErrObjectNotFound
	}, "versions")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatal("disappearance during pagination was accepted", err)
	}
}

func TestPruneAbsentPackageNeedsNoRegistryOrWorkflowReads(t *testing.T) {
	api := func(path, method string) (any, error) {
		if method != "GET" {
			t.Fatal("empty cache caused a mutation", method)
		}
		switch path {
		case "users/test":
			return map[string]any{"type": "User"}, nil
		case "users/test/packages/container/infra-ci/versions?per_page=100&page=1":
			return nil, ErrObjectNotFound
		default:
			t.Fatal("unexpected inventory request", path)
			return nil, nil
		}
	}
	if deleted, err := Prune(api, nil, cacheTestRepository, io.Discard); err != nil || deleted != 0 {
		t.Fatal("absent package blocked cleanup", deleted, err)
	}
}

func TestRetentionRejectsRepeatedAndChangingInventories(t *testing.T) {
	batch := []map[string]any{}
	for i := 0; i < 100; i++ {
		batch = append(batch, map[string]any{"id": i})
	}

	if _, err := Pages(func(string, string) (any, error) { return batch, nil }, "versions", ""); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatal(err)
	}

	f := newRetentionFixture()
	f.changeInventory = true
	if _, _, err := Inventory(f.api, cacheTestRepository); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal(err)
	}
}

func TestPruneDeletesOnlyCompleteVerifiedPlan(t *testing.T) {
	f := newRetentionFixture()
	f.add(1, []string{"nixos-cache-pool-1-1-aarch64-linux-inputs-0"}, map[string]any{"kind": "pool", "run": "1"})
	storage := retentionStorage{fixture: f}

	deleted, err := Prune(f.api, storage, cacheTestRepository, io.Discard)
	if err != nil || deleted != 1 || !reflect.DeepEqual(f.deleted, []int64{1}) {
		t.Fatal(deleted, f.deleted, err)
	}

	f.changeInventory = true
	f.inventoryCalls = 0
	if _, err = Prune(f.api, storage, cacheTestRepository, io.Discard); err == nil {
		t.Fatal("changed inventory did not abort")
	}

	if !reflect.DeepEqual(f.deleted, []int64{1}) {
		t.Fatal("deleted after unsafe inventory")
	}
}

func TestPruneRechecksCacheVersionsBeforeDeletion(t *testing.T) {
	for _, change := range []string{"pin", "digest", "updated"} {
		t.Run(change, func(t *testing.T) {
			f := newRetentionFixture()
			f.add(1, []string{}, map[string]any{"kind": "pool", "run": "1"})
			api := func(path, method string) (any, error) {
				if strings.HasSuffix(path, "/versions/1") && method == "GET" {
					switch change {
					case "pin":
						f.versions[1].Metadata.Container.Tags = []string{"keep"}
					case "digest":
						f.versions[1].Name = "sha256:" + strings.Repeat("f", 64)
					case "updated":
						f.versions[1].UpdatedAt = "2026-08-02T00:00:00Z"
					}
				}
				return f.api(path, method)
			}
			if _, err := Prune(api, retentionStorage{fixture: f}, cacheTestRepository, io.Discard); err == nil || len(f.deleted) != 0 {
				t.Fatal("deleted after cache changed", f.deleted, err)
			}
		})
	}
}

func TestCleanupTagRecognition(t *testing.T) {
	for tag, want := range map[string]string{
		"nixos-cache-pool-12-1-aarch64-darwin-inputs-0": "12",
		"nixos-cache-pool-12-1-aarch64-darwin-inputs-1": "12",
		"nixos-cache-pool-12-1-aarch64-darwin-inputs-2": "12",
		"nixos-cache-pool-12-1-aarch64-darwin-result-2": "12",
		"nixos-cache-pool-12-1-aarch64-darwin-result-3": "",
		"manual": "",
	} {
		if got := TagRun(tag); got != want {
			t.Fatal(tag, got)
		}
	}
}

func TestRetentionKeepsActivePoolRecordsAndExpiresCompletedRecentRuns(t *testing.T) {
	f := newRetentionFixture()
	f.active = []map[string]any{{"id": "100"}}
	f.add(101, []string{"nixos-cache-pool-100-1-aarch64-darwin-result-1"}, map[string]any{"kind": "pool", "run": "100"})
	f.add(102, []string{}, map[string]any{"kind": "pool", "run": "100"})
	f.add(103, []string{"nixos-cache-pool-99-1-aarch64-darwin-inputs-0"}, map[string]any{"kind": "pool", "run": "99"})
	f.add(104, []string{}, map[string]any{"kind": "pool", "run": "99"})
	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{103, 104}) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionDrainsCompletedPoolAndKeepsOtherActiveRuns(t *testing.T) {
	f := newRetentionFixture()
	f.active = []map[string]any{{"id": "12"}}
	id := int64(200)
	want := []int64{}
	for _, run := range []string{"11", "12", "13"} {
		for _, role := range []string{"inputs", "result"} {
			for runner := range RunnersPerSystem {
				if role == "inputs" && runner != 0 || role == "result" && runner == 0 {
					continue
				}
				for _, tagged := range []bool{true, false} {
					id++
					tags := []string{}
					if tagged {
						tags = append(tags, fmt.Sprintf("nixos-cache-pool-%s-1-aarch64-linux-%s-%d", run, role, runner))
					}
					f.add(id, tags, map[string]any{"kind": "pool", "run": run})
					if run != "12" {
						want = append(want, id)
					}
				}
			}
		}
	}
	// Manual pins survive even when their pool no longer exists.
	f.add(500, []string{"manual", "nixos-cache-pool-13-1-aarch64-linux-result-2"}, map[string]any{"kind": "pool", "run": "13"})
	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), want) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionRejectsUnidentifiablePoolRecords(t *testing.T) {
	for _, test := range []struct {
		name     string
		tags     []string
		metadata map[string]any
	}{
		{"missing run", []string{}, map[string]any{"kind": "pool"}},
		{"invalid run", []string{}, map[string]any{"kind": "pool", "run": "invalid"}},
		{"zero run", []string{}, map[string]any{"kind": "pool", "run": "0"}},
		{"different run", []string{"nixos-cache-pool-2-1-aarch64-linux-result-2"}, map[string]any{"kind": "pool", "run": "3"}},
		{"different kind", []string{"nixos-cache-pool-2-1-aarch64-linux-result-2"}, map[string]any{"kind": "live", "run": "2", "system": "aarch64-linux"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRetentionFixture()
			f.add(1, []string{}, map[string]any{"kind": "pool", "run": "1"})
			f.add(2, test.tags, test.metadata)
			if candidates, err := f.plan(); err == nil || len(candidates) != 0 {
				t.Fatal("invalid pool metadata produced a deletion plan", candidates, err)
			}
		})
	}
}
