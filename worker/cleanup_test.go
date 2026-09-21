package worker

import (
	"encoding/json"
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
	active, recent  []map[string]any
	latest          string
	finalizingRun   string
	deleted         []int64
	inventoryCalls  int
	changeInventory bool
}

type retentionStorage struct {
	Storage
	fixture *retentionFixture
}

func (s retentionStorage) GetManifest(repository, reference string) (Manifest, string, error) {
	if reference == "nixos-cache-latest" {
		if s.fixture.latest == "" {
			return Manifest{}, "", ErrObjectNotFound
		}

		reference = s.fixture.latest
	}

	manifest, ok := s.fixture.manifests[reference]
	if !ok {
		return Manifest{}, "", ErrObjectNotFound
	}
	return manifest, reference, nil
}

func newRetentionFixture() *retentionFixture {
	f := &retentionFixture{manifests: map[string]Manifest{}}
	f.latest = f.add(100, []string{"nixos-cache-latest", "nixos-cache-run-100-1"}, map[string]any{
		"kind": "commit",
		"run":  "100",
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

	return map[string]any{"workflow_runs": f.recent}, nil
}

func (f *retentionFixture) plan() ([]Version, error) {
	plan, err := PlanCleanup(f.api, retentionStorage{fixture: f}, cacheTestRepository, f.finalizingRun, nil)
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

func TestRetentionKeepsActiveParentsAndManualPins(t *testing.T) {
	for _, tag := range []string{
		"nixos-cache-stage-2-1-1-" + strings.Repeat("a", 32),
		"nixos-cache-result-2-1-aarch64-linux",
	} {
		t.Run(tag, func(t *testing.T) {
			f := newRetentionFixture()
			parent := f.add(1, []string{"nixos-cache-run-1-1"}, map[string]any{"kind": "commit", "run": "1"})
			f.add(2, []string{tag}, map[string]any{"kind": "stage", "run": "2", "parent": parent})
			f.add(3, []string{"nixos-cache-result-3-1-aarch64-darwin"}, map[string]any{"kind": "stage", "run": "3"})
			f.add(4, []string{"manual"}, map[string]any{"kind": "commit", "run": "4"})
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
	f.add(1, []string{"nixos-cache-run-1-1"}, map[string]any{"kind": "commit", "run": "1"})
	f.add(2, []string{"nixos-cache-stage-2-1-1-" + strings.Repeat("a", 32)}, map[string]any{"kind": "stage", "run": "2"})
	f.add(3, []string{}, map[string]any{"kind": "commit", "run": "3"})

	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{1, 2, 3}) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionKeepsRecentBuilds(t *testing.T) {
	f := newRetentionFixture()
	f.add(1, []string{"nixos-cache-run-1-1"}, map[string]any{"kind": "commit", "run": "1"})
	f.add(3, []string{"nixos-cache-result-3-1-aarch64-linux"}, map[string]any{"kind": "stage", "run": "3"})
	f.recent = []map[string]any{{"id": 1}}
	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{3}) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionFailsClosedOnMissingParentsAndRunIDs(t *testing.T) {
	f := newRetentionFixture()
	f.active = []map[string]any{{"id": 100}}
	f.add(1, []string{"nixos-cache-stage-100-1-1-" + strings.Repeat("a", 32)}, map[string]any{
		"kind":   "stage",
		"run":    "100",
		"parent": "sha256:" + strings.Repeat("b", 64),
	})
	if _, err := f.plan(); err == nil || !strings.Contains(err.Error(), "parent is missing") {
		t.Fatal(err)
	}

	for _, id := range []any{nil, "invalid", 0, -1} {
		f = newRetentionFixture()
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
	f.add(1, []string{"nixos-cache-run-1-1"}, map[string]any{"kind": "commit", "run": "1"})
	storage := retentionStorage{fixture: f}

	deleted, err := Prune(f.api, storage, cacheTestRepository, "", io.Discard)
	if err != nil || deleted != 1 || !reflect.DeepEqual(f.deleted, []int64{1}) {
		t.Fatal(deleted, f.deleted, err)
	}

	f.changeInventory = true
	f.inventoryCalls = 0
	if _, err = Prune(f.api, storage, cacheTestRepository, "", io.Discard); err == nil {
		t.Fatal("changed inventory did not abort")
	}

	if !reflect.DeepEqual(f.deleted, []int64{1}) {
		t.Fatal("deleted after unsafe inventory")
	}
}

func TestPruneRechecksCacheVersionsBeforeDeletion(t *testing.T) {
	for _, change := range []string{"latest", "pin", "digest", "updated"} {
		t.Run(change, func(t *testing.T) {
			f := newRetentionFixture()
			f.add(1, []string{}, map[string]any{"kind": "commit", "run": "1"})
			api := func(path, method string) (any, error) {
				// Pool inspection finishes the plan. Change the cache before its
				// first deletion to exercise the independent candidate recheck.
				if path == "users/test/packages/container/infra-ci-pool" {
					switch change {
					case "latest":
						f.latest = ""
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
			if _, err := Prune(api, retentionStorage{fixture: f}, cacheTestRepository, "", io.Discard); err == nil || len(f.deleted) != 0 {
				t.Fatal("deleted after cache changed", f.deleted, err)
			}
		})
	}
}

func TestCleanupTagRecognition(t *testing.T) {
	for tag, want := range map[string]string{
		"nixos-cache-run-12-1":                                "12",
		"nixos-cache-stage-15-2-4-" + strings.Repeat("a", 32): "15",
		"nixos-cache-result-7-1-aarch64-linux":                "7",
		"nixos-cache-pool-12-1-aarch64-darwin-inputs-0":       "12",
		"nixos-cache-pool-12-1-aarch64-darwin-result-2":       "12",
		"nixos-cache-pool-12-1-aarch64-darwin-result-3":       "",
		"manual": "",
		"nixos-cache-stage-1-1-5-" + strings.Repeat("a", 32): "",
	} {
		if got := TagRun(tag); got != want {
			t.Fatal(tag, got)
		}
	}
}

func TestRetentionKeepsActivePoolRecordsAndExpiresCompletedRecentRuns(t *testing.T) {
	f := newRetentionFixture()
	f.active = []map[string]any{{"id": "100"}}
	f.recent = []map[string]any{{"id": "100"}, {"id": "99"}}
	f.add(101, []string{"nixos-cache-pool-100-1-aarch64-darwin-result-1"}, map[string]any{"kind": "pool", "run": "100"})
	f.add(102, []string{}, map[string]any{"kind": "pool", "run": "100"})
	f.add(103, []string{"nixos-cache-pool-99-1-aarch64-darwin-inputs-0"}, map[string]any{"kind": "pool", "run": "99"})
	f.add(104, []string{}, map[string]any{"kind": "pool", "run": "99"})
	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), []int64{103, 104}) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionDrainsFinalizingPoolAndKeepsOtherActiveRuns(t *testing.T) {
	f := newRetentionFixture()
	f.finalizingRun = "11"
	f.active = []map[string]any{{"id": "11"}, {"id": "12"}}
	f.recent = []map[string]any{{"id": "11"}, {"id": "12"}, {"id": "13"}}
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
	// Pins and recovery results survive even when their pool no longer exists.
	f.add(500, []string{"manual", "nixos-cache-pool-13-1-aarch64-linux-result-2"}, map[string]any{"kind": "pool", "run": "13"})
	f.add(501, []string{ResultTag("11", "aarch64-linux", 1)}, map[string]any{"kind": "stage", "run": "11"})
	f.add(502, []string{}, map[string]any{"kind": "stage", "run": "13"})
	candidates, err := f.plan()
	if err != nil || !reflect.DeepEqual(versionIDs(candidates), want) {
		t.Fatal(versionIDs(candidates), err)
	}
}

func TestRetentionProtectsParentsOfUntaggedRecentCheckpoints(t *testing.T) {
	f := newRetentionFixture()
	f.recent = []map[string]any{{"id": "3"}}
	parent := f.add(1, []string{}, map[string]any{"kind": "commit", "run": "1"})
	checkpoint := f.add(2, []string{}, map[string]any{"kind": "stage", "run": "2", "parent": parent})
	f.add(3, []string{}, map[string]any{"kind": "stage", "run": "3", "parent": checkpoint})
	candidates, err := f.plan()
	if err != nil || len(candidates) != 0 {
		t.Fatal("untagged recovery chain lost its parent", versionIDs(candidates), err)
	}
	delete(f.manifests, parent)
	if _, err := f.plan(); err == nil {
		t.Fatal("missing untagged parent accepted")
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
		{"different kind", []string{"nixos-cache-pool-2-1-aarch64-linux-result-2"}, map[string]any{"kind": "stage", "run": "2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRetentionFixture()
			f.add(1, []string{}, map[string]any{"kind": "commit", "run": "1"})
			f.add(2, test.tags, test.metadata)
			if candidates, err := f.plan(); err == nil || len(candidates) != 0 {
				t.Fatal("invalid pool metadata produced a deletion plan", candidates, err)
			}
		})
	}
}
