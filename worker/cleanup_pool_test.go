package worker

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type poolRetentionFixture struct {
	*retentionFixture
	packageInfo     map[string]any
	pool            *retentionFixture
	deletedPackages []string
}

func newPoolRetentionFixture() *poolRetentionFixture {
	return &poolRetentionFixture{retentionFixture: newRetentionFixture()}
}

func (f *poolRetentionFixture) addPool(run string, count int) *retentionFixture {
	if f.pool == nil {
		f.packageInfo = map[string]any{
			"id": 1, "name": "infra-ci-pool", "package_type": "container",
			"repository": map[string]any{"full_name": "test/infra-ci"},
		}
		f.pool = &retentionFixture{}
	}
	pool := f.pool
	for i := 1; i <= count; i++ {
		tags := []string{}
		if i == count {
			tags = append(tags, "nixos-cache-pool-"+run+"-1-aarch64-linux-status-2")
		}
		pool.add(int64(len(pool.versions)+1), tags, map[string]any{"kind": "control", "run": run})
	}
	return pool
}

func (f *poolRetentionFixture) api(path, method string) (any, error) {
	parsed, _ := url.Parse(path)
	if parsed.Query().Get("package_type") == "container" {
		return nil, errors.New("organization-wide package listing denied")
	}
	const endpoint = "users/test/packages/container/infra-ci-pool"
	if strings.HasPrefix(parsed.Path, endpoint+"/") && f.pool != nil {
		return f.pool.api(path, method)
	}
	if parsed.Path == endpoint && f.pool != nil {
		if method == "DELETE" {
			f.deletedPackages = append(f.deletedPackages, "infra-ci-pool")
			f.pool = nil
			return nil, nil
		}
		return f.packageInfo, nil
	}
	return f.retentionFixture.api(path, method)
}

type poolRetentionStorage struct {
	Storage
	fixture *poolRetentionFixture
}

func (s poolRetentionStorage) GetManifest(repository, reference string) (Manifest, string, error) {
	fixture := s.fixture.retentionFixture
	if repository != cacheTestRepository {
		fixture = s.fixture.pool
		if repository != cacheTestRepository+"-pool" || fixture == nil {
			return Manifest{}, "", ErrObjectNotFound
		}
	}
	return (retentionStorage{fixture: fixture}).GetManifest(repository, reference)
}

func TestPoolRetentionDeletesWholePackagesAndKeepsCache(t *testing.T) {
	f := newPoolRetentionFixture()
	f.active = []map[string]any{{"id": "12"}, {"id": "13"}}
	f.recent = []map[string]any{{"id": "12"}, {"id": "13"}}
	f.addPool("12", 205)
	f.addPool("1", 3) // Cancelled run outside the recent-run window.
	storage := poolRetentionStorage{fixture: f}
	deleted, err := Prune(f.api, storage, cacheTestRepository, "12", io.Discard)
	if err != nil || deleted != 208 || !reflect.DeepEqual(f.deletedPackages, []string{"infra-ci-pool"}) {
		t.Fatal(deleted, f.deletedPackages, err)
	}
	if len(f.deleted) != 0 {
		t.Fatal("deleted cache data")
	}
	if _, _, err := storage.GetManifest(cacheTestRepository, "nixos-cache-latest"); err != nil {
		t.Fatal("cache was lost with control messages", err)
	}
}

func TestPoolRetentionProtectsPinsAndUnownedContents(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*poolRetentionFixture, *retentionFixture)
	}{
		{"manual tag", func(_ *poolRetentionFixture, p *retentionFixture) {
			p.versions[0].Metadata.Container.Tags = []string{"keep"}
		}},
		{"latest tag", func(_ *poolRetentionFixture, p *retentionFixture) {
			p.versions[0].Metadata.Container.Tags = []string{"nixos-cache-latest"}
		}},
		{"unmarked", func(_ *poolRetentionFixture, p *retentionFixture) {
			delete(p.manifests[p.versions[0].Name].Annotations, retentionAnnotation)
		}},
		{"foreign manifest", func(_ *poolRetentionFixture, p *retentionFixture) {
			p.manifests[p.versions[0].Name].Annotations["org.opencontainers.image.source"] = "https://github.com/other/repo"
		}},
		{"cache data", func(_ *poolRetentionFixture, p *retentionFixture) {
			p.manifests[p.versions[0].Name].Annotations[retentionAnnotation] = `{"kind":"pool","run":"12"}`
		}},
		{"unlinked package", func(f *poolRetentionFixture, _ *retentionFixture) { delete(f.packageInfo, "repository") }},
		{"foreign package", func(f *poolRetentionFixture, _ *retentionFixture) {
			f.packageInfo["repository"] = map[string]any{"full_name": "other/repo"}
		}},
		{"unrelated name", func(f *poolRetentionFixture, _ *retentionFixture) { f.packageInfo["name"] = "another-pool" }},
		{"empty package", func(_ *poolRetentionFixture, p *retentionFixture) { p.versions = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newPoolRetentionFixture()
			p := f.addPool("12", 2)
			test.change(f, p)
			if _, err := Prune(f.api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard); err != nil {
				t.Fatal(err)
			}
			if len(f.deletedPackages) != 0 {
				t.Fatal("deleted protected package")
			}
		})
	}
}

func TestPoolRetentionInvalidPlanDeletesNothing(t *testing.T) {
	for _, raw := range []string{`{`, `{"kind":"control","run":"0"}`, `{"kind":"control","run":"12","parent":"sha256:` + strings.Repeat("a", 64) + `"}`} {
		t.Run(raw, func(t *testing.T) {
			f := newPoolRetentionFixture()
			f.add(1, []string{}, map[string]any{"kind": "commit", "run": "1"})
			p := f.addPool("12", 3)
			p.manifests[p.versions[1].Name].Annotations[retentionAnnotation] = raw
			if _, err := Prune(f.api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard); err == nil {
				t.Fatal("accepted invalid pool metadata")
			}
			if len(f.deleted) != 0 || len(f.deletedPackages) != 0 {
				t.Fatal("deleted before validating all packages")
			}
		})
	}
}

func TestPoolRetentionRechecksBeforeDeleting(t *testing.T) {
	for _, change := range []string{"pin", "upload", "replace", "unlink", "tag run", "inventory error", "delete error"} {
		t.Run(change, func(t *testing.T) {
			f := newPoolRetentionFixture()
			p := f.addPool("12", 3)
			packageReads := 0
			api := func(path, method string) (any, error) {
				if path == "users/test/packages/container/infra-ci-pool" && method == "GET" {
					packageReads++
				}
				if packageReads == 2 {
					switch change {
					case "pin":
						p.versions[0].Metadata.Container.Tags = []string{"keep"}
					case "upload":
						p.add(4, []string{}, map[string]any{"kind": "control", "run": "12"})
					case "replace":
						f.packageInfo["id"] = 999
					case "unlink":
						delete(f.packageInfo, "repository")
					case "inventory error":
						p.changeInventory = true
					}
				}
				if change == "delete error" && method == "DELETE" {
					return nil, errors.New("deletion denied")
				}
				return f.api(path, method)
			}
			if change == "tag run" {
				p.versions[0].Metadata.Container.Tags = []string{"nixos-cache-pool-13-1-aarch64-linux-status-2"}
			}
			if _, err := Prune(api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard); err == nil {
				t.Fatal("ignored changed package or failed request")
			}
			if len(f.deletedPackages) != 0 {
				t.Fatal("deleted changed package")
			}
		})
	}
}

func TestPoolRetentionSupportsOrganizationEndpoints(t *testing.T) {
	f := newPoolRetentionFixture()
	f.addPool("12", 1)
	api := func(path, method string) (any, error) {
		if path == "users/test" {
			return map[string]any{"type": "Organization"}, nil
		}
		if strings.HasPrefix(path, "users/test/packages") {
			return nil, fmt.Errorf("used user endpoint for organization")
		}
		return f.api(strings.Replace(path, "orgs/test/", "users/test/", 1), method)
	}
	if _, err := Prune(api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard); err != nil || len(f.deletedPackages) != 1 {
		t.Fatal(f.deletedPackages, err)
	}
}

func TestPoolRetentionKeepsMessagesForAnotherActiveRun(t *testing.T) {
	f := newPoolRetentionFixture()
	f.active = []map[string]any{{"id": "12"}, {"id": "13"}}
	f.addPool("12", 3)
	f.addPool("13", 2)
	deleted, err := Prune(f.api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard)
	if err != nil || deleted != 0 || len(f.deletedPackages) != 0 || len(f.pool.versions) != 5 {
		t.Fatal(deleted, f.deletedPackages, err)
	}
}

func TestPoolRetentionFailsClosedWhenPackageLookupIsDenied(t *testing.T) {
	f := newPoolRetentionFixture()
	f.add(1, nil, map[string]any{"kind": "pool", "run": "1"})
	api := func(path, method string) (any, error) {
		if path == "users/test/packages/container/infra-ci-pool" {
			return nil, errors.New("package access denied")
		}
		return f.api(path, method)
	}
	if _, err := Prune(api, poolRetentionStorage{fixture: f}, cacheTestRepository, "12", io.Discard); err == nil || len(f.deleted) != 0 {
		t.Fatal("deleted before completing package inspection", f.deleted, err)
	}
}

func TestPoolRetentionNextRunCompletesInterruptedCleanup(t *testing.T) {
	for _, failedPath := range []string{
		"users/test/packages/container/infra-ci/versions/2",
		"users/test/packages/container/infra-ci-pool",
	} {
		t.Run(failedPath, func(t *testing.T) {
			f := newPoolRetentionFixture()
			f.active = []map[string]any{{"id": "12"}, {"id": "13"}}
			f.recent = []map[string]any{{"id": "12"}, {"id": "13"}}
			f.add(1, []string{}, map[string]any{"kind": "pool", "run": "12"})
			f.add(2, []string{}, map[string]any{"kind": "pool", "run": "12"})
			f.add(3, []string{}, map[string]any{"kind": "pool", "run": "13"})
			f.add(11, []string{ResultTag("12", "aarch64-linux", 1)}, map[string]any{
				"kind": "stage", "run": "12", "parent": f.latest,
			})
			f.addPool("12", 3)
			storage := poolRetentionStorage{fixture: f}
			failure := errors.New("temporary deletion failure")
			api := func(path, method string) (any, error) {
				if method == "DELETE" && path == failedPath {
					return nil, failure
				}
				return f.api(path, method)
			}
			if deleted, err := Prune(api, storage, cacheTestRepository, "12", io.Discard); !errors.Is(err, failure) || deleted == 0 {
				t.Fatal("did not exercise an interrupted cleanup", deleted, err)
			}
			if f.pool == nil || len(f.deletedPackages) != 0 {
				t.Fatal("lost messages before the later run could recover")
			}

			// The first run has stopped. The next finalization sees both old
			// messages and its own messages, plus only the remaining cache versions.
			f.active = []map[string]any{{"id": "13"}}
			f.addPool("13", 2)
			if _, err := Prune(f.api, storage, cacheTestRepository, "13", io.Discard); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(versionIDs(f.versions), []int64{100, 11}) || f.pool != nil || len(f.deletedPackages) != 1 {
				t.Fatal("later run did not remove leftovers or lost retained cache", versionIDs(f.versions), f.deletedPackages)
			}
		})
	}
}
