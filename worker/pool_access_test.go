package worker

import (
	"errors"
	"strings"
	"testing"
)

func TestPoolRequiresPrivateVisibility(t *testing.T) {
	for _, visibility := range []string{"private", "public", "internal", ""} {
		t.Run(visibility, func(t *testing.T) {
			storage := &repositoryCache{}
			api := func(path, method string) (any, error) {
				if path == "users/test" {
					return map[string]any{"type": "User"}, nil
				}
				return map[string]any{"visibility": visibility}, nil
			}
			err := preparePool(api, storage, cacheTestRepository, "12", Secret{}, true)
			if (err == nil) != (visibility == "private") {
				t.Fatal(err)
			}
			if len(storage.repositories) != 0 {
				t.Fatal("modified existing package")
			}
		})
	}
}

func TestPoolBootstrapAndVisibilityRecheck(t *testing.T) {
	for _, visibility := range []string{"private", "public", "internal", ""} {
		t.Run(visibility, func(t *testing.T) {
			storage := &repositoryCache{}
			identity, recipients := cacheKeys(t)
			const pool = cacheTestRepository + "-pool"
			const tag = "nixos-cache-pool-12-bootstrap"
			api := func(path, method string) (any, error) {
				if path == "users/test" {
					return map[string]any{"type": "Organization"}, nil
				}
				if method != "GET" || path != "orgs/test/packages/container/infra-ci-pool" {
					t.Fatalf("unexpected request: %s %s", method, path)
				}
				if _, _, err := storage.GetManifest(pool, tag); err != nil {
					return nil, err
				}
				return map[string]any{"visibility": visibility}, nil
			}
			err := preparePool(api, storage, cacheTestRepository, "12", recipients, true)
			if (err == nil) != (visibility == "private") {
				t.Fatal(err)
			}
			snapshot, err := LoadSnapshot(storage, pool, tag, identity)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Manifest.Annotations["org.opencontainers.image.source"] != "" || snapshot.Manifest.Annotations[poolSourceAnnotation] != "https://github.com/test/infra-ci" {
				t.Fatal("bootstrap must retain ownership without linking the repository")
			}
			if len(snapshot.Metadata) != 2 || snapshot.Metadata["kind"] != "control" || snapshot.Metadata["run"] != "12" || len(snapshot.Files) != 0 {
				t.Fatal("bootstrap contains runner data", snapshot.Metadata)
			}
		})
	}
}

func TestPoolAccessErrorsDoNotWrite(t *testing.T) {
	for _, lookupErr := range []error{ErrObjectNotFound, errors.New("access denied")} {
		for _, create := range []bool{false, true} {
			if create && errors.Is(lookupErr, ErrObjectNotFound) {
				continue
			}
			storage := &repositoryCache{}
			api := func(path, method string) (any, error) {
				if !strings.Contains(path, "/packages/") {
					return map[string]any{"type": "User"}, nil
				}
				return nil, lookupErr
			}
			if err := preparePool(api, storage, cacheTestRepository, "12", Secret{}, create); !errors.Is(err, lookupErr) {
				t.Fatal(err)
			}
			if len(storage.repositories) != 0 {
				t.Fatal("wrote package after failed lookup")
			}
		}
	}
}

func TestPoolAPICredentialsAreScopedToExactPackage(t *testing.T) {
	const endpoint = "orgs/test/packages/container/infra-ci-pool"
	actions := func(string, string) (any, error) { return "actions", nil }
	pool := func(string, string) (any, error) { return "pool", nil }
	api := poolPackageAPI(actions, pool, endpoint)
	for path, want := range map[string]string{
		endpoint: "pool", endpoint + "/versions?page=2": "pool",
		endpoint + "/versions/1": "pool", endpoint + "-other": "actions",
		"orgs/test/packages/container/infra-ci/versions": "actions",
		"repos/test/infra-ci/actions/runs":               "actions", "users/test": "actions",
	} {
		for _, method := range []string{"GET", "DELETE"} {
			got, err := api(path, method)
			if err != nil || got != want {
				t.Fatal(path, method, got, err)
			}
		}
	}
}

func TestPoolRejectsRepositoryLink(t *testing.T) {
	api := func(path, method string) (any, error) {
		if path == "users/test" {
			return map[string]any{"type": "User"}, nil
		}
		return map[string]any{"visibility": "private", "repository": map[string]any{"full_name": "test/infra-ci"}}, nil
	}
	if err := preparePool(api, &repositoryCache{}, cacheTestRepository, "12", Secret{}, true); err == nil {
		t.Fatal("accepted repository-linked pool")
	}
}
