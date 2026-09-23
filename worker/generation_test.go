package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const protectedMessage = "Package version cannot be deleted because it has more than 5,000 downloads."

func protectedResponse() error {
	body, _ := json.Marshal(map[string]string{"message": protectedMessage})
	return githubResponseError("DELETE", 403, body)
}

func TestDownloadProtectionClassification(t *testing.T) {
	for _, tc := range []struct {
		method    string
		status    int
		body      string
		protected bool
	}{
		{"DELETE", 403, `{"message":"` + protectedMessage + `"}`, true},
		{"DELETE", 400, `{"message":"You cannot delete this package version because it has been downloaded more than 5000 times."}`, true},
		{"DELETE", 422, `{"message":"Cannot delete a package version with over 5000 downloads."}`, true},
		{"GET", 403, `{"message":"` + protectedMessage + `"}`, false},
		{"DELETE", 500, `{"message":"` + protectedMessage + `"}`, false},
		{"DELETE", 403, `{"message":"Resource not accessible by integration; private-secret"}`, false},
		{"DELETE", 403, `{"message":"API rate limit exceeded"}`, false},
		{"DELETE", 403, `{"message":"Cannot delete package"}`, false},
		{"DELETE", 403, `not JSON`, false},
	} {
		err := githubResponseError(tc.method, tc.status, []byte(tc.body))
		if errors.Is(err, errDownloadProtected) != tc.protected || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestProtectedLiveGenerationsKeepTagsAndAllowFurtherPublication(t *testing.T) {
	_, recipients := cacheKeys(t)
	storage := newMemoryCache()
	versions := &registryVersions{storage: storage}
	protected := ""
	api := func(path, method string) (any, error) {
		if strings.Contains(path, "/actions/") {
			return map[string]any{"workflow_runs": []map[string]any{}, "total_count": 0}, nil
		}
		if method == "DELETE" {
			v, err := versions.api(path, "GET")
			if err != nil {
				return nil, err
			}
			current, err := decodeVersion(v)
			if err != nil {
				return nil, err
			}
			if current.Name == protected {
				return nil, protectedResponse()
			}
		}
		return versions.api(path, method)
	}
	var log bytes.Buffer
	retirer := newVersionRetirer(api, storage, cacheTestRepository)
	retirer.log = &log
	const system = "x86_64-linux"
	p := &livePublisher{snapshot: NewSnapshot(storage, cacheTestRepository), system: system, run: "123", attempt: 2, recipients: recipients, retire: retirer.retire}
	delta := NewSnapshot(storage, cacheTestRepository)
	delta.Metadata = liveTestMetadata("123", system, 2)
	for publication := 1; publication <= 3; publication++ {
		if err := p.publish(delta, false); err != nil {
			t.Fatal(err)
		}
		if publication == 1 {
			protected = p.snapshot.Digest
		}
		if storage.tags[PlatformTag(system)] != p.snapshot.Digest || storage.tags[generationTag(system, "123", 2, publication)] != p.snapshot.Digest {
			t.Fatal("head and generation tag do not address the same manifest")
		}
	}
	if len(storage.manifests) != 2 || len(storage.tags) != 3 || storage.tags[generationTag(system, "123", 2, 1)] != protected {
		t.Fatal("protected history was lost or ordinary retirement stopped", storage.tags)
	}
	if !strings.Contains(log.String(), "download limit") {
		t.Fatal("missing protection diagnostic", &log)
	}
	// Admission must also tolerate the protected old generation and preserve the head.
	if deleted, err := Prune(api, storage, cacheTestRepository, &log); err != nil || deleted != 0 || len(storage.manifests) != 2 {
		t.Fatal("protected generation blocked admission", deleted, err)
	}
	// A workflow retry has a distinct historical tag even when its counter restarts.
	p = &livePublisher{snapshot: p.snapshot, system: system, run: "123", attempt: 3, recipients: recipients, retire: retirer.retire}
	delta.Metadata = liveTestMetadata("123", system, 3)
	if err := p.publish(delta, true); err != nil {
		t.Fatal(err)
	}
	if storage.tags[generationTag(system, "123", 3, 1)] != p.snapshot.Digest || storage.tags[generationTag(system, "123", 2, 1)] != protected {
		t.Fatal("attempt tags collided")
	}
}

func TestGenerationCleanupBindingsAndProtectedDeletion(t *testing.T) {
	for _, rolling := range []bool{false, true} {
		for _, mismatch := range []bool{false, true} {
			t.Run(fmt.Sprintf("rolling=%t/mismatch=%t", rolling, mismatch), func(t *testing.T) {
				f := newRetentionFixture()
				metadata := map[string]any{"kind": "live", "system": "x86_64-linux", "run": "1", "attempt": 2, "publication": 1}
				tag := generationTag("x86_64-linux", "1", 2, 1)
				if mismatch {
					tag = generationTag("x86_64-linux", "2", 2, 1)
				}
				first := f.add(1, []string{tag}, metadata)
				metadata["publication"] = 2
				second := f.add(2, []string{generationTag("x86_64-linux", "1", 2, 2)}, metadata)
				metadata["publication"] = 3
				pinned := f.add(3, []string{generationTag("x86_64-linux", "1", 2, 3), "manual"}, metadata)
				api := func(path, method string) (any, error) {
					if method == "DELETE" && strings.HasSuffix(path, "/1") {
						return nil, protectedResponse()
					}
					return f.api(path, method)
				}
				var err error
				if rolling {
					err = newVersionRetirer(api, retentionStorage{fixture: f}, cacheTestRepository).retire(first, second, pinned)
				} else {
					var deleted int
					deleted, err = Prune(api, retentionStorage{fixture: f}, cacheTestRepository, nil)
					if !mismatch && deleted != 1 {
						t.Fatal("incorrect deletion count", deleted)
					}
				}
				if mismatch {
					if err == nil || len(f.deleted) != 0 {
						t.Fatal("mismatched tag accepted", err, f.deleted)
					}
				} else if err != nil || len(f.deleted) != 1 || f.deleted[0] != 2 {
					t.Fatal("protected version prevented later deletion or manual pin lost", err, f.deleted)
				}
			})
		}
	}
}

type failingHeadStorage struct {
	Storage
	failTag string
	calls   []string
}

func (s *failingHeadStorage) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	s.calls = append(s.calls, tag)
	if tag == s.failTag {
		return "", errors.New("tag upload failed")
	}
	return s.Storage.PutManifest(repository, tag, manifest)
}

func TestGenerationTagPublicationFailurePreservesPreviousHead(t *testing.T) {
	for _, failHead := range []bool{false, true} {
		t.Run(fmt.Sprint(failHead), func(t *testing.T) {
			_, recipients := cacheKeys(t)
			storage := newMemoryCache()
			const system = "aarch64-linux"
			base := NewSnapshot(storage, cacheTestRepository)
			base.Metadata = map[string]any{"kind": "live", "system": system, "run": "1"}
			previous := cachePublish(t, base, PlatformTag(system), recipients)
			historical := generationTag(system, "2", 1, 1)
			failTag := historical
			if failHead {
				failTag = PlatformTag(system)
			}
			failing := &failingHeadStorage{Storage: storage, failTag: failTag}
			base.Storage = failing
			retired := false
			p := &livePublisher{snapshot: base, system: system, run: "2", attempt: 1, recipients: recipients, retire: func(...string) error { retired = true; return nil }}
			delta := NewSnapshot(storage, cacheTestRepository)
			delta.Metadata = liveTestMetadata("2", system, 1)
			if err := p.publish(delta, false); err == nil {
				t.Fatal("upload failure ignored")
			}
			if retired || storage.tags[PlatformTag(system)] != previous {
				t.Fatal("failed publication retired or replaced previous head")
			}
			if (storage.tags[historical] != "") != failHead || failing.calls[0] != historical {
				t.Fatal("historical tag was not published first")
			}
		})
	}
}
