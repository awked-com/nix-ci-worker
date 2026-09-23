package worker

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRetentionReportsHTTPFailuresWithoutPrivateErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		http bool
	}{
		{"permission", &githubStatusError{method: "GET", status: 403}, true},
		{"transport", errors.New("private URL and credential"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var log bytes.Buffer
			api := func(string, string) (any, error) { return nil, test.err }
			if _, err := Prune(api, nil, cacheTestRepository, &log); !errors.Is(err, test.err) {
				t.Fatal("lost failure", err)
			}
			if !strings.Contains(log.String(), "planning cleanup") || strings.Contains(log.String(), "private") || strings.Contains(log.String(), "HTTP 403") != test.http {
				t.Fatal("missing diagnostic or exposed private error", &log)
			}
		})
	}
}

type unavailableCatalogs struct{ Storage }

func (s unavailableCatalogs) Blob(string, Descriptor) (io.ReadCloser, error) {
	return nil, errors.New("catalog downloads disabled")
}

func TestRetentionPlansFromManifestsWithoutCatalogDownloads(t *testing.T) {
	f, storage := publishedRetentionFixture(t, 40)
	delayed := &delayedRetentionStorage{Storage: unavailableCatalogs{storage}, delay: 2 * time.Millisecond}
	plan, err := PlanCleanup(f.api, delayed, cacheTestRepository, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates := plan.versions
	if len(candidates) != 40 {
		t.Fatal(len(candidates), err)
	}
	if peak := delayed.maxActive.Load(); peak < 2 || peak > retentionReaders {
		t.Fatal("manifest scan concurrency is not bounded", peak)
	}
}

func TestRetentionRejectsMalformedAnnotationsBeforeDeletion(t *testing.T) {
	for _, raw := range []string{
		"",
		`{`,
		`{"kind":"pool","run":"0"}`,
		`{"kind":"unknown","run":"1"}`,
		`{"kind":"live","run":"1","system":"unknown"}`,
		`{"kind":"pool","run":"1","unexpected":true}`,
		`{"kind":"pool","run":"1"} {}`,
	} {
		t.Run(raw, func(t *testing.T) {
			f, storage := publishedRetentionFixture(t, 20)
			manifest, _, err := storage.GetManifest(cacheTestRepository, f.versions[10].Name)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Annotations[retentionAnnotation] = raw
			digest, err := storage.PutManifest(cacheTestRepository, "invalid", manifest)
			if err != nil {
				t.Fatal(err)
			}
			f.versions[10].Name = digest
			if _, err := Prune(f.api, storage, cacheTestRepository, io.Discard); err == nil || len(f.deleted) != 0 {
				t.Fatal("invalid annotation allowed deletion", f.deleted, err)
			}
		})
	}
}

func TestRetentionAnnotationsExcludePrivateMetadata(t *testing.T) {
	_, recipients := cacheKeys(t)
	snapshot := NewSnapshot(newMemoryCache(), cacheTestRepository)
	snapshot.Metadata = map[string]any{
		"kind": "pool", "run": "1",
		"binding":   map[string]any{"source": "private-revision"},
		"selection": map[string]string{"host": "private-host", "package": "private-package"},
	}
	cachePublish(t, snapshot, "nixos-cache-pool-1-1-aarch64-linux-result-1", recipients)
	for _, value := range snapshot.Manifest.Annotations {
		if strings.Contains(value, "private-") {
			t.Fatal("private metadata in manifest annotations")
		}
	}
}

func TestRetentionRequiresBothOwnershipAnnotations(t *testing.T) {
	for _, annotation := range []string{retentionAnnotation, "org.opencontainers.image.source"} {
		t.Run(annotation, func(t *testing.T) {
			f, storage := publishedRetentionFixture(t, 2)
			manifest, _, err := storage.GetManifest(cacheTestRepository, f.versions[0].Name)
			if err != nil {
				t.Fatal(err)
			}
			delete(manifest.Annotations, annotation)
			digest, err := storage.PutManifest(cacheTestRepository, "unmarked", manifest)
			if err != nil {
				t.Fatal(err)
			}
			f.versions[0].Name = digest
			deleted, err := Prune(f.api, unavailableCatalogs{storage}, cacheTestRepository, io.Discard)
			if err != nil || deleted != 1 || !reflect.DeepEqual(f.deleted, []int64{2}) {
				t.Fatal("retention managed an unmarked artifact", f.deleted, err)
			}
		})
	}
}

func TestPruneStopsWhenCandidateReadFails(t *testing.T) {
	f := newRetentionFixture()
	f.add(1, []string{}, map[string]any{"kind": "pool", "run": "1"})
	failure := errors.New("candidate lookup failed")
	api := func(path, method string) (any, error) {
		if strings.HasSuffix(path, "/versions/1") && method == "GET" {
			return nil, failure
		}
		return f.api(path, method)
	}
	deleted, err := Prune(api, retentionStorage{fixture: f}, cacheTestRepository, io.Discard)
	if !errors.Is(err, failure) || deleted != 0 || len(f.deleted) != 0 {
		t.Fatal("deleted after failed check", deleted, err)
	}
}
