package worker

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
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
			if _, err := Prune(api, nil, cacheTestRepository, "12", &log); !errors.Is(err, test.err) {
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
	plan, err := PlanCleanup(f.api, delayed, cacheTestRepository, "1", nil)
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
		`{"kind":"stage","run":"1","parent":"missing"}`,
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
			if _, err := Prune(f.api, storage, cacheTestRepository, "1", io.Discard); err == nil || len(f.deleted) != 0 {
				t.Fatal("invalid annotation allowed deletion", f.deleted, err)
			}
		})
	}
}

func TestRetentionAnnotationsExcludePrivateMetadata(t *testing.T) {
	_, recipients := cacheKeys(t)
	snapshot := NewSnapshot(newMemoryCache(), cacheTestRepository)
	snapshot.Metadata = map[string]any{
		"kind": "stage", "run": "1", "parent": "sha256:" + strings.Repeat("a", 64),
		"binding":   map[string]any{"source": "private-revision"},
		"selection": map[string]string{"host": "private-host", "package": "private-package"},
	}
	cachePublish(t, snapshot, ResultTag("1", "aarch64-linux", 1), recipients)
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
			deleted, err := Prune(f.api, unavailableCatalogs{storage}, cacheTestRepository, "1", io.Discard)
			if err != nil || deleted != 1 || !reflect.DeepEqual(f.deleted, []int64{2}) {
				t.Fatal("retention managed an unmarked artifact", f.deleted, err)
			}
		})
	}
}

func TestRetentionPreservesArchivesUsedByExistingNodeClients(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	f := &retentionFixture{manifests: map[string]Manifest{}}
	parent := NewSnapshot(storage, cacheTestRepository)
	parent.Metadata = map[string]any{"kind": "commit", "run": "1"}
	path := cacheRecord(parent, "a")
	archive := "cache/nar/" + strings.Repeat("a", 64) + ".nar.zst"
	if err := cacheAdd(parent, archive, strings.NewReader("cached archive"), recipients); err != nil {
		t.Fatal(err)
	}
	cachePublish(t, parent, "nixos-cache-run-1-1", recipients)
	if _, err := storage.PutManifest(cacheTestRepository, "nixos-cache-latest", parent.Manifest); err != nil {
		t.Fatal(err)
	}
	f.add(1, []string{"nixos-cache-run-1-1"}, nil)
	f.versions[0].Name = parent.Digest
	pinned, err := LoadSnapshot(storage, cacheTestRepository, "nixos-cache-latest", identity)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := CacheUnion(parent, NewSnapshot(storage, cacheTestRepository))
	if err != nil {
		t.Fatal(err)
	}
	combined.Metadata = map[string]any{"kind": "commit", "run": "2"}
	digest := cachePublish(t, combined, "nixos-cache-run-2-1", recipients)
	storage.PutManifest(cacheTestRepository, "nixos-cache-latest", combined.Manifest)
	f.add(2, []string{"nixos-cache-run-2-1", "nixos-cache-latest"}, nil)
	f.versions[1].Name, f.latest = digest, digest
	api := func(endpoint, method string) (any, error) {
		if method == "DELETE" {
			id, _ := strconv.ParseInt(endpoint[strings.LastIndex(endpoint, "/")+1:], 10, 64)
			for _, version := range f.versions {
				if version.ID == id {
					storage.mu.Lock()
					delete(storage.manifests, version.Name)
					for tag, digest := range storage.tags {
						if digest == version.Name {
							delete(storage.tags, tag)
						}
					}
					storage.mu.Unlock()
				}
			}
		}
		return f.api(endpoint, method)
	}
	if _, err := Prune(api, storage, cacheTestRepository, "2", io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.deleted, []int64{1}) {
		t.Fatal("old manifest was not removed", f.deleted)
	}
	// Collect blobs no longer referenced by any retained manifest, as a registry
	// can do after version deletion. Both old and refreshed clients must work.
	keep := map[string]bool{}
	for _, version := range f.versions {
		manifest, _, err := storage.GetManifest(cacheTestRepository, version.Name)
		if err != nil {
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
	latest, err := LoadSnapshot(storage, cacheTestRepository, "nixos-cache-latest", identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []*Snapshot{pinned, latest} {
		if !snapshot.Contains(path) {
			t.Fatal("cached path disappeared")
		}
		reader, err := snapshot.Read(archive, identity)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || string(data) != "cached archive" {
			t.Fatal("cached archive became unreadable", err)
		}
	}
}
