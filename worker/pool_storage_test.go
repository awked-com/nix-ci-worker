package worker

import (
	"io"
	"strings"
	"sync"
	"testing"
)

// Keep registry namespaces separate so a pool cannot accidentally read its
// control records from the cache package or publish archives with its leases.
type repositoryCache struct {
	mu           sync.Mutex
	repositories map[string]*memoryCache
}

func (s *repositoryCache) cache(repository string) *memoryCache {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repositories == nil {
		s.repositories = map[string]*memoryCache{}
	}
	if s.repositories[repository] == nil {
		s.repositories[repository] = newMemoryCache()
	}
	return s.repositories[repository]
}

func (s *repositoryCache) UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error) {
	return s.cache(repository).UploadBlob(repository, source, encrypted)
}

func (s *repositoryCache) Blob(repository string, descriptor Descriptor) (io.ReadCloser, error) {
	return s.cache(repository).Blob(repository, descriptor)
}

func (s *repositoryCache) BlobRange(repository string, file SnapshotFile) (io.ReadCloser, error) {
	return s.cache(repository).BlobRange(repository, file)
}

func (s *repositoryCache) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	return s.cache(repository).PutManifest(repository, tag, manifest)
}

func (s *repositoryCache) GetManifest(repository, reference string) (Manifest, string, error) {
	return s.cache(repository).GetManifest(repository, reference)
}

func TestPoolControlPackageCanBeRemovedWithoutLosingCache(t *testing.T) {
	storage := &repositoryCache{}
	bus := poolFixture(t)
	bus.storage, bus.control = storage, storage
	cache := NewSnapshot(storage, bus.repository)
	cache.Metadata = map[string]any{"kind": "commit", "run": bus.run}
	if err := cacheAdd(cache, "cache/nar/"+strings.Repeat("a", 64)+".nar.zst", strings.NewReader("cache archive"), bus.recipients); err != nil {
		t.Fatal(err)
	}
	digest := cachePublish(t, cache, "nixos-cache-latest", bus.recipients)
	for _, role := range []string{"coordinator", "assignment", "status"} {
		runner := 1
		if role == "coordinator" {
			runner = 0
		}
		if err := bus.write(role, runner, poolMessage{State: "ready"}); err != nil {
			t.Fatal(err)
		}
		message, err := bus.read(role, runner)
		if err != nil || message.State != "ready" {
			t.Fatal(message, err)
		}
		manifest, _, err := storage.GetManifest(bus.controlRepository(), bus.tag(role, runner))
		if err != nil || manifest.Annotations[poolSourceAnnotation] != "https://github.com/test/infra-ci" || manifest.Annotations["org.opencontainers.image.source"] != "" {
			t.Fatal(manifest, err)
		}
		control, err := LoadSnapshot(storage, bus.controlRepository(), bus.tag(role, runner), bus.identity)
		if err != nil {
			t.Fatal(err)
		}
		if len(control.Files) != 0 || control.Metadata["kind"] != "control" {
			t.Fatal("control package contains cache data", control.Metadata)
		}
	}
	if len(storage.cache(bus.repository).manifests) != 1 {
		t.Fatal("control records leaked into cache package")
	}
	delete(storage.repositories, bus.controlRepository())
	retained, err := LoadSnapshot(storage, bus.repository, digest, bus.identity)
	if err != nil {
		t.Fatal(err)
	}
	for name := range retained.Files {
		if string(cacheRead(t, retained, name, bus.identity)) != "cache archive" {
			t.Fatal("lost retained archive")
		}
	}
}
