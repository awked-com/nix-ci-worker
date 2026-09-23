package worker

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

type memoryCoordination struct {
	sync.Mutex
	objects   map[string][]byte
	latest    map[string]string
	downloads int
}

func newMemoryCoordination() *memoryCoordination {
	return &memoryCoordination{objects: map[string][]byte{}, latest: map[string]string{}}
}

func (s *memoryCoordination) Write(key string, data []byte) error {
	s.Lock()
	defer s.Unlock()
	s.objects[key] = bytes.Clone(data)
	s.latest[key[:len(key)-32]] = key
	return nil
}

func (s *memoryCoordination) Read(prefix, previous string) (string, []byte, error) {
	s.Lock()
	defer s.Unlock()
	key := s.latest[prefix]
	if key == "" {
		return "", nil, ErrObjectNotFound
	}
	if key == previous {
		return key, nil, nil
	}
	s.downloads++
	return key, bytes.Clone(s.objects[key]), nil
}

func TestCoordinationEvictionKeepsPublishedCache(t *testing.T) {
	bus := poolFixture(t)
	cache := NewSnapshot(bus.storage, bus.repository)
	cache.Metadata = map[string]any{"kind": "live", "run": bus.run, "system": bus.system}
	if err := cacheAdd(cache, "cache/nar/"+strings.Repeat("a", 64)+".nar.zst", strings.NewReader("cache archive"), bus.recipients); err != nil {
		t.Fatal(err)
	}
	digest := cachePublish(t, cache, PlatformTag(bus.system), bus.recipients)
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
	}
	storage := bus.storage.(*memoryCache)
	if len(storage.manifests) != 1 {
		t.Fatal("coordination leaked into GHCR")
	}
	bus.control = newMemoryCoordination()
	retained, err := LoadSnapshot(bus.storage, bus.repository, digest, bus.identity)
	if err != nil {
		t.Fatal(err)
	}
	for name := range retained.Files {
		if string(cacheRead(t, retained, name, bus.identity)) != "cache archive" {
			t.Fatal("lost retained archive")
		}
	}
}
