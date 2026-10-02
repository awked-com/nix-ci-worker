package worker

import (
	"bytes"
	"sync"
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
