package worker

import (
	"errors"
	"fmt"
	"testing"
)

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
			base.Metadata = map[string]any{"kind": "live", "system": system, "run": "1", "attempt": 1, "publication": 1}
			previous := cachePublish(t, base, PlatformTag(system), recipients)
			historical := generationTag(system, "2", 1, 1)
			failTag := historical
			if failHead {
				failTag = PlatformTag(system)
			}
			failing := &failingHeadStorage{Storage: storage, failTag: failTag}
			base.Storage = failing
			p := &livePublisher{snapshot: base, system: system, run: "2", attempt: 1, recipients: recipients}
			delta := NewSnapshot(storage, cacheTestRepository)
			delta.Metadata = liveTestMetadata("2", system, 1)
			if err := p.publish(delta, false); err == nil {
				t.Fatal("upload failure ignored")
			}
			if storage.tags[PlatformTag(system)] != previous {
				t.Fatal("failed publication retired or replaced previous head")
			}
			if (storage.tags[historical] != "") != failHead || failing.calls[0] != historical {
				t.Fatal("historical tag was not published first")
			}
		})
	}
}
