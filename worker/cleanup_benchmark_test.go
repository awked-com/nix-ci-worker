package worker

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

func publishedRetentionFixture(t testing.TB, count int) (*retentionFixture, *memoryCache) {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := Secret{Data: []byte(key.Recipient().String())}
	storage := newMemoryCache()
	f := &retentionFixture{manifests: map[string]Manifest{}}
	for i := 1; i <= count; i++ {
		snapshot := NewSnapshot(storage, cacheTestRepository)
		snapshot.Metadata = map[string]any{"kind": "pool", "run": "1", "sequence": i}
		digest, err := snapshot.Publish("nixos-cache-pool-1-1-aarch64-linux-inputs-0", recipients)
		if err != nil {
			t.Fatal(err)
		}
		f.add(int64(i), []string{}, nil)
		f.versions[i-1].Name = digest
	}
	return f, storage
}

// Model request latency without depending on GHCR availability or credentials.
type delayedRetentionStorage struct {
	Storage
	delay     time.Duration
	requests  atomic.Int64
	active    atomic.Int64
	maxActive atomic.Int64
}

func (s *delayedRetentionStorage) GetManifest(repository, reference string) (Manifest, string, error) {
	s.requests.Add(1)
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for peak := s.maxActive.Load(); active > peak; peak = s.maxActive.Load() {
		if s.maxActive.CompareAndSwap(peak, active) {
			break
		}
	}
	time.Sleep(s.delay)
	return s.Storage.GetManifest(repository, reference)
}

func BenchmarkRetentionPlanning(b *testing.B) {
	for _, versions := range []int{100, 400} {
		b.Run(fmt.Sprint(versions), func(b *testing.B) {
			f, storage := publishedRetentionFixture(b, versions)
			delayed := &delayedRetentionStorage{Storage: storage, delay: 2 * time.Millisecond}
			b.ResetTimer()
			for b.Loop() {
				plan, err := PlanCleanup(f.api, delayed, cacheTestRepository, "1", nil)
				if err != nil {
					b.Fatal(err)
				}
				candidates := plan.versions
				if len(candidates) != versions {
					b.Fatal(len(candidates), err)
				}
			}
			b.ReportMetric(float64(delayed.requests.Load())/float64(b.N), "registry-requests/op")
		})
	}
}

func (s *delayedRetentionStorage) ManifestDigest(repository, reference string) (string, error) {
	_, digest, err := s.GetManifest(repository, reference)
	return digest, err
}

func BenchmarkRetentionDeletion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f, storage := publishedRetentionFixture(b, 100)
		delayed := &delayedRetentionStorage{Storage: storage, delay: 2 * time.Millisecond}
		api := func(path, method string) (any, error) {
			if method == "DELETE" || strings.Contains(path, "/versions/") {
				time.Sleep(2 * time.Millisecond)
			}
			return f.api(path, method)
		}
		b.StartTimer()
		deleted, err := Prune(api, delayed, cacheTestRepository, "1", nil)
		if err != nil || deleted != 100 {
			b.Fatal(deleted, err)
		}
	}
}
