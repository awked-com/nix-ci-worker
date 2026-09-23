package worker

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type measuredCatalogStorage struct {
	Storage
	mu               sync.Mutex
	reads            map[string]int
	bytes            int64
	heads, manifests int
}

func (m *measuredCatalogStorage) Blob(repository string, descriptor Descriptor) (io.ReadCloser, error) {
	m.mu.Lock()
	m.reads[descriptor.Digest]++
	m.bytes += descriptor.Size
	m.mu.Unlock()
	return m.Storage.Blob(repository, descriptor)
}

func (m *measuredCatalogStorage) ManifestDigest(repository, reference string) (string, error) {
	m.mu.Lock()
	m.heads++
	m.mu.Unlock()
	return m.Storage.ManifestDigest(repository, reference)
}

func (m *measuredCatalogStorage) GetManifest(repository, reference string) (Manifest, string, error) {
	m.mu.Lock()
	m.manifests++
	m.mu.Unlock()
	return m.Storage.GetManifest(repository, reference)
}

func catalogFixture(storage Storage, count int) *Snapshot {
	snapshot := NewSnapshot(storage, cacheTestRepository)
	for i := range count {
		key := strings.ReplaceAll(fmt.Sprintf("%032x", i), "e", "g")
		path := "/nix/store/" + key + "-package"
		archive := "nar/" + strings.TrimPrefix(contentDigest([]byte(path)), "sha256:") + ".nar.zst"
		snapshot.Files["cache/"+archive] = wholeFile(Descriptor{Digest: contentDigest([]byte(path)), Size: 100, MediaType: "application/octet-stream"})
		snapshot.Narinfos[NarinfoKey(path)] = fmt.Sprintf("StorePath: %s\nURL: %s\nCompression: zstd\nNarHash: sha256:abc\nNarSize: 100\nReferences: \nSig: test:signature\n", path, archive)
	}
	return snapshot
}

func TestCatalogLazyLookupAndCiphertextReuse(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := catalogFixture(storage, 3000)
	snapshot.Metadata["graph"] = strings.Repeat("private build graph ", 100000)
	snapshot.Upstream["/nix/store/"+strings.Repeat("z", 32)+"-upstream"] = []string{}
	first := cachePublish(t, snapshot, "catalog", recipients)
	view, err := openCatalog(storage, cacheTestRepository, snapshot.Manifest, first, identity)
	if err != nil {
		t.Fatal(err)
	}
	measured := &measuredCatalogStorage{Storage: storage, reads: map[string]int{}}
	reader := NewSnapshotReader(measured, cacheTestRepository, "catalog", identity, nil)
	name := sortedKeys(snapshot.Narinfos)[0]
	loaded, err := reader.Current(name)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Narinfos[name] != snapshot.Narinfos[name] || len(loaded.Narinfos) == len(snapshot.Narinfos) {
		t.Fatal("lookup did not load a bounded leaf")
	}
	if len(loaded.Metadata) != 0 || len(loaded.Upstream) != 0 || (measured.reads[view.root.Writer.Digest] != 0 || measured.reads[view.root.Metadata.Digest] != 0) {
		t.Fatal("consumer loaded writer data")
	}
	if measured.bytes >= catalogNodeLimit || len(measured.reads) > 4 {
		t.Fatalf("oversized lookup: %d bytes, %d blobs", measured.bytes, len(measured.reads))
	}
	for _, descriptor := range snapshot.Manifest.Layers {
		if descriptor.Annotations[CatalogTitle] == "files" && descriptor.Size > catalogRootLimit {
			t.Fatal("oversized root")
		}
	}
	before := len(storage.objects)
	if again := cachePublish(t, snapshot, "catalog", recipients); again != first || len(storage.objects) != before {
		t.Fatal("unchanged publication uploaded fresh ciphertext")
	}
	snapshot.Metadata["updated"] = true
	second := cachePublish(t, snapshot, "catalog", recipients)
	if second == first || len(storage.objects) != before+2 {
		t.Fatalf("writer change rewrote consumer shards: objects %d -> %d", before, len(storage.objects))
	}
	full := cacheLoad(t, storage, "catalog", identity)
	if !reflect.DeepEqual(full.Files, snapshot.Files) || !reflect.DeepEqual(full.Narinfos, snapshot.Narinfos) || !reflect.DeepEqual(full.Upstream, snapshot.Upstream) || !reflect.DeepEqual(full.Metadata, snapshot.Metadata) {
		t.Fatal("full writer round trip lost data")
	}
	before = len(storage.objects)
	if republished := cachePublish(t, full, "catalog", recipients); republished != second || len(storage.objects) != before {
		t.Fatal("reload lost ciphertext reuse")
	}
	reader.deadline = time.Time{}
	if _, err = reader.Current(name); err != nil {
		t.Fatal(err)
	}
	beforeReads, beforeGets := measured.bytes, measured.manifests
	reader.deadline = time.Time{}
	if _, err = reader.Current(name); err != nil {
		t.Fatal(err)
	}
	if measured.bytes != beforeReads || measured.manifests != beforeGets || measured.heads != 2 {
		t.Fatal("unchanged refresh did not use HEAD")
	}
}

func publishV2Fixture(t *testing.T, snapshot *Snapshot, tag string, recipients Secret) string {
	t.Helper()
	data := snapshotCatalog{Format: SnapshotFormat, Version: 2, Files: snapshot.Files, Metadata: snapshot.Metadata, Narinfos: snapshot.Narinfos, Upstream: snapshot.Upstream}
	descriptor := encryptedCatalogFixture(t, snapshot.Storage, data, recipients)
	descriptor.Annotations = map[string]string{CatalogTitle: "files"}
	layers := []Descriptor{descriptor}
	for _, file := range snapshot.Files {
		layers = append(layers, file.Blob)
	}
	annotations := map[string]string{"org.opencontainers.image.source": "https://github.com/" + strings.TrimPrefix(snapshot.Repository, "ghcr.io/")}
	retention := snapshotRetention(snapshot.Metadata)
	if retention.Kind != "" {
		if err := retention.validate(); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(retention)
		if err != nil {
			t.Fatal(err)
		}
		annotations[retentionAnnotation] = string(raw)
	}
	config, err := snapshot.Storage.UploadBlob(snapshot.Repository, strings.NewReader("{}"), false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Storage.PutManifest(snapshot.Repository, tag, Manifest{SchemaVersion: 2, MediaType: manifestMediaType, Config: config, Layers: layers, Annotations: annotations})
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestCatalogLegacyMigrationAndPlatformUnion(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	legacy := catalogFixture(storage, 1)
	legacy.Metadata["legacy"] = true
	first := publishV2Fixture(t, legacy, "nixos-cache-latest", recipients)
	migrated := cacheLoad(t, storage, first, identity)
	if !reflect.DeepEqual(migrated.Narinfos, legacy.Narinfos) || !reflect.DeepEqual(migrated.Metadata, legacy.Metadata) {
		t.Fatal("legacy data lost")
	}
	systems := sortedKeys(Systems)
	platform := NewSnapshot(storage, cacheTestRepository)
	platformName := NarinfoKey(cacheRecord(platform, "a"))
	cachePublish(t, platform, PlatformTag(systems[0]), recipients)
	reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, nil)
	legacyName := sortedKeys(legacy.Narinfos)[0]
	for _, name := range []string{legacyName, platformName} {
		current, err := reader.Current(name)
		if err != nil || !current.HasFile(name) {
			t.Fatalf("migration union missing %s: %v", name, err)
		}
	}
	for _, system := range systems {
		cachePublish(t, migrated, PlatformTag(system), recipients)
	}
	measured := &measuredCatalogStorage{Storage: storage, reads: map[string]int{}}
	reader = NewSnapshotReader(measured, cacheTestRepository, "", identity, nil)
	current, err := reader.Current(legacyName)
	if err != nil || !current.HasFile(legacyName) {
		t.Fatal(err)
	}
	if len(reader.views) != len(Systems) || reader.views["nixos-cache-latest"] != nil {
		t.Fatal("complete migration still downloads legacy catalog")
	}
	if measured.manifests != len(Systems) {
		t.Fatalf("unexpected manifest reads %d", measured.manifests)
	}
}

func TestCatalogConcurrentLookupsPreserveImmutableViews(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := catalogFixture(storage, 3000)
	cachePublish(t, snapshot, "catalog", recipients)
	reader := NewSnapshotReader(storage, cacheTestRepository, "catalog", identity, nil)
	names := sortedKeys(snapshot.Narinfos)
	original, err := reader.Current(names[0])
	if err != nil {
		t.Fatal(err)
	}
	originalFiles, originalRecords := len(original.Files), len(original.Narinfos)
	var done sync.WaitGroup
	for i := range 32 {
		done.Add(1)
		go func() {
			defer done.Done()
			name := names[i*90]
			current, err := reader.Current(name)
			if err != nil || !current.HasFile(name) {
				t.Errorf("lookup %s: %v", name, err)
			}
		}()
	}
	done.Wait()
	if len(original.Files) != originalFiles || len(original.Narinfos) != originalRecords {
		t.Fatal("reader mutated caller-owned snapshot")
	}
}

func TestCatalogRefreshesAfterUnloadedShardCollection(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := catalogFixture(storage, 3000)
	digest := cachePublish(t, snapshot, "catalog", recipients)
	reader := NewSnapshotReader(storage, cacheTestRepository, "catalog", identity, nil)
	if _, err := reader.Current(""); err != nil {
		t.Fatal(err)
	}
	obsolete := reader.views["catalog"].root.Index
	name := sortedKeys(snapshot.Narinfos)[0]
	snapshot.Narinfos[name] += "Sig: additional:signature\n"
	next := cachePublish(t, snapshot, "catalog", recipients)
	if next == digest {
		t.Fatal("fixture did not change root")
	}
	delete(storage.objects, obsolete.Digest)
	current, err := reader.Current(name)
	if err != nil || current.Narinfos[name] != snapshot.Narinfos[name] || current.Digest != next {
		t.Fatalf("did not recover collected shard: %v", err)
	}
}

func TestCatalogWriterShardsReuseUnchangedCoverage(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := catalogFixture(storage, 1)
	for i := range 20000 {
		path := "/nix/store/" + strings.ReplaceAll(fmt.Sprintf("%032x", i), "e", "g") + "-upstream"
		snapshot.Upstream[path] = []string{}
	}
	cachePublish(t, snapshot, "catalog", recipients)
	loaded := cacheLoad(t, storage, "catalog", identity)
	if !reflect.DeepEqual(loaded.Upstream, snapshot.Upstream) {
		t.Fatal("writer shards lost upstream coverage")
	}
	first, err := openCatalog(storage, cacheTestRepository, snapshot.Manifest, snapshot.Digest, identity)
	if err != nil {
		t.Fatal(err)
	}
	count := len(storage.objects)
	snapshot.Metadata["progress"] = 1
	cachePublish(t, snapshot, "catalog", recipients)
	second, err := openCatalog(storage, cacheTestRepository, snapshot.Manifest, snapshot.Digest, identity)
	if err != nil {
		t.Fatal(err)
	}
	if second.root.Writer.Digest != first.root.Writer.Digest || len(storage.objects) != count+2 {
		t.Fatal("progress change rewrote cumulative writer coverage")
	}
	count = len(storage.objects)
	snapshot.Upstream["/nix/store/"+strings.Repeat("z", 32)+"-additional"] = []string{}
	cachePublish(t, snapshot, "catalog", recipients)
	if added := len(storage.objects) - count; added < 3 || added > 5 {
		t.Fatalf("single coverage addition uploaded %d blobs", added)
	}
	loaded = cacheLoad(t, storage, "catalog", identity)
	if !reflect.DeepEqual(loaded.Upstream, snapshot.Upstream) {
		t.Fatal("changed writer coverage did not round trip")
	}
}

func TestCatalogEmptySnapshotsAndRecipientRotation(t *testing.T) {
	oldIdentity, oldRecipients := cacheKeys(t)
	newIdentity, newRecipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	first := cachePublish(t, snapshot, "catalog", oldRecipients)
	count := len(storage.objects)
	if second := cachePublish(t, snapshot, "catalog", oldRecipients); first != second || len(storage.objects) != count {
		t.Fatal("empty snapshot did not reuse ciphertext")
	}
	if loaded := cacheLoad(t, storage, "catalog", oldIdentity); len(loaded.Files) != 0 || len(loaded.Narinfos) != 0 || len(loaded.Upstream) != 0 {
		t.Fatal("empty round trip changed")
	}
	cachePublish(t, snapshot, "catalog", newRecipients)
	if _, err := LoadSnapshot(storage, cacheTestRepository, "catalog", oldIdentity); err == nil {
		t.Fatal("rotated catalogs reused old recipients")
	}
	cacheLoad(t, storage, "catalog", newIdentity)
}

func TestCatalogValidatesBeforeUploading(t *testing.T) {
	_, recipients := cacheKeys(t)
	for _, kind := range []string{"metadata", "record", "tag"} {
		t.Run(kind, func(t *testing.T) {
			storage := newMemoryCache()
			snapshot := catalogFixture(storage, 2)
			if kind == "metadata" {
				snapshot.Metadata["invalid"] = make(chan int)
			} else if kind == "record" {
				name := sortedKeys(snapshot.Narinfos)[0]
				snapshot.Narinfos[name] += "Sig: test:" + strings.Repeat("x", catalogNodeLimit) + "\n"
			}
			tag := "catalog"
			if kind == "tag" {
				tag = "invalid/tag"
			}
			if _, err := snapshot.Publish(tag, recipients); err == nil {
				t.Fatal("invalid input accepted")
			}
			if len(storage.objects) != 0 || len(storage.manifests) != 0 {
				t.Fatal("invalid input uploaded data")
			}
		})
	}
}

func encryptedCatalogFixture(t *testing.T, storage Storage, value any, recipients Secret) Descriptor {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	stream, err := EncryptedStream(&compressed, recipients)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := storage.UploadBlob(cacheTestRepository, stream, true)
	stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func TestCatalogRejectsMalformedNodesAndPreservesUsableRecords(t *testing.T) {
	identity, recipients := cacheKeys(t)
	for _, kind := range []string{"empty", "writer-data", "unsigned", "archive", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			storage := newMemoryCache()
			snapshot := catalogFixture(storage, 1)
			cachePublish(t, snapshot, "catalog", recipients)
			name := sortedKeys(snapshot.Narinfos)[0]
			reader := NewSnapshotReader(storage, cacheTestRepository, "catalog", identity, nil)
			initial, err := reader.Current(name)
			if err != nil {
				t.Fatal(err)
			}
			view := reader.views["catalog"]
			node, err := view.node(view.root.Index, "", true, identity)
			if err != nil {
				t.Fatal(err)
			}
			record := node.Records[name]
			switch kind {
			case "empty":
				node = catalogNode{}
			case "writer-data":
				refs := []string{}
				record.References = &refs
			case "unsigned":
				record.Narinfo = strings.ReplaceAll(record.Narinfo, "Sig: test:signature\n", "")
			case "archive":
				record.Archive = nil
			case "oversized":
				record.Narinfo += "Sig: test:" + strings.Repeat("x", catalogNodeLimit) + "\n"
			}
			if kind != "empty" {
				node.Records[name] = record
			}
			index := encryptedCatalogFixture(t, storage, node, recipients)
			root := view.root
			root.Index = index
			descriptor := encryptedCatalogFixture(t, storage, root, recipients)
			descriptor.Annotations = map[string]string{CatalogTitle: "files"}
			descriptor.MediaType = catalogRootMediaType
			manifest := view.manifest
			manifest.Layers = []Descriptor{index, descriptor}
			for _, layer := range view.manifest.Layers {
				if layer.Annotations[CatalogTitle] != "files" {
					manifest.Layers = append(manifest.Layers, layer)
				}
			}
			if _, err = storage.PutManifest(cacheTestRepository, "catalog", manifest); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadSnapshot(storage, cacheTestRepository, "catalog", identity); err == nil {
				t.Fatal("accepted malformed catalog")
			}
			fresh := NewSnapshotReader(storage, cacheTestRepository, "catalog", identity, nil)
			if _, err = fresh.Current(name); err == nil {
				t.Fatal("consumer accepted malformed catalog")
			}
			reader.deadline = time.Time{}
			usable, err := reader.Current(name)
			if err != nil || usable.Narinfos[name] != initial.Narinfos[name] {
				t.Fatalf("lost usable stale record: %v", err)
			}
		})
	}
}

func TestCatalogUnionChecksRecordsBeforeMerging(t *testing.T) {
	identity, recipients := cacheKeys(t)
	for _, conflicting := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflicting=%v", conflicting), func(t *testing.T) {
			storage := newMemoryCache()
			systems := sortedKeys(Systems)
			first := NewSnapshot(storage, cacheTestRepository)
			a := NarinfoKey(cacheRecord(first, "a"))
			cachePublish(t, first, PlatformTag(systems[0]), recipients)
			second := NewSnapshot(storage, cacheTestRepository)
			cacheRecord(second, "a")
			b := NarinfoKey(cacheRecord(second, "b"))
			archive := "cache/nar/" + strings.Repeat("a", 64) + ".nar.zst"
			second.Files[archive] = wholeFile(Descriptor{Digest: contentDigest([]byte("another encryption")), Size: 3, MediaType: "application/octet-stream"})
			if conflicting {
				second.Narinfos[a] = strings.ReplaceAll(second.Narinfos[a], "NarSize: 3", "NarSize: 4")
			}
			cachePublish(t, second, PlatformTag(systems[1]), recipients)
			reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, nil)
			original, err := reader.Current(a)
			if err != nil {
				t.Fatal(err)
			}
			merged, err := reader.Current(b)
			if conflicting {
				if err == nil || !strings.Contains(err.Error(), "conflicting cache record") {
					t.Fatalf("accepted conflict: %v", err)
				}
				if reader.snapshot.HasFile(b) {
					t.Fatal("conflicting source partially changed reader")
				}
			} else if err != nil || !merged.HasFile(b) {
				t.Fatalf("equivalent duplicate rejected: %v", err)
			}
			current, err := reader.Current(a)
			if err != nil || current.Narinfos[a] != original.Narinfos[a] || current.Files[archive].Blob.Digest != original.Files[archive].Blob.Digest {
				t.Fatal("duplicate records replaced usable ciphertext")
			}
		})
	}
}

// Requests stay blocked until the test observes the full worker pool. This
// proves network operations overlap without relying on elapsed-time thresholds.
type blockedCatalogStorage struct {
	Storage
	uploads bool
	blobs   map[string]bool
	entered chan struct{}
	release chan struct{}
	failure error
	active  atomic.Int32
	maximum atomic.Int32
}

func (s *blockedCatalogStorage) block() error {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for maximum := s.maximum.Load(); active > maximum; maximum = s.maximum.Load() {
		if s.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return s.failure
}

func (s *blockedCatalogStorage) UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error) {
	if s.uploads {
		if err := s.block(); err != nil {
			return Descriptor{}, err
		}
	}
	return s.Storage.UploadBlob(repository, source, encrypted)
}

func (s *blockedCatalogStorage) Blob(repository string, descriptor Descriptor) (io.ReadCloser, error) {
	if s.blobs[descriptor.Digest] {
		if err := s.block(); err != nil {
			return nil, err
		}
	}
	return s.Storage.Blob(repository, descriptor)
}

func waitCatalogRequests(t *testing.T, storage *blockedCatalogStorage) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for range catalogConcurrency {
		select {
		case <-storage.entered:
		case <-deadline.C:
			t.Fatal("catalog requests did not run concurrently")
		}
	}
	if got := storage.maximum.Load(); got != catalogConcurrency {
		t.Fatalf("concurrent requests = %d, want %d", got, catalogConcurrency)
	}
}

func TestCatalogBoundedParallelPublicationAndFailure(t *testing.T) {
	_, recipients := cacheKeys(t)
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			memory := newMemoryCache()
			storage := &blockedCatalogStorage{Storage: memory, uploads: true, entered: make(chan struct{}, catalogConcurrency), release: make(chan struct{})}
			if fail {
				storage.failure = errors.New("failed catalog upload")
			}
			defer func() {
				if storage.release != nil {
					close(storage.release)
				}
			}()
			snapshot := catalogFixture(storage, 3000)
			result := make(chan error, 1)
			go func() { _, err := snapshot.Publish("catalog", recipients); result <- err }()
			waitCatalogRequests(t, storage)
			close(storage.release)
			if err := <-result; !errors.Is(err, storage.failure) {
				t.Fatalf("publication error = %v, want %v", err, storage.failure)
			}
			storage.release = nil
			if storage.maximum.Load() > catalogConcurrency || storage.active.Load() != 0 {
				t.Fatal("catalog publication exceeded its concurrency bound or left requests running")
			}
			if fail && (snapshot.Digest != "" || len(memory.manifests) != 0) {
				t.Fatal("failed catalog upload published a partial manifest")
			}
		})
	}
}

func TestCatalogBoundedParallelLoadAndFailure(t *testing.T) {
	identity, recipients := cacheKeys(t)
	memory := newMemoryCache()
	snapshot := catalogFixture(memory, 3000)
	cachePublish(t, snapshot, "catalog", recipients)
	view, err := openCatalog(memory, cacheTestRepository, snapshot.Manifest, snapshot.Digest, identity)
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string]bool{}
	for _, descriptor := range snapshot.Manifest.Layers {
		if descriptor.Annotations[CatalogTitle] != "files" && descriptor.Digest != view.root.Index.Digest && descriptor.Digest != view.root.Writer.Digest && descriptor.Digest != view.root.Metadata.Digest {
			blobs[descriptor.Digest] = true
		}
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			storage := &blockedCatalogStorage{Storage: memory, blobs: blobs, entered: make(chan struct{}, catalogConcurrency), release: make(chan struct{})}
			if fail {
				storage.failure = errors.New("failed catalog download")
			}
			defer func() {
				if storage.release != nil {
					close(storage.release)
				}
			}()
			result := make(chan error, 1)
			go func() {
				loaded, err := LoadSnapshot(storage, cacheTestRepository, "catalog", identity)
				if err == nil && (!reflect.DeepEqual(snapshot.Files, loaded.Files) || !reflect.DeepEqual(snapshot.Narinfos, loaded.Narinfos)) {
					err = errors.New("parallel catalog load lost records")
				}
				if err != nil && loaded != nil {
					err = errors.New("failed load returned a partial snapshot")
				}
				result <- err
			}()
			waitCatalogRequests(t, storage)
			close(storage.release)
			if err := <-result; !errors.Is(err, storage.failure) {
				t.Fatalf("load error = %v, want %v", err, storage.failure)
			}
			storage.release = nil
			if storage.maximum.Load() > catalogConcurrency || storage.active.Load() != 0 {
				t.Fatal("catalog load exceeded its concurrency bound or left requests running")
			}
		})
	}
}

func TestCatalogConsumerAndWriterNodeBounds(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	// One large record fits a writer node, while the consumer bound is kept
	// small independently of the larger writer-only coverage shards.
	snapshot := NewSnapshot(storage, cacheTestRepository)
	path := "/nix/store/" + strings.Repeat("0", 32) + "-coverage"
	snapshot.Upstream[path] = make([]string, 3000)
	for i := range snapshot.Upstream[path] {
		snapshot.Upstream[path][i] = path
	}
	cachePublish(t, snapshot, "catalog", recipients)
	loaded := cacheLoad(t, storage, "catalog", identity)
	if !reflect.DeepEqual(loaded.Upstream, snapshot.Upstream) {
		t.Fatal("larger writer node lost coverage")
	}
	view, err := openCatalog(storage, cacheTestRepository, snapshot.Manifest, snapshot.Digest, identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readCatalogBlob(storage, cacheTestRepository, view.root.Writer, identity, catalogWriterNodeLimit)
	if err != nil || len(raw) <= catalogNodeLimit {
		t.Fatalf("writer node size=%d error=%v", len(raw), err)
	}
	if _, err = readCatalogBlob(storage, cacheTestRepository, view.root.Writer, identity, catalogNodeLimit); err == nil {
		t.Fatal("consumer size bound was relaxed")
	}
	snapshot.Upstream[path] = make([]string, catalogWriterNodeLimit/len(path)+1)
	for i := range snapshot.Upstream[path] {
		snapshot.Upstream[path][i] = path
	}
	before := len(storage.objects)
	if _, err = snapshot.Publish("oversized", recipients); err == nil {
		t.Fatal("oversized writer record accepted")
	}
	if len(storage.objects) != before {
		t.Fatal("invalid writer tree uploaded partial data")
	}
}
