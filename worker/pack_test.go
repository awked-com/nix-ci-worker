package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPackedArchivesRoundTripAndRetainSharedBlobs(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	packer := newNARPacker(snapshot, recipients)
	packer.limit = 4096
	payloads := map[string][]byte{}
	for i := range 24 {
		payloads[fmt.Sprintf("cache/nar/%02d.nar.zst", i)] = bytes.Repeat([]byte{byte(i)}, 100+i*17)
	}
	payloads["cache/nar/large.nar.zst"] = bytes.Repeat([]byte("large archive"), packedArchiveLimit/4)
	var group sync.WaitGroup
	for name, payload := range payloads {
		group.Go(func() {
			if err := packer.add(name, bytes.NewReader(payload)); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if err := packer.finish(); err != nil {
		t.Fatal(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	if len(storage.objects) >= len(payloads)/2 || len(storage.objects) < 3 {
		t.Fatalf("unexpected packing: %d blobs for %d archives", len(storage.objects), len(payloads))
	}
	var encrypted int64
	for name, file := range snapshot.Files {
		encrypted += file.Size
		if name == "cache/nar/large.nar.zst" {
			if file.Offset != 0 || file.Size != file.Blob.Size || file.Digest != file.Blob.Digest {
				t.Fatal("large archive was not streamed as a standalone blob")
			}
		} else if file.Blob.Size > int64(packer.limit) {
			t.Fatal("pack exceeded size bound")
		}
	}
	if packer.completed.Load() != int64(len(payloads)) || packer.encrypted.Load() != encrypted || packer.blobs.Load() != int64(len(storage.objects)) {
		t.Fatal("upload progress does not reflect durable archives")
	}
	cachePublish(t, snapshot, "packed", recipients)
	loaded := cacheLoad(t, storage, "packed", identity)
	for name, want := range payloads {
		if got := cacheRead(t, loaded, name, identity); !bytes.Equal(got, want) {
			t.Fatalf("wrong packed payload: %s", name)
		}
	}
	child := NewSnapshot(storage, cacheTestRepository)
	if err := child.Merge(loaded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(child.Files, loaded.Files) {
		t.Fatal("merge changed existing pack locations")
	}
	var keep string
	for name, file := range child.Files {
		if file.Offset > 0 {
			keep = name
			break
		}
	}
	if keep == "" {
		t.Fatal("no shared pack")
	}
	for name := range child.Files {
		if name != keep {
			delete(child.Files, name)
		}
	}
	cachePublish(t, child, "retained", recipients)
	retained := cacheLoad(t, storage, "retained", identity)
	if len(retained.Manifest.Layers) != 2 || !bytes.Equal(cacheRead(t, retained, keep, identity), payloads[keep]) {
		t.Fatal("surviving archive lost its shared pack")
	}
	if retained.Files[keep].Blob.Digest != loaded.Files[keep].Blob.Digest {
		t.Fatal("retention repacked existing ciphertext")
	}
}

func TestPackingContinuesWhilePreviousPackUploads(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := &stalledCache{memoryCache: newMemoryCache(), started: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(storage.release) })
	defer release()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	packer := newNARPacker(snapshot, recipients)
	packer.limit = 4096
	payload := strings.Repeat("x", 3000)
	if err := packer.add("first", strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	added := make(chan error, 1)
	go func() { added <- packer.add("second", strings.NewReader(payload)) }()
	defer func() { release(); packer.finish() }()
	select {
	case <-storage.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first pack upload did not start")
	}
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("next pack blocked on the previous upload")
	}
	if packer.completed.Load() != 0 {
		t.Fatal("pending packs advertised as uploaded")
	}
	finished := make(chan error, 1)
	go func() { finished <- packer.finish() }()
	select {
	case err := <-finished:
		t.Fatalf("publication finished before the pack uploaded: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second"} {
		if got := string(cacheRead(t, snapshot, name, identity)); got != payload {
			t.Fatalf("pack payload was overwritten: %s", name)
		}
	}
}

type rejectedPackStorage struct {
	Storage
	reject bool
}

func (s *rejectedPackStorage) UploadBlob(repo string, source io.Reader, encrypted bool) (Descriptor, error) {
	if s.reject {
		return Descriptor{}, errors.New("upload failed")
	}
	return s.Storage.UploadBlob(repo, source, encrypted)
}

type brokenArchive struct{}

func (brokenArchive) Read([]byte) (int, error) { return 0, errors.New("archive failed") }

func TestPackFailuresPublishOnlyCompleteUploadedRecords(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := &rejectedPackStorage{Storage: newMemoryCache()}
	snapshot := NewSnapshot(storage, cacheTestRepository)
	packer := newNARPacker(snapshot, recipients)
	if err := packer.add("cache/nar/good.nar.zst", strings.NewReader("good")); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Files) != 0 || packer.completed.Load() != 0 {
		t.Fatal("pending record advertised before upload")
	}
	if err := packer.add("cache/nar/broken.nar.zst", brokenArchive{}); err == nil {
		t.Fatal("incomplete archive accepted")
	}
	if err := packer.finish(); err != nil {
		t.Fatal(err)
	}
	if err := packer.add("cache/nar/rejected.nar.zst", strings.NewReader("rejected")); err != nil {
		t.Fatal(err)
	}
	storage.reject = true
	if err := packer.finish(); err == nil {
		t.Fatal("upload failure suppressed")
	}
	if len(snapshot.Files) != 1 || packer.completed.Load() != 1 {
		t.Fatal("failed pack changed durable records")
	}
	storage.reject = false
	if err := packer.finish(); err == nil {
		t.Fatal("ambiguous failed upload was replayed")
	}
	cachePublish(t, snapshot, "salvaged", recipients)
	loaded := cacheLoad(t, storage, "salvaged", identity)
	if string(cacheRead(t, loaded, "cache/nar/good.nar.zst", identity)) != "good" || len(loaded.Files) != 1 {
		t.Fatal("completed record was not salvaged")
	}
}

func TestSnapshotRejectsInvalidPackedLocations(t *testing.T) {
	file := SnapshotFile{
		Blob:   Descriptor{Digest: "sha256:" + strings.Repeat("a", 64), Size: 1000},
		Offset: 100, Size: 200, Digest: "sha256:" + strings.Repeat("b", 64),
	}
	for _, mutate := range []func(*SnapshotFile){
		func(f *SnapshotFile) { f.Offset = -1 },
		func(f *SnapshotFile) { f.Offset = 900 },
		func(f *SnapshotFile) { f.Offset = math.MaxInt64 },
		func(f *SnapshotFile) { f.Size = math.MaxInt64 },
		func(f *SnapshotFile) { f.Size = 0 },
		func(f *SnapshotFile) { f.Digest = "invalid" },
		func(f *SnapshotFile) { f.Blob.Digest = "invalid" },
		func(f *SnapshotFile) { f.Blob.Size = blobLimit },
		func(f *SnapshotFile) { f.Offset, f.Size = 0, f.Blob.Size },
	} {
		bad := file
		mutate(&bad)
		raw, _ := json.Marshal(map[string]SnapshotFile{"record": bad})
		var files map[string]SnapshotFile
		if err := json.Unmarshal(raw, &files); err == nil {
			t.Fatalf("accepted invalid packed file: %s", raw)
		}
	}
}
