package worker

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

func packFixture(payload []byte, offset, size int64) SnapshotFile {
	return SnapshotFile{Blob: Descriptor{Digest: contentDigest(payload), Size: int64(len(payload))}, Offset: offset, Size: size, Digest: contentDigest(payload[offset : offset+size])}
}

func TestPackDownloadsCoalesceAndVerifyRecords(t *testing.T) {
	payload := bytes.Repeat([]byte("encrypted record"), 256)
	file := packFixture(payload, 100, 200)
	cache := newPackDownloads(int64(len(payload)))
	var full, ranges atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	fetch := func(part SnapshotFile) (io.ReadCloser, error) {
		if part.Size == part.Blob.Size {
			full.Add(1)
			close(started)
			<-release
		} else {
			ranges.Add(1)
		}
		return io.NopCloser(bytes.NewReader(payload[part.Offset : part.Offset+part.Size])), nil
	}
	read := func() error {
		reader, err := cache.read("repository", file, fetch)
		if err != nil {
			return err
		}
		defer reader.Close()
		data, err := io.ReadAll(reader)
		if err == nil && !bytes.Equal(data, payload[file.Offset:file.Offset+file.Size]) {
			return errors.New("wrong packed record")
		}
		return err
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if err := read(); err != nil {
				t.Error(err)
			}
		})
	}
	<-started
	close(release)
	group.Wait()
	if full.Load() != 1 || ranges.Load() != 1 {
		t.Fatalf("16 readers downloaded %d packs and %d ranges", full.Load(), ranges.Load())
	}
	file.Digest = contentDigest([]byte("wrong ciphertext"))
	if _, err := cache.read("repository", file, fetch); err == nil {
		t.Fatal("cached pack bypassed record verification")
	}
	file.Blob.Size++
	if _, err := cache.read("repository", file, fetch); err == nil {
		t.Fatal("conflicting descriptor accepted")
	}
}

func TestPackDownloadsBoundPinnedAndPendingBytes(t *testing.T) {
	first := bytes.Repeat([]byte("a"), 4096)
	second := bytes.Repeat([]byte("b"), 4096)
	a, b := packFixture(first, 0, 100), packFixture(second, 0, 100)
	cache := newPackDownloads(4096)
	var full atomic.Int32
	fetch := func(part SnapshotFile) (io.ReadCloser, error) {
		payload := first
		if part.Blob.Digest == b.Blob.Digest {
			payload = second
		}
		if part.Size == part.Blob.Size {
			full.Add(1)
		}
		return io.NopCloser(bytes.NewReader(payload[part.Offset : part.Offset+part.Size])), nil
	}
	read := func(file SnapshotFile) io.ReadCloser {
		reader, err := cache.read("repository", file, fetch)
		if err != nil {
			t.Fatal(err)
		}
		return reader
	}
	read(a).Close()
	pinned := read(a)
	read(b).Close()
	read(b).Close()
	if cache.bytes > cache.limit || full.Load() != 1 {
		t.Fatal("pinned pack did not protect the memory budget")
	}
	pinned.Close()
	pinned.Close()
	read(b).Close()
	if cache.bytes != 4096 || full.Load() != 2 {
		t.Fatal("unused pack was not evicted")
	}
	for n := range downloadHistoryEntries + 10 {
		file := a
		file.Blob.Digest = contentDigest([]byte{byte(n), byte(n >> 8)})
		read(file).Close()
	}
	if len(cache.recent) > downloadHistoryEntries {
		t.Fatal("unbounded sparse-read history")
	}
}

func TestPackDownloadsRejectCorruptionAndRetryFailures(t *testing.T) {
	for _, fault := range []string{"digest", "truncated", "oversized", "transport"} {
		t.Run(fault, func(t *testing.T) {
			payload := bytes.Repeat([]byte("c"), 4096)
			file := packFixture(payload, 0, 100)
			cache := newPackDownloads(4096)
			fail := true
			fetch := func(part SnapshotFile) (io.ReadCloser, error) {
				data := payload[part.Offset : part.Offset+part.Size]
				if fail && part.Size == part.Blob.Size {
					switch fault {
					case "digest":
						data = bytes.Repeat([]byte("d"), len(data))
					case "truncated":
						data = data[:len(data)-1]
					case "oversized":
						data = append(bytes.Clone(data), 0)
					case "transport":
						return nil, errors.New("interrupted")
					}
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			reader, err := cache.read("repository", file, fetch)
			if err != nil {
				t.Fatal(err)
			}
			reader.Close()
			if _, err = cache.read("repository", file, fetch); err == nil {
				t.Fatal("corrupt download accepted")
			}
			if cache.bytes != 0 {
				t.Fatal("failed download retained reservation")
			}
			fail = false
			reader, err = cache.read("repository", file, fetch)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, payload[:100]) {
				t.Fatal("retry lost the record", err)
			}
		})
	}
}
