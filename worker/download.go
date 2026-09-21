package worker

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

const downloadCacheBytes = 128 * 1024 * 1024
const downloadHistoryEntries = 1024

type downloadedPack struct {
	descriptor Descriptor
	ready      chan struct{}
	data       []byte
	err        error
	readers    int
	used       uint64
}

// Only ciphertext is retained. Reservations include downloads and packs held
// by readers, so parallel substitutions cannot exceed the cache's byte budget.
type packDownloads struct {
	mu     sync.Mutex
	limit  int64
	bytes  int64
	clock  uint64
	packs  map[string]*downloadedPack
	recent map[string]uint64
}

func newPackDownloads(limit int64) *packDownloads {
	return &packDownloads{limit: limit, packs: map[string]*downloadedPack{}, recent: map[string]uint64{}}
}

type packReader struct {
	*bytes.Reader
	release func()
}

func (r *packReader) Close() error { r.release(); return nil }

func (c *packDownloads) read(repository string, file SnapshotFile, fetch func(SnapshotFile) (io.ReadCloser, error)) (io.ReadCloser, error) {
	if err := file.validate(); err != nil {
		return nil, err
	}
	key := repository + "@" + file.Blob.Digest
	c.mu.Lock()
	c.clock++
	pack := c.packs[key]
	if pack != nil && (pack.descriptor.Size != file.Blob.Size || pack.descriptor.MediaType != file.Blob.MediaType) {
		c.mu.Unlock()
		return nil, errors.New("conflicting packed blob descriptors")
	}
	if file.Size == file.Blob.Size || file.Blob.Size > cachePackSize || file.Blob.Size > c.limit {
		c.mu.Unlock()
		return fetch(file)
	}
	owner := false
	if pack == nil {
		_, seen := c.recent[key]
		c.recent[key] = c.clock
		if len(c.recent) > downloadHistoryEntries {
			oldest, age := "", c.clock
			for name, used := range c.recent {
				if used < age {
					oldest, age = name, used
				}
			}
			delete(c.recent, oldest)
		}
		// Keep the first sparse read cheap. A second record justifies fetching
		// the pack once; subsequent requests join that download.
		if !seen {
			c.mu.Unlock()
			return fetch(file)
		}
		for c.bytes+file.Blob.Size > c.limit {
			oldest, age := "", c.clock
			for name, candidate := range c.packs {
				if candidate.readers == 0 && candidate.used < age {
					oldest, age = name, candidate.used
				}
			}
			if oldest == "" {
				c.mu.Unlock()
				return fetch(file)
			}
			c.bytes -= c.packs[oldest].descriptor.Size
			delete(c.packs, oldest)
		}
		pack = &downloadedPack{descriptor: file.Blob, ready: make(chan struct{})}
		c.packs[key] = pack
		c.bytes += file.Blob.Size
		owner = true
	}
	pack.readers++
	pack.used = c.clock
	c.mu.Unlock()
	release := sync.OnceFunc(func() {
		c.mu.Lock()
		pack.readers--
		c.mu.Unlock()
	})
	if owner {
		stream, err := fetch(wholeFile(file.Blob))
		var data []byte
		if err == nil {
			// Allocate exactly the reservation instead of growing a read buffer.
			data = make([]byte, file.Blob.Size)
			_, err = io.ReadFull(stream, data)
			if err == nil {
				var extra [1]byte
				_, err = io.ReadFull(stream, extra[:])
				if err == io.EOF {
					err = nil
				} else if err == nil {
					err = errors.New("registry pack exceeds declared size")
				}
			}
			err = errors.Join(err, stream.Close())
			if err == nil && contentDigest(data) != file.Blob.Digest {
				err = errors.New("registry pack digest mismatch")
			}
		}
		c.mu.Lock()
		pack.data, pack.err = data, err
		if err != nil {
			pack.data = nil
			delete(c.packs, key)
			c.bytes -= file.Blob.Size
		}
		close(pack.ready)
		c.mu.Unlock()
	} else {
		<-pack.ready
	}
	if pack.err != nil {
		release()
		return nil, pack.err
	}
	data := pack.data[file.Offset : file.Offset+file.Size]
	if contentDigest(data) != file.Digest {
		release()
		return nil, errors.New("registry packed record digest mismatch")
	}
	return &packReader{Reader: bytes.NewReader(data), release: release}, nil
}
