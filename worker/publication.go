package worker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

const UploadWorkers = 16
const cachePackSize = 16 * 1024 * 1024
const packedArchiveLimit = 1024 * 1024

func PublicationRoots(source string, log io.Writer) ([]string, error) {
	b, e := NixRun(source, log, []string{"path-info", "--all"}, true, nil)
	if e != nil {
		return nil, e
	}

	set := map[string]bool{}
	for _, p := range strings.Fields(string(b)) {
		set[p] = true
	}

	return sortedKeys(set), nil
}

func localStorePaths(source string, log io.Writer, paths []string) ([]string, error) {
	local := []string{}
	for offset := 0; offset < len(paths); offset += 512 {
		batch := paths[offset:min(offset+512, len(paths))]
		data, err := NixRun(source, log, []string{"path-info", "--json", "--json-format", "1", "--stdin"}, true, []byte(strings.Join(batch, "\n")+"\n"))
		if err != nil {
			return nil, err
		}
		var info map[string]*pathInfo
		if err = json.Unmarshal(data, &info); err != nil {
			return nil, err
		}
		for _, path := range batch {
			value, ok := info[path]
			if !ok {
				return nil, errors.New("local store query omitted a requested path")
			}
			// Nix returns null for paths that have not finished building.
			if value != nil {
				local = append(local, path)
			}
		}
	}
	return local, nil
}

type UpstreamCollector interface {
	Collect([]string) (map[string][]string, error)
}

type pathInfo struct {
	NarHash    string   `json:"narHash"`
	NarSize    uint64   `json:"narSize"`
	References []string `json:"references"`
	Deriver    string   `json:"deriver"`
	Signatures []string `json:"signatures"`
	CA         string   `json:"ca"`
}

func narStream(path, source string, log io.Writer) (io.ReadCloser, error) {
	nar, err := ProcessStream([]string{"nix-store", "--dump", path}, source, log, BuildEnvironment())
	if err != nil {
		return nil, err
	}

	return transformStream(nar, func(output io.Writer) error {
		// Publication already runs multiple streams in parallel.
		writer, err := zstd.NewWriter(output, zstd.WithEncoderConcurrency(1))
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, nar)
		return errors.Join(err, writer.Close())
	}), nil
}

func signingPublicKey(secret []byte) (string, error) {
	name, encoded, ok := strings.Cut(strings.TrimSpace(string(secret)), ":")
	key, err := base64.StdEncoding.DecodeString(encoded)
	if !ok || name == "" || err != nil || len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Nix signing key")
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	return name + ":" + base64.StdEncoding.EncodeToString(public), nil
}

type narPacker struct {
	snapshot   *Snapshot
	recipients Secret
	mu         sync.Mutex
	buffer     bytes.Buffer
	files      map[string]SnapshotFile
	limit      int
	err        error
	upload     <-chan error
	completed  atomic.Int64
	encrypted  atomic.Int64
	blobs      atomic.Int64
}

func newNARPacker(snapshot *Snapshot, recipients Secret) *narPacker {
	return &narPacker{snapshot: snapshot, recipients: recipients, files: map[string]SnapshotFile{}, limit: cachePackSize}
}

func (p *narPacker) add(name string, source io.Reader) error {
	stream, err := EncryptedStream(source, p.recipients)
	if err != nil {
		return err
	}
	defer stream.Close()

	// Probe only a bounded prefix; large archives retain streaming uploads.
	limit := min(p.limit, packedArchiveLimit)
	prefix, err := io.ReadAll(io.LimitReader(stream, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(prefix) > limit {
		blob, err := p.snapshot.Storage.UploadBlob(p.snapshot.Repository, io.MultiReader(bytes.NewReader(prefix), stream), true)
		if err != nil {
			return err
		}
		p.snapshot.mu.Lock()
		p.snapshot.Files[name] = wholeFile(blob)
		p.snapshot.mu.Unlock()
		p.completed.Add(1)
		p.encrypted.Add(blob.Size)
		p.blobs.Add(1)
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if p.buffer.Len()+len(prefix) > p.limit {
		if err := p.flush(); err != nil {
			return err
		}
	}
	p.files[name] = SnapshotFile{Offset: int64(p.buffer.Len()), Size: int64(len(prefix)), Digest: contentDigest(prefix)}
	p.buffer.Write(prefix)
	return nil
}

func (p *narPacker) finish() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.flush(); err != nil {
		return err
	}
	return p.waitUpload()
}

func (p *narPacker) waitUpload() error {
	if p.upload != nil {
		p.err = <-p.upload
		p.upload = nil
	}
	return p.err
}

func (p *narPacker) flush() error {
	// Keep at most one pack uploading while the next pack fills.
	if err := p.waitUpload(); err != nil || p.buffer.Len() == 0 {
		return err
	}
	data, files := p.buffer.Bytes(), p.files
	p.buffer = bytes.Buffer{}
	p.files = map[string]SnapshotFile{}
	done := make(chan error, 1)
	p.upload = done
	go func() {
		blob, err := p.snapshot.Storage.UploadBlob(p.snapshot.Repository, bytes.NewReader(data), true)
		if err == nil {
			p.snapshot.mu.Lock()
			for name, file := range files {
				file.Blob = blob
				p.snapshot.Files[name] = file
			}
			p.snapshot.mu.Unlock()
			p.completed.Add(int64(len(files)))
			p.encrypted.Add(blob.Size)
			p.blobs.Add(1)
		}
		done <- err
	}()
	return nil
}

func PublishStore(source string, required map[string]bool, snapshot, parent *Snapshot, signingKey, recipients Secret, log io.Writer, upstream UpstreamCollector) (int, error) {
	started := time.Now()
	unknown := []string{}
	for p, needed := range required {
		if needed && !snapshot.Contains(p) && !parent.Contains(p) {
			unknown = append(unknown, p)
		}
	}
	if len(unknown) == 0 {
		return 0, nil
	}
	fmt.Fprintf(log, "Cache: checking %d local store paths\n", len(unknown))
	selected, e := localStorePaths(source, log, unknown)
	if e != nil {
		return 0, e
	}
	if len(selected) == 0 {
		return 0, nil
	}

	// Include references discovered in built outputs, even outside the evaluated graph.
	b, e := NixRun(source, log, []string{"path-info", "--recursive", "--stdin"}, true, []byte(strings.Join(selected, "\n")+"\n"))
	if e != nil {
		return 0, e
	}
	local := strings.Fields(string(b))

	candidates := []string{}
	for _, p := range local {
		if !snapshot.Contains(p) && !parent.Contains(p) {
			candidates = append(candidates, p)
		}
	}

	fmt.Fprintf(log, "Cache: checking upstream for %d of %d local paths\n", len(candidates), len(local))
	found, e := upstream.Collect(candidates)
	if e != nil {
		return 0, e
	}

	for p, refs := range found {
		snapshot.Upstream[p] = refs
	}

	roots := []string{}
	for _, p := range candidates {
		if !snapshot.Contains(p) && !parent.Contains(p) {
			roots = append(roots, p)
		}
	}

	fmt.Fprintf(log, "Cache: signing %d paths\n", len(roots))
	paths := map[string]pathInfo{}
	for offset := 0; offset < len(roots); offset += 128 {
		batch := roots[offset:min(offset+128, len(roots))]
		e = withCredential(signingKey, func(path string, files []*os.File) error {
			cmd := exec.Command("nix", append([]string{
				"--extra-experimental-features", "nix-command flakes",
				"store",
				"sign",
				"--key-file",
				path,
			}, batch...)...)
			cmd.Dir = source
			cmd.Env = BuildEnvironment()
			cmd.Stdout = log
			cmd.Stderr = log
			cmd.ExtraFiles = files
			return cmd.Run()
		})
		if e != nil {
			return 0, e
		}

		b, e := NixRun(source, log, append([]string{"path-info", "--json", "--json-format", "1"}, batch...), true, nil)
		if e != nil {
			return 0, e
		}

		var values map[string]pathInfo
		if e = json.Unmarshal(b, &values); e != nil {
			return 0, e
		}

		for p, v := range values {
			paths[p] = v
		}
	}

	type record struct{ archive, text string }
	archives := map[string]string{}
	records := map[string]record{}
	for p, info := range paths {
		algorithm, encoded, ok := strings.Cut(info.NarHash, "-")
		if !ok || algorithm != "sha256" {
			return 0, errors.New("unsupported NAR hash")
		}

		hash, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(hash) != 32 {
			return 0, errors.New("invalid NAR hash")
		}

		archive := "nar/" + hex.EncodeToString(hash) + ".nar.zst"
		archives[archive] = p
		refs := []string{}
		for _, ref := range info.References {
			refs = append(refs, filepath.Base(ref))
		}

		sort.Strings(refs)
		lines := []string{
			"StorePath: " + p,
			"URL: " + archive,
			"Compression: zstd",
			"NarHash: " + info.NarHash,
			fmt.Sprintf("NarSize: %d", info.NarSize),
			"References: " + strings.Join(refs, " "),
		}
		if info.Deriver != "" {
			lines = append(lines, "Deriver: "+filepath.Base(info.Deriver))
		}

		for _, signature := range info.Signatures {
			lines = append(lines, "Sig: "+signature)
		}

		if info.CA != "" {
			lines = append(lines, "CA: "+info.CA)
		}

		records[p] = record{archive, strings.Join(lines, "\n") + "\n"}
	}

	type uploadItem struct{ archive, path string }
	pending := make(chan uploadItem)
	results := make(chan error, len(archives))
	var group sync.WaitGroup
	var failed atomic.Bool
	packer := newNARPacker(snapshot, recipients)
	uploadStarted := time.Now()
	for range UploadWorkers {
		group.Add(1)
		go func() {
			defer group.Done()

			for item := range pending {
				if failed.Load() {
					continue
				}

				name := "cache/" + item.archive
				snapshot.mu.Lock()
				descriptor, inParent := parent.Files[name]
				_, exists := snapshot.Files[name]
				if inParent {
					snapshot.Files[name] = descriptor
				}

				snapshot.mu.Unlock()
				if exists || inParent {
					continue
				}

				stream, err := narStream(item.path, source, log)
				if err == nil {
					err = packer.add(name, stream)
					stream.Close()
				}

				if err != nil {
					failed.Store(true)
					results <- err
				}
			}
		}()
	}

	go func() {
		for archive, path := range archives {
			pending <- uploadItem{archive, path}
		}

		close(pending)
		group.Wait()
		// Salvage complete records even when another archive failed to stream.
		if err := packer.finish(); err != nil {
			results <- err
		}
		close(results)
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var uploadError error
	done := false
	for !done {
		select {
		case err, ok := <-results:
			if !ok {
				done = true
			} else if uploadError == nil {
				uploadError = err
			}
		case <-ticker.C:
			fmt.Fprintf(
				log,
				"Cache upload: %d archives, %d blobs, %.1f MiB uploaded (%.1fs)\n",
				packer.completed.Load(),
				packer.blobs.Load(),
				float64(packer.encrypted.Load())/(1024*1024),
				time.Since(uploadStarted).Seconds(),
			)
		}
	}

	ready := map[string]bool{}
	for p, record := range records {
		if _, ok := snapshot.Files["cache/"+record.archive]; ok {
			ready[p] = true
		}
	}

	consumers := map[string][]string{}
	invalid := []string{}
	for p := range ready {
		for _, ref := range paths[p].References {
			if ready[ref] {
				consumers[ref] = append(consumers[ref], p)
			} else if !parent.Contains(ref) && !snapshot.Contains(ref) {
				invalid = append(invalid, p)
			}
		}
	}

	for len(invalid) > 0 {
		p := invalid[0]
		invalid = invalid[1:]
		if ready[p] {
			delete(ready, p)
			invalid = append(invalid, consumers[p]...)
		}
	}

	for p := range ready {
		snapshot.Narinfos[NarinfoKey(p)] = records[p].text
	}

	fmt.Fprintf(log, "Cache: %d/%d paths ready (%.1fs); uploaded %d archives in %d blobs, %.1f MiB\n", len(ready), len(paths), time.Since(started).Seconds(), packer.completed.Load(), packer.blobs.Load(), float64(packer.encrypted.Load())/(1024*1024))
	return len(ready), uploadError
}
