package worker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
)

const MaxCheckpoints = 4
const DiskReserve = 8 * 1024 * 1024 * 1024
const DiskStop = 4 * 1024 * 1024 * 1024
const UploadWorkers = 16
const cachePackSize = 16 * 1024 * 1024
const packedArchiveLimit = 1024 * 1024
const publicationInterval = 30 * time.Second

func BuildEnvironment() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "RUNNER_TRACKING_ID" || key == "NIX_SIGNING_KEY" {
			continue
		}

		private := false
		for _, prefix := range []string{"INPUT_", "CI_", "REGISTRY_", "ACTIONS_", "GITHUB_"} {
			private = private || strings.HasPrefix(key, prefix)
		}

		if !private {
			env = append(env, entry)
		}
	}

	return env
}

func NixRun(source string, log io.Writer, args []string, capture bool, data []byte) ([]byte, error) {
	cmd := exec.Command("nix", append([]string{"--extra-experimental-features", "nix-command flakes"}, args...)...)
	cmd.Dir = source
	cmd.Env = BuildEnvironment()
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = log
	if capture {
		return cmd.Output()
	}

	cmd.Stdout = log
	return nil, cmd.Run()
}

func substituter(storage Storage, snapshot *Snapshot, identity, signingKey Secret, log io.Writer) (*CacheHandler, *http.Server, []string, error) {
	public, e := signingPublicKey(signingKey.Data)
	if e != nil {
		return nil, nil, nil, e
	}

	return publicSubstituter(storage, snapshot, identity, public, log)
}

func publicSubstituter(storage Storage, snapshot *Snapshot, identity Secret, public string, log io.Writer) (*CacheHandler, *http.Server, []string, error) {
	handler := NewCacheHandler(storage, "", "", identity, log)
	handler.SetSnapshot(snapshot)
	server, listener, e := StartCacheServer(handler, 0)
	if e != nil {
		return nil, nil, nil, e
	}

	options := []string{
		"--substituters", "http://" + listener.Addr().String() + "?priority=50 https://cache.nixos.org",
		"--trusted-public-keys", public + " cache.nixos.org-1:" + UpstreamPublicKey,
		"--require-sigs",
		"--option", "fallback", "false",
		"--option", "narinfo-cache-negative-ttl", "0",
	}
	return handler, server, options, nil
}

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

func diskFree(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if e := syscall.Statfs(path, &stat); e != nil {
		return 0, e
	}

	return stat.Bavail * uint64(stat.Bsize), nil
}

func dedicatedRunner() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted"
}

func LoadParent(storage Storage, repository string, identity Secret) (*Snapshot, error) {
	manifest, digest, e := storage.GetManifest(repository, "nixos-cache-latest")
	if errors.Is(e, ErrObjectNotFound) {
		return NewSnapshot(storage, repository), nil
	}
	if e != nil {
		return nil, e
	}

	return loadSnapshot(storage, repository, manifest, digest, identity)
}

func BuildParent(storage Storage, repository string, identity Secret, pinned string, admitted, attempt int) (*Snapshot, error) {
	if admitted < 1 || admitted > attempt {
		return nil, errors.New("missing or invalid admission attempt")
	}
	if admitted != attempt {
		return LoadParent(storage, repository, identity)
	}
	if pinned != "" {
		return LoadSnapshot(storage, repository, pinned, identity)
	}

	return NewSnapshot(storage, repository), nil
}

func StageTag(run, system string, attempt, sequence int, identity Secret) string {
	mac := hmac.New(sha256.New, identity.Data)
	fmt.Fprintf(mac, "checkpoint\x00%s:%s:%d:%d", run, system, attempt, sequence)
	return fmt.Sprintf("nixos-cache-stage-%s-%d-%d-%s", run, attempt, sequence, hex.EncodeToString(mac.Sum(nil))[:32])
}

func BuildBinding(submitted BuildRequest, system string) map[string]any {
	return map[string]any{
		"request": submitted.ID,
		"source":  submitted.Source,
		"system":  system,
		"policy":  Policy,
	}
}

func PriorStage(storage Storage, repository, run, system string, attempt int, identity Secret, expected map[string]any) (*Snapshot, error) {
	for previous := attempt; previous > 0; previous-- {
		refs := []string{ResultTag(run, system, previous)}
		for seq := MaxCheckpoints; seq > 0; seq-- {
			refs = append(refs, StageTag(run, system, previous, seq, identity))
		}

		for _, ref := range refs {
			manifest, digest, e := storage.GetManifest(repository, ref)
			if errors.Is(e, ErrObjectNotFound) {
				continue
			}
			if e != nil {
				return nil, e
			}

			stage, e := loadSnapshot(storage, repository, manifest, digest, identity)
			if e != nil {
				return nil, e
			}
			if !equivalent(stage.Metadata["binding"], expected) || stage.Metadata["kind"] != "stage" || String(stage.Metadata["run"]) != run || Int(stage.Metadata["attempt"]) != previous {
				return nil, errors.New("checkpoint binding mismatch")
			}

			return stage, nil
		}
	}

	return nil, nil
}

func CacheUnion(parent, delta *Snapshot) (*Snapshot, error) {
	result := NewSnapshot(parent.Storage, parent.Repository)
	if e := result.Merge(parent); e != nil {
		return nil, e
	}

	if e := result.Merge(delta); e != nil {
		return nil, e
	}

	if e := result.RequireClosed(); e != nil {
		return nil, e
	}

	return result, nil
}

func Reclaim(source string, log io.Writer, graph *Plan, durable *Snapshot, roots string) (uint64, error) {
	if !dedicatedRunner() {
		return 0, errors.New("disk reclamation requires a dedicated hosted runner")
	}

	local, e := PublicationRoots(source, log)
	if e != nil {
		return 0, e
	}

	protected := map[string]bool{}
	for p := range graph.Required {
		protected[p] = true
	}

	for _, outputs := range graph.Outputs {
		for _, p := range outputs {
			delete(protected, p)
		}
	}

	entries, e := os.ReadDir(roots)
	if e != nil {
		return 0, e
	}

	for _, entry := range entries {
		if e = os.Remove(filepath.Join(roots, entry.Name())); e != nil {
			return 0, e
		}
	}

	protect, disposable := []string{}, []string{}
	for _, p := range local {
		if protected[p] {
			if !strings.HasSuffix(p, ".drv") {
				protect = append(protect, p)
			}
		} else if durable.Contains(p) {
			disposable = append(disposable, p)
		}
	}

	for offset := 0; offset < len(protect); offset += 128 {
		args := append([]string{"--add-root", filepath.Join(roots, strconv.Itoa(offset)), "--indirect", "--realise"}, protect[offset:min(offset+128, len(protect))]...)
		if _, e = runCommand("", log, "nix-store", args...); e != nil {
			return 0, e
		}
	}

	for offset := 0; offset < len(disposable); offset += 128 {
		runCommand(
			"",
			log,
			"nix-store",
			append([]string{"--delete"}, disposable[offset:min(offset+128, len(disposable))]...)...,
		)
	}

	return diskFree("/nix/store")
}

func BuildCommand(system string, jobs, cores int, options []string) []string {
	sandbox := "true"
	if strings.HasSuffix(system, "-darwin") {
		sandbox = "relaxed"
	}

	return append([]string{
		"--extra-experimental-features", "nix-command flakes",
		"build",
		"--no-link",
		"--print-build-logs",
		"--keep-going",
		"--stdin",
		"--max-jobs", strconv.Itoa(jobs),
		"--cores", strconv.Itoa(cores),
		"--option", "max-substitution-jobs", "8",
		"--option", "min-free", "0",
		"--option", "sandbox", sandbox,
		"--option", "sandbox-fallback", "false",
	}, options...)
}

type DiskGuard struct {
	Paths       []string
	MinimumFree uint64
	Measure     func(string) (uint64, error)
}

func NewDiskGuard(source string) *DiskGuard {
	paths := []string{"/nix/store", source, os.TempDir()}
	for _, key := range []string{"RUNNER_TEMP", "GITHUB_WORKSPACE"} {
		if v := os.Getenv(key); v != "" {
			paths = append(paths, v)
		}
	}

	return &DiskGuard{paths, math.MaxUint64, diskFree}
}

func (g *DiskGuard) Sample() error {
	for _, p := range g.Paths {
		free, e := g.Measure(p)
		if e != nil {
			return e
		}

		g.MinimumFree = min(g.MinimumFree, free)
		if free < DiskStop {
			return errors.New("runner disk safety reserve reached; build cancelled to preserve diagnostics and checkpoints")
		}
	}

	return nil
}

func (g *DiskGuard) Run(cmd *exec.Cmd) error {
	if e := cmd.Start(); e != nil {
		return e
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if e := g.Sample(); e != nil {
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
			}

			return e
		}

		select {
		case e := <-done:
			return e
		case <-ticker.C:
		}
	}
}

type buildSecrets struct {
	identity, recipients, signingKey Secret
}

type nativeBuild struct {
	source, system, run string
	attempt             int
	parent, delta       *Snapshot
	secrets             buildSecrets
	log                 io.Writer
	upstream            UpstreamCollector
	pool                *BuildPool
}

func (b *nativeBuild) publish(required map[string]bool) (int, error) {
	return PublishStore(b.source, required, b.delta, b.parent, b.secrets.signingKey, b.secrets.recipients, b.log, b.upstream)
}

func (b *nativeBuild) checkpoint(sequence int) error {
	if sequence > MaxCheckpoints {
		return errors.New("checkpoint budget exhausted; more runner disk is required")
	}
	if _, err := CacheUnion(b.parent, b.delta); err != nil {
		return err
	}

	tag := ResultTag(b.run, b.system, b.attempt)
	if b.delta.Metadata["terminal"] != true {
		tag = StageTag(b.run, b.system, b.attempt, sequence, b.secrets.identity)
	}

	fmt.Fprintf(b.log, "Checkpoint %d: publishing\n", sequence)
	started := time.Now()
	if _, err := b.delta.Publish(tag, b.secrets.recipients); err != nil {
		return err
	}
	fmt.Fprintf(b.log, "Checkpoint %d: published (%.1fs)\n", sequence, time.Since(started).Seconds())
	if b.delta.ManifestBytes >= 8*1024*1024 {
		fmt.Fprintln(b.log, "warning: checkpoint manifest exceeds 8 MiB")
	}
	return nil
}

func snapshotState(s *Snapshot) string {
	b, _ := json.Marshal([]any{s.Files, s.Narinfos, s.Upstream})
	return string(b)
}

type buildLog struct {
	mu sync.Mutex
	io.Writer
}

func (l *buildLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Writer.Write(data)
}

type cachePublisher struct {
	updates chan map[string]bool
	stop    chan struct{}
	done    chan struct{}
	err     error
}

func startCachePublisher(required map[string]bool, interval time.Duration, publish func(map[string]bool) error) *cachePublisher {
	p := &cachePublisher{
		updates: make(chan map[string]bool, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	required = maps.Clone(required)
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			if p.err = publish(required); p.err != nil {
				return
			}
			timer := time.NewTimer(interval)
			select {
			case <-p.stop:
				timer.Stop()
				return
			case required = <-p.updates:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
	return p
}

func (p *cachePublisher) update(required map[string]bool) error {
	select {
	case <-p.done:
		return p.err
	default:
	}
	// Only the latest plan is needed; slow publication cannot queue more work.
	select {
	case <-p.updates:
	default:
	}
	p.updates <- maps.Clone(required)
	return nil
}

func (p *cachePublisher) close() error {
	close(p.stop)
	<-p.done
	return p.err
}

func (b nativeBuild) execute() (bool, error) {
	if b.upstream == nil {
		upstream := NewUpstream()
		defer upstream.Close()
		b.upstream = upstream
	}
	started := time.Now()
	b.log = &buildLog{Writer: b.log}
	source, system, parent, delta := b.source, b.system, b.parent, b.delta
	signingKey, recipients, log := b.secrets.signingKey, b.secrets.recipients, b.log
	upstream, pool := b.upstream, b.pool
	fmt.Fprintf(log, "Build capacity: 1 build, %d CPUs\n", runtime.NumCPU())

	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(source, log, args, capture, data)
	}

	selection, e := buildSelection(delta.Metadata)
	if e != nil {
		return false, e
	}

	planKey, e := sourceEvaluationKey(source, system, selection, nix)
	if e != nil {
		return false, e
	}
	graph, e := loadEvaluation(source, system, planKey, parent, b.secrets.identity, signingKey, log)
	if e != nil {
		return false, e
	}
	planFile, reusedPlan := parent.Files[evaluationFile(system)], graph != nil
	if graph == nil {
		graph, e = Evaluate(source, system, nix, selection, log)
		if e != nil {
			return false, e
		}
	}

	fmt.Fprintf(log, "Evaluation finished (%.1fs)\n", time.Since(started).Seconds())
	if graph.Static() {
		parentIndex, err := newSnapshotIndex(parent)
		if err != nil {
			return false, err
		}
		parent = parentIndex.selectPaths(graph.Required)
		b.parent = parent
	}
	saved := snapshotState(delta)
	unknown := []string{}
	for p := range graph.Required {
		if !parent.Contains(p) && !delta.Contains(p) {
			unknown = append(unknown, p)
		}
	}

	lookupStarted := time.Now()
	found, e := upstream.Collect(unknown)
	if e != nil {
		return false, e
	}

	for p, refs := range found {
		delta.Upstream[p] = refs
	}

	fmt.Fprintf(log, "Upstream cache: checked %d paths (%.1fs)\n", len(unknown), time.Since(lookupStarted).Seconds())
	available, e := CacheUnion(parent, delta)
	if e != nil {
		return false, e
	}
	index, e := newSnapshotIndex(available)
	if e != nil {
		return false, e
	}

	uncachedOutputs := map[string]bool{}
	for _, outputs := range graph.Outputs {
		for _, path := range outputs {
			if path != "" && !available.Contains(path) {
				uncachedOutputs[path] = true
			}
		}
	}
	localPaths, e := localStorePaths(source, log, sortedKeys(uncachedOutputs))
	if e != nil {
		return false, e
	}
	local := map[string]bool{}
	for _, p := range localPaths {
		local[p] = true
	}

	missing := graph.Missing(available, local)

	fmt.Fprintf(
		log,
		"Build plan: %d targets, %d derivations, %d paths, %d output groups to build\n",
		len(graph.Targets),
		len(graph.Derivations),
		len(graph.Required),
		len(missing),
	)
	sequence := 0
	lastCheckpoint := time.Now()
	initialFiles := map[string]bool{}
	for n := range delta.Files {
		initialFiles[n] = true
	}

	minimumFree, e := diskFree("/nix/store")
	if e != nil {
		return false, e
	}

	var failure error
	exitCode := 0
	var publication *cachePublisher
	waitPublication := func() error {
		if publication == nil {
			return nil
		}
		err := publication.close()
		publication = nil
		return err
	}

	build := func() error {
		roots, e := os.MkdirTemp("", "cache-roots-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(roots)

		handler, server, options, e := substituter(parent.Storage, available, b.secrets.identity, signingKey, log)
		if e != nil {
			return e
		}
		defer server.Close()

		batches, e := graph.Batches(missing, 32)
		if e != nil {
			return e
		}

		publish := func(required map[string]bool) error {
			covered := len(delta.Narinfos) + len(delta.Upstream)
			if _, err := b.publish(required); err != nil {
				return err
			}
			if covered == len(delta.Narinfos)+len(delta.Upstream) {
				return nil
			}
			view, err := index.extend(delta)
			if err == nil {
				handler.SetSnapshot(view)
			}
			return err
		}
		startPublication := func() error {
			if publication != nil {
				return publication.update(graph.Required)
			}
			// Only the publisher touches delta until waitPublication returns.
			publication = startCachePublisher(graph.Required, publicationInterval, publish)
			return nil
		}
		checkpointIfNeeded := func() error {
			free, err := diskFree("/nix/store")
			if err != nil {
				return err
			}
			minimumFree = min(minimumFree, free)
			pressure := free < DiskReserve
			timed := sequence < MaxCheckpoints-1 && time.Since(lastCheckpoint) >= 30*time.Minute
			if !pressure && !timed {
				return nil
			}
			if sequence >= MaxCheckpoints-1 {
				return errors.New("disk reserve reached; checkpoint budget reserved for completion")
			}

			// Pool results are already published; batches must drain the publisher.
			if publication != nil {
				if err := waitPublication(); err != nil {
					return err
				}
				if err := publish(graph.Required); err != nil {
					return err
				}
			}
			if state := snapshotState(delta); state != saved {
				if err := b.checkpoint(sequence + 1); err != nil {
					return err
				}
				sequence++
				saved = state
				lastCheckpoint = time.Now()
			}

			durable, err := CacheUnion(parent, delta)
			if err != nil {
				return err
			}
			handler.SetSnapshot(durable)
			if pressure {
				free, err = Reclaim(source, log, graph, durable, roots)
				if err != nil {
					return err
				}
				if free < DiskReserve {
					return errors.New("pending build working set exceeds runner disk capacity")
				}
			}
			return nil
		}

		if pool != nil {
			if graph.Static() {
				err := pool.build(source, system, graph, missing, delta, signingKey, recipients, log, options, func() (*snapshotIndex, error) {
					if err := publish(graph.Required); err != nil {
						return nil, err
					}
					if err := checkpointIfNeeded(); err != nil {
						return nil, err
					}
					return index, nil
				})
				if err == nil && len(handler.Errors()) > 0 {
					return errors.New("inherited cache read failed; refusing a cache fallback")
				}
				return err
			}
			fmt.Fprintln(log, "Building unresolved derivation plan on coordinator")
			pool.Drain()
		}

		for number, batch := range batches {
			if e = startPublication(); e != nil {
				return e
			}
			batchStarted := time.Now()
			fmt.Fprintf(log, "Build batch %d/%d: %d output groups\n", number+1, len(batches), len(batch))
			cmd := exec.Command("nix", BuildCommand(system, 1, runtime.NumCPU(), options)...)
			cmd.Dir = source
			cmd.Env = BuildEnvironment()
			cmd.Stdin = strings.NewReader(strings.Join(batch, "\n") + "\n")
			cmd.Stdout = log
			cmd.Stderr = log
			guard := NewDiskGuard(source)
			err := guard.Run(cmd)
			minimumFree = min(minimumFree, guard.MinimumFree)
			if err != nil {
				var code *exec.ExitError
				if errors.As(err, &code) {
					exitCode = code.ExitCode()
				} else {
					return err
				}
			}

			fmt.Fprintf(log, "Build batch %d/%d: exited with code %d (%.1fs)\n", number+1, len(batches), cmd.ProcessState.ExitCode(), time.Since(batchStarted).Seconds())
			if e = graph.Resolve(nix); e != nil {
				return e
			}
			if e = checkpointIfNeeded(); e != nil {
				return e
			}
		}

		if len(handler.Errors()) > 0 {
			return errors.New("inherited cache read failed; refusing a cache fallback")
		}

		return nil
	}

	failure = build()
	if pool != nil {
		pool.Drain()
	}
	if e = waitPublication(); failure == nil {
		failure = e
	}
	if e = graph.Resolve(nix); failure == nil {
		failure = e
	}

	if _, e = b.publish(graph.Required); failure == nil {
		failure = e
	}
	if reusedPlan {
		delta.Files[evaluationFile(system)] = planFile
	} else if e = saveEvaluation(system, planKey, graph, delta, recipients); failure == nil {
		failure = e
	}

	available, e = CacheUnion(parent, delta)
	if e != nil {
		return false, e
	}

	results := graph.Results(available, system)
	complete := failure == nil && exitCode == 0 && graph.Complete(available)
	for _, r := range results {
		complete = complete && r["status"] == "success"
	}

	status := "failure"
	if complete {
		status = "success"
	}

	newBytes := int64(0)
	for n, d := range delta.Files {
		if !initialFiles[n] {
			newBytes += d.Size
		}
	}

	for k, v := range map[string]any{
		"status":                status,
		"terminal":              true,
		"results":               results,
		"required_hash":         graph.Hash(),
		"seconds":               math.Round(time.Since(started).Seconds()*1000) / 1000,
		"checkpoints":           sequence + 1,
		"targets":               len(graph.Targets),
		"required_paths":        len(graph.Required),
		"missing_output_groups": len(missing),
		"minimum_free_bytes":    minimumFree,
		"new_ciphertext_bytes":  newBytes,
	} {
		delta.Metadata[k] = v
	}

	if e = b.checkpoint(sequence + 1); e != nil {
		return false, e
	}

	if failure != nil {
		fmt.Fprintf(log, "Build failed: %v\n", failure)
	}

	return complete, nil
}

func Assemble(storage Storage, repository string, submitted BuildRequest, run string, attempt int, identity Secret, jobs map[string]ActionJob, matrix BuildMatrix) (*Snapshot, *Snapshot, error) {
	systems, e := matrix.Systems()
	if e != nil {
		return nil, nil, e
	}
	selection := submitted.Selection
	if (selection == nil && len(systems) != len(Systems)) || (selection != nil && len(systems) != 1) {
		return nil, nil, errors.New("admission matrix does not match the build selection")
	}
	parent, e := LoadParent(storage, repository, identity)
	if e != nil {
		return nil, nil, e
	}

	result := NewSnapshot(storage, repository)
	if e = result.Merge(parent); e != nil {
		return nil, nil, e
	}

	states := map[string]string{}
	mergedParents := map[string]bool{parent.Digest: true}
	success := true
	for _, system := range systems {
		job, found := jobs[system]
		jobAttempt := attempt
		if found {
			jobAttempt = job.RunAttempt
		}

		if jobAttempt < 1 || jobAttempt > attempt {
			return nil, nil, errors.New("invalid job attempt")
		}

		stage, e := PriorStage(storage, repository, run, system, jobAttempt, identity, BuildBinding(submitted, system))
		if e != nil {
			return nil, nil, e
		}

		states[system] = "failure"
		if stage != nil {
			if digest := String(stage.Metadata["parent"]); digest != "" && !mergedParents[digest] {
				base, e := LoadSnapshot(storage, repository, digest, identity)
				if e != nil {
					return nil, nil, e
				}

				if e = result.Merge(base); e != nil {
					return nil, nil, e
				}
				mergedParents[digest] = true
			}

			if e = result.Merge(stage); e != nil {
				return nil, nil, e
			}

			if found && job.Status == "completed" && job.Conclusion == "success" && stage.Metadata["terminal"] == true && stage.Metadata["status"] == "success" && Int(stage.Metadata["attempt"]) == jobAttempt {
				states[system] = "success"
			}
		}

		success = success && states[system] == "success"
	}

	if e = result.PreferUpstream(); e != nil {
		return nil, nil, e
	}

	if e = result.RequireClosed(); e != nil {
		return nil, nil, e
	}

	status := "failure"
	if success {
		status = "success"
	}

	result.Metadata = map[string]any{
		"kind":    "commit",
		"run":     run,
		"attempt": attempt,
		"request": submitted.ID,
		"status":  status,
		"systems": states,
	}
	return parent, result, nil
}

func RunWorker(log io.Writer) error {
	request, sourceRevision := os.Getenv("INPUT_REQUEST"), os.Getenv("INPUT_SOURCE")
	mode, system := os.Getenv("INPUT_MODE"), os.Getenv("INPUT_SYSTEM")
	run := os.Getenv("GITHUB_RUN_ID")
	attempt, e := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	validMode := mode == "admit" || mode == "build" || mode == "builder" || mode == "finalize"
	_, native := Systems[system]
	if e != nil || attempt < 1 || !regexpRun.MatchString(run) || !validMode || ((mode == "build" || mode == "builder") && !native) {
		return errors.New("invalid worker inputs")
	}

	submitted, e := NewBuildRequest(request, sourceRevision, os.Getenv("INPUT_HOST"), os.Getenv("INPUT_PACKAGE"))
	if e != nil {
		return e
	}

	var config map[string]any
	if e = json.Unmarshal([]byte(takeEnv("CI_STORAGE")), &config); e != nil {
		return e
	}

	identity := Secret{Data: []byte(takeEnv("CI_IDENTITY"))}
	recipientsText := takeEnv("CI_RECIPIENTS")
	signingKey := Secret{Data: []byte(takeEnv("NIX_SIGNING_KEY"))}
	token, user := takeEnv("REGISTRY_TOKEN"), takeEnv("REGISTRY_USER")
	poolToken, poolUser := takeEnv("CI_POOL_TOKEN"), takeEnv("CI_POOL_USER")
	if poolToken == "" || poolUser == "" {
		return errors.New("missing dedicated pool credentials")
	}
	storage := NewRegistry(RegistryCredential(user, token))
	defer storage.Close()

	repository := String(config["repository"])
	if os.Getenv("GITHUB_REPOSITORY") != strings.TrimPrefix(repository, "ghcr.io/") {
		return errors.New("worker repository mismatch")
	}

	storage.repositoryAuth = map[string]Secret{repository + "-pool": RegistryCredential(poolUser, poolToken)}
	api := NewGitHub(token)
	poolEndpoint, e := EndpointFor(api, repository+"-pool")
	if e != nil {
		return e
	}
	api = poolPackageAPI(api, NewGitHub(poolToken), strings.TrimSuffix(poolEndpoint, "/versions"))
	workerRecipients, e := IdentityRecipients(identity)
	if e != nil {
		return e
	}
	recipients := Secret{Data: append([]byte(strings.TrimRight(recipientsText, "\r\n")+"\n"), workerRecipients.Data...)}
	source := os.Getenv("INPUT_SOURCE_PATH")
	if source == "" {
		return errors.New("missing source checkout path")
	}
	if mode != "finalize" {
		if e = preparePool(api, storage, repository, run, workerRecipients, mode == "admit"); e != nil {
			fmt.Fprintln(log, "Builder pool unavailable: require a private, unlinked package accessible with CI_POOL_USER and CI_POOL_TOKEN.")
			return e
		}
	}
	var bus *poolBus
	if mode == "build" || mode == "builder" {
		revision, err := runCommand(source, log, "git", "rev-parse", "HEAD")
		if err != nil {
			return errors.New("resolve builder source commit")
		}
		binding := BuildBinding(submitted, system)
		binding["revision"] = strings.TrimSpace(string(revision))
		bus, err = newPoolBus(storage, repository, run, system, attempt, identity, recipients, binding)
		if err != nil {
			return err
		}
	}

	if mode == "builder" {
		runner, err := strconv.Atoi(os.Getenv("INPUT_BUILDER"))
		if err != nil || runner < 1 || runner >= RunnersPerSystem {
			return errors.New("invalid builder runner")
		}
		return RunBuilder(source, runner, bus, log)
	}

	if mode == "admit" {
		matrix, e := AdmissionMatrix(source, submitted.Selection, func(args []string, capture bool, data []byte) ([]byte, error) {
			return NixRun(source, log, args, capture, data)
		})
		if e != nil {
			return e
		}

		parent, e := LoadParent(storage, repository, identity)
		if e != nil {
			return e
		}

		if e = parent.RequireClosed(); e != nil {
			return e
		}

		f, e := os.OpenFile(os.Getenv("GITHUB_OUTPUT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()

		encoded, e := json.Marshal(matrix)
		if e != nil {
			return e
		}
		helpers, e := matrix.Helpers()
		if e != nil {
			return e
		}
		helperJSON, e := json.Marshal(helpers)
		if e != nil {
			return e
		}
		revision, e := runCommand(source, log, "git", "rev-parse", "HEAD")
		if e != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(strings.TrimSpace(string(revision))) {
			return errors.New("resolve admitted source commit")
		}
		_, e = fmt.Fprintf(f, "parent=%s\nattempt=%d\nmatrix=%s\nhelpers=%s\nrevision=%s\n", parent.Digest, attempt, encoded, helperJSON, strings.TrimSpace(string(revision)))
		if e != nil {
			return e
		}
		for _, row := range matrix.Include {
			fmt.Fprintf(log, "Admitted runner: %s\n", row.System)
		}
		return nil
	}

	if mode == "build" {
		admitted, _ := strconv.Atoi(os.Getenv("INPUT_ADMISSION_ATTEMPT"))

		parent, e := BuildParent(storage, repository, identity, os.Getenv("INPUT_PARENT"), admitted, attempt)
		if e != nil {
			return e
		}

		parentDigest := parent.Digest
		if e = parent.RequireClosed(); e != nil {
			return e
		}

		expected := BuildBinding(submitted, system)
		prior, e := PriorStage(storage, repository, run, system, attempt-1, identity, expected)
		if e != nil {
			return e
		}

		if prior != nil {
			if digest := String(prior.Metadata["parent"]); digest != "" {
				base, e := LoadSnapshot(storage, repository, digest, identity)
				if e != nil {
					return e
				}

				if e = parent.Merge(base); e != nil {
					return e
				}
			}

			if e = parent.Merge(prior); e != nil {
				return e
			}

			fmt.Fprintf(log, "Resuming checkpoint: %d cached paths, %d upstream paths\n", len(prior.Narinfos), len(prior.Upstream))
		}

		if e = parent.RequireClosed(); e != nil {
			return e
		}

		delta := NewSnapshot(storage, repository)
		var parentValue any
		if parentDigest != "" {
			parentValue = parentDigest
		}

		delta.Metadata = map[string]any{
			"kind":    "stage",
			"binding": expected,
			"parent":  parentValue,
			"run":     run,
			"attempt": attempt,
			"request": request,
			"status":  "failure",
		}
		if submitted.Selection != nil {
			delta.Metadata["selection"] = submitted.Selection
		}

		if prior != nil {
			if e = delta.Merge(prior); e != nil {
				return e
			}

			delta.Digest = prior.Digest
		}

		pool := StartBuildPool(bus, log)
		defer pool.Close()
		success, e := (nativeBuild{
			source: source, system: system, run: run, attempt: attempt,
			parent: parent, delta: delta, pool: pool, log: log,
			secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: signingKey},
		}).execute()
		if e != nil {
			return e
		}
		if !success {
			return errors.New("native build failed")
		}

		return nil
	}

	var matrix BuildMatrix
	if e = json.Unmarshal([]byte(os.Getenv("INPUT_MATRIX")), &matrix); e != nil {
		return errors.New("invalid admission matrix")
	}
	return Finalize(api, storage, repository, submitted, run, attempt, identity, recipients, matrix, log)
}

func Finalize(api GitHubAPI, storage Storage, repository string, submitted BuildRequest, run string, attempt int, identity, recipients Secret, matrix BuildMatrix, log io.Writer) error {
	// Retention uses manifests, so failed job lookups or unreadable catalogs must
	// not prevent cleanup. Keep current checkpoints and their parents for assembly.
	if _, err := Prune(api, storage, repository, run, log); err != nil {
		return err
	}

	jobs, e := ActionJobs(api, strings.TrimPrefix(repository, "ghcr.io/"), run, attempt)
	if e != nil {
		return e
	}

	parent, combined, e := Assemble(storage, repository, submitted, run, attempt, identity, jobs, matrix)
	if e != nil {
		return e
	}

	for system, state := range combined.Metadata["systems"].(map[string]string) {
		fmt.Fprintf(log, "%s: %s\n", system, state)
	}

	if snapshotState(combined) != snapshotState(parent) {
		if _, e = combined.Publish(fmt.Sprintf("nixos-cache-run-%s-%d", run, attempt), recipients); e != nil {
			return e
		}

		if _, e = storage.PutManifest(repository, "nixos-cache-latest", combined.Manifest); e != nil {
			return e
		}

		if combined.ManifestBytes >= 8*1024*1024 {
			fmt.Fprintln(log, "warning: combined cache manifest exceeds 8 MiB")
		}
	}

	if combined.Metadata["status"] != "success" {
		return errors.New("one or more native builds failed")
	}

	return nil
}
