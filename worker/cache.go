package worker

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SnapshotReader struct {
	storage               Storage
	repository, reference string
	identity              cacheIdentity
	log                   io.Writer
	mu                    sync.Mutex
	stateMu               sync.RWMutex
	snapshot              *Snapshot
	views                 map[string]*catalogView
	deadline, retryAfter  time.Time
	refreshError          error
	now                   func() time.Time
}

func NewSnapshotReader(storage Storage, repository, reference string, identity Secret, log io.Writer) *SnapshotReader {
	return newSnapshotReader(storage, repository, reference, cacheIdentity{secret: identity}, log)
}

func newSnapshotReader(storage Storage, repository, reference string, identity cacheIdentity, log io.Writer) *SnapshotReader {
	if reference == "" {
		reference = "nixos-cache-latest"
	}
	return &SnapshotReader{
		storage:    storage,
		repository: repository,
		reference:  reference,
		identity:   identity,
		log:        log,
		now:        time.Now,
		views:      map[string]*catalogView{},
	}
}

func (r *SnapshotReader) Current(name string) (*Snapshot, error) {
	r.stateMu.RLock()
	snapshot := r.snapshot
	r.stateMu.RUnlock()
	if snapshot != nil && (name == "" || snapshot.HasFile(name)) {
		if !r.mu.TryLock() {
			return snapshot, nil
		}
	} else {
		r.mu.Lock()
	}
	missing := r.snapshot == nil || (name != "" && !r.snapshot.HasFile(name))
	now := r.now()
	if !now.Before(r.deadline) || (missing && !now.Before(r.retryAfter)) {
		r.refresh()
	}
	snapshot = r.snapshot
	views := r.currentViews()
	refreshError := r.refreshError
	r.mu.Unlock()
	if snapshot != nil && name != "" && !snapshot.HasFile(name) {
		err := r.lookup(name, views)
		if errors.Is(err, ErrObjectNotFound) {
			// Recover a missing shard after external registry changes.
			r.mu.Lock()
			r.refresh()
			views = r.currentViews()
			refreshError = r.refreshError
			r.mu.Unlock()
			err = r.lookup(name, views)
			if errors.Is(err, ErrObjectNotFound) {
				err = errors.New("cache catalog references a missing blob")
			}
		}
		r.stateMu.RLock()
		snapshot = r.snapshot
		r.stateMu.RUnlock()
		if err != nil && !snapshot.HasFile(name) {
			return nil, fmt.Errorf("cache catalog lookup failed: %w", err)
		}
	}
	if refreshError != nil && (snapshot == nil || (name != "" && !snapshot.HasFile(name))) {
		return nil, refreshError
	}
	if snapshot == nil {
		return nil, ErrObjectNotFound
	}
	return snapshot, nil
}

// Called under mu; views remain valid while a later refresh replaces the heads.
func (r *SnapshotReader) currentViews() []*catalogView {
	views := []*catalogView{}
	for _, reference := range r.references() {
		if view := r.views[reference]; view != nil {
			views = append(views, view)
		}
	}
	return views
}

func (r *SnapshotReader) references() []string {
	if r.reference != "nixos-cache-latest" {
		return []string{r.reference}
	}
	return platformTags()
}

func (r *SnapshotReader) refresh() {
	var failures []error
	references := r.references()
	type result struct {
		view *catalogView
		err  error
	}
	results := make([]result, len(references))
	var group sync.WaitGroup
	for i, reference := range references {
		prior := r.views[reference]
		group.Add(1)
		go func() {
			defer group.Done()
			var digest string
			var err error
			view := prior
			if prior != nil {
				digest, err = r.storage.ManifestDigest(r.repository, reference)
			}
			if err == nil && (prior == nil || prior.digest != digest) {
				var manifest Manifest
				manifest, digest, err = r.storage.GetManifest(r.repository, reference)
				if err == nil {
					var identity Secret
					identity, err = r.identity.read()
					if err == nil {
						view, err = openCatalog(r.storage, r.repository, manifest, digest, identity)
					}
					if err == nil && prior != nil {
						prior.mu.Lock()
						for hash, node := range prior.nodes {
							if _, reachable := view.reachable[hash]; reachable {
								view.nodes[hash] = node
							}
						}
						prior.mu.Unlock()
					}
				}
			}
			results[i] = result{view, err}
		}()
	}
	group.Wait()
	for i, reference := range references {
		result := results[i]
		if result.err == nil {
			r.views[reference] = result.view
		} else if !errors.Is(result.err, ErrObjectNotFound) || r.views[reference] != nil || len(references) == 1 {
			failures = append(failures, result.err)
		}
	}
	if len(r.views) == 0 && len(failures) == 0 {
		failures = append(failures, ErrObjectNotFound)
	}
	if len(r.views) > 0 {
		next := r.copySnapshot()
		digests := []string{}
		for _, reference := range references {
			view := r.views[reference]
			if view == nil {
				continue
			}
			digests = append(digests, view.digest)
		}
		if len(digests) == 1 {
			next.Digest = digests[0]
		} else {
			next.Digest = contentDigest([]byte(strings.Join(digests, "\n")))
		}
		r.setSnapshot(next)
	}
	if len(failures) > 0 {
		r.refreshError = fmt.Errorf("cache catalog refresh failed: %w", errors.Join(failures...))
		r.deadline, r.retryAfter = r.now().Add(5*time.Second), r.now().Add(5*time.Second)
		if r.log != nil {
			fmt.Fprintln(r.log, r.refreshError)
		}
	} else {
		r.refreshError = nil
		r.deadline, r.retryAfter = r.now().Add(30*time.Second), r.now().Add(5*time.Second)
		if strings.HasPrefix(r.reference, "sha256:") {
			r.deadline = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			r.retryAfter = r.deadline
		}
	}
}

func (r *SnapshotReader) copySnapshot() *Snapshot {
	next := NewSnapshot(r.storage, r.repository)
	if r.snapshot != nil {
		next.Digest = r.snapshot.Digest
		next.Files, next.Narinfos = maps.Clone(r.snapshot.Files), maps.Clone(r.snapshot.Narinfos)
	}
	return next
}

func (r *SnapshotReader) setSnapshot(snapshot *Snapshot) {
	r.stateMu.Lock()
	r.snapshot = snapshot
	r.stateMu.Unlock()
}

func mergeConsumerRecords(target, source *Snapshot) error {
	for name, text := range source.Narinfos {
		if old, exists := target.Narinfos[name]; exists {
			if err := matchingNarinfos(old, text); err != nil {
				return err
			}
		}
	}
	for name, file := range source.Files {
		if consumerFile(name) {
			if _, exists := target.Files[name]; !exists {
				target.Files[name] = file
			}
		}
	}
	for name, text := range source.Narinfos {
		if _, exists := target.Narinfos[name]; !exists {
			target.Narinfos[name] = text
		}
	}
	return nil
}

func (r *SnapshotReader) lookup(name string, views []*catalogView) error {
	identity, err := r.identity.read()
	if err != nil {
		return err
	}
	var failures []error
	for _, view := range views {
		found, err := view.lookup(name, identity)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		r.mu.Lock()
		next := r.copySnapshot()
		err = mergeConsumerRecords(next, found)
		if err == nil {
			r.setSnapshot(next)
		}
		r.mu.Unlock()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if next.HasFile(name) {
			break
		}
	}
	return errors.Join(failures...)
}

var cachePathPattern = regexp.MustCompile(`^(?:nix-cache-info|[0-9abcdfghijklmnpqrsvwxyz]{32}\.narinfo|nar/[A-Za-z0-9._-]+\.nar(?:\.[A-Za-z0-9]+)?)$`)

func ValidCachePath(path string) bool { return cachePathPattern.MatchString(path) }

type CacheHandler struct {
	identity cacheIdentity
	reader   *SnapshotReader
	log      io.Writer
	mu       sync.RWMutex
	snapshot *Snapshot
	errors   []error
	slots    chan struct{}
}

func NewCacheHandler(storage Storage, repository, reference string, identity Secret, log io.Writer) *CacheHandler {
	return newCacheHandler(storage, repository, reference, cacheIdentity{secret: identity}, log)
}

// NewFileCacheHandler re-reads identityPath before decrypting each cache catalog or NAR.
func NewFileCacheHandler(storage Storage, repository, reference, identityPath string, log io.Writer) *CacheHandler {
	return newCacheHandler(storage, repository, reference, cacheIdentity{path: identityPath}, log)
}

type cacheIdentity struct {
	secret Secret
	path   string
}

func (i cacheIdentity) read() (Secret, error) {
	if i.path != "" {
		return ReadCredentialFile(i.path)
	}

	return i.secret, nil
}

func newCacheHandler(storage Storage, repository, reference string, identity cacheIdentity, log io.Writer) *CacheHandler {
	h := &CacheHandler{
		identity: identity,
		log:      log,
		slots:    make(chan struct{}, 32),
	}
	if repository != "" {
		h.reader = newSnapshotReader(storage, repository, reference, identity, log)
	}

	return h
}

func (h *CacheHandler) SetSnapshot(snapshot *Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.snapshot = snapshot
}

func (h *CacheHandler) Errors() []error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return slices.Clone(h.errors)
}

func (h *CacheHandler) current(name string) (*Snapshot, error) {
	h.mu.RLock()
	snapshot := h.snapshot
	h.mu.RUnlock()
	if snapshot != nil {
		return snapshot, nil
	}
	if h.reader == nil {
		return nil, ErrObjectNotFound
	}

	return h.reader.Current(name)
}

func (h *CacheHandler) failure(w http.ResponseWriter, name string, err error, started bool) {
	if !errors.Is(err, ErrObjectNotFound) {
		h.mu.Lock()
		h.errors = append(h.errors, err)
		if h.log != nil {
			fmt.Fprintf(h.log, "Cache request %s failed: %v\n", name, err)
		}

		h.mu.Unlock()
	}

	if started {
		panic(http.ErrAbortHandler)
	}

	status := http.StatusBadGateway
	if errors.Is(err, ErrObjectNotFound) {
		status = http.StatusNotFound
	}

	http.Error(w, http.StatusText(status), status)
}

func (h *CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-r.Context().Done():
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.RequestURI, "/")
	if !ValidCachePath(name) {
		http.NotFound(w, r)
		return
	}

	if name == "nix-cache-info" {
		data := "StoreDir: /nix/store\nWantMassQuery: 1\n"
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(200)
		if r.Method != "HEAD" {
			io.WriteString(w, data)
		}

		return
	}

	snapshot, err := h.current("cache/" + name)
	if err != nil {
		h.failure(w, name, err, false)
		return
	}

	if r.Method == "HEAD" {
		if !snapshot.HasFile("cache/" + name) {
			h.failure(w, name, ErrObjectNotFound, false)
			return
		}

		w.WriteHeader(200)
		return
	}

	identity := Secret{}
	_, plaintextRecord := snapshot.Narinfos["cache/"+name]
	if _, encrypted := snapshot.Files["cache/"+name]; encrypted && !plaintextRecord {
		identity, err = h.identity.read()
		if err != nil {
			h.failure(w, name, err, false)
			return
		}
	}

	stream, err := snapshot.Read("cache/"+name, identity)
	if err != nil {
		h.failure(w, name, err, false)
		return
	}
	defer stream.Close()

	buffer := make([]byte, 64*1024)
	n, readErr := stream.Read(buffer)
	if readErr != nil && readErr != io.EOF && n == 0 {
		h.failure(w, name, readErr, false)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(200)
	for {
		if n > 0 {
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(120 * time.Second))
			if _, err = w.Write(buffer[:n]); err != nil {
				return
			}

			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}

		if readErr != nil {
			if readErr != io.EOF {
				h.failure(w, name, readErr, true)
			}

			return
		}

		n, readErr = stream.Read(buffer)
	}
}

func StartCacheServer(handler http.Handler, port int) (*http.Server, net.Listener, error) {
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go server.Serve(listener)
	return server, listener, nil
}
