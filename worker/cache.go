package worker

import (
	"errors"
	"fmt"
	"io"
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
	defer r.mu.Unlock()

	missing := r.snapshot == nil || (name != "" && !r.snapshot.HasFile(name))
	now := r.now()
	if !now.Before(r.deadline) || (missing && !now.Before(r.retryAfter)) {
		manifest, digest, err := r.storage.GetManifest(r.repository, r.reference)
		var loaded *Snapshot
		if err == nil && (r.snapshot == nil || r.snapshot.Digest != digest) {
			var identity Secret
			identity, err = r.identity.read()
			if err == nil {
				loaded, err = loadSnapshot(r.storage, r.repository, manifest, digest, identity)
			}
		}

		if err != nil {
			r.refreshError = fmt.Errorf("cache catalog refresh failed: %w", err)
			r.deadline, r.retryAfter = r.now().Add(5*time.Second), r.now().Add(5*time.Second)
			if r.log != nil {
				fmt.Fprintln(r.log, r.refreshError)
			}
		} else {
			if loaded != nil {
				r.stateMu.Lock()
				r.snapshot = loaded
				r.stateMu.Unlock()
			}

			r.refreshError = nil
			r.deadline, r.retryAfter = r.now().Add(30*time.Second), r.now().Add(5*time.Second)
			if strings.HasPrefix(r.reference, "sha256:") {
				r.deadline = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
				r.retryAfter = r.deadline
			}
		}
	}

	if r.refreshError != nil && (r.snapshot == nil || (name != "" && !r.snapshot.HasFile(name))) {
		return nil, r.refreshError
	}

	return r.snapshot, nil
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
	default:
		panic(http.ErrAbortHandler)
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

type cacheListener struct {
	net.Listener
	slots chan struct{}
}

type cacheConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *cacheConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (l *cacheListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		select {
		case l.slots <- struct{}{}:
			return &cacheConnection{
				Conn:    connection,
				release: func() { <-l.slots },
			}, nil
		default:
			connection.Close()
		}
	}
}

func StartCacheServer(handler http.Handler, port int) (*http.Server, net.Listener, error) {
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}

	bounded := &cacheListener{
		Listener: listener,
		slots:    make(chan struct{}, 32),
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go server.Serve(bounded)
	return server, bounded, nil
}
