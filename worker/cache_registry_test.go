package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type cacheRoundTripper func(*http.Request) (*http.Response, error)

func (f cacheRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type registryFixture struct {
	mu                                   sync.Mutex
	payload                              []byte
	requests                             []string
	tokenRequests                        int
	rejectToken, corrupt, truncate       bool
	status                               int
	redirect                             string
	rangeFault                           string
	uploads                              map[string][]byte
	blobs                                map[string][]byte
	rejected                             map[string]bool
	rateLimit                            bool
	failWrite                            int
	completionStatus, completionFailures int
	commitFailure                        bool
	slow                                 bool
	blockUploads                         bool
	started, release                     chan struct{}
}

func newRegistryFixture(t *testing.T) (*registryFixture, *Registry) {
	t.Helper()
	f := &registryFixture{
		payload:  bytes.Repeat([]byte("ciphertext"), 20000),
		status:   200,
		uploads:  map[string][]byte{},
		blobs:    map[string][]byte{},
		rejected: map[string]bool{},
		started:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	r := NewRegistry(Secret{})
	base, _ := url.Parse(server.URL)
	for _, client := range []*http.Client{r.HTTP, r.UploadHTTP} {
		original := client.Transport
		client.Transport = cacheRoundTripper(func(request *http.Request) (*http.Response, error) {
			copy := request.Clone(request.Context())
			copy.URL.Scheme, copy.URL.Host = base.Scheme, base.Host
			return original.RoundTrip(copy)
		})
		t.Cleanup(original.(*http.Transport).CloseIdleConnections)
	}
	t.Cleanup(r.Close)
	return f, r
}

func (f *registryFixture) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	r.Body.Close()
	if f.blockUploads && r.Method == "POST" {
		f.started <- struct{}{}
		<-f.release
	}
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
	if r.URL.Path == "/token" {
		f.tokenRequests++
		token := f.tokenRequests
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"token":      fmt.Sprint(token),
			"expires_in": 300,
		})
		return
	}

	if f.rejectToken && r.Header.Get("Authorization") == "Bearer 1" {
		f.mu.Unlock()
		http.Error(w, "expired", 401)
		return
	}

	if r.Method == "HEAD" {
		data, ok := f.blobs[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Header().Set("Docker-Content-Digest", contentDigest(data))
		w.WriteHeader(200)
		return
	}
	if r.Method != "GET" {
		key := r.Method + " " + r.URL.Path
		if f.failWrite != 0 {
			status := f.failWrite
			f.mu.Unlock()
			http.Error(w, "sensitive backend body", status)
			return
		}

		if f.rateLimit && !f.rejected[key] {
			f.rejected[key] = true
			f.mu.Unlock()
			w.Header().Set("Retry-After", "10")
			http.Error(w, "limit", 429)
			return
		}

		switch r.Method {
		case "POST":
			location := fmt.Sprintf("/upload/%d", len(f.uploads))
			f.uploads[location] = []byte{}
			f.mu.Unlock()
			w.Header().Set("Location", location)
			w.WriteHeader(202)
			return
		case "PATCH":
			if len(body) > UploadChunkSize {
				f.mu.Unlock()
				http.Error(w, "oversize", 413)
				return
			}

			f.uploads[r.URL.Path] = append(f.uploads[r.URL.Path], body...)
			f.mu.Unlock()
			w.Header().Set("Location", r.URL.Path)
			w.WriteHeader(202)
			return
		case "PUT":
			if strings.Contains(r.URL.Path, "/manifests/") {
				f.mu.Unlock()
				w.WriteHeader(201)
				return
			}

			if f.completionFailures > 0 && !f.commitFailure {
				f.completionFailures--
				status := f.completionStatus
				f.mu.Unlock()
				http.Error(w, "sensitive backend body", status)
				return
			}
			f.uploads[r.URL.Path] = append(f.uploads[r.URL.Path], body...)
			data := f.uploads[r.URL.Path]
			digest := r.URL.Query().Get("digest")
			if digest != contentDigest(data) {
				f.mu.Unlock()
				http.Error(w, "wrong digest", 400)
				return
			}

			f.blobs[digest] = append([]byte{}, data...)
			if f.completionFailures > 0 {
				f.completionFailures--
				status := f.completionStatus
				f.mu.Unlock()
				http.Error(w, "sensitive backend body", status)
				return
			}
			f.mu.Unlock()
			w.WriteHeader(201)
			return
		}
	}

	if f.status != 200 {
		status := f.status
		f.mu.Unlock()
		http.Error(w, "failure", status)
		return
	}

	if strings.Contains(r.URL.Path, "/manifests/") {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			f.mu.Unlock()
			http.NotFound(w, r)
			return
		}

		manifest := Manifest{
			Layers: []Descriptor{
				{
					Digest:    contentDigest(f.payload),
					Size:      int64(len(f.payload)),
					MediaType: "application/octet-stream",
				},
			},
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(manifest)
		return
	}

	if f.redirect != "" && strings.Contains(r.URL.Path, "/blobs/") {
		redirect := f.redirect
		f.mu.Unlock()
		w.Header().Set("Location", redirect)
		w.WriteHeader(307)
		return
	}

	data := append([]byte{}, f.payload...)
	truncate, slow, corrupt, rangeFault := f.truncate, f.slow, f.corrupt, f.rangeFault
	f.mu.Unlock()
	status := http.StatusOK
	if value := r.Header.Get("Range"); value != "" && rangeFault != "ignored" {
		var start, end int
		if n, err := fmt.Sscanf(value, "bytes=%d-%d", &start, &end); err != nil || n != 2 || start < 0 || end < start || end >= len(data) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		contentRange := fmt.Sprintf("bytes %d-%d/%d", start, end, len(data))
		switch rangeFault {
		case "offset":
			contentRange = fmt.Sprintf("bytes %d-%d/%d", start+1, end+1, len(data))
		case "total":
			contentRange = fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)+1)
		case "missing":
			contentRange = ""
		}
		w.Header().Set("Content-Range", contentRange)
		data = data[start : end+1]
		if rangeFault == "extra" {
			data = append(data, 0)
		}
		status = http.StatusPartialContent
	}
	if corrupt {
		data[0] ^= 1
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.WriteHeader(status)
	if truncate {
		w.Write(data[:100])
		return
	}

	if slow {
		w.Write(data[:70000])
		w.(http.Flusher).Flush()
		select {
		case f.started <- struct{}{}:
		default:
		}

		<-f.release
		w.Write(data[70000:])
		return
	}

	w.Write(data)
}

func fixtureBlob(t *testing.T, r *Registry) ([]byte, error) {
	t.Helper()
	manifest, _, err := r.GetManifest(cacheTestRepository, "tag")
	if err != nil {
		return nil, err
	}

	reader, err := r.Blob(cacheTestRepository, manifest.Layers[0])
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

func TestRegistryReadsShareTokensAndRefreshRejectedCredentials(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	var group sync.WaitGroup
	for range 24 {
		group.Go(func() {
			body, err := fixtureBlob(t, registry)
			if err == nil && !bytes.Equal(body, fixture.payload) {
				err = errors.New("mixed body")
			}

			if err != nil {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if fixture.tokenRequests != 1 {
		t.Fatal("anonymous tokens not shared")
	}

	fixture.rejectToken = true
	for range 8 {
		group.Go(func() {
			_, _, err := registry.GetManifest(cacheTestRepository, "tag")
			if err != nil {
				t.Error(err)
			}
		})
	}

	group.Wait()
	if fixture.tokenRequests != 2 {
		t.Fatal("rejected token refreshed more than once")
	}

	if _, _, err := registry.GetManifest(cacheTestRepository, "missing"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatal(err)
	}

	for _, status := range []int{401, 403, 429, 500} {
		fixture.status = status
		if _, _, err := registry.GetManifest(cacheTestRepository, "tag"); err == nil || errors.Is(err, ErrObjectNotFound) {
			t.Fatalf("status %d: %v", status, err)
		}
	}
}

func TestRegistryRedirectSecurityAndIntegrity(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	fixture.redirect = "https://pkg-containers.githubusercontent.com/cdn?signature=opaque"
	data, err := fixtureBlob(t, registry)
	if err != nil || !bytes.Equal(data, fixture.payload) {
		t.Fatal(err)
	}

	for _, request := range fixture.requests {
		if strings.Contains(request, "/cdn ") && !strings.HasSuffix(request, "/cdn ") {
			t.Fatal("credentials followed CDN redirect")
		}
	}

	for _, redirect := range []string{
		"http://ghcr.io/blob",
		"https://evil.example/blob",
		"https://ghcr.io@evil.example/blob",
		"https://ghcr.io:444/blob",
		"https://pkg-containers.githubusercontent.com.evil.example/blob",
	} {
		fixture.redirect = redirect
		if _, err := fixtureBlob(t, registry); err == nil || !strings.Contains(err.Error(), "unexpected registry download endpoint") {
			t.Fatal(redirect, err)
		}
	}

	fixture.redirect = "https://ghcr.io/v2/test/cache/blobs/loop"
	if _, err := fixtureBlob(t, registry); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatal(err)
	}

	fixture.redirect = ""
	fixture.corrupt = true
	if _, err := fixtureBlob(t, registry); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatal(err)
	}

	fixture.corrupt = false
	fixture.truncate = true
	if _, err := fixtureBlob(t, registry); err == nil {
		t.Fatal("truncated blob accepted")
	}

	fixture.truncate = false
	if _, err := fixtureBlob(t, registry); err != nil {
		t.Fatal("failure poisoned connection pool", err)
	}
}

func TestRegistryAbortedReadsReleaseConnections(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	descriptor := Descriptor{
		Digest: contentDigest(fixture.payload),
		Size:   int64(len(fixture.payload)),
	}
	for i := 0; i < 20; i++ {
		reader, err := registry.Blob(cacheTestRepository, descriptor)
		if err != nil {
			t.Fatal(err)
		}

		buffer := make([]byte, 1)
		if _, err = reader.Read(buffer); err != nil {
			t.Fatal(err)
		}

		reader.Close()
	}

	if _, err := fixtureBlob(t, registry); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryRangeReadsVerifySegmentsAcrossRedirects(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	fixture.redirect = "https://pkg-containers.githubusercontent.com/cdn?signature=opaque"
	blob := Descriptor{Digest: contentDigest(fixture.payload), Size: int64(len(fixture.payload))}
	for _, span := range [][2]int64{{0, 256}, {123, 456}, {blob.Size - 256, 256}} {
		want := fixture.payload[span[0] : span[0]+span[1]]
		file := SnapshotFile{Blob: blob, Offset: span[0], Size: span[1], Digest: contentDigest(want)}
		reader, err := registry.blobRange(cacheTestRepository, file)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("incorrect range %v: %v", span, err)
		}
	}
	for _, request := range fixture.requests {
		if strings.Contains(request, "/cdn ") && !strings.HasSuffix(request, "/cdn ") {
			t.Fatal("credentials followed range redirect")
		}
	}
	fixture.rejectToken = true
	file := SnapshotFile{Blob: blob, Offset: 100, Size: 256, Digest: contentDigest(fixture.payload[100:356])}
	reader, err := registry.blobRange(cacheTestRepository, file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(got, fixture.payload[100:356]) {
		t.Fatalf("range failed after token refresh: %v", err)
	}
}

func TestRegistryRejectsIncorrectRangeResponses(t *testing.T) {
	for _, fault := range []string{"ignored", "offset", "total", "missing", "extra", "corrupt", "truncated", "unavailable"} {
		t.Run(fault, func(t *testing.T) {
			fixture, registry := newRegistryFixture(t)
			file := SnapshotFile{
				Blob:   Descriptor{Digest: contentDigest(fixture.payload), Size: int64(len(fixture.payload))},
				Offset: 128, Size: 512, Digest: contentDigest(fixture.payload[128:640]),
			}
			fixture.rangeFault = fault
			fixture.corrupt = fault == "corrupt"
			fixture.truncate = fault == "truncated"
			if fault == "unavailable" {
				fixture.status = http.StatusRequestedRangeNotSatisfiable
			}
			reader, err := registry.BlobRange(cacheTestRepository, file)
			if err == nil {
				_, err = io.ReadAll(reader)
				reader.Close()
			}
			if err == nil {
				t.Fatal("incorrect range accepted")
			}
		})
	}
}

func TestRegistryDownloadsContinueWhenUploadConnectionsAreFull(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	registry.auth = Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)}
	fixture.blockUploads = true
	fixture.started = make(chan struct{}, UploadWorkers)
	var group sync.WaitGroup
	defer group.Wait()
	defer close(fixture.release)
	for i := range UploadWorkers {
		group.Go(func() {
			payload := fmt.Sprintf("age-encryption.org/v1\npayload %d", i)
			if _, err := registry.UploadBlob(cacheTestRepository, strings.NewReader(payload), true); err != nil {
				t.Error(err)
			}
		})
	}
	for range UploadWorkers {
		select {
		case <-fixture.started:
		case <-time.After(10 * time.Second):
			t.Fatal("uploads did not fill the connection pool")
		}
	}

	download := make(chan error, 1)
	group.Go(func() {
		data, err := fixtureBlob(t, registry)
		if err == nil && !bytes.Equal(data, fixture.payload) {
			err = errors.New("download payload changed")
		}
		download <- err
	})
	select {
	case err := <-download:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("download stalled behind uploads")
	}
}

func TestRegistryUploadsBoundBodiesAndPreserveConcurrentPayloads(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	registry.auth = Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)}
	_, recipients := cacheKeys(t)
	snapshot := NewSnapshot(registry, cacheTestRepository)
	payload := bytes.Repeat([]byte("private build data"), 500000)
	if err := cacheAdd(snapshot, "cache/nar/test.nar.zst", bytes.NewReader(payload), recipients); err != nil {
		t.Fatal(err)
	}

	d := snapshot.Files["cache/nar/test.nar.zst"]
	if int64(len(fixture.blobs[d.Digest])) != d.Size || d.Size < int64(len(payload)) {
		t.Fatal("incomplete large upload")
	}

	var group sync.WaitGroup
	for i := range 24 {
		group.Go(func() {
			payload := []byte(fmt.Sprintf("age-encryption.org/v1\nprivate %d", i))
			d, err := registry.UploadBlob(cacheTestRepository, bytes.NewReader(payload), true)
			if err != nil {
				t.Error(err)
				return
			}

			fixture.mu.Lock()
			actual := append([]byte{}, fixture.blobs[d.Digest]...)
			fixture.mu.Unlock()
			if !bytes.Equal(actual, payload) {
				t.Error("upload mixed payloads")
			}
		})
	}

	group.Wait()
	if fixture.tokenRequests != 1 {
		t.Fatal("write token not shared")
	}
}

func TestRegistryRejectsPlaintextAndUnsafeUploadLocations(t *testing.T) {
	_, registry := newRegistryFixture(t)
	registry.auth = Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)}
	for _, test := range []struct {
		body      string
		encrypted bool
	}{
		{"private data", true},
		{"not empty config", false},
		{"{}tail", false},
	} {
		if _, err := registry.UploadBlob(cacheTestRepository, strings.NewReader(test.body), test.encrypted); err == nil {
			t.Fatal("accepted plaintext")
		}
	}

	for _, location := range []string{
		"http://ghcr.io/upload",
		"https://evil.example/upload",
		"https://ghcr.io:444/upload",
		"https://user@ghcr.io/upload",
	} {
		if _, err := uploadLocation("https://ghcr.io/v2/test/cache/", http.Header{"Location": {location}}); err == nil {
			t.Fatal("accepted unsafe endpoint", location)
		}
	}
}

func TestRegistryRateLimitsRetryWithoutReconsumingStream(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	fixture.rateLimit = true
	registry.auth = Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)}
	now := time.Unix(1000, 0)

	registry.now = func() time.Time { return now }

	registry.sleep = func(delay time.Duration) {
		if delay > 60*time.Second {
			t.Fatal("unbounded wait")
		}

		now = now.Add(delay)
	}

	registry.jitter = func() time.Duration { return 0 }

	payload := append([]byte("age-encryption.org/v1\n"), bytes.Repeat([]byte("x"), UploadChunkSize)...)
	descriptor, err := registry.UploadBlob(cacheTestRepository, bytes.NewReader(payload), true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture.blobs[descriptor.Digest], payload) {
		t.Fatal("rate retry corrupted payload")
	}

	if _, err = registry.PutManifest(cacheTestRepository, "tag", Manifest{SchemaVersion: 2}); err != nil {
		t.Fatal(err)
	}

	if now.Sub(time.Unix(1000, 0)) < 40*time.Second {
		t.Fatal("did not respect Retry-After")
	}
}

func TestRegistryRetryBoundsAndAmbiguousWriteFailures(t *testing.T) {
	registry := NewRegistry(Secret{})
	defer registry.Close()

	now := time.Unix(1000, 0)

	registry.now = func() time.Time { return now }

	registry.sleep = func(delay time.Duration) { now = now.Add(delay) }

	registry.jitter = func() time.Duration { return 0 }

	attempts := 0
	if err := registry.retryUpload(func() error {
		attempts++
		return &UploadError{
			Status:    429,
			Operation: "test",
		}
	}); err == nil || attempts != 9 || now.Sub(time.Unix(1000, 0)) >= 600*time.Second {
		t.Fatalf("unbounded retries %d %v", attempts, err)
	}

	registry.cooldownUntil = time.Time{}
	attempts = 0
	before := now
	if err := registry.retryUpload(func() error {
		attempts++
		return &UploadError{
			Status:     429,
			RetryAfter: time.Hour,
		}
	}); err == nil || attempts != 1 || !now.Equal(before) {
		t.Fatal("waited beyond retry budget")
	}

	registry.cooldownUntil = time.Time{}
	for _, failure := range []error{errors.New("timeout"), &UploadError{Status: 503}, &UploadError{Status: 403}} {
		attempts = 0
		err := registry.retryUpload(func() error {
			attempts++
			return failure
		})
		if err != failure || attempts != 1 {
			t.Fatal("replayed ambiguous or permanent failure")
		}
	}

	registry.uploadRetries = 0
	registry.retryUpload(func() error {
		return &UploadError{
			Status:     429,
			RetryAfter: 45 * time.Second,
		}
	})
	before = now
	if err := registry.retryUpload(func() error { return nil }); err != nil || now.Sub(before) != 45*time.Second {
		t.Fatal("exhaustion lost shared cooldown")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, test := range []struct {
		value string
		delay time.Duration
		valid bool
	}{
		{"120", 120 * time.Second, true},
		{now.Add(120 * time.Second).UTC().Format(http.TimeFormat), 120 * time.Second, true},
		{now.Add(-time.Second).UTC().Format(http.TimeFormat), 0, true},
		{"-1", 0, false},
		{"+1", 0, false},
		{"", 0, false},
		{"1.5", 0, false},
		{"9223372037", 0, false},
		{"nan", 0, false},
		{strings.Repeat("1", 10000), 0, false},
	} {
		delay, valid := RetryAfterSeconds(test.value, now)
		if delay != test.delay || valid != test.valid {
			t.Fatalf("%q: %v %t", test.value, delay, valid)
		}
	}
}

func TestRegistryDoesNotExposeSensitiveWriteBodies(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	fixture.failWrite = 403
	registry.auth = Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)}
	_, err := registry.UploadBlob(cacheTestRepository, strings.NewReader("age-encryption.org/v1\nsecret"), true)
	if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "encoded") {
		t.Fatal(err)
	}
}

func TestAgeHTTPStreamingWaitsForRegistryIntegrity(t *testing.T) {
	identity, recipients := cacheKeys(t)
	fixture, registry := newRegistryFixture(t)
	plaintext := bytes.Repeat([]byte("private payload"), 30000)
	encrypted, err := EncryptedStream(bytes.NewReader(plaintext), recipients)
	if err != nil {
		t.Fatal(err)
	}

	fixture.payload, err = io.ReadAll(encrypted)
	encrypted.Close()
	if err != nil {
		t.Fatal(err)
	}

	fixture.slow = true
	snapshot := NewSnapshot(registry, cacheTestRepository)
	record := bytes.Clone(fixture.payload)
	fixture.payload = append(fixture.payload, record...)
	file := SnapshotFile{
		Blob:   Descriptor{Digest: contentDigest(fixture.payload), Size: int64(len(fixture.payload))},
		Offset: int64(len(record)), Size: int64(len(record)), Digest: contentDigest(record),
	}
	snapshot.Files["cache/nar/test.nar.zst"] = file
	handler := NewCacheHandler(registry, "", "", identity, nil)
	handler.SetSnapshot(snapshot)
	server := httptest.NewServer(handler)
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)

		response, err := server.Client().Get(server.URL + "/nar/test.nar.zst")
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()

		first := make([]byte, 1024)
		if _, err = io.ReadFull(response.Body, first); err != nil {
			t.Error(err)
			return
		}

		if !bytes.Equal(first, plaintext[:1024]) {
			t.Error("wrong plaintext")
		}

		close(fixture.release)
		rest, err := io.ReadAll(response.Body)
		if err != nil || !bytes.Equal(append(first, rest...), plaintext) {
			t.Errorf("stream failed: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(fixture.release)
		t.Fatal("plaintext blocked on full ciphertext download")
	}

	fixture.slow = false
	file.Digest = "sha256:" + strings.Repeat("0", 64)
	snapshot.Files["cache/nar/test.nar.zst"] = file
	response, err := server.Client().Get(server.URL + "/nar/test.nar.zst")
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err == nil && response.StatusCode == http.StatusOK {
		t.Fatal("registry integrity failure was lost after successful age decryption")
	}
}

func TestRegistryLongCooldownRefreshesExpiredWriteToken(t *testing.T) {
	registry := NewRegistry(Secret{Data: []byte(`{"auths":{"ghcr.io":{"auth":"encoded"}}}`)})
	defer registry.Close()

	now := time.Unix(1000, 0)

	registry.now = func() time.Time { return now }

	registry.sleep = func(delay time.Duration) { now = now.Add(delay) }

	registry.jitter = func() time.Duration { return 0 }

	tokens := 0
	used := []string{}
	registry.UploadHTTP.Transport = cacheRoundTripper(func(request *http.Request) (*http.Response, error) {
		response := &http.Response{
			StatusCode: 202,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}
		if request.URL.Path == "/token" {
			tokens++
			response.StatusCode = 200
			response.Body = io.NopCloser(strings.NewReader(fmt.Sprintf(`{"token":"token-%d","expires_in":10}`, tokens)))
		} else {
			used = append(used, request.Header.Get("Authorization"))
			if len(used) == 1 {
				response.StatusCode = 429
				response.Header.Set("Retry-After", "20")
			}
		}

		return response, nil
	})
	if _, _, err := registry.writeRequest(cacheTestRepository, "https://ghcr.io/upload/one", "PATCH", nil, []byte("ciphertext"), 202); err != nil {
		t.Fatal(err)
	}

	if tokens != 2 || len(used) != 2 || used[0] != "Bearer token-1" || used[1] != "Bearer token-2" {
		t.Fatal(tokens, used)
	}
}

func TestRegistryScopesPoolCredentials(t *testing.T) {
	registry := NewRegistry(RegistryCredential("workflow", "cache-token"))
	defer registry.Close()
	registry.repositoryAuth = map[string]Secret{cacheTestRepository + "-pool": RegistryCredential("pool-user", "pool-token")}
	transport := cacheRoundTripper(func(request *http.Request) (*http.Response, error) {
		user, token, ok := request.BasicAuth()
		pool := strings.Contains(request.URL.Query().Get("scope"), "infra-ci-pool:")
		wantUser, wantToken := "workflow", "cache-token"
		if pool {
			wantUser, wantToken = "pool-user", "pool-token"
		}
		if !ok || user != wantUser || token != wantToken {
			t.Fatal("wrong credential for scope", request.URL.Query().Get("scope"))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"token":"scoped","expires_in":300}`)), Request: request}, nil
	})
	registry.HTTP.Transport, registry.UploadHTTP.Transport = transport, transport
	for _, repository := range []string{cacheTestRepository, cacheTestRepository + "-pool", cacheTestRepository + "-pool-other"} {
		for _, write := range []bool{false, true} {
			if _, err := registry.token(repository, "", write); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestRegistryRecoversBlobCompletion(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		for _, committed := range []bool{false, true} {
			for _, large := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/committed=%v/large=%v", status, committed, large), func(t *testing.T) {
					fixture, registry := newRegistryFixture(t)
					registry.auth = RegistryCredential("user", "token")
					now := time.Unix(1000, 0)
					registry.now = func() time.Time { return now }
					registry.sleep = func(delay time.Duration) { now = now.Add(delay) }
					registry.jitter = func() time.Duration { return 0 }
					fixture.completionStatus, fixture.completionFailures, fixture.commitFailure = status, 1, committed
					payload := []byte("age-encryption.org/v1\nprivate payload")
					if large {
						payload = append(payload, bytes.Repeat([]byte("x"), UploadChunkSize)...)
					}
					descriptor, err := registry.UploadBlob(cacheTestRepository, bytes.NewReader(payload), true)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(fixture.blobs[descriptor.Digest], payload) || descriptor.Size != int64(len(payload)) {
						t.Fatal("completion recovery corrupted blob")
					}
					puts := 0
					for _, request := range fixture.requests {
						if strings.HasPrefix(request, "PUT ") {
							puts++
						}
					}
					want := 2
					if committed {
						want = 1
					}
					if puts != want {
						t.Fatalf("completion requests: got %d, want %d", puts, want)
					}
				})
			}
		}
	}
}

func TestRegistryCompletionRetryBounds(t *testing.T) {
	fixture, registry := newRegistryFixture(t)
	registry.auth = RegistryCredential("user", "token")
	now := time.Unix(1000, 0)
	registry.now = func() time.Time { return now }
	registry.sleep = func(delay time.Duration) { now = now.Add(delay) }
	registry.jitter = func() time.Duration { return 0 }
	fixture.completionStatus, fixture.completionFailures = 500, 100
	_, err := registry.UploadBlob(cacheTestRepository, strings.NewReader("{}"), false)
	var upload *UploadError
	if !errors.As(err, &upload) || upload.Status != 500 || fixture.completionFailures != 91 || now.Sub(time.Unix(1000, 0)) >= 600*time.Second {
		t.Fatalf("unexpected completion retry outcome: %v, failures left %d", err, fixture.completionFailures)
	}
}

func TestRegistryRejectsMismatchedCompletedBlob(t *testing.T) {
	for _, header := range []string{"Content-Length", "Docker-Content-Digest"} {
		t.Run(header, func(t *testing.T) {
			fixture, registry := newRegistryFixture(t)
			registry.auth = RegistryCredential("user", "token")
			now := time.Unix(1000, 0)
			registry.now = func() time.Time { return now }
			registry.sleep = func(delay time.Duration) { now = now.Add(delay) }
			registry.jitter = func() time.Duration { return 0 }
			fixture.completionStatus, fixture.completionFailures, fixture.commitFailure = 500, 1, true
			transport := registry.UploadHTTP.Transport
			registry.UploadHTTP.Transport = cacheRoundTripper(func(request *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(request)
				if err == nil && request.Method == "HEAD" {
					response.Header.Set(header, "0")
				}
				return response, err
			})
			if _, err := registry.UploadBlob(cacheTestRepository, strings.NewReader("{}"), false); err == nil {
				t.Fatal("accepted mismatched blob metadata")
			}
		})
	}
}
