package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	UploadChunkSize   = 4 * 1024 * 1024
	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	blobLimit         = int64(10 * 1024 * 1024 * 1024)
	metadataLimit     = 16 * 1024 * 1024
)

var ErrObjectNotFound = errors.New("object not found")

var repositoryPattern = regexp.MustCompile(`^ghcr\.io/([a-z0-9-]+)/([a-z0-9][a-z0-9._-]*)$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var referencePattern = regexp.MustCompile(`^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|sha256:[a-f0-9]{64})$`)

func RepositoryParts(repository string) (string, string, error) {
	m := repositoryPattern.FindStringSubmatch(repository)
	if m == nil {
		return "", "", errors.New("expected ghcr.io/OWNER/PACKAGE")
	}

	return m[1], m[2], nil
}
func ManifestPath(reference string) (string, error) {
	if !referencePattern.MatchString(reference) {
		return "", errors.New("invalid object tag")
	}

	return "/manifests/" + reference, nil
}

func contentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type Descriptor struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	MediaType   string            `json:"mediaType,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (d *Descriptor) UnmarshalJSON(data []byte) error {
	var value struct {
		Digest      string            `json:"digest"`
		Size        *int64            `json:"size"`
		MediaType   string            `json:"mediaType"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	if value.Size == nil {
		return errors.New("missing layer size")
	}

	*d = Descriptor{
		Digest:      value.Digest,
		Size:        *value.Size,
		MediaType:   value.MediaType,
		Annotations: value.Annotations,
	}
	return nil
}

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type Storage interface {
	ManifestDigest(repository, reference string) (string, error)
	GetManifest(repository, reference string) (Manifest, string, error)
	PutManifest(repository, tag string, manifest Manifest) (string, error)
	UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error)
	Blob(repository string, descriptor Descriptor) (io.ReadCloser, error)
	BlobRange(repository string, file SnapshotFile) (io.ReadCloser, error)
}

type UploadError struct {
	Status     int
	Operation  string
	RetryAfter time.Duration
}

func (e *UploadError) Error() string {
	return fmt.Sprintf("GHCR %s failed (HTTP %d)", e.Operation, e.Status)
}

func RetryAfterSeconds(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64((1<<63-1)/int64(time.Second)) {
			return 0, false
		}

		return time.Duration(seconds) * time.Second, true
	}

	t, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}

	return max(0, t.Sub(now)), true
}

type registryToken struct {
	Value    string
	Deadline time.Time
}

type Registry struct {
	auth                                Secret
	HTTP, UploadHTTP                    *http.Client
	tokensMu, writeTokensMu, cooldownMu sync.Mutex
	tokens, writeTokens                 map[string]registryToken
	cooldownUntil                       time.Time
	now                                 func() time.Time
	sleep                               func(time.Duration)
	jitter                              func() time.Duration
	uploadRetries                       int
	downloads                           *packDownloads
}

type deadlineConn struct{ net.Conn }

func (c deadlineConn) Read(p []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(120 * time.Second))
	return c.Conn.Read(p)
}

func (c deadlineConn) Write(p []byte) (int, error) {
	c.SetWriteDeadline(time.Now().Add(120 * time.Second))
	return c.Conn.Write(p)
}

func NewRegistry(auth Secret) *Registry {
	dialer := net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   16,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		DisableCompression:    true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}

			return deadlineConn{conn}, nil
		},
	}
	return &Registry{
		auth: auth,
		HTTP: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		// Publishing must not consume the connection slots used by substitution.
		UploadHTTP: &http.Client{
			Transport:     transport.Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		tokens:        map[string]registryToken{},
		writeTokens:   map[string]registryToken{},
		now:           time.Now,
		sleep:         time.Sleep,
		jitter:        func() time.Duration { return time.Duration(rand.Int64N(int64(5 * time.Second))) },
		uploadRetries: 8,
		downloads:     newPackDownloads(downloadCacheBytes),
	}
}

func (r *Registry) Close() {
	r.HTTP.CloseIdleConnections()
	r.UploadHTTP.CloseIdleConnections()
}

func readLimited(reader io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("response exceeds size limit")
	}

	return b, nil
}

func basicAuth(credential Secret) (string, error) {
	var config struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(credential.Data, &config); err != nil {
		return "", errors.New("invalid registry authentication configuration")
	}

	auth := config.Auths["ghcr.io"].Auth
	if auth == "" {
		return "", errors.New("missing registry authentication")
	}

	return auth, nil
}

func (r *Registry) response(method, endpoint string, headers http.Header, body []byte, readRetry bool) (*http.Response, error) {
	tries := 1
	client := r.UploadHTTP
	if readRetry {
		tries = 3
		client = r.HTTP
	}

	for i := 0; i < tries; i++ {
		req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("invalid registry endpoint")
		}

		req.Header.Set("User-Agent", "https://github.com/awked-com/nix-ci-worker")
		req.Header.Set("Accept-Encoding", "identity")
		for key, values := range headers {
			req.Header[key] = slices.Clone(values)
		}

		req.GetBody = nil // A lost write response is ambiguous and must never be replayed.
		response, err := client.Do(req)
		if err == nil {
			return response, nil
		}
		if i+1 == tries {
			return nil, fmt.Errorf("registry %s transport failed", method)
		}
	}

	panic("unreachable")
}

func (r *Registry) HTTPRequest(endpoint, method string, headers http.Header, data []byte, expected int) (http.Header, []byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "ghcr.io" || u.User != nil {
		return nil, nil, errors.New("unexpected upload endpoint")
	}

	response, err := r.response(method, endpoint, headers, data, false)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	body, err := readLimited(response.Body, 1024*1024)
	if err != nil {
		return nil, nil, err
	}

	if response.StatusCode != expected {
		operation := "request"
		switch {
		case u.Path == "/token":
			operation = "authentication"
		case strings.Contains(u.Path, "/manifests/"):
			operation = "manifest publication"
		case method == "POST":
			operation = "starting blob upload"
		case method == "PATCH":
			operation = "streaming blob upload"
		case method == "PUT":
			operation = "completing blob upload"
		}

		retry, _ := RetryAfterSeconds(response.Header.Get("Retry-After"), r.now())
		return nil, nil, &UploadError{response.StatusCode, operation, retry}
	}

	return response.Header, body, nil
}

func (r *Registry) retryUpload(operation func() error) error {
	return r.retryPublication(operation, false)
}

func (r *Registry) retryPublication(operation func() error, completion bool) error {
	deadline := r.now().Add(600 * time.Second)
	var last error = &UploadError{
		Status:    429,
		Operation: "waiting for registry rate limit",
	}
	for attempt := 0; attempt <= r.uploadRetries; attempt++ {
		for {
			now := r.now()
			r.cooldownMu.Lock()
			delay := r.cooldownUntil.Sub(now)
			r.cooldownMu.Unlock()
			if !now.Before(deadline) || now.Add(max(0, delay)).After(deadline) {
				return last
			}
			if delay <= 0 {
				break
			}

			r.sleep(min(delay, 60*time.Second))
		}

		err := operation()
		if err == nil {
			return nil
		}

		var upload *UploadError
		if !errors.As(err, &upload) || (upload.Status != 429 && !(completion && transientUploadStatus(upload.Status))) {
			return err
		}

		delay := max(min(60*time.Second, 5*time.Second*time.Duration(1<<attempt))+r.jitter(), upload.RetryAfter)
		r.cooldownMu.Lock()
		if next := r.now().Add(delay); next.After(r.cooldownUntil) {
			r.cooldownUntil = next
		}

		until := r.cooldownUntil
		r.cooldownMu.Unlock()
		if attempt == r.uploadRetries || !until.Before(deadline) {
			return err
		}

		last = err
	}

	return last
}

func (r *Registry) token(repository, rejected string, write bool) (string, error) {
	owner, packageName, err := RepositoryParts(repository)
	if err != nil {
		return "", err
	}

	lock, tokens := &r.tokensMu, r.tokens
	scope := "pull"
	if write {
		if len(r.auth.Data) == 0 {
			return "", errors.New("publishing requires GHCR write credentials")
		}

		lock, tokens = &r.writeTokensMu, r.writeTokens
		scope = "pull,push"
	}

	lock.Lock()
	defer lock.Unlock()

	cached := tokens[repository]
	if cached.Value != "" && cached.Value != rejected && r.now().Before(cached.Deadline) {
		return cached.Value, nil
	}

	query := url.Values{
		"service": {"ghcr.io"},
		"scope":   {"repository:" + owner + "/" + packageName + ":" + scope},
	}
	headers := http.Header{}
	if len(r.auth.Data) != 0 {
		auth, err := basicAuth(r.auth)
		if err != nil {
			return "", err
		}

		headers.Set("Authorization", "Basic "+auth)
	}

	var data []byte
	if write {
		err = r.retryUpload(func() error {
			var err error
			_, data, err = r.HTTPRequest("https://ghcr.io/token?"+query.Encode(), "GET", headers, nil, 200)
			return err
		})
	} else {
		var response *http.Response
		response, err = r.response("GET", "https://ghcr.io/token?"+query.Encode(), headers, nil, true)
		if err == nil {
			defer response.Body.Close()

			if response.StatusCode != 200 {
				return "", fmt.Errorf("registry token request failed (HTTP %d)", response.StatusCode)
			}

			data, err = readLimited(response.Body, metadataLimit)
		}
	}

	if err != nil {
		return "", err
	}

	var result struct {
		Token     string   `json:"token"`
		ExpiresIn *float64 `json:"expires_in"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return "", err
	}

	if result.Token == "" {
		return "", errors.New("registry returned an empty token")
	}

	lifetime := 60.0
	if result.ExpiresIn != nil {
		lifetime = max(1, *result.ExpiresIn)
	}

	tokens[repository] = registryToken{result.Token, r.now().Add(time.Duration(lifetime * 0.9 * float64(time.Second)))}
	return result.Token, nil
}

func (r *Registry) Token(repository, rejected string) (string, error) {
	return r.token(repository, rejected, false)
}

func (r *Registry) WriteToken(repository, rejected string) (string, error) {
	return r.token(repository, rejected, true)
}

func (r *Registry) registryResponse(repository, path, method string, headers http.Header) (*http.Response, error) {
	token, err := r.Token(repository, "")
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < 2; attempt++ {
		h := headers.Clone()
		if h == nil {
			h = http.Header{}
		}
		h.Set("Authorization", "Bearer "+token)
		h.Set("Accept", manifestMediaType)
		response, err := r.response(method, "https://"+strings.Replace(repository, "ghcr.io/", "ghcr.io/v2/", 1)+path, h, nil, true)
		if err != nil {
			return nil, err
		}

		if response.StatusCode != 401 || attempt == 1 {
			if response.StatusCode == 404 {
				_, err = readLimited(response.Body, metadataLimit)
				response.Body.Close()
				if err != nil {
					return nil, err
				}

				return nil, ErrObjectNotFound
			}

			return response, nil
		}

		_, err = readLimited(response.Body, metadataLimit)
		response.Body.Close()
		if err != nil {
			return nil, err
		}

		token, err = r.Token(repository, token)
		if err != nil {
			return nil, err
		}
	}

	panic("unreachable")
}

func (r *Registry) writeRequest(repository, endpoint, method string, headers http.Header, data []byte, expected int) (http.Header, []byte, error) {
	var resultHeaders http.Header
	var result []byte
	err := r.retryUpload(func() error {
		token, err := r.WriteToken(repository, "")
		if err != nil {
			return err
		}

		for attempt := 0; attempt < 2; attempt++ {
			h := headers.Clone()
			if h == nil {
				h = http.Header{}
			}

			h.Set("Authorization", "Bearer "+token)
			resultHeaders, result, err = r.HTTPRequest(endpoint, method, h, data, expected)
			var upload *UploadError
			if !errors.As(err, &upload) || upload.Status != 401 || attempt == 1 {
				return err
			}

			token, err = r.WriteToken(repository, token)
			if err != nil {
				return err
			}
		}

		return err
	})
	return resultHeaders, result, err
}

func uploadLocation(current string, headers http.Header) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", err
	}

	location := headers.Get("Location")
	if location == "" {
		return "", errors.New("missing registry upload endpoint")
	}

	target, err := base.Parse(location)
	if err != nil || target.Scheme != "https" || target.Host != "ghcr.io" || target.User != nil {
		return "", errors.New("unexpected registry upload endpoint")
	}

	return target.String(), nil
}

func (r *Registry) UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error) {
	var empty Descriptor
	owner, packageName, err := RepositoryParts(repository)
	if err != nil {
		return empty, err
	}

	first := make([]byte, UploadChunkSize)
	n, readErr := io.ReadFull(source, first)
	first = first[:n]
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return empty, readErr
	}

	var next []byte
	if readErr == nil {
		buffer := make([]byte, UploadChunkSize)
		n, err := io.ReadFull(source, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return empty, err
		}

		next = buffer[:n]
	}

	if encrypted && !bytes.HasPrefix(first, []byte("age-encryption.org/v1\n")) {
		return empty, errors.New("refusing unencrypted upload")
	}
	if !encrypted && (!bytes.Equal(first, []byte("{}")) || len(next) > 0) {
		return empty, errors.New("only an empty OCI config may be uploaded as plaintext")
	}

	base := "https://ghcr.io/v2/" + owner + "/" + packageName
	headers, _, err := r.writeRequest(repository, base+"/blobs/uploads/", "POST", nil, nil, 202)
	if err != nil {
		return empty, err
	}

	location, err := uploadLocation(base+"/", headers)
	if err != nil {
		return empty, err
	}

	checksum := sha256.New()
	var size int64

	send := func(chunk []byte) error {
		if len(chunk) == 0 {
			return nil
		}
		if size+int64(len(chunk)) >= blobLimit {
			return errors.New("object exceeds GHCR layer size limit")
		}

		h, _, err := r.writeRequest(repository, location, "PATCH", http.Header{
			"Content-Type":  {"application/octet-stream"},
			"Content-Range": {fmt.Sprintf("%d-%d", size, size+int64(len(chunk))-1)},
		}, chunk, 202)
		if err != nil {
			return err
		}

		location, err = uploadLocation(location, h)
		if err != nil {
			return err
		}

		checksum.Write(chunk)
		size += int64(len(chunk))
		return nil
	}

	if err = send(first); err != nil {
		return empty, err
	}

	if err = send(next); err != nil {
		return empty, err
	}

	buffer := make([]byte, UploadChunkSize)
	for {
		n, err := io.ReadFull(source, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return empty, err
		}

		if e := send(buffer[:n]); e != nil {
			return empty, e
		}

		if err != nil {
			break
		}
	}

	digest := "sha256:" + hex.EncodeToString(checksum.Sum(nil))
	u, _ := url.Parse(location)
	query := u.Query()
	query.Set("digest", digest)
	u.RawQuery = query.Encode()
	err = r.completeBlob(repository, base, u.String(), digest, size)
	return Descriptor{
		Digest:    digest,
		Size:      size,
		MediaType: "application/octet-stream",
	}, err
}

func transientUploadStatus(status int) bool {
	return status == 500 || status == 502 || status == 503 || status == 504
}

func (r *Registry) completeBlob(repository, base, endpoint, digest string, size int64) error {
	// All bytes have been PATCHed. Retrying an empty completion cannot append
	// data twice. A failed response may still have committed the blob, so check
	// its content address before trying the upload session again.
	check := false
	return r.retryPublication(func() error {
		if check {
			headers, _, err := r.writeRequest(repository, base+"/blobs/"+digest, "HEAD", nil, nil, 200)
			if err == nil {
				length, parseErr := strconv.ParseInt(headers.Get("Content-Length"), 10, 64)
				if parseErr != nil || length != size || headers.Get("Docker-Content-Digest") != digest {
					return errors.New("completed blob digest or size mismatch")
				}
				return nil
			}
			var upload *UploadError
			if !errors.As(err, &upload) || upload.Status != 404 {
				return err
			}
		}
		_, _, err := r.writeRequest(repository, endpoint, "PUT", nil, nil, 201)
		check = true
		return err
	}, true)
}

func (r *Registry) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	path, err := ManifestPath(tag)
	if err != nil {
		return "", err
	}

	owner, packageName, err := RepositoryParts(repository)
	if err != nil {
		return "", err
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	if len(data) > metadataLimit {
		return "", errors.New("snapshot manifest exceeds size limit")
	}

	_, _, err = r.writeRequest(
		repository,
		"https://ghcr.io/v2/"+owner+"/"+packageName+path,
		"PUT",
		http.Header{"Content-Type": {manifestMediaType}},
		data,
		201,
	)
	if err != nil {
		return "", err
	}

	return contentDigest(data), nil
}

// ManifestDigest checks a mutable tag without transferring its layer inventory.
func (r *Registry) ManifestDigest(repository, reference string) (string, error) {
	path, err := ManifestPath(reference)
	if err != nil {
		return "", err
	}
	response, err := r.registryResponse(repository, path, "HEAD", nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("registry manifest lookup failed (HTTP %d)", response.StatusCode)
	}
	digest := response.Header.Get("Docker-Content-Digest")
	if !digestPattern.MatchString(digest) || strings.HasPrefix(reference, "sha256:") && reference != digest {
		return "", errors.New("invalid registry manifest digest")
	}
	return digest, nil
}

func (r *Registry) GetManifest(repository, reference string) (Manifest, string, error) {
	var manifest Manifest
	path, err := ManifestPath(reference)
	if err != nil {
		return manifest, "", err
	}

	response, err := r.registryResponse(repository, path, "GET", nil)
	if err != nil {
		return manifest, "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return manifest, "", fmt.Errorf("registry manifest request failed (HTTP %d)", response.StatusCode)
	}

	body, err := readLimited(response.Body, metadataLimit)
	if err != nil {
		return manifest, "", err
	}

	digest := contentDigest(body)
	if strings.HasPrefix(reference, "sha256:") && reference != digest {
		return manifest, "", errors.New("manifest digest mismatch")
	}

	err = json.Unmarshal(body, &manifest)
	return manifest, digest, err
}

type verifiedBlob struct {
	source     io.ReadCloser
	descriptor Descriptor
	checksum   hash.Hash
	received   int64
	terminal   error
}

func (v *verifiedBlob) Read(p []byte) (int, error) {
	if v.terminal != nil {
		return 0, v.terminal
	}

	n, err := v.source.Read(p)
	v.received += int64(n)
	v.checksum.Write(p[:n])
	if v.received > v.descriptor.Size {
		v.terminal = errors.New("registry blob exceeds declared size")
		return 0, v.terminal
	}

	if err == io.EOF && (v.received != v.descriptor.Size || "sha256:"+hex.EncodeToString(v.checksum.Sum(nil)) != v.descriptor.Digest) {
		err = errors.New("registry blob size or digest mismatch")
	}

	if err != nil {
		v.terminal = err
	}

	return n, err
}

func (v *verifiedBlob) Close() error { return v.source.Close() }

func (r *Registry) Blob(repository string, descriptor Descriptor) (io.ReadCloser, error) {
	return r.BlobRange(repository, wholeFile(descriptor))
}

func (r *Registry) BlobRange(repository string, file SnapshotFile) (io.ReadCloser, error) {
	return r.downloads.read(repository, file, func(part SnapshotFile) (io.ReadCloser, error) {
		return r.blobRange(repository, part)
	})
}

func (r *Registry) blobRange(repository string, file SnapshotFile) (io.ReadCloser, error) {
	if err := file.validate(); err != nil {
		return nil, err
	}
	headers := http.Header{}
	expectedStatus := http.StatusOK
	expectedRange := ""
	if file.Size != file.Blob.Size {
		end := file.Offset + file.Size - 1
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", file.Offset, end))
		expectedStatus = http.StatusPartialContent
		expectedRange = fmt.Sprintf("bytes %d-%d/%d", file.Offset, end, file.Blob.Size)
	}

	path := "/blobs/" + file.Blob.Digest
	endpoint := "https://" + strings.Replace(repository, "ghcr.io/", "ghcr.io/v2/", 1) + path
	response, err := r.registryResponse(repository, path, "GET", headers)
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < 6; attempt++ {
		if slices.Contains([]int{301, 302, 303, 307, 308}, response.StatusCode) {
			base, _ := url.Parse(endpoint)
			next, e := base.Parse(response.Header.Get("Location"))
			_, readErr := readLimited(response.Body, metadataLimit)
			response.Body.Close()
			if e != nil || next.Scheme != "https" || next.User != nil || (next.Port() != "" && next.Port() != "443") || !(next.Hostname() == "ghcr.io" || strings.HasSuffix(next.Hostname(), ".githubusercontent.com")) {
				return nil, errors.New("unexpected registry download endpoint")
			}
			if readErr != nil {
				return nil, readErr
			}
			if attempt == 5 {
				return nil, errors.New("too many registry download redirects")
			}

			endpoint = next.String()
			response, err = r.response("GET", endpoint, headers, nil, true)
			if err != nil {
				return nil, err
			}

			continue
		}

		if response.StatusCode != expectedStatus {
			response.Body.Close()
			return nil, fmt.Errorf("registry blob request failed (HTTP %d)", response.StatusCode)
		}
		if response.Header.Get("Content-Range") != expectedRange || (response.ContentLength >= 0 && response.ContentLength != file.Size) {
			response.Body.Close()
			return nil, errors.New("registry blob range or length mismatch")
		}
		if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
			response.Body.Close()
			return nil, errors.New("unexpected registry blob encoding")
		}

		return &verifiedBlob{
			source:     response.Body,
			descriptor: Descriptor{Digest: file.Digest, Size: file.Size},
			checksum:   sha256.New(),
		}, nil
	}

	panic("unreachable")
}

func RegistryCredential(user, token string) Secret {
	b, _ := json.Marshal(map[string]any{
		"auths": map[string]any{
			"ghcr.io": map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + token))},
		},
	})
	return Secret{Data: b}
}
