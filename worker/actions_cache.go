package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const actionsCacheRPC = "/twirp/github.actions.results.api.v1.CacheService/"

var coordinationKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,512}$`)
var actionsCacheVersion = func() string {
	sum := sha256.Sum256([]byte("nix-ci-worker-encrypted-coordination-v1"))
	return hex.EncodeToString(sum[:])
}()

type actionsCache struct {
	endpoint      string
	token         Secret
	client        *http.Client
	mu            sync.Mutex
	cooldown      time.Time
	writes        chan struct{}
	nextWrite     time.Time
	writeInterval time.Duration
}

func newActionsCache(endpoint string, token Secret) (*actionsCache, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !actionsCacheURL(u, false) || u.RawQuery != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid Actions cache endpoint")
	}
	if len(token.Data) == 0 || len(token.Data) > credentialLimit || bytes.ContainsAny(token.Data, "\r\n") {
		return nil, errors.New("missing or invalid Actions runtime token")
	}
	return &actionsCache{
		endpoint:      u.Scheme + "://" + u.Host,
		token:         token,
		writes:        make(chan struct{}, 1),
		writeInterval: 4 * time.Second,
		client: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func actionsCacheURL(u *url.URL, blob bool) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Host != u.Hostname() {
		return false
	}
	host := u.Hostname()
	return strings.HasSuffix(host, ".actions.githubusercontent.com") ||
		(blob && strings.HasSuffix(host, ".blob.core.windows.net"))
}

// Wire fields follow the Actions toolkit's cache v2 protocol:
// https://github.com/actions/toolkit/tree/main/packages/cache/src/generated/results/api/v1
func (c *actionsCache) Write(key string, data []byte) error {
	if !coordinationKey.MatchString(key) || len(data) == 0 || len(data) > coordinationLimit {
		return errors.New("invalid coordination record")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.beginWrite(ctx); err != nil {
		return err
	}
	defer func() { <-c.writes }()
	var reservation struct {
		OK  bool   `json:"ok"`
		URL string `json:"signed_upload_url"`
	}
	if err := c.rpc(ctx, "CreateCacheEntry", map[string]string{"key": key, "version": actionsCacheVersion}, &reservation); err != nil {
		return err
	}
	if !reservation.OK {
		return errors.New("Actions cache reservation failed")
	}
	u, err := url.Parse(reservation.URL)
	if err != nil || !actionsCacheURL(u, true) {
		return errors.New("invalid Actions cache upload URL")
	}
	// A small block blob can be uploaded atomically with one PUT. The signed URL
	// authorizes this request; the runtime token must stay on the RPC endpoint.
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "X-Ms-Blob-Type": {"BlockBlob"}, "X-Ms-Version": {"2020-04-08"}}
	if _, err = c.request(ctx, http.MethodPut, reservation.URL, data, headers, http.StatusCreated); err != nil {
		return err
	}
	var finalized struct {
		OK bool `json:"ok"`
	}
	if err = c.rpc(ctx, "FinalizeCacheEntryUpload", map[string]string{
		"key": key, "version": actionsCacheVersion, "size_bytes": strconv.Itoa(len(data)),
	}, &finalized); err != nil {
		return err
	}
	if !finalized.OK {
		return errors.New("Actions cache publication failed")
	}
	return nil
}

func (c *actionsCache) Read(prefix, previous string) (string, []byte, error) {
	if !coordinationKey.MatchString(prefix) || (previous != "" && (!coordinationKey.MatchString(previous) || !strings.HasPrefix(previous, prefix))) {
		return "", nil, errors.New("invalid coordination mailbox")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var entry struct {
		OK  bool   `json:"ok"`
		Key string `json:"matched_key"`
		URL string `json:"signed_download_url"`
	}
	if err := c.rpc(ctx, "GetCacheEntryDownloadURL", map[string]any{
		"key": prefix, "restore_keys": []string{prefix}, "version": actionsCacheVersion,
	}, &entry); err != nil {
		return "", nil, err
	}
	if !entry.OK {
		return "", nil, ErrObjectNotFound
	}
	if !coordinationKey.MatchString(entry.Key) || !strings.HasPrefix(entry.Key, prefix) || entry.Key == prefix {
		return "", nil, errors.New("Actions cache returned an unrelated coordination record")
	}
	if entry.Key == previous {
		return entry.Key, nil, nil
	}
	u, err := url.Parse(entry.URL)
	if err != nil || !actionsCacheURL(u, true) {
		return "", nil, errors.New("invalid Actions cache download URL")
	}
	data, err := c.request(ctx, http.MethodGet, entry.URL, nil, nil, http.StatusOK)
	if err != nil {
		return "", nil, err
	}
	if len(data) == 0 {
		return "", nil, errors.New("empty Actions cache coordination record")
	}
	return entry.Key, data, nil
}

// Nine runners with four seconds between uploads stay below the repository's
// 200 uploads/minute limit, with room for retries and ordinary dependency caches.
// Reads use a separate path so a delayed publication cannot block lease checks.
func (c *actionsCache) beginWrite(ctx context.Context) error {
	select {
	case c.writes <- struct{}{}:
	case <-ctx.Done():
		return errors.New("Actions cache publication timed out")
	}
	timer := time.NewTimer(max(0, time.Until(c.nextWrite)))
	defer timer.Stop()
	select {
	case <-timer.C:
		c.nextWrite = time.Now().Add(c.writeInterval)
		return nil
	case <-ctx.Done():
		<-c.writes
		return errors.New("Actions cache publication timed out")
	}
}

func (c *actionsCache) rpc(ctx context.Context, method string, value, result any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("invalid Actions cache request")
	}
	headers := http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer " + string(c.token.Data)}}
	data, err = c.request(ctx, http.MethodPost, c.endpoint+actionsCacheRPC+method, data, headers, http.StatusOK)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, result); err != nil {
		return errors.New("invalid Actions cache response")
	}
	return nil
}

func (c *actionsCache) request(ctx context.Context, method, endpoint string, data []byte, headers http.Header, expected int) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, errors.New("Actions cache request timed out")
			case <-timer.C:
			}
		}
		c.mu.Lock()
		cooldown := time.Until(c.cooldown)
		c.mu.Unlock()
		if cooldown > 0 {
			return nil, errors.New("Actions cache requests temporarily rate limited")
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("invalid Actions cache request URL")
		}
		request.Header = headers.Clone()
		if request.Header == nil {
			request.Header = http.Header{}
		}
		request.Header.Set("User-Agent", "https://github.com/awked-com/nix-ci-worker")
		response, err := c.client.Do(request)
		if err != nil {
			last = errors.New("Actions cache request transport failed")
			continue
		}
		if response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusForbidden && response.Header.Get("Retry-After") != "") {
			delay, ok := RetryAfterSeconds(response.Header.Get("Retry-After"), time.Now())
			if !ok || delay <= 0 {
				delay = time.Minute
			}
			c.mu.Lock()
			if until := time.Now().Add(delay); until.After(c.cooldown) {
				c.cooldown = until
			}
			c.mu.Unlock()
		}
		if response.StatusCode != expected {
			io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			last = fmt.Errorf("Actions cache request failed (HTTP %d)", response.StatusCode)
			if response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504 || response.StatusCode == 500 {
				continue
			}
			return nil, last
		}
		body, err := readLimited(response.Body, coordinationLimit)
		response.Body.Close()
		if err != nil {
			return nil, errors.New("invalid Actions cache response body")
		}
		return body, nil
	}
	return nil, last
}
