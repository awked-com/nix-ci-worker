package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func cacheHTTPFixture(t *testing.T, handler http.HandlerFunc) *actionsCache {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	endpoint, _ := url.Parse(server.URL)
	cache, err := newActionsCache("https://results-receiver.actions.githubusercontent.com/", Secret{Data: []byte("runtime-secret")})
	if err != nil {
		t.Fatal(err)
	}
	cache.writeInterval = 0
	transport := server.Client().Transport
	cache.client.Transport = cacheRoundTripper(func(r *http.Request) (*http.Response, error) {
		request := r.Clone(r.Context())
		request.Host = r.URL.Host
		request.URL.Scheme, request.URL.Host = endpoint.Scheme, endpoint.Host
		return transport.RoundTrip(request)
	})
	return cache
}

func TestActionsCacheMailboxRoundTrip(t *testing.T) {
	var mu sync.Mutex
	reserved := map[string]bool{}
	blobs := map[string][]byte{}
	var published []string
	var downloads int
	cache := cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Host == "cache.blob.core.windows.net" {
			if r.Header.Get("Authorization") != "" {
				t.Error("runtime token leaked to blob endpoint")
			}
			key := r.URL.Query().Get("key")
			if r.URL.Query().Get("sig") != "signed-secret" {
				t.Error("signed URL query was not preserved")
			}
			switch r.Method {
			case http.MethodPut:
				if !reserved[key] || r.Header.Get("X-Ms-Blob-Type") != "BlockBlob" || r.Header.Get("X-Ms-Version") == "" {
					t.Error("invalid block blob upload")
				}
				blobs[key], _ = io.ReadAll(r.Body)
				if r.ContentLength != int64(len(blobs[key])) {
					t.Error("upload content length differs from uploaded bytes")
				}
				w.WriteHeader(http.StatusCreated)
			case http.MethodGet:
				downloads++
				w.Write(blobs[key])
			default:
				t.Errorf("unexpected blob method %s", r.Method)
			}
			return
		}
		if r.Host != "results-receiver.actions.githubusercontent.com" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer runtime-secret" {
			t.Error("invalid authenticated RPC request")
		}
		var request struct {
			Key         string   `json:"key"`
			Version     string   `json:"version"`
			SizeBytes   string   `json:"size_bytes"`
			RestoreKeys []string `json:"restore_keys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Version != actionsCacheVersion {
			t.Error("cache protocol version mismatch")
		}
		blobURL := "https://cache.blob.core.windows.net/records?key=" + url.QueryEscape(request.Key) + "&sig=signed-secret"
		switch r.URL.Path {
		case actionsCacheRPC + "CreateCacheEntry":
			if reserved[request.Key] {
				json.NewEncoder(w).Encode(map[string]bool{"ok": false})
				return
			}
			reserved[request.Key] = true
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "signed_upload_url": blobURL})
		case actionsCacheRPC + "FinalizeCacheEntryUpload":
			if request.SizeBytes != strconv.Itoa(len(blobs[request.Key])) || len(blobs[request.Key]) == 0 {
				t.Error("finalized an incomplete record")
			}
			published = append(published, request.Key)
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry_id": "1"})
		case actionsCacheRPC + "GetCacheEntryDownloadURL":
			if len(request.RestoreKeys) != 1 || request.RestoreKeys[0] != request.Key {
				t.Error("missing prefix lookup")
			}
			for i := len(published) - 1; i >= 0; i-- {
				if key := published[i]; strings.HasPrefix(key, request.Key) {
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "matched_key": key,
						"signed_download_url": "https://cache.blob.core.windows.net/records?key=" + url.QueryEscape(key) + "&sig=signed-secret"})
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": false})
		default:
			t.Errorf("unexpected RPC %s", r.URL.Path)
		}
	})
	if _, _, err := cache.Read("mailbox-", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatal("missing mailbox", err)
	}
	for _, key := range []string{"mailbox-old", "different-mailbox", "mailbox-new"} {
		if err := cache.Write(key, []byte("encrypted-"+key)); err != nil {
			t.Fatal(err)
		}
	}
	key, data, err := cache.Read("mailbox-", "")
	if err != nil || key != "mailbox-new" || string(data) != "encrypted-mailbox-new" {
		t.Fatalf("latest record = %q %q %v", key, data, err)
	}
	key, data, err = cache.Read("mailbox-", key)
	if err != nil || key != "mailbox-new" || data != nil || downloads != 1 {
		t.Fatalf("unchanged record downloaded again: %q %q %v (%d downloads)", key, data, err, downloads)
	}
	if err = cache.Write("mailbox-new", []byte("replacement")); err == nil {
		t.Fatal("replaced immutable cache record")
	}
	mu.Lock()
	published = nil
	mu.Unlock()
	if _, _, err = cache.Read("mailbox-", key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatal("evicted mailbox", err)
	}
	if err = cache.Write("mailbox-recreated", []byte("recovered")); err != nil {
		t.Fatal(err)
	}
	if _, data, err = cache.Read("mailbox-", key); err != nil || string(data) != "recovered" {
		t.Fatal("mailbox did not recover after eviction", err)
	}
}

func TestActionsCacheValidatesBeforeRequests(t *testing.T) {
	for _, endpoint := range []string{
		"", "http://results-receiver.actions.githubusercontent.com/", "https://example.com/",
		"https://actions.githubusercontent.com.evil.example/", "https://results-receiver.actions.githubusercontent.com:443/",
		"https://user:password@results-receiver.actions.githubusercontent.com/", "https://results-receiver.actions.githubusercontent.com/?query=yes",
		"https://results-receiver.actions.githubusercontent.com/wrong", "https://results-receiver.actions.githubusercontent.com/#fragment",
		"https://results-receiver.actions.githubusercontent.com/?", "https://results-receiver.actions.githubusercontent.com:/",
	} {
		if _, err := newActionsCache(endpoint, Secret{Data: []byte("token")}); err == nil {
			t.Errorf("accepted invalid endpoint %q", endpoint)
		}
	}
	for _, token := range []string{"", "line\nbreak", "line\rbreak"} {
		if _, err := newActionsCache("https://results-receiver.actions.githubusercontent.com", Secret{Data: []byte(token)}); err == nil {
			t.Fatal("accepted invalid runtime token")
		}
	}
	cache := cacheHTTPFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid input caused request") })
	for _, key := range []string{"", "bad,key", "bad key", strings.Repeat("x", 513)} {
		if err := cache.Write(key, []byte("ciphertext")); err == nil {
			t.Fatal("accepted invalid record key")
		}
		if _, _, err := cache.Read(key, ""); err == nil {
			t.Fatal("accepted invalid lookup key")
		}
	}
	for _, data := range [][]byte{nil, make([]byte, coordinationLimit+1)} {
		if err := cache.Write("valid", data); err == nil {
			t.Fatal("accepted invalid record size")
		}
	}
	if _, _, err := cache.Read("mailbox-", "different-mailbox-1"); err == nil {
		t.Fatal("accepted unrelated previous key")
	}
}

func TestActionsCacheRejectsInvalidLookupResponses(t *testing.T) {
	for _, tc := range []struct {
		name, key, location, body string
	}{
		{"wrong mailbox", "other-1", "https://cache.blob.core.windows.net/blob", "ciphertext"},
		{"bare prefix", "mailbox-", "https://cache.blob.core.windows.net/blob", "ciphertext"},
		{"insecure blob", "mailbox-1", "http://cache.blob.core.windows.net/blob", "ciphertext"},
		{"external blob", "mailbox-1", "https://example.com/blob", "ciphertext"},
		{"blob userinfo", "mailbox-1", "https://token@cache.blob.core.windows.net/blob", "ciphertext"},
		{"empty blob", "mailbox-1", "https://cache.blob.core.windows.net/blob", ""},
		{"oversized blob", "mailbox-1", "https://cache.blob.core.windows.net/blob", strings.Repeat("x", coordinationLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "matched_key": tc.key, "signed_download_url": tc.location})
					return
				}
				io.WriteString(w, tc.body)
			})
			if _, _, err := cache.Read("mailbox-", ""); err == nil {
				t.Fatal("accepted invalid cache response")
			}
		})
	}
}

func TestActionsCachePublicationFailures(t *testing.T) {
	for _, failure := range []string{"reservation", "upload URL", "upload", "finalization", "invalid JSON"} {
		t.Run(failure, func(t *testing.T) {
			var finalized bool
			cache := cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case actionsCacheRPC + "CreateCacheEntry":
					if failure == "invalid JSON" {
						fmt.Fprint(w, "private detail: not JSON")
						return
					}
					location := "https://cache.blob.core.windows.net/blob?sig=private-secret"
					if failure == "upload URL" {
						location = "https://untrusted.example/upload"
					}
					json.NewEncoder(w).Encode(map[string]any{"ok": failure != "reservation", "signed_upload_url": location, "message": "private-secret"})
				case actionsCacheRPC + "FinalizeCacheEntryUpload":
					finalized = true
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "message": "private-secret"})
				case "/blob":
					if failure == "upload" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, "private-secret")
						return
					}
					w.WriteHeader(http.StatusCreated)
				default:
					t.Error("unexpected request")
				}
			})
			err := cache.Write("mailbox-1", []byte("ciphertext"))
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsanitized publication failure: %v", err)
			}
			if finalized != (failure == "finalization") {
				t.Fatal("attempted to finalize incomplete upload")
			}
		})
	}
}

func TestActionsCacheRetriesAndRateLimits(t *testing.T) {
	var requests int
	cache := cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": false})
	})
	if _, _, err := cache.Read("mailbox-", ""); !errors.Is(err, ErrObjectNotFound) || requests != 2 {
		t.Fatal("transient failure did not recover", requests, err)
	}
	for _, status := range []int{http.StatusTooManyRequests, http.StatusForbidden} {
		requests = 0
		cache = cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(status)
			fmt.Fprint(w, "private diagnostic")
		})
		for range 2 {
			if _, _, err := cache.Read("mailbox-", ""); err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("rate limit did not fail safely", err)
			}
		}
		if requests != 1 {
			t.Fatal("retried while rate limited", requests)
		}
	}
}

func TestActionsCacheDoesNotFollowRedirects(t *testing.T) {
	var requests int
	cache := cacheHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Location", "https://untrusted.example/token-collector")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	if _, _, err := cache.Read("mailbox-", ""); err == nil || requests != 1 {
		t.Fatal("followed authenticated redirect", requests, err)
	}
}

func TestActionsCacheTransportErrorsArePrivate(t *testing.T) {
	cache, err := newActionsCache("https://results-receiver.actions.githubusercontent.com", Secret{Data: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	cache.client.Transport = cacheRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("secret signed URL with private paths")
	})
	_, _, err = cache.Read("mailbox-", "")
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
		t.Fatal("transport error disclosed details", err)
	}
}

func TestActionsCacheWritePacingCancellation(t *testing.T) {
	cache, err := newActionsCache("https://results-receiver.actions.githubusercontent.com", Secret{Data: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.beginWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cache.beginWrite(ctx); err == nil {
		t.Fatal("did not cancel waiting for active publication")
	}
	<-cache.writes
	cache.nextWrite = time.Now().Add(time.Hour)
	if err := cache.beginWrite(ctx); err == nil {
		t.Fatal("did not cancel waiting for upload rate limit")
	}
	if len(cache.writes) != 0 {
		t.Fatal("cancellation retained publication lock")
	}
	cache.nextWrite = time.Now().Add(20 * time.Millisecond)
	started := time.Now()
	if err := cache.beginWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-cache.writes
	if time.Since(started) < 20*time.Millisecond {
		t.Fatal("did not wait for upload rate limit")
	}
}
