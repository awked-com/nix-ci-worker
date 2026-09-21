package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signedNarinfo(t *testing.T, hash string, refs []string) (string, []byte, string) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	path := "/nix/store/" + strings.Repeat("a", 32) + "-target"
	canonical, e := CanonicalHash(hash)
	if e != nil {
		t.Fatal(e)
	}

	fingerprint := fmt.Sprintf("1;%s;%s;123;%s", path, canonical, strings.Join(refs, ","))
	sig := ed25519.Sign(private, []byte(fingerprint))
	names := []string{}
	for _, ref := range refs {
		names = append(names, strings.TrimPrefix(ref, "/nix/store/"))
	}

	body := fmt.Sprintf(
		"StorePath: %s\nNarHash: %s\nNarSize: 123\nReferences: %s\nSig: cache.nixos.org-1:%s\n",
		path,
		hash,
		strings.Join(names, " "),
		base64.StdEncoding.EncodeToString(sig),
	)
	return path, []byte(body), base64.StdEncoding.EncodeToString(public)
}

func TestCanonicalHashUsesNixBitOrder(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 1
	value, e := CanonicalHash("sha256:" + hex.EncodeToString(raw))
	if e != nil {
		t.Fatal(e)
	}
	if value != "sha256:"+strings.Repeat("0", 51)+"1" {
		t.Fatal(value)
	}

	raw[0] = 0
	raw[31] = 128
	value, e = CanonicalHash("sha256:" + hex.EncodeToString(raw))
	if e != nil || value != "sha256:1"+strings.Repeat("0", 51) {
		t.Fatal(value, e)
	}
}

func TestUpstreamSignaturesAuthenticateCanonicalIdentity(t *testing.T) {
	ref := "/nix/store/" + strings.Repeat("b", 32) + "-dependency"
	path, body, key := signedNarinfo(t, "sha256:"+strings.Repeat("01", 32), []string{ref})
	refs, e := verifyUpstreamKey(body, path, key)
	if e != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatal(refs, e)
	}

	for _, bad := range [][]byte{
		[]byte(strings.ReplaceAll(string(body), "NarSize: 123", "NarSize: 124")),
		[]byte(strings.ReplaceAll(string(body), "References: "+strings.TrimPrefix(ref, "/nix/store/"), "References: ")),
		append(append([]byte{}, body...), []byte("NarHash: duplicate\n")...),
		[]byte(strings.ReplaceAll(string(body), "NarSize: 123", "NarSize: 0")),
		[]byte(strings.ReplaceAll(string(body), "NarSize: 123", "NarSize: +123")),
	} {
		if _, e := verifyUpstreamKey(bad, path, key); e == nil {
			t.Fatalf("invalid narinfo accepted: %s", bad)
		}
	}

	if _, e := verifyUpstreamKey(body, ref, key); e == nil {
		t.Fatal("path mismatch accepted")
	}

	path, body, key = signedNarinfo(t, "sha256:"+strings.Repeat("0", 64), []string{})
	refs, e = verifyUpstreamKey(body, path, key)
	if e != nil || refs == nil || len(refs) != 0 {
		t.Fatal(refs, e)
	}
}

func TestUpstreamMissTTLAndFailureAreDistinct(t *testing.T) {
	requests := 0
	status := 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(status)
	}))
	defer server.Close()

	u := NewUpstream()
	defer u.Close()

	u.URL = server.URL
	path := "/nix/store/" + strings.Repeat("a", 32) + "-target"
	for range 2 {
		refs, e := u.Query(path)
		if e != nil || refs != nil {
			t.Fatal(refs, e)
		}
	}

	if requests != 1 {
		t.Fatal(requests)
	}

	u.known[path] = upstreamKnown{nil, time.Now().Add(-time.Second)}
	status = 403
	if _, e := u.Query(path); e == nil {
		t.Fatal("access failure treated as cache miss")
	}

	if requests != 2 {
		t.Fatal(requests)
	}

	status = 200
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", 1024*1024+1)) })
	if _, e := u.Query(path); e == nil {
		t.Fatal("unbounded metadata accepted")
	}
}
