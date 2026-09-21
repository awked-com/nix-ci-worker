package worker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const UpstreamURL = "https://cache.nixos.org"
const UpstreamPublicKey = "6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

var storePathRE = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+$`)
var nix32Hash = regexp.MustCompile(`^sha256:[01][0-9abcdfghijklmnpqrsvwxyz]{51}$`)
var hexHash = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)

func CanonicalHash(value string) (string, error) {
	if nix32Hash.MatchString(value) {
		return value, nil
	}
	if !hexHash.MatchString(value) {
		return "", errors.New("invalid upstream NAR identity")
	}

	raw, _ := hex.DecodeString(value[7:])
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}

	n := new(big.Int).SetBytes(raw)
	const alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
	s := "sha256:"
	for shift := 255; shift >= 0; shift -= 5 {
		v := new(big.Int).Rsh(new(big.Int).Set(n), uint(shift))
		s += string(alphabet[v.Uint64()&31])
	}

	return s, nil
}

func verifyUpstreamKey(body []byte, path, key string) ([]string, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("invalid upstream narinfo encoding")
	}

	fields := map[string]string{}
	sigs := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ": ")
		if !ok {
			return nil, errors.New("invalid upstream narinfo")
		}

		if _, ok := fields[k]; ok {
			return nil, errors.New("invalid upstream narinfo")
		}

		if k == "Sig" {
			sigs = append(sigs, v)
		} else {
			fields[k] = v
		}
	}

	if fields["StorePath"] != path || !storePathRE.MatchString(path) {
		return nil, errors.New("upstream store path mismatch")
	}

	hash, e := CanonicalHash(fields["NarHash"])
	if e != nil {
		return nil, e
	}
	size, e := strconv.ParseUint(fields["NarSize"], 10, 64)
	if e != nil || size == 0 {
		return nil, errors.New("invalid upstream NAR identity")
	}

	refs := []string{}
	previous := ""
	for _, r := range strings.Fields(fields["References"]) {
		ref := "/nix/store/" + r
		if !storePathRE.MatchString(ref) || ref <= previous {
			return nil, errors.New("invalid upstream references")
		}

		previous = ref
		refs = append(refs, ref)
	}

	fingerprint := fmt.Sprintf("1;%s;%s;%d;%s", path, hash, size, strings.Join(refs, ","))
	public, e := base64.StdEncoding.DecodeString(key)
	if e != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid upstream signing key")
	}

	for _, sig := range sigs {
		name, enc, _ := strings.Cut(sig, ":")
		if name != "cache.nixos.org-1" {
			continue
		}

		b, e := base64.StdEncoding.Strict().DecodeString(enc)
		if e == nil && ed25519.Verify(public, []byte(fingerprint), b) {
			return refs, nil
		}
	}

	return nil, errors.New("upstream narinfo has no valid cache.nixos.org signature")
}

type upstreamKnown struct {
	refs     []string
	deadline time.Time
}

type Upstream struct {
	HTTP  *http.Client
	URL   string
	mu    sync.Mutex
	known map[string]upstreamKnown
}

func NewUpstream() *Upstream {
	return &Upstream{
		HTTP: &http.Client{
			Timeout:       40 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   32,
				MaxConnsPerHost:       32,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
		URL:   UpstreamURL,
		known: map[string]upstreamKnown{},
	}
}

func (u *Upstream) Close() { u.HTTP.CloseIdleConnections() }

func (u *Upstream) Query(path string) ([]string, error) {
	if !storePathRE.MatchString(path) {
		return nil, errors.New("invalid upstream query path")
	}

	u.mu.Lock()
	known, ok := u.known[path]
	u.mu.Unlock()
	if ok && time.Now().Before(known.deadline) {
		return known.refs, nil
	}

	url := u.URL + "/" + strings.SplitN(strings.TrimPrefix(path, "/nix/store/"), "-", 2)[0] + ".narinfo"
	for attempt := 0; attempt < 5; attempt++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept-Encoding", "identity")
		r, e := u.HTTP.Do(req)
		if e != nil {
			if attempt == 4 {
				return nil, e
			}

			time.Sleep(time.Duration(1<<attempt) * 500 * time.Millisecond)
			continue
		}

		body, e := io.ReadAll(io.LimitReader(r.Body, 1024*1024+1))
		r.Body.Close()
		if e != nil {
			if attempt == 4 {
				return nil, e
			}

			continue
		}

		if len(body) > 1024*1024 {
			return nil, errors.New("upstream narinfo exceeds limit")
		}

		if r.StatusCode == 200 || r.StatusCode == 404 {
			var refs []string
			ttl := time.Minute
			if r.StatusCode == 200 {
				refs, e = verifyUpstreamKey(body, path, UpstreamPublicKey)
				ttl = time.Hour
			}

			if e != nil {
				return nil, e
			}

			u.mu.Lock()
			u.known[path] = upstreamKnown{refs, time.Now().Add(ttl)}
			u.mu.Unlock()
			return refs, nil
		}

		if (r.StatusCode == 429 || r.StatusCode == 500 || r.StatusCode == 502 || r.StatusCode == 503 || r.StatusCode == 504) && attempt < 4 {
			delay := time.Duration(1<<attempt) * 500 * time.Millisecond
			if seconds, e := strconv.Atoi(r.Header.Get("Retry-After")); e == nil {
				delay = time.Duration(min(seconds, 60)) * time.Second
			}

			time.Sleep(delay)
			continue
		}

		return nil, fmt.Errorf("upstream availability check failed (HTTP %d)", r.StatusCode)
	}

	return nil, errors.New("upstream availability check failed")
}

func (u *Upstream) Collect(paths []string) (map[string][]string, error) {
	found := map[string][]string{}
	seen := map[string]bool{}
	todo := append([]string{}, paths...)
	for len(todo) > 0 {
		batch := []string{}
		for len(todo) > 0 && len(batch) < 32 {
			p := todo[0]
			todo = todo[1:]
			if !seen[p] {
				seen[p] = true
				batch = append(batch, p)
			}
		}

		type result struct {
			path string
			refs []string
			err  error
		}
		ch := make(chan result, len(batch))
		for _, p := range batch {
			go func(p string) {
				r, e := u.Query(p)
				ch <- result{p, r, e}
			}(p)
		}

		for range batch {
			r := <-ch
			if r.err != nil {
				return nil, r.err
			}

			if r.refs != nil {
				found[r.path] = r.refs
				todo = append(todo, r.refs...)
			}
		}
	}

	for _, refs := range found {
		for _, ref := range refs {
			if _, ok := found[ref]; !ok {
				return nil, errors.New("upstream cache has incomplete references")
			}
		}
	}

	return found, nil
}
