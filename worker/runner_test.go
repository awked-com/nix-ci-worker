package worker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunnerCommandHelper(t *testing.T) {
	if os.Getenv("INFRA_GO_COMMAND_HELPER") != "1" {
		return
	}

	index := 0
	for i, a := range os.Args {
		if a == "--" {
			index = i + 1
			break
		}
	}

	args := os.Args[index:]
	if len(args) == 0 {
		os.Exit(2)
	}

	name, args := args[0], args[1:]
	if file := os.Getenv("TEST_CALLS"); file != "" {
		f, e := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if e != nil {
			os.Exit(3)
		}

		fmt.Fprintf(f, "%s %s\n", name, strings.Join(args, " "))
		f.Close()
	}

	if name == "nix-store" && len(args) > 0 && args[0] == "--dump" {
		if args[1] == os.Getenv("TEST_DUMP_FAIL") {
			os.Exit(17)
		}

		fmt.Print("NAR " + args[1])
		os.Exit(0)
	}

	if name == "nix-store" && len(args) > 0 && (args[0] == "--add-root" || args[0] == "--delete") {
		os.Exit(0)
	}

	if name == "nix" {
		for len(args) > 0 && strings.HasPrefix(args[0], "--extra-") {
			args = args[2:]
		}

		var paths map[string]pathInfo
		data := []byte(os.Getenv("TEST_PATHS"))
		if file := os.Getenv("TEST_PATHS_FILE"); file != "" {
			var err error
			data, err = os.ReadFile(file)
			if err != nil {
				os.Exit(6)
			}
		}
		json.Unmarshal(data, &paths)
		if len(args) > 1 && args[0] == "path-info" {
			if args[1] == "--all" {
				for _, p := range sortedKeys(paths) {
					fmt.Println(p)
				}
			} else if args[1] == "--recursive" {
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					os.Exit(6)
				}
				pending := strings.Fields(string(data))
				seen := map[string]bool{}
				for len(pending) > 0 {
					p := pending[len(pending)-1]
					pending = pending[:len(pending)-1]
					info, ok := paths[p]
					if seen[p] || !ok {
						continue
					}
					seen[p] = true
					fmt.Println(p)
					pending = append(pending, info.References...)
				}
			} else {
				selected := args[4:]
				if len(selected) == 1 && selected[0] == "--stdin" {
					data, err := io.ReadAll(os.Stdin)
					if err != nil {
						os.Exit(6)
					}
					selected = strings.Fields(string(data))
				}
				result := map[string]*pathInfo{}
				for _, p := range selected {
					result[p] = nil
					if value, ok := paths[p]; ok {
						result[p] = &value
					}
				}

				b, _ := json.Marshal(result)
				os.Stdout.Write(b)
			}

			os.Exit(0)
		}

		if len(args) > 3 && args[0] == "store" && args[1] == "sign" {
			if data, e := os.ReadFile(args[3]); e != nil || len(data) == 0 {
				os.Exit(4)
			}

			os.Exit(0)
		}
	}

	os.Exit(5)
}

func runnerCommands(t *testing.T, paths map[string]pathInfo) {
	t.Helper()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}

	dir := t.TempDir()
	for _, name := range []string{"nix", "nix-store"} {
		script := fmt.Sprintf("#!/bin/sh\nexec %s -test.run=^TestRunnerCommandHelper$ -- %s \"$@\"\n", shellQuote(binary), name)
		if e = os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
	}

	b, _ := json.Marshal(paths)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("INFRA_GO_COMMAND_HELPER", "1")
	t.Setenv("TEST_PATHS", string(b))
	t.Setenv("TEST_CALLS", filepath.Join(t.TempDir(), "calls"))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

type knownUpstream map[string][]string

func (k knownUpstream) Collect(paths []string) (map[string][]string, error) {
	result := map[string][]string{}
	for _, p := range paths {
		if refs, ok := k[p]; ok {
			result[p] = refs
		}
	}

	return result, nil
}

func fixturePath(letter string) string {
	return "/nix/store/" + strings.Repeat(letter, 32) + "-fixture"
}

func fixtureInfo(letter string, refs ...string) pathInfo {
	return pathInfo{
		NarHash:    "sha256-" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte(letter), 32)),
		NarSize:    3,
		References: refs,
		Signatures: []string{"test:signature"},
	}
}

func TestBackgroundPublicationFindsOutputsWithoutAnotherBatch(t *testing.T) {
	_, recipients := cacheKeys(t)
	runnerCommands(t, nil)
	file := filepath.Join(t.TempDir(), "paths.json")
	t.Setenv("TEST_PATHS_FILE", file)
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	a := fixturePath("a")
	required := map[string]bool{a: true}
	storage := newMemoryCache()
	parent, delta := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
	progress := make(chan bool, 8)
	publisher := startCachePublisher(required, 20*time.Millisecond, func(required map[string]bool) error {
		_, err := PublishStore(".", required, delta, parent, Secret{Data: []byte("key")}, recipients, io.Discard, knownUpstream{})
		progress <- delta.Contains(a)
		return err
	})
	var closeErr error
	closePublisher := sync.OnceFunc(func() { closeErr = publisher.close() })
	defer closePublisher()
	delete(required, a)
	select {
	case available := <-progress:
		if available {
			t.Fatal("unfinished output was published")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("initial publication stalled")
	}
	data, _ := json.Marshal(map[string]pathInfo{a: fixtureInfo("a")})
	if err := os.WriteFile(file+".new", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file+".new", file); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(20 * time.Second)
	for {
		select {
		case available := <-progress:
			if !available {
				continue
			}
			closePublisher()
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if err := delta.RequireClosed(); err != nil {
				t.Fatal(err)
			}
			return
		case <-deadline:
			t.Fatal("new output was not published during the batch")
		}
	}
}

func TestBackgroundPublicationCoalescesUpdatesAndReportsFailure(t *testing.T) {
	first, latest := fixturePath("a"), fixturePath("c")
	started := make(chan struct{})
	release := make(chan struct{})
	seen := make(chan map[string]bool, 1)
	failure := errors.New("publication failed")
	publisher := startCachePublisher(map[string]bool{first: true}, time.Hour, func(required map[string]bool) error {
		if required[first] {
			close(started)
			<-release
			return nil
		}
		seen <- required
		return failure
	})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var closeErr error
	closePublisher := sync.OnceFunc(func() { unblock(); closeErr = publisher.close() })
	defer closePublisher()
	<-started
	for range 100 {
		if err := publisher.update(map[string]bool{fixturePath("b"): true}); err != nil {
			t.Fatal(err)
		}
	}
	required := map[string]bool{latest: true}
	if err := publisher.update(required); err != nil {
		t.Fatal(err)
	}
	delete(required, latest)
	unblock()
	select {
	case required := <-seen:
		if len(required) != 1 || !required[latest] {
			t.Fatalf("publication used a stale or mutable plan: %v", required)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("latest plan was not published")
	}
	closePublisher()
	if !errors.Is(closeErr, failure) {
		t.Fatalf("publication failure lost during shutdown: %v", closeErr)
	}
}

func TestPublicationDeduplicatesNarsAndClosesReferenceComponents(t *testing.T) {
	identity, recipients := cacheKeys(t)
	a, b, c, d, e, f := fixturePath("a"), fixturePath("b"), fixturePath("c"), fixturePath("d"), fixturePath("e"), fixturePath("f")
	paths := map[string]pathInfo{
		a:                fixtureInfo("a", b),
		b:                fixtureInfo("a", a),
		c:                fixtureInfo("c", d),
		d:                fixtureInfo("d", e),
		f:                fixtureInfo("f"),
		fixturePath("g"): fixtureInfo("g"),
	}
	required := map[string]bool{a: true, c: true, d: true, e: true, f: true}
	runnerCommands(t, paths)
	storage := newMemoryCache()
	parent, delta := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
	n, err := PublishStore(".", required, delta, parent, Secret{Data: []byte("key")}, recipients, io.Discard, knownUpstream{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || !delta.Contains(a) || !delta.Contains(b) || !delta.Contains(f) || delta.Contains(c) || delta.Contains(d) || delta.Contains(e) || delta.Contains(fixturePath("g")) {
		t.Fatalf("publication %d: %+v", n, delta.Narinfos)
	}
	if len(delta.Files) != 4 {
		t.Fatalf("same NAR not deduplicated: %d", len(delta.Files))
	}
	if len(storage.objects) != 1 {
		t.Fatalf("small archives occupy %d blobs, want one pack", len(storage.objects))
	}
	cachePublish(t, delta, "packed", recipients)
	loaded := cacheLoad(t, storage, "packed", identity)
	for name := range loaded.Files {
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := decoder.DecodeAll(cacheRead(t, loaded, name, identity), nil)
		decoder.Close()
		if err != nil || !bytes.HasPrefix(plain, []byte("NAR /nix/store/")) {
			t.Fatalf("packed NAR did not survive publication: %v", err)
		}
	}

	if err = delta.RequireClosed(); err != nil {
		t.Fatal(err)
	}

	before := len(storage.objects)
	if _, err = PublishStore(".", required, delta, parent, Secret{Data: []byte("key")}, recipients, io.Discard, knownUpstream{}); err != nil {
		t.Fatal(err)
	}

	if len(storage.objects) != before {
		t.Fatal("existing ciphertext reuploaded")
	}
}

func TestPublicationPrefersUpstreamAndSalvagesAfterFailure(t *testing.T) {
	_, recipients := cacheKeys(t)
	a, b, c := fixturePath("a"), fixturePath("b"), fixturePath("c")
	required := map[string]bool{c: true}
	runnerCommands(t, map[string]pathInfo{
		a: fixtureInfo("a"),
		b: fixtureInfo("b", a),
		c: fixtureInfo("c", b),
	})
	storage := newMemoryCache()
	parent, delta := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
	t.Setenv("TEST_DUMP_FAIL", b)
	if _, e := PublishStore(".", required, delta, parent, Secret{Data: []byte("key")}, recipients, io.Discard, knownUpstream{a: []string{}}); e == nil {
		t.Fatal("failed upload accepted")
	}

	if !delta.Contains(a) || delta.Contains(b) || delta.Contains(c) {
		t.Fatal(delta.Narinfos)
	}

	t.Setenv("TEST_DUMP_FAIL", "")
	if _, e := PublishStore(".", required, delta, parent, Secret{Data: []byte("key")}, recipients, io.Discard, knownUpstream{a: []string{}}); e != nil {
		t.Fatal(e)
	}

	if !delta.Contains(b) || !delta.Contains(c) {
		t.Fatal(delta.Narinfos)
	}

	if e := delta.RequireClosed(); e != nil {
		t.Fatal(e)
	}
}

func TestRunnerEnvironmentStripsCredentialsAndActionTracking(t *testing.T) {
	for _, name := range []string{
		"CI_IDENTITY",
		"REGISTRY_TOKEN",
		"ACTIONS_RUNTIME_TOKEN",
		"ACTIONS_RESULTS_URL",
		"NIX_SIGNING_KEY",
		"INPUT_REQUEST",
		"ACTIONS_TOKEN",
		"GITHUB_TOKEN",
		"RUNNER_TRACKING_ID",
	} {
		t.Setenv(name, "private")
	}

	t.Setenv("KEEP_BUILD_VALUE", "safe")
	env := strings.Join(BuildEnvironment(), "\n")
	if strings.Contains(env, "=private") {
		t.Fatal("worker credential leaked")
	}
	if !strings.Contains(env, "KEEP_BUILD_VALUE=safe") {
		t.Fatal("ordinary build environment lost")
	}
}

func TestDiskGuardCancelsBlockedProcessAndFailsClosed(t *testing.T) {
	for _, measurement := range []func(string) (uint64, error){
		func(p string) (uint64, error) {
			if p == "runner-volume" {
				return DiskStop - 1, nil
			}

			return DiskReserve * 2, nil
		},
		func(string) (uint64, error) { return 0, errors.New("disk measurement unavailable") },
	} {
		g := &DiskGuard{
			Paths:       []string{"store", "runner-volume"},
			MinimumFree: ^uint64(0),
			Measure:     measurement,
		}
		start := time.Now()
		e := g.Run(exec.Command("/bin/sh", "-c", "exec sleep 60"))
		if e == nil || time.Since(start) > 10*time.Second {
			t.Fatal(e, time.Since(start))
		}
	}

	g := &DiskGuard{
		Paths:       []string{"store"},
		MinimumFree: ^uint64(0),
		Measure:     func(string) (uint64, error) { return DiskReserve * 2, nil },
	}
	if e := g.Run(exec.Command("/bin/sh", "-c", "exit 0")); e != nil {
		t.Fatal(e)
	}
}

func TestBuildCommandRequiresNativeSandbox(t *testing.T) {
	for _, system := range []string{"x86_64-linux", "aarch64-darwin"} {
		command := strings.Join(BuildCommand(system, 1, 2, nil), " ")
		sandbox := "true"
		if strings.HasSuffix(system, "-darwin") {
			sandbox = "relaxed"
		}

		if !strings.Contains(command, "--option sandbox "+sandbox) || !strings.Contains(command, "--option sandbox-fallback false") || !strings.Contains(command, "--keep-going --stdin") {
			t.Fatal(command)
		}
	}
}

func TestBuildCommandUsesRequestedCPUCapacity(t *testing.T) {
	command := strings.Join(BuildCommand("x86_64-linux", 1, 8, nil), " ")
	for _, option := range []string{"--max-jobs 1 ", "--cores 8 "} {
		if !strings.Contains(command, option) {
			t.Fatal("build command ignored its CPU budget", command)
		}
	}
}

func TestReclaimProtectsSourcesAndUnpublishedPaths(t *testing.T) {
	source, drv, out, extra, unpublished := fixturePath("a"), fixturePath("b")+".drv", fixturePath("c"), fixturePath("d"), fixturePath("e")
	d := derivation(out)
	d.InputSrcs = []string{source}
	graph, e := NewPlan(map[string]string{"target": drv}, map[string]Derivation{drv: d}, nil)
	if e != nil {
		t.Fatal(e)
	}

	paths := map[string]pathInfo{}
	for _, p := range []string{source, drv, out, extra, unpublished} {
		paths[p] = fixtureInfo("a")
	}

	runnerCommands(t, paths)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	durable := NewSnapshot(newMemoryCache(), cacheTestRepository)
	for _, p := range []string{source, drv, out, extra} {
		durable.Upstream[p] = []string{}
	}

	roots := t.TempDir()
	os.WriteFile(filepath.Join(roots, "old"), []byte(""), 0600)
	if _, e = Reclaim(".", io.Discard, graph, durable, roots); e != nil {
		t.Fatal(e)
	}

	calls, e := os.ReadFile(os.Getenv("TEST_CALLS"))
	if e != nil {
		t.Fatal(e)
	}

	for _, line := range strings.Split(string(calls), "\n") {
		if strings.HasPrefix(line, "nix-store --delete ") {
			if !strings.Contains(line, out) || !strings.Contains(line, extra) || strings.Contains(line, source) || strings.Contains(line, unpublished) || strings.Contains(line, drv) {
				t.Fatal(line)
			}
		}

		if strings.Contains(line, "--realise") && strings.Contains(line, ".drv") {
			t.Fatal("realized derivation as GC root", line)
		}
	}

	t.Setenv("RUNNER_ENVIRONMENT", "self-hosted")
	if _, e = Reclaim(".", io.Discard, graph, durable, roots); e == nil {
		t.Fatal("self hosted reclamation allowed")
	}
}
