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
	"reflect"
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

func TestCheckpointResumeAndFinalizeSalvageFailedJob(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	submitted := BuildRequest{ID: strings.Repeat("a", 32), Source: strings.Repeat("b", 40)}
	parent := NewSnapshot(storage, cacheTestRepository)
	jobs := map[string]ActionJob{}
	paths := []string{}
	for i, system := range sortedKeys(Systems) {
		stage := NewSnapshot(storage, cacheTestRepository)
		path := cacheRecord(stage, string(rune('a'+i)))
		paths = append(paths, path)
		stage.Metadata = map[string]any{
			"kind":     "stage",
			"binding":  BuildBinding(submitted, system),
			"run":      "1",
			"attempt":  1,
			"status":   "success",
			"terminal": true,
		}
		if e := (&nativeBuild{
			system: system, run: "1", attempt: 1, parent: parent, delta: stage, log: io.Discard,
			secrets: buildSecrets{identity: identity, recipients: recipients},
		}).checkpoint(1); e != nil {
			t.Fatal(e)
		}

		jobs[system] = ActionJob{RunAttempt: 1, Status: "completed", Conclusion: "success"}
	}

	failed := jobs["aarch64-linux"]
	failed.Conclusion = "failure"
	jobs["aarch64-linux"] = failed
	_, combined, e := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, jobs, allBuildRunners(t))
	if e != nil {
		t.Fatal(e)
	}
	if combined.Metadata["status"] != "failure" {
		t.Fatal(combined.Metadata)
	}

	for _, path := range paths {
		if !combined.Contains(path) {
			t.Fatal("completed output lost", path)
		}
	}

	if _, ok := storage.tags["nixos-cache-latest"]; ok {
		t.Fatal("assembly moved latest before publication")
	}

	prior, e := PriorStage(storage, cacheTestRepository, "1", "aarch64-linux", 2, identity, BuildBinding(submitted, "aarch64-linux"))
	if e != nil || prior == nil {
		t.Fatal(prior, e)
	}

	submitted.Source = strings.Repeat("c", 40)
	if _, e = PriorStage(storage, cacheTestRepository, "1", "aarch64-linux", 2, identity, BuildBinding(submitted, "aarch64-linux")); e == nil {
		t.Fatal("checkpoint from another source commit accepted")
	}

	if e = (&nativeBuild{
		system: "aarch64-linux", run: "1", attempt: 1, parent: parent, delta: combined, log: io.Discard,
		secrets: buildSecrets{identity: identity, recipients: recipients},
	}).checkpoint(5); e == nil {
		t.Fatal("checkpoint budget ignored")
	}
}

func TestFinalizePrunesBeforeReadingResultsAndPublishing(t *testing.T) {
	for _, test := range []struct {
		name, conclusion, wantError                          string
		unchanged, invalidInventory                          bool
		jobsUnavailable, catalogsUnavailable, invalidBinding bool
	}{
		{name: "successful build", conclusion: "success"},
		{name: "unchanged cache", conclusion: "success", unchanged: true},
		{name: "failed build", conclusion: "failure", wantError: "native builds failed"},
		{name: "changed inventory", conclusion: "success", invalidInventory: true, wantError: "package inventory changed"},
		{name: "job lookup failed", jobsUnavailable: true, wantError: "job lookup failed"},
		{name: "catalog read failed", conclusion: "success", catalogsUnavailable: true, wantError: "catalog downloads disabled"},
		{name: "checkpoint validation failed", conclusion: "success", invalidBinding: true, wantError: "checkpoint binding mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, recipients := cacheKeys(t)
			storage := newMemoryCache()
			fixture := newRetentionFixture()
			fixture.versions = nil
			fixture.active = []map[string]any{{"id": 10}}
			fixture.changeInventory = test.invalidInventory
			publish := func(snapshot *Snapshot, id int64, tags ...string) string {
				t.Helper()
				digest := cachePublish(t, snapshot, tags[0], recipients)
				fixture.add(id, tags, nil)
				fixture.versions[len(fixture.versions)-1].Name = digest
				return digest
			}
			obsolete := NewSnapshot(storage, cacheTestRepository)
			obsolete.Metadata = map[string]any{"kind": "commit", "run": "1"}
			publish(obsolete, 1, "nixos-cache-run-1-1")
			parent := NewSnapshot(storage, cacheTestRepository)
			parentPath := cacheRecord(parent, "a")
			parent.Metadata = map[string]any{"kind": "commit", "run": "2"}
			parentDigest := publish(parent, 2, "nixos-cache-latest", "nixos-cache-run-2-1")
			submitted := BuildRequest{
				ID: strings.Repeat("a", 32), Source: strings.Repeat("b", 40),
				Selection: map[string]string{"host": "host", "package": "hello"},
			}
			system := "aarch64-linux"
			matrix := BuildMatrix{Include: []BuildRunner{{System: system, Runner: Systems[system]}}}
			stage := NewSnapshot(storage, cacheTestRepository)
			stage.Metadata = map[string]any{
				"kind": "stage", "binding": BuildBinding(submitted, system),
				"run": "10", "attempt": 1, "parent": parentDigest,
				"status": "success", "terminal": true,
			}
			if test.invalidBinding {
				stage.Metadata["binding"] = BuildBinding(BuildRequest{ID: "other-request"}, system)
			}
			stagePath := parentPath
			if !test.unchanged {
				stagePath = cacheRecord(stage, "b")
			}
			stageDigest := publish(stage, 10, ResultTag("10", system, 1))
			poolTag := "nixos-cache-pool-10-1-aarch64-linux-result-2"
			for id := int64(11); id <= 12; id++ {
				pool := NewSnapshot(storage, cacheTestRepository)
				if err := pool.Merge(stage); err != nil {
					t.Fatal(err)
				}
				pool.Metadata = map[string]any{"kind": "pool", "run": "10"}
				publish(pool, id, poolTag)
			}
			// Moving the result tag leaves the earlier version untagged. Its
			// retention annotation must still make it eligible for cleanup.
			fixture.versions[len(fixture.versions)-2].Metadata.Container.Tags = []string{}
			api := func(path, method string) (any, error) {
				if path == "repos/test/infra-ci/actions/runs/10/attempts/1/jobs?per_page=100" && method == "GET" {
					if test.jobsUnavailable {
						return nil, errors.New("job lookup failed")
					}
					return map[string]any{"total_count": 1, "jobs": []map[string]any{{
						"id": 1, "name": "Build " + system, "run_attempt": 1,
						"status": "completed", "conclusion": test.conclusion,
					}}}, nil
				}
				return fixture.api(path, method)
			}
			var finalizationStorage Storage = storage
			if test.catalogsUnavailable {
				finalizationStorage = unavailableCatalogs{storage}
			}
			err := Finalize(api, finalizationStorage, cacheTestRepository, submitted, "10", 1, identity, recipients, matrix, io.Discard)
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("finalization: %v", err)
			}
			if test.invalidInventory {
				if len(fixture.deleted) != 0 || storage.tags["nixos-cache-latest"] != parentDigest || storage.tags["nixos-cache-run-10-1"] != "" {
					t.Fatal("changed inventory allowed deletion or publication")
				}
				return
			}
			if !reflect.DeepEqual(fixture.deleted, []int64{1, 11, 12}) || len(fixture.versions) != 2 {
				t.Fatal("retention must delete the obsolete run and finished pool", fixture.deleted)
			}
			if fixture.versions[0].Name != parentDigest || fixture.versions[1].Name != stageDigest {
				t.Fatal("retention lost the latest cache or active checkpoint")
			}
			if test.jobsUnavailable || test.catalogsUnavailable || test.invalidBinding {
				if storage.tags["nixos-cache-latest"] != parentDigest || storage.tags["nixos-cache-run-10-1"] != "" {
					t.Fatal("failed assembly published a combined cache")
				}
				return
			}
			latest, err := LoadParent(storage, cacheTestRepository, identity)
			if err != nil {
				t.Fatal(err)
			}
			if !latest.Contains(parentPath) || !latest.Contains(stagePath) {
				t.Fatal("finalization lost completed outputs")
			}
			if test.unchanged {
				if latest.Digest != parentDigest || storage.tags["nixos-cache-run-10-1"] != "" {
					t.Fatal("unchanged cache was republished")
				}
			} else if latest.Digest == parentDigest || storage.tags["nixos-cache-run-10-1"] != latest.Digest || latest.Metadata["status"] != test.conclusion {
				t.Fatal("combined cache was not published with the build outcome", latest.Metadata)
			}
		})
	}
}

func TestAssembleMergesEachParentOnce(t *testing.T) {
	for _, historical := range []bool{false, true} {
		t.Run(fmt.Sprintf("historical=%t", historical), func(t *testing.T) {
			identity, recipients := cacheKeys(t)
			storage := newMemoryCache()
			submitted := BuildRequest{ID: strings.Repeat("a", 32), Source: strings.Repeat("b", 40)}
			parent := NewSnapshot(storage, cacheTestRepository)
			basePath := cacheRecord(parent, "a")
			cachePublish(t, parent, "nixos-cache-latest", recipients)
			paths := []string{basePath}
			if historical {
				latest := NewSnapshot(storage, cacheTestRepository)
				paths = append(paths, cacheRecord(latest, "b"))
				cachePublish(t, latest, "nixos-cache-latest", recipients)
			}
			jobs := map[string]ActionJob{}
			for i, system := range sortedKeys(Systems) {
				stage := NewSnapshot(storage, cacheTestRepository)
				paths = append(paths, cacheRecord(stage, string("cdf"[i]), filepath.Base(basePath)))
				stage.Metadata = map[string]any{
					"kind": "stage", "binding": BuildBinding(submitted, system),
					"run": "1", "attempt": 1, "parent": parent.Digest,
					"status": "success", "terminal": true,
				}
				cachePublish(t, stage, ResultTag("1", system, 1), recipients)
				jobs[system] = ActionJob{RunAttempt: 1, Status: "completed", Conclusion: "success"}
			}
			storage.gets = 0
			_, combined, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, jobs, allBuildRunners(t))
			if err != nil {
				t.Fatal(err)
			}
			if combined.Metadata["status"] != "success" {
				t.Fatal(combined.Metadata)
			}
			for _, path := range paths {
				if !combined.Contains(path) {
					t.Fatal("lost parent or stage output", path)
				}
			}
			// Three stage catalogs plus each distinct parent catalog.
			wantReads := len(Systems) + 1
			if historical {
				wantReads++
			}
			if storage.gets != wantReads {
				t.Fatalf("downloaded %d catalogs, want %d", storage.gets, wantReads)
			}
			if historical {
				delete(storage.manifests, parent.Digest)
				if _, _, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, jobs, allBuildRunners(t)); !errors.Is(err, ErrObjectNotFound) {
					t.Fatalf("missing historical parent accepted: %v", err)
				}
			}
		})
	}
}

func TestAssembleRequiresOnlyAdmittedJobsAcrossRetries(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	submitted := BuildRequest{
		ID:        strings.Repeat("a", 32),
		Source:    strings.Repeat("b", 40),
		Selection: map[string]string{"host": "host", "package": "hello"},
	}
	system := "aarch64-linux"
	matrix := BuildMatrix{Include: []BuildRunner{{System: system, Runner: Systems[system]}}}
	stage := NewSnapshot(storage, cacheTestRepository)
	path := cacheRecord(stage, "a")
	stage.Metadata = map[string]any{
		"kind": "stage", "binding": BuildBinding(submitted, system),
		"run": "1", "attempt": 1, "status": "success", "terminal": true,
	}
	cachePublish(t, stage, ResultTag("1", system, 1), recipients)
	for _, test := range []struct {
		name    string
		attempt int
		job     *ActionJob
		status  string
	}{
		{"success", 1, &ActionJob{RunAttempt: 1, Status: "completed", Conclusion: "success"}, "success"},
		{"finalize retry", 2, &ActionJob{RunAttempt: 1, Status: "completed", Conclusion: "success"}, "success"},
		{"missing job", 1, nil, "failure"},
		{"failed job", 1, &ActionJob{RunAttempt: 1, Status: "completed", Conclusion: "failure"}, "failure"},
		{"cancelled retry", 2, &ActionJob{RunAttempt: 2, Status: "completed", Conclusion: "cancelled"}, "failure"},
		{"missing retry checkpoint", 2, &ActionJob{RunAttempt: 2, Status: "completed", Conclusion: "success"}, "failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			jobs := map[string]ActionJob{}
			if test.job != nil {
				jobs[system] = *test.job
			}
			_, combined, err := Assemble(storage, cacheTestRepository, submitted, "1", test.attempt, identity, jobs, matrix)
			if err != nil {
				t.Fatal(err)
			}
			states := combined.Metadata["systems"].(map[string]string)
			if combined.Metadata["status"] != test.status || len(states) != 1 || states[system] != test.status || !combined.Contains(path) {
				t.Fatal(combined.Metadata, combined.Narinfos)
			}
		})
	}
	if _, _, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, nil, BuildMatrix{}); err == nil {
		t.Fatal("missing matrix accepted")
	}
	if _, _, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, nil, allBuildRunners(t)); err == nil {
		t.Fatal("selected build accepted extra runners")
	}
	submitted.Selection = nil
	if _, _, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, nil, matrix); err == nil {
		t.Fatal("full build accepted a partial matrix")
	}
	_, combined, err := Assemble(storage, cacheTestRepository, submitted, "1", 1, identity, map[string]ActionJob{
		system: {RunAttempt: 1, Status: "completed", Conclusion: "success"},
	}, allBuildRunners(t))
	if err != nil || combined.Metadata["status"] != "failure" || len(combined.Metadata["systems"].(map[string]string)) != len(Systems) {
		t.Fatal(combined, err)
	}
}

func TestBuildParentRetriesUseLatestAndStagesAreOpaque(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	first := NewSnapshot(storage, cacheTestRepository)
	first.Metadata["version"] = 1
	cachePublish(t, first, "nixos-cache-latest", recipients)
	second := NewSnapshot(storage, cacheTestRepository)
	second.Metadata["version"] = 2
	cachePublish(t, second, "nixos-cache-latest", recipients)
	p, e := BuildParent(storage, cacheTestRepository, identity, first.Digest, 1, 1)
	if e != nil || p.Digest != first.Digest {
		t.Fatal(p, e)
	}

	p, e = BuildParent(storage, cacheTestRepository, identity, first.Digest, 1, 2)
	if e != nil || p.Digest != second.Digest {
		t.Fatal(p, e)
	}

	a := StageTag("123", "aarch64-linux", 2, 1, identity)
	b := StageTag("123", "aarch64-darwin", 2, 1, identity)
	if a == b || strings.Contains(a, "linux") || !strings.HasPrefix(a, "nixos-cache-stage-123-2-1-") {
		t.Fatal(a, b)
	}

	if _, e = BuildParent(storage, cacheTestRepository, identity, "", 0, 2); e == nil {
		t.Fatal("missing admission accepted")
	}
}

func TestRunnerEnvironmentStripsCredentialsAndActionTracking(t *testing.T) {
	for _, name := range []string{
		"CI_IDENTITY",
		"REGISTRY_TOKEN",
		"CI_POOL_TOKEN",
		"CI_POOL_USER",
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

func TestActionJobsSelectsLatestExecutedAttempt(t *testing.T) {
	responses := map[string]string{
		"repos/test/infra-ci/actions/runs/123/attempts/2/jobs?per_page=100": `{"total_count":2,"jobs":[
			{"id":20,"name":"Build x86_64-linux","run_attempt":2,"status":"completed","conclusion":"skipped"},
			{"id":21,"name":"Build aarch64-linux","run_attempt":2,"status":"completed","conclusion":"success"}
		]}`,
		"repos/test/infra-ci/actions/runs/123/attempts/1/jobs?per_page=100": `{"total_count":2,"jobs":[
			{"id":9007199254740993,"name":"Build x86_64-linux","run_attempt":1,"status":"completed","conclusion":"success"},
			{"id":11,"name":"Build aarch64-linux","run_attempt":1,"status":"completed","conclusion":"failure"}
		]}`,
	}
	api := func(path, method string) (any, error) {
		response, ok := responses[path]
		if !ok || method != "GET" {
			t.Fatalf("unexpected GitHub request: %s %s", method, path)
		}
		var value any
		decoder := json.NewDecoder(strings.NewReader(response))
		decoder.UseNumber()
		err := decoder.Decode(&value)
		return value, err
	}
	jobs, err := ActionJobs(api, "test/infra-ci", "123", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs["x86_64-linux"].ID != 9007199254740993 || jobs["aarch64-linux"].ID != 21 {
		t.Fatal("latest executed jobs or exact IDs changed", jobs)
	}
}

func TestActionJobsRejectsMalformedInventories(t *testing.T) {
	if _, err := ActionJobs(nil, "test/infra-ci", "123", 0); err == nil {
		t.Fatal("zero workflow attempt accepted")
	}
	const inventory = `{"total_count":1,"jobs":[{"id":42,"name":"Build x86_64-linux","run_attempt":1,"status":"completed","conclusion":"success"}]}`
	for _, test := range []struct{ name, response string }{
		{"missing count", `{"jobs":[]}`},
		{"null count", `{"total_count":null,"jobs":[]}`},
		{"missing jobs", `{"total_count":0}`},
		{"null jobs", `{"total_count":0,"jobs":null}`},
		{"incomplete inventory", `{"total_count":101,"jobs":[]}`},
		{"count mismatch", `{"total_count":1,"jobs":[]}`},
		{"fractional count", strings.Replace(inventory, `"total_count":1`, `"total_count":1.5`, 1)},
		{"missing ID", strings.Replace(inventory, `"id":42,`, "", 1)},
		{"zero ID", strings.Replace(inventory, `"id":42`, `"id":0`, 1)},
		{"fractional ID", strings.Replace(inventory, `"id":42`, `"id":4.2`, 1)},
		{"string ID", strings.Replace(inventory, `"id":42`, `"id":"42"`, 1)},
		{"missing name", strings.Replace(inventory, `"name":"Build x86_64-linux",`, "", 1)},
		{"missing attempt", strings.Replace(inventory, `"run_attempt":1,`, "", 1)},
		{"wrong attempt", strings.Replace(inventory, `"run_attempt":1`, `"run_attempt":2`, 1)},
		{"missing status", strings.Replace(inventory, `"status":"completed",`, "", 1)},
		{"invalid conclusion", strings.Replace(inventory, `"conclusion":"success"`, `"conclusion":{"private-response":true}`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := func(string, string) (any, error) { return json.RawMessage(test.response), nil }
			_, err := ActionJobs(api, "test/infra-ci", "123", 1)
			if err == nil {
				t.Fatal("malformed job inventory accepted")
			}
			if strings.Contains(err.Error(), "private-response") {
				t.Fatal("GitHub response leaked in error", err)
			}
		})
	}
}
