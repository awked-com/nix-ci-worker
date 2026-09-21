package worker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("INFRA_NATIVE_NIX_TESTS") != "1" {
		t.Skip("set INFRA_NATIVE_NIX_TESTS=1 to run against the local Nix daemon")
	}

	for _, tool := range []string{"nix", "nix-store"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Fatalf("%s required: %v", tool, e)
		}
	}
}

type stalledCache struct {
	*memoryCache
	once             sync.Once
	started, release chan struct{}
	failure          error
}

func (s *stalledCache) UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error) {
	var err error
	s.once.Do(func() {
		close(s.started)
		<-s.release
		err = s.failure
	})
	if err != nil {
		return Descriptor{}, err
	}
	return s.memoryCache.UploadBlob(repository, source, encrypted)
}

type batchProgressLog struct {
	bytes.Buffer
	done chan struct{}
}

func (l *batchProgressLog) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("Build batch 2/2: exited")) {
		close(l.done)
	}
	return l.Buffer.Write(data)
}

func TestNativeBuildContinuesDuringPublicationAndDrainsBeforeCompletion(t *testing.T) {
	nativeEnabled(t)
	identity, recipients := cacheKeys(t)
	system, err := NativeSystem()
	if err != nil {
		t.Fatal(err)
	}
	signing, err := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "native-test").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("upload-failure=%v", failed), func(t *testing.T) {
			source := t.TempDir()
			flake := fmt.Sprintf(`{ outputs = { self }: { hydraJobs.%q = builtins.listToAttrs (builtins.genList (i: {
  name = "target-${toString i}";
  value = builtins.derivation {
    name = "ci-background-${toString i}";
    system = %q;
    salt = %q;
    allowSubstitutes = false;
    builder = "/bin/sh";
    args = [ "-c" "echo ${toString i} > $out" ];
  };
}) 33); }; }`, system, system, source)
			if err := os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); err != nil {
				t.Fatal(err)
			}
			storage := &stalledCache{
				memoryCache: newMemoryCache(),
				started:     make(chan struct{}),
				release:     make(chan struct{}),
			}
			if failed {
				storage.failure = errors.New("publication interrupted")
			}
			parent, delta := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
			log := &batchProgressLog{done: make(chan struct{})}
			type result struct {
				success bool
				err     error
			}
			done := make(chan result, 1)
			var group sync.WaitGroup
			group.Add(1)
			defer group.Wait()
			release := sync.OnceFunc(func() { close(storage.release) })
			defer release()
			go func() {
				defer group.Done()
				success, err := (nativeBuild{
					source: source, system: system, run: "1", attempt: 1,
					parent: parent, delta: delta, log: log, upstream: knownUpstream{},
					secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
				}).execute()
				done <- result{success, err}
			}()
			for _, event := range []<-chan struct{}{storage.started, log.done} {
				select {
				case <-event:
				case r := <-done:
					t.Fatalf("build ended before both batches finished: %+v\n%s", r, log.String())
				case <-time.After(45 * time.Second):
					t.Fatal("build batches stalled behind cache publication")
				}
			}
			select {
			case r := <-done:
				t.Fatalf("build returned without draining publication: %+v", r)
			default:
			}
			release()
			r := <-done
			if r.err != nil || r.success == failed {
				t.Fatalf("success=%v, error=%v\n%s", r.success, r.err, log.String())
			}
			saved := cacheLoad(t, storage, ResultTag("1", system, 1), identity)
			if saved.Metadata["terminal"] != true || (saved.Metadata["status"] == "success") == failed {
				t.Fatal(saved.Metadata)
			}
			results := saved.Metadata["results"].([]any)
			if len(results) != 33 {
				t.Fatalf("saved %d targets, want 33", len(results))
			}
			for _, value := range results {
				if value.(map[string]any)["status"] != "success" {
					t.Fatalf("completed target was not salvaged: %v", value)
				}
			}
		})
	}
}

func TestNativeBuildCheckpointsSplitOutputsAndWarmResume(t *testing.T) {
	nativeEnabled(t)
	identity, recipients := cacheKeys(t)
	system, e := NativeSystem()
	if e != nil {
		t.Fatal(e)
	}

	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%v", failed), func(t *testing.T) {
			source := t.TempDir()
			salt := filepath.Base(source)
			extra := ""
			if failed {
				extra = `bad = make "ci-native-failed" "echo unfinished > $out; exit 17";`
			}

			targets := "first = dep; alias = dep;"
			if failed {
				targets += " inherit bad;"
			}

			flake := fmt.Sprintf(
				`{ outputs = { self }: let make = name: script: builtins.derivation { inherit name; system = %q; salt = %q; builder = "/bin/sh"; args = [ "-c" script ]; }; dep = builtins.derivation { name = "ci-native-split"; system = %q; salt = %q; builder = "/bin/sh"; outputs = [ "out" "dev" ]; args = [ "-c" "echo output > $out; echo headers > $dev" ]; }; %s in { hydraJobs.%q = { %s }; }; }`,
				system,
				salt,
				system,
				salt,
				extra,
				system,
				targets,
			)
			if e = os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); e != nil {
				t.Fatal(e)
			}

			var log bytes.Buffer

			nix := func(args []string, capture bool, data []byte) ([]byte, error) {
				return NixRun(source, &log, args, capture, data)
			}

			graph, e := Evaluate(source, system, nix, nil, &log)
			if e != nil {
				t.Fatalf("evaluate: %v\n%s", e, log.String())
			}

			t.Setenv("GITHUB_ACTIONS", "")
			signing, e := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "native-test").Output()
			if e != nil {
				t.Fatal(e)
			}

			storage := newMemoryCache()
			parent := NewSnapshot(storage, cacheTestRepository)
			delta := NewSnapshot(storage, cacheTestRepository)
			binding := map[string]any{"fixture": salt}
			delta.Metadata = map[string]any{
				"kind":    "stage",
				"binding": binding,
				"run":     "1",
				"attempt": 1,
			}
			success, e := (nativeBuild{
				source: source, system: system, run: "1", attempt: 1,
				parent: parent, delta: delta, log: &log, upstream: knownUpstream{},
				secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
			}).execute()
			if e != nil || success == failed {
				t.Fatalf("build success=%v expected=%v error=%v\n%s", success, !failed, e, log.String())
			}

			saved, e := PriorStage(storage, cacheTestRepository, "1", system, 1, identity, binding)
			if e != nil || saved == nil {
				t.Fatal(saved, e)
			}

			for _, path := range graph.Outputs[graph.Targets["first"]] {
				if !saved.Contains(path) {
					t.Fatalf("completed output missing: %s\n%s", path, log.String())
				}
			}

			if failed {
				if saved.Contains(graph.Outputs[graph.Targets["bad"]]["out"]) {
					t.Fatal("failed output published")
				}
			} else if !graph.Complete(saved) {
				t.Fatal("successful build coverage incomplete")
			}

			if e = parent.Merge(saved); e != nil {
				t.Fatal(e)
			}

			second := NewSnapshot(storage, cacheTestRepository)
			second.Metadata = map[string]any{
				"kind":    "stage",
				"binding": binding,
				"run":     "1",
				"attempt": 2,
			}
			if e = second.Merge(saved); e != nil {
				t.Fatal(e)
			}

			log.Reset()
			success, e = (nativeBuild{
				source: source, system: system, run: "1", attempt: 2,
				parent: parent, delta: second, log: &log, upstream: knownUpstream{},
				secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
			}).execute()
			if e != nil || success == failed {
				t.Fatalf("resume success=%v error=%v\n%s", success, e, log.String())
			}

			if integer := Int(second.Metadata["new_ciphertext_bytes"]); integer != 0 {
				t.Fatalf("completed data reuploaded: %v", second.Metadata)
			}

			if !failed && second.Metadata["missing_output_groups"] != 0 {
				t.Fatal(second.Metadata)
			}
			if failed && second.Metadata["missing_output_groups"] != 1 {
				t.Fatal(second.Metadata)
			}

			publicCommand := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "convert-secret-to-public")
			publicCommand.Stdin = bytes.NewReader(signing)
			public, e := publicCommand.Output()
			if e != nil {
				t.Fatal(e)
			}

			_, server, options, e := substituter(storage, parent, identity, Secret{Data: signing}, &log)
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()

			for _, path := range graph.Outputs[graph.Targets["first"]] {
				command := exec.Command(
					"nix",
					"--extra-experimental-features", "nix-command",
					"store",
					"verify",
					"--store", strings.Fields(options[1])[0],
					"--sigs-needed", "1",
					"--option", "trusted-public-keys", strings.TrimSpace(string(public)),
					path,
				)
				if b, e := command.CombinedOutput(); e != nil {
					t.Fatalf("cache signature verification: %v\n%s", e, b)
				}
			}

		})
	}
}

func TestNativeDarwinSandboxProfileRemainsIsolated(t *testing.T) {
	nativeEnabled(t)
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin sandbox")
	}

	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}

	root, e := os.MkdirTemp(home, "infra-ci-sandbox-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)

	allowed, denied := filepath.Join(root, "allowed"), filepath.Join(root, "denied")
	os.WriteFile(allowed, []byte("explicit profile access\n"), 0600)
	os.WriteFile(denied, []byte("must remain inaccessible\n"), 0600)
	profile := fmt.Sprintf("(allow file-read* (literal %q))", allowed)
	script := fmt.Sprintf("read -r value < %s || exit 31; echo \"$value\"; if (read -r value < %s) 2>/dev/null; then exit 32; fi; echo okay > $out", shellQuote(allowed), shellQuote(denied))
	profileJSON := strconv.Quote(profile)
	scriptJSON := strconv.Quote(script)
	expr := fmt.Sprintf(`builtins.derivation { name = "ci-sandbox-profile"; system = builtins.currentSystem; builder = "/bin/sh"; __sandboxProfile = %s; args = [ "-c" %s ]; }`, profileJSON, scriptJSON)
	options := []string{
		"--store", "local?store=" + root + "/store&state=" + root + "/state&log=" + root + "/log",
		"--option", "build-users-group", "",
		"--option", "substitute", "false",
	}
	b, e := exec.Command("nix-instantiate", append(options, "--expr", expr)...).CombinedOutput()
	if e != nil {
		t.Fatalf("instantiate: %v\n%s", e, b)
	}

	lines := strings.Fields(string(b))
	drv := ""
	for _, line := range lines {
		if strings.HasSuffix(line, ".drv") {
			drv = line
		}
	}

	if drv == "" {
		t.Fatalf("no derivation: %s", b)
	}

	command := BuildCommand("aarch64-darwin", 1, 1, options)
	strict := exec.Command("nix", append(append([]string{}, command...), "--option", "sandbox", "true")...)
	strict.Stdin = strings.NewReader(drv + "^*\n")
	if e = strict.Run(); e == nil {
		t.Fatal("strict sandbox unexpectedly accepted custom profile")
	}

	relaxed := exec.Command("nix", command...)
	relaxed.Stdin = strings.NewReader(drv + "^*\n")
	b, e = relaxed.CombinedOutput()
	if e != nil {
		t.Fatalf("custom profile isolation: %v\n%s", e, b)
	}
}
