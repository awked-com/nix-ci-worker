package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeRegistryBuilderTransfersInputsAndSignedOutputs(t *testing.T) {
	nativeEnabled(t)
	t.Setenv("GITHUB_ACTIONS", "")
	source := t.TempDir()
	system, err := NativeSystem()
	if err != nil {
		t.Fatal(err)
	}
	flake := fmt.Sprintf(`{ outputs = { self }: { hydraJobs.%q.fixture = builtins.derivation {
 name = "registry-builder-fixture"; system = %q; builder = "/bin/sh";
 input = builtins.toFile "registry-builder-input" %q;
 args = [ "-c" "read -r text < $input; echo $text > $out; echo $NIX_BUILD_CORES >> $out" ];
 }; }; }`, system, system, "registry transfer "+source+"\n")
	if err = os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	log := &buildLog{Writer: &diagnostics}
	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(source, log, args, capture, data)
	}
	graph, err := Evaluate(source, system, nix, nil, log)
	if err != nil {
		t.Fatalf("evaluate: %v\n%s", err, &diagnostics)
	}
	identity, recipients := cacheKeys(t)
	storage := &repositoryCache{}
	bus, err := newPoolBus(storage, cacheTestRepository, "123", system, 1, identity, recipients, "native-fixture")
	if err != nil {
		t.Fatal(err)
	}
	signing, err := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "registry-fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	public, err := signingPublicKey(signing)
	if err != nil {
		t.Fatal(err)
	}
	empty, inputs := NewSnapshot(storage, bus.repository), NewSnapshot(storage, bus.repository)
	if _, err = PublishStore(source, graph.Required, inputs, empty, Secret{Data: signing}, recipients, log, knownUpstream{}); err != nil {
		t.Fatalf("publish input: %v\n%s", err, &diagnostics)
	}
	digest, err := inputs.Publish(bus.tag("inputs", 0), recipients)
	if err != nil {
		t.Fatal(err)
	}
	drv := graph.Targets["fixture"]
	output := graph.Outputs[drv]["out"]
	t.Run("inputs split between caches", func(t *testing.T) {
		// Upstream-covered paths are omitted from the encrypted cache. A helper
		// must fetch a closure from both caches even when its own store is empty.
		input := graph.Derivations[drv].InputSrcs[0]
		upstream := NewSnapshot(storage, bus.repository)
		upstream.Narinfos[NarinfoKey(input)] = inputs.Narinfos[NarinfoKey(input)]
		fields, err := NarinfoFields(upstream.Narinfos[NarinfoKey(input)])
		if err != nil {
			t.Fatal(err)
		}
		archive := "cache/" + fields["URL"]
		upstream.Files[archive] = inputs.Files[archive]
		private := NewSnapshot(storage, bus.repository)
		if err := private.Merge(inputs); err != nil {
			t.Fatal(err)
		}
		private.Upstream[input] = []string{}
		if err := private.PreferUpstream(); err != nil {
			t.Fatal(err)
		}
		if err := private.RequireClosed(); err != nil {
			t.Fatal(err)
		}
		_, privateServer, options, err := publicSubstituter(storage, private, identity, public, log)
		if err != nil {
			t.Fatal(err)
		}
		defer privateServer.Close()
		_, upstreamServer, upstreamOptions, err := publicSubstituter(storage, upstream, identity, public, log)
		if err != nil {
			t.Fatal(err)
		}
		defer upstreamServer.Close()
		options[1] = strings.Fields(options[1])[0] + " " + strings.Fields(upstreamOptions[1])[0]
		store, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("NIX_REMOTE", "local?root="+store)
		if err := substitutePoolPaths(context.Background(), source, []string{drv}, options, "", log); err != nil {
			t.Fatalf("fetch split closure: %v\n%s", err, &diagnostics)
		}
		for _, path := range []string{drv, input} {
			if _, err := os.Stat(store + path); err != nil {
				t.Fatalf("missing transferred input: %v", err)
			}
		}
		if _, err := os.Stat(store + output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("input transfer built a derivation output", err)
		}
	})
	// The isolated store above exercises input transfer without requiring the
	// local daemon to trust a test HTTP cache. Build the fixture in its own store.
	buildInputs, err := graph.BuildInputs(drv)
	if err != nil {
		t.Fatal(err)
	}
	task := poolTask{Cores: runtime.NumCPU(), Installable: drv + "^out", BuildInputs: buildInputs, Inputs: digest, PublicKey: public, Outputs: []string{output}}
	resultDigest, err := executePoolBuild(context.Background(), bus, source, 2, task, knownUpstream{}, log)
	if err != nil {
		t.Fatalf("helper build: %v\n%s", err, &diagnostics)
	}
	result, err := LoadSnapshot(storage, bus.repository, resultDigest, identity)
	if err != nil {
		t.Fatal(err)
	}
	transfer := bus.signingKey(2)
	transportPublic, err := signingPublicKey(transfer.Data)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorStore, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldRemote := os.Getenv("NIX_REMOTE")
	t.Setenv("NIX_REMOTE", "local?root="+coordinatorStore)
	if err = poolCopy(context.Background(), source, result, identity, public+" "+transportPublic, []string{output}, log); err != nil {
		t.Fatalf("coordinator import: %v\n%s", err, &diagnostics)
	}
	data, err := os.ReadFile(coordinatorStore + output)
	if err != nil || strings.TrimSpace(string(data)) != fmt.Sprintf("registry transfer %s\n%d", source, task.Cores) {
		t.Fatal(string(data), err)
	}
	t.Setenv("NIX_REMOTE", oldRemote)
	final := NewSnapshot(storage, bus.repository)
	for name, file := range result.Files {
		final.Files[name] = file
	}
	before := len(storage.cache(cacheTestRepository).objects)
	if _, err = PublishStore(source, map[string]bool{output: true}, final, inputs, Secret{Data: signing}, recipients, log, knownUpstream{}); err != nil {
		t.Fatalf("final publication: %v\n%s", err, &diagnostics)
	}
	if !strings.Contains(final.Narinfos[NarinfoKey(output)], "Sig: registry-fixture:") {
		t.Fatal("final output was not signed by coordinator")
	}
	if len(storage.cache(cacheTestRepository).objects) != before {
		t.Fatal("verified output archive was uploaded twice")
	}
	rejectedStore, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NIX_REMOTE", "local?root="+rejectedStore)
	// A helper's signature is never sufficient for the final cache trust key.
	if err = poolCopy(context.Background(), source, result, identity, public, []string{output}, log); err == nil {
		t.Fatal("untrusted transfer signature accepted")
	}
}

func TestNativeRegistryPoolBuildsAndFinalizesDependencyGraph(t *testing.T) {
	nativeEnabled(t)
	t.Setenv("GITHUB_ACTIONS", "")
	system, err := NativeSystem()
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	flake := fmt.Sprintf(`{ outputs = { self }: let
 make = name: input: builtins.derivation { inherit name input; system = %q; salt = %q; builder = "/bin/sh"; args = [ "-c" "echo complete > $out" ]; };
 a = make "registry-pool-a" "";
 in { hydraJobs.%q = { inherit a; b = make "registry-pool-b" ""; c = make "registry-pool-c" ""; d = make "registry-pool-d" ""; e = make "registry-pool-e" ""; f = make "registry-pool-f" ""; g = make "registry-pool-g" a; }; }; }`, system, source, system)
	if err = os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); err != nil {
		t.Fatal(err)
	}
	identity, recipients := cacheKeys(t)
	storage := &repositoryCache{}
	bus, err := newPoolBus(storage, cacheTestRepository, "456", system, 1, identity, recipients, "native-pool")
	if err != nil {
		t.Fatal(err)
	}
	timing := poolTiming{20 * time.Millisecond, 50 * time.Millisecond, 10 * time.Second, 10 * time.Second}
	var output bytes.Buffer
	log := &buildLog{Writer: &output}
	p := startBuildPool(bus, log, timing)
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	helpers := make(chan error, 2)
	for runner := 1; runner < RunnersPerSystem; runner++ {
		go func() {
			helpers <- servePoolBuilder(ctx, bus, runner, []string{"big-parallel"}, timing, func(ctx context.Context, task poolTask) (string, error) {
				return executePoolBuild(ctx, bus, source, runner, task, knownUpstream{}, log)
			}, log)
		}()
	}
	awaitPool(t, func() bool {
		for runner := 1; runner < RunnersPerSystem; runner++ {
			if p.statuses[runner].Load() == nil {
				return false
			}
		}
		return true
	})
	signing, err := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "registry-pool-final").Output()
	if err != nil {
		t.Fatal(err)
	}
	parent, delta := NewSnapshot(storage, bus.repository), NewSnapshot(storage, bus.repository)
	success, err := (nativeBuild{
		source: source, system: system, run: bus.run, attempt: bus.attempt,
		parent: parent, delta: delta, log: log, upstream: knownUpstream{}, pool: p,
		secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
	}).execute()
	if err != nil || !success {
		t.Fatalf("pool build: success=%v err=%v\n%s", success, err, &output)
	}
	for range 2 {
		select {
		case err := <-helpers:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("helper stayed alive after final upload")
		}
	}
	for runner := 1; runner < RunnersPerSystem; runner++ {
		status, err := bus.read("status", runner)
		if err != nil || status.State != "done" || status.Sequence == 0 {
			t.Fatal("helper did not build", runner, status, err)
		}
	}
	saved, err := LoadSnapshot(storage, bus.repository, ResultTag(bus.run, system, bus.attempt), identity)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Metadata["status"] != "success" || saved.Metadata["terminal"] != true {
		t.Fatal(saved.Metadata)
	}
	if err = saved.RequireClosed(); err != nil {
		t.Fatal(err)
	}
}

func TestNativePoolImportsNonSubstitutableDependencies(t *testing.T) {
	nativeEnabled(t)
	t.Setenv("GITHUB_ACTIONS", "")
	system, err := NativeSystem()
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	flake := fmt.Sprintf(`{ outputs = { self }: let
 dep = builtins.derivation { name = "pool-shared-input"; system = %q; salt = %q;
   builder = "/bin/sh"; allowSubstitutes = false;
   args = [ "-c" "echo original-$$ > $out" ]; };
 in { hydraJobs.%q = { inherit dep; consumer = builtins.derivation {
   name = "pool-input-consumer"; system = %q; input = dep; builder = "/bin/sh";
   args = [ "-c" "echo $input > $out" ];
 }; }; }; }`, system, source, system, system)
	if err = os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	log := &buildLog{Writer: &diagnostics}
	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(source, log, args, capture, data)
	}
	graph, err := Evaluate(source, system, nix, nil, log)
	if err != nil {
		t.Fatalf("evaluate: %v\n%s", err, &diagnostics)
	}
	dependency, consumer := graph.Targets["dep"], graph.Targets["consumer"]
	dependencyOutput, output := graph.Outputs[dependency]["out"], graph.Outputs[consumer]["out"]
	if _, err = nix([]string{"build", "--no-link", dependency + "^out"}, false, nil); err != nil {
		t.Fatalf("build dependency: %v\n%s", err, &diagnostics)
	}
	original, err := os.ReadFile(dependencyOutput)
	if err != nil {
		t.Fatal(err)
	}
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	signing, err := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "dependency-fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	public, err := signingPublicKey(signing)
	if err != nil {
		t.Fatal(err)
	}
	empty, inputs := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
	if _, err = PublishStore(source, graph.Required, inputs, empty, Secret{Data: signing}, recipients, log, knownUpstream{}); err != nil {
		t.Fatalf("publish inputs: %v\n%s", err, &diagnostics)
	}
	buildInputs, err := graph.BuildInputs(consumer)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%v", missing), func(t *testing.T) {
			store, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("NIX_REMOTE", "local?root="+store)
			t.Setenv("NIX_CONFIG", "build-users-group =\nsandbox = false\n")
			temporary := t.TempDir()
			t.Setenv("TMPDIR", temporary)
			snapshot, err := CacheUnion(empty, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if missing {
				delete(snapshot.Narinfos, NarinfoKey(dependencyOutput))
			}
			_, server, options, err := publicSubstituter(storage, snapshot, identity, public, log)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if missing {
				err := buildPoolDerivation(context.Background(), source, system, consumer+"^out", 1, buildInputs, options, log)
				if err == nil || !strings.Contains(err.Error(), "build input import failed") {
					t.Fatalf("missing input did not stop before compilation: %v\n%s", err, &diagnostics)
				}
				for _, path := range []string{dependencyOutput, output} {
					if _, err := os.Stat(store + path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("missing input was rebuilt", path, err)
					}
				}
				if roots, err := filepath.Glob(filepath.Join(temporary, "pool-inputs-*")); err != nil || len(roots) != 0 {
					t.Fatal("failed import retained input roots", roots, err)
				}
				return
			}
			release, err := preparePoolInputs(context.Background(), source, buildInputs, options, log)
			if err != nil {
				t.Fatalf("input import: %v\n%s", err, &diagnostics)
			}
			defer release()
			got, err := os.ReadFile(store + dependencyOutput)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("shared dependency was rebuilt", string(got), err)
			}
			// macOS cannot compile inside a diverted store. Ask Nix which work
			// remains; the shared dependency must not appear in its build plan.
			var planned bytes.Buffer
			if _, err = NixRun(source, &planned, []string{"build", "--dry-run", "--no-link", "--offline", "--option", "substitute", "false", "--option", "always-allow-substitutes", "false", consumer + "^out"}, true, nil); err != nil {
				t.Fatalf("plan consumer build: %v\n%s", err, &planned)
			}
			if !strings.Contains(planned.String(), consumer) || strings.Contains(planned.String(), dependency) {
				t.Fatalf("consumer would rebuild its dependency:\n%s", &planned)
			}
			live := func() string {
				t.Helper()
				out, err := exec.Command("nix-store", "--gc", "--print-live").CombinedOutput()
				if err != nil {
					t.Fatalf("read live store paths: %v\n%s", err, out)
				}
				return string(out)
			}
			if !strings.Contains(live(), dependencyOutput) {
				t.Fatal("imported dependency is not rooted during the build")
			}
			release()
			if strings.Contains(live(), dependencyOutput) {
				t.Fatal("finished build retained its input roots")
			}
		})
	}
}
