package worker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func nativeEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("INFRA_NATIVE_NIX_TESTS") != "1" {
		t.Skip("set INFRA_NATIVE_NIX_TESTS=1 to run against the local Nix daemon")
	}

	if runtime.GOOS != "linux" {
		t.Skip("native CI build tests require Linux")
	}
	for _, tool := range []string{"nix", "nix-store"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Fatalf("%s required: %v", tool, e)
		}
	}
}

func TestNativeBuildPublishesSplitOutputsAndWarmResume(t *testing.T) {
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
			binding := map[string]any{"fixture": salt, "system": system}
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

			saved, e := loadPlatform(storage, cacheTestRepository, system, identity)
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
