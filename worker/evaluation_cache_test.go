package worker

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluationKeyIncludesAllInputs(t *testing.T) {
	base := evaluationKey("commit", "nix-1", "aarch64-linux", nil)
	for _, key := range []string{
		evaluationKey("changed", "nix-1", "aarch64-linux", nil),
		evaluationKey("commit", "nix-2", "aarch64-linux", nil),
		evaluationKey("commit", "nix-1", "x86_64-linux", nil),
		evaluationKey("commit", "nix-1", "aarch64-linux", map[string]string{"host": "fixture"}),
	} {
		if key == base {
			t.Fatal("evaluation inputs shared a key")
		}
	}
}

func TestEvaluationPlansReplaceOnlyTheirPlatform(t *testing.T) {
	_, recipients := cacheKeys(t)
	storage := newMemoryCache()
	parent := NewSnapshot(storage, cacheTestRepository)
	plan := &Plan{Targets: map[string]string{}, Derivations: map[string]Derivation{}, Required: map[string]bool{}, Outputs: map[string]map[string]string{}}
	for system := range Systems {
		if err := saveEvaluation(system, "first", plan, parent, recipients); err != nil {
			t.Fatal(err)
		}
	}
	other := parent.Files[evaluationFile("aarch64-linux")]
	old := parent.Files[evaluationFile("x86_64-linux")]
	delta := NewSnapshot(storage, cacheTestRepository)
	if err := saveEvaluation("x86_64-linux", "second", plan, delta, recipients); err != nil {
		t.Fatal(err)
	}
	if err := parent.Merge(delta); err != nil {
		t.Fatal(err)
	}
	if len(parent.Files) != len(Systems) || parent.Files[evaluationFile("x86_64-linux")].Digest == old.Digest || parent.Files[evaluationFile("aarch64-linux")].Digest != other.Digest {
		t.Fatal("plan replacement changed another platform or accumulated plans")
	}
	if err := parent.PreferUpstream(); err != nil {
		t.Fatal(err)
	}
	if len(parent.Files) != len(Systems) {
		t.Fatal("cache assembly discarded evaluation plans")
	}
}

func TestEvaluationCacheRejectsCorruptionAndMissesChangedKeys(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	plan := &Plan{Targets: map[string]string{}, Derivations: map[string]Derivation{}}
	if err := saveEvaluation("x86_64-linux", "original", plan, snapshot, recipients); err != nil {
		t.Fatal(err)
	}
	if got, err := loadEvaluation("", "x86_64-linux", "changed", snapshot, identity, Secret{}, io.Discard); err != nil || got != nil {
		t.Fatal("changed inputs reused an evaluation", err)
	}
	if _, err := loadEvaluation("", "x86_64-linux", "original", snapshot, identity, Secret{}, io.Discard); err == nil {
		t.Fatal("invalid cached plan accepted")
	}
	descriptor := snapshot.Files[evaluationFile("x86_64-linux")]
	storage.objects[descriptor.Blob.Digest][0] ^= 1
	if _, err := loadEvaluation("", "x86_64-linux", "original", snapshot, identity, Secret{}, io.Discard); err == nil {
		t.Fatal("corrupt encrypted plan accepted")
	}
}

func TestNativeEvaluationCacheRestoresAnEmptyStore(t *testing.T) {
	nativeEnabled(t)
	t.Setenv("GITHUB_ACTIONS", "")
	system, err := NativeSystem()
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	flake := fmt.Sprintf(`{ outputs = { self }: let
 system = %q;
 input = builtins.derivation {
 name = "evaluation-cache-dependency"; inherit system; builder = "/bin/sh";
 allowSubstitutes = false;
 input = builtins.toFile "evaluation-cache-input" %q;
 args = [ "-c" "read -r text < $input; echo $text > $out" ];
 };
 in { hydraJobs.${system}.fixture = builtins.derivation {
 name = "evaluation-cache-fixture"; inherit system input; builder = "/bin/sh";
 allowSubstitutes = false;
 args = [ "-c" "read -r text < $input; echo $text > $out" ];
 }; }; }`, system, source+"\n")
	if err = os.WriteFile(filepath.Join(source, "flake.nix"), []byte(flake), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "flake.nix"}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = source
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
	}
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	parent, delta := NewSnapshot(storage, cacheTestRepository), NewSnapshot(storage, cacheTestRepository)
	signing, err := exec.Command("nix", "--extra-experimental-features", "nix-command", "key", "generate-secret", "--key-name", "evaluation-fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	success, err := (nativeBuild{
		source: source, system: system, run: "90", attempt: 1,
		parent: parent, delta: delta, log: &log, upstream: knownUpstream{},
		secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
	}).execute()
	if err != nil || !success {
		t.Fatalf("initial build: %v %v\n%s", success, err, &log)
	}
	if !delta.HasFile(evaluationFile(system)) {
		t.Fatal("clean checkout did not save a plan")
	}
	parent, err = CacheUnion(parent, delta)
	if err != nil {
		t.Fatal(err)
	}
	store, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NIX_REMOTE", "local?root="+store)
	log.Reset()
	next := NewSnapshot(storage, cacheTestRepository)
	success, err = (nativeBuild{
		source: source, system: system, run: "91", attempt: 1,
		parent: parent, delta: next, log: &log, upstream: knownUpstream{},
		secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: Secret{Data: signing}},
	}).execute()
	if err != nil || !success {
		t.Fatalf("cached build: %v %v\n%s", success, err, &log)
	}
	if !strings.Contains(log.String(), "Evaluation cache: restored") || strings.Contains(log.String(), "Target evaluation finished") {
		t.Fatalf("cached build evaluated again:\n%s", &log)
	}
	if next.Files[evaluationFile(system)].Digest != delta.Files[evaluationFile(system)].Digest {
		t.Fatal("unchanged plan uploaded again")
	}
	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(source, io.Discard, args, capture, data)
	}
	if err = os.WriteFile(filepath.Join(source, "untracked"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := sourceEvaluationKey(source, system, nil, nix); err != nil || key != "" {
		t.Fatal("dirty source reused a commit key", err)
	}
	if err = os.WriteFile(filepath.Join(source, ".git", "info", "exclude"), []byte("untracked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := sourceEvaluationKey(source, system, nil, nix); err != nil || key != "" {
		t.Fatal("ignored source reused a commit key", err)
	}
}
