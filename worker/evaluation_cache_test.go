package worker

import (
	"io"
	"testing"
)

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
}

func TestEvaluationCacheRejectsCorruptionAndMissesChangedKeys(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	plan := &Plan{Targets: map[string]string{}, Derivations: map[string]Derivation{}}
	key := evaluationKey("commit", "nix-1", "x86_64-linux", nil)
	if err := saveEvaluation("x86_64-linux", key, plan, snapshot, recipients); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{
		evaluationKey("changed", "nix-1", "x86_64-linux", nil),
		evaluationKey("commit", "nix-2", "x86_64-linux", nil),
		evaluationKey("commit", "nix-1", "aarch64-linux", nil),
		evaluationKey("commit", "nix-1", "x86_64-linux", map[string]string{"host": "fixture"}),
	} {
		if got, err := loadEvaluation("", "x86_64-linux", changed, snapshot, identity, Secret{}, io.Discard); err != nil || got != nil {
			t.Fatal("changed inputs reused an evaluation", err)
		}
	}
	if _, err := loadEvaluation("", "x86_64-linux", key, snapshot, identity, Secret{}, io.Discard); err == nil {
		t.Fatal("invalid cached plan accepted")
	}
	descriptor := snapshot.Files[evaluationFile("x86_64-linux")]
	storage.objects[descriptor.Blob.Digest][0] ^= 1
	if _, err := loadEvaluation("", "x86_64-linux", key, snapshot, identity, Secret{}, io.Discard); err == nil {
		t.Fatal("corrupt encrypted plan accepted")
	}
}
