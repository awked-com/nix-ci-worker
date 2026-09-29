package cli_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWorkerSuppressesPrivateErrors(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "nix-ci-worker")
	build := exec.Command("go", "build", "-o", binary, "./cmd/nix-ci-worker")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(binary, "cache", "--config", filepath.Join(t.TempDir(), "private-sentinel.json"), "--identity", "private-identity", "--port", "8080")
	var out, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	status, ok := err.(*exec.ExitError)
	if !ok || status.ExitCode() != 1 || out.Len() != 0 || diagnostic.String() != "error: CI worker failed.\n" {
		t.Fatalf("private failure escaped: %v stdout=%q stderr=%q", err, &out, &diagnostic)
	}
}
