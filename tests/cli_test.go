package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandUX(t *testing.T) {
	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", bin+string(os.PathSeparator), "./cmd/...")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")
	name := "nix-ci-worker"
	binary := filepath.Join(bin, name)
	for _, args := range [][]string{{"--help"}, {"--unknown-option"}} {
		t.Run(name+" "+strings.Join(args, " "), func(t *testing.T) {
			cmd := exec.Command(binary, args...)
			cmd.Dir = t.TempDir()
			var out, diagnostic bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diagnostic
			err := cmd.Run()
			if args[0] == "--unknown-option" {
				status, ok := err.(*exec.ExitError)
				if !ok || status.ExitCode() != 2 || out.Len() != 0 || strings.Count(diagnostic.String(), "error:") != 1 {
					t.Fatalf("usage: %v, stdout=%q stderr=%q", err, &out, &diagnostic)
				}
			} else if err != nil || diagnostic.Len() != 0 || out.Len() == 0 {
				t.Fatalf("help: %v, stdout=%q stderr=%q", err, &out, &diagnostic)
			}
			if strings.Contains(out.String()+diagnostic.String(), "\x1b[") {
				t.Fatal("color escaped into redirected output")
			}
		})
	}
	t.Run(name+" terminal", func(t *testing.T) {
		script, err := exec.LookPath("script")
		if err != nil {
			t.Skip("script is unavailable for terminal checks")
		}
		for _, policy := range []struct {
			variable, value string
			color           bool
		}{{"NO_COLOR", "", true}, {"NO_COLOR", "1", false}, {"CLICOLOR", "0", false}, {"TERM", "dumb", false}} {
			t.Run(policy.variable+"="+policy.value, func(t *testing.T) {
				t.Setenv(policy.variable, policy.value)
				var cmd *exec.Cmd
				switch runtime.GOOS {
				case "darwin":
					cmd = exec.Command(script, "-q", "/dev/null", binary, "--help")
				case "linux":
					cmd = exec.Command(script, "-qec", "'"+strings.ReplaceAll(binary, "'", "'\"'\"'")+"' --help", "/dev/null")
				default:
					t.Skip("terminal harness supports Linux and macOS")
				}
				out, err := cmd.CombinedOutput()
				if err != nil || !bytes.Contains(out, []byte("Usage:")) || bytes.Contains(out, []byte("\x1b[")) != policy.color {
					t.Fatalf("terminal help: %v %q", err, out)
				}
			})
		}
	})
}

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
