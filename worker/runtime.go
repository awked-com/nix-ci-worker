package worker

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
)

func runCommand(dir string, log io.Writer, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = BuildEnvironment()
	cmd.Stderr = log
	return cmd.Output()
}

func NativeSystem() (string, error) {
	arch := map[string]string{
		"arm64": "aarch64",
		"amd64": "x86_64",
	}[runtime.GOARCH]
	s := arch + "-" + runtime.GOOS
	if arch == "" || (runtime.GOOS != "linux" && s != "aarch64-darwin") {
		return "", errors.New("unsupported runtime system")
	}

	return s, nil
}

func takeEnv(name string) string {
	v := os.Getenv(name)
	os.Unsetenv(name)
	return v
}
