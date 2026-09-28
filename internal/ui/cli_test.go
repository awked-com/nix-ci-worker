package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestHelpOutput(t *testing.T) {
	command := New("fixture", "Inspect a fixture", "fixture [flags]", "  fixture --config example.json")
	command.Flags.String("config", "default.json", "Configuration file")
	var out bytes.Buffer
	if err := command.Help(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fixture", "Usage:", "Flags:", "Examples:", "--config string", "default.json", "--help"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %q", want, &out)
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("redirected help contains color")
	}
	if err := command.Help(brokenWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost output failure: %v", err)
	}
}
