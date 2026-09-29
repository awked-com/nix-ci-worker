package ui

import (
	"errors"
	"io"
	"testing"
)

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestHelpPropagatesOutputFailure(t *testing.T) {
	command := New("fixture", "Inspect a fixture", "fixture [flags]", "")
	if err := command.Help(brokenWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost output failure: %v", err)
	}
}
