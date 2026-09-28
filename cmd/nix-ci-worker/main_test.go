package main

import (
	"errors"
	"flag"
	"testing"

	"github.com/awked-com/nix-ci-worker/internal/ui"
)

func TestCacheHelpAndValidation(t *testing.T) {
	for _, args := range [][]string{{"cache", "--help"}, {"help", "cache"}} {
		if err := run(args); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("help started cache: %v", err)
		}
	}
	for _, args := range [][]string{{"cache"}, {"cache", "--config", "missing", "--identity", "missing", "--port", "65536"}} {
		if err := run(args); !ui.IsUsage(err) {
			t.Fatalf("invalid parameters loaded configuration: %v", err)
		}
	}
}
