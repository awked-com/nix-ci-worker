package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/awked-com/nix-ci-worker/internal/ui"
	"github.com/awked-com/nix-ci-worker/worker"
)

func main() {
	err := run(os.Args[1:])
	// Operational failures can contain private build details or credentials.
	if err != nil && !errors.Is(err, flag.ErrHelp) && !ui.IsUsage(err) {
		err = errors.New("CI worker failed.")
	}
	os.Exit(ui.Report(err, 1))
}

func run(args []string) error {
	command := ui.New("nix-ci-worker", "Run the Actions worker protocol or serve an encrypted cache", "nix-ci-worker\n  nix-ci-worker cache --config FILE --identity FILE --port PORT", "  nix-ci-worker cache --config cache.json --identity /path/to/age-key --port 8080")
	if ui.IsHelp(args) {
		return command.Help(os.Stdout)
	}
	if len(args) > 0 && args[0] == "help" && len(args) == 2 && args[1] == "cache" {
		return cacheMain([]string{"--help"})
	}
	if len(args) > 0 && args[0] != "cache" {
		return command.Invalid("unknown command; expected cache or no arguments for the Actions protocol")
	}
	if len(args) == 0 {
		syscall.Umask(0077)
		return worker.RunWorker(os.Stdout)
	}
	return cacheMain(args[1:])
}

func cacheMain(args []string) error {
	command := ui.New("nix-ci-worker cache", "Serve an encrypted cache on IPv4 loopback until interrupted", "nix-ci-worker cache --config FILE --identity FILE --port PORT", "  nix-ci-worker cache --config cache.json --identity /path/to/age-key --port 8080")
	flags := command.Flags

	configPath := flags.String("config", "", "JSON configuration file")
	identity := flags.String("identity", "", "age identity file")
	port := flags.Int("port", 0, "IPv4 loopback port")
	if e := command.Parse(args); e != nil {
		return e
	}

	if *configPath == "" || *identity == "" || *port < 1 || *port > 65535 || flags.NArg() != 0 {
		return command.Invalid("cache requires --config FILE --identity FILE and --port between 1 and 65535")
	}
	syscall.Umask(0077)

	data, e := os.ReadFile(*configPath)
	if e != nil {
		return e
	}

	var config struct {
		Repository string `json:"repository"`
		Reference  string `json:"reference"`
	}
	if e = json.Unmarshal(data, &config); e != nil {
		return e
	}
	if _, _, e = worker.RepositoryParts(config.Repository); e != nil {
		return e
	}

	// Validate the initial identity before listening. The handler re-reads this
	// file before every catalog and NAR decryption.
	credential, e := worker.ReadCredentialFile(*identity)
	if e != nil {
		return e
	}
	if _, e = worker.IdentityRecipients(credential); e != nil {
		return e
	}

	storage := worker.NewRegistry(worker.Secret{})
	defer storage.Close()

	handler := worker.NewFileCacheHandler(storage, config.Repository, config.Reference, *identity, os.Stderr)
	server, _, e := worker.StartCacheServer(handler, *port)
	if e != nil {
		return e
	}
	defer server.Close()

	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)

	<-stopped
	return nil
}
