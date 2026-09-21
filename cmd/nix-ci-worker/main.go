package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/awked-com/nix-ci-worker/worker"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	syscall.Umask(0077)
	var err error
	switch {
	case len(os.Args) == 1:
		err = worker.RunWorker(os.Stdout)
	case len(os.Args) > 1 && os.Args[1] == "cache":
		err = cacheMain(os.Args[2:])
	default:
		err = errors.New("usage: nix-ci-worker [cache --config FILE --identity FILE --port PORT]")
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "CI worker failed.")
		os.Exit(1)
	}
}

func cacheMain(args []string) error {
	flags := flag.NewFlagSet("nix-ci-worker cache", flag.ContinueOnError)
	configPath := flags.String("config", "", "JSON configuration file")
	identity := flags.String("identity", "", "age identity file")
	port := flags.Int("port", 0, "IPv4 loopback port")
	if e := flags.Parse(args); e != nil {
		return e
	}

	if *configPath == "" || *identity == "" || *port < 1 || *port > 65535 || flags.NArg() != 0 {
		return errors.New("cache requires --config FILE --identity FILE --port PORT")
	}

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
