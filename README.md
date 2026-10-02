# Nix CI worker

## Build and test

Use Go 1.25.8 or newer:

```sh
go build -o bin/nix-ci-worker ./cmd/nix-ci-worker
go test ./...
```

Native integration tests additionally need Linux, Git, and a working Nix daemon,
with `nix`, `nix-store`, and `nix-instantiate` on PATH:

```sh
INFRA_NATIVE_NIX_TESTS=1 go test ./worker -run '^TestNative' -count=1
```

Tests create temporary derivations and store paths. Nix must support version 4
derivation JSON (`nix derivation show`) and `nix path-info --json-format 1`.

## Serve an encrypted cache

Create `cache.json`:

```json
{
  "repository": "ghcr.io/example/build-cache",
  "reference": "nixos-cache-latest"
}
```

```sh
./bin/nix-ci-worker cache --config cache.json --identity /path/to/age-key --port 8080
```

Point a Nix substituter at `http://127.0.0.1:8080` with the cache’s public signing
key. The server listens on IPv4 loopback and reloads the age identity for each
decryption. The GHCR package must allow anonymous reads; payloads stay encrypted.
SIGINT or SIGTERM stops the server. Use `--help` for command syntax.

## Run builds

Use the [CI workflow](https://github.com/awked-com/infra-ci) with Nix installed on
each runner. It runs one coordinator and three helpers on each of x86_64-linux
and aarch64-linux. Full builds evaluate `hydraJobs.<system>`; put required systems
and checks there. Host/package selections follow NixOS configuration attributes.

The worker reads these environment variables:

| Variable | Meaning |
| --- | --- |
| `INPUT_MODE` | `admit`, `build` (coordinator), or `builder` (helper) |
| `INPUT_REQUEST` | Request ID containing 32 lowercase hexadecimal characters |
| `INPUT_SOURCE` | Source ref used to bind the request |
| `INPUT_SOURCE_PATH` | Local source checkout; builds use the admitted commit |
| `INPUT_SYSTEM` | Native system for a coordinator or helper |
| `INPUT_HOST`, `INPUT_PACKAGE` | Optional host and dotted package selection |
| `INPUT_BUILDER` | Helper index, starting at 1 |
| `CI_STORAGE` | JSON object with a `repository` GHCR reference |
| `CI_IDENTITY` | Age identity bytes, not a filename |
| `CI_RECIPIENTS` | Newline-separated age recipients |
| `NIX_SIGNING_KEY` | Final cache signing key for coordinators |
| `REGISTRY_USER`, `REGISTRY_TOKEN` | Cache registry credentials |
| `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RESULTS_URL` | Automatic Actions cache credentials, supplied by the JavaScript action launching the worker |
| `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_REPOSITORY` | Actions run identity |
| `GITHUB_OUTPUT` | Actions output file used by admission |

The storage owner/package must match `GITHUB_REPOSITORY`. Serialize builds for
that package and retry with the admitted matrices and source revision. Launch
through a JavaScript action to inherit GitHub’s job-scoped cache credentials.
Helpers must not receive the final signing key.

Each coordinator updates its cumulative platform cache every 30 seconds, with
forced publication at completion and before disk reclamation. Every generation
is tagged before advancing the head. Outputs, historical generations, results,
and helper snapshots are retained permanently; registry storage grows over time.
Publication needs no package Admin access.

Coordination messages are encrypted and bound to the request, revision, run,
attempt, platform, and runner. Missing or expired messages return work to the
coordinator. Terminal results include request counts and throttle wait time under
`coordination`. Build subprocesses receive no credential environment variables;
top-level errors suppress private failure details.
