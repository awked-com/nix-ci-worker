# Nix CI worker

Distributed Nix builds on GitHub Actions, with encrypted binary caches in GHCR.
The Go worker plans derivation builds, coordinates helper runners, checkpoints
progress, and publishes signed cache metadata. Consumers own their workflows,
source checkouts, credentials, and deployment tooling.

## Build and test

Use Go 1.25.8 or newer:

```sh
go build -o bin/nix-ci-worker ./cmd/nix-ci-worker
go test ./...
```

Native integration tests additionally need Git and a working local Nix daemon,
with `nix`, `nix-store`, and `nix-instantiate` on PATH:

```sh
INFRA_NATIVE_NIX_TESTS=1 go test ./worker -run '^TestNative' -count=1
```

The native tests create temporary Nix derivations and store paths. The test gate
keeps its original name for existing test runners. The planner requires Nix's
version 4 derivation JSON schema (`nix derivation show`), and cache queries use
`nix path-info --json-format 1`. Use a Nix release supporting both interfaces.

## Serve an encrypted cache

Create a JSON configuration with your GHCR package and cache reference:

```json
{
  "repository": "ghcr.io/example/build-cache",
  "reference": "nixos-cache-latest"
}
```

```sh
./bin/nix-ci-worker cache --config cache.json --identity /path/to/age-key --port 8080
```

The server listens on IPv4 loopback. Point a Nix substituter at
`http://127.0.0.1:8080` and configure the public signing key matching your cache.
The identity file is an age identity, reloaded for catalog and NAR decryption.
This command reads registry objects anonymously, so the package must allow
anonymous reads; payloads remain encrypted. SIGINT or SIGTERM stops the server.

## Run builds

Without arguments the executable runs the GitHub Actions worker protocol.
Install Nix on each runner. Full builds evaluate `hydraJobs.<system>` in the
source flake. Select host system derivations and required checks there; their
transitive dependencies determine which packages need building on each platform.
Optional host/package selection follows NixOS configuration attributes; see
[`SelectedTargets`](worker/planner.go). Supported systems and runner labels are
owned by [`Systems`](worker/planner.go).

The workflow supplies these environment variables:

| Variable | Meaning |
| --- | --- |
| `INPUT_MODE` | `admit`, `build` (coordinator), `builder` (helper), or `finalize` |
| `INPUT_REQUEST` | Request ID containing 32 lowercase hexadecimal characters |
| `INPUT_SOURCE` | Source ref used to bind the request |
| `INPUT_SOURCE_PATH` | Local source checkout; builds use the admitted commit |
| `INPUT_SYSTEM` | Native system for a coordinator or helper |
| `INPUT_HOST`, `INPUT_PACKAGE` | Optional host and dotted package selection |
| `INPUT_BUILDER` | Helper index, starting at 1 |
| `INPUT_PARENT`, `INPUT_ADMISSION_ATTEMPT` | Admission outputs passed to coordinators |
| `INPUT_MATRIX` | Admitted build matrix passed to finalization |
| `CI_STORAGE` | JSON object with a `repository` GHCR reference |
| `CI_IDENTITY` | Age identity bytes, not a filename |
| `CI_RECIPIENTS` | Newline-separated age recipients |
| `NIX_SIGNING_KEY` | Final cache signing key for coordinators |
| `REGISTRY_USER`, `REGISTRY_TOKEN` | Cache registry and GitHub Actions API credentials |
| `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RESULTS_URL` | Automatic Actions cache credentials, supplied by the JavaScript action launching the worker |
| `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_REPOSITORY` | Actions run identity |
| `GITHUB_OUTPUT` | Actions output file used by admission |

The storage owner/package must match `GITHUB_REPOSITORY`. Admission emits the
parent cache digest, attempt, coordinator matrix, helper matrix, and resolved
source revision. Retry jobs with those admitted inputs. Finalization expects
all admitted coordinators and performs retention before publication.

Coordinators and helpers exchange small encrypted, authenticated messages through
GitHub Actions cache v2. The workflow must launch the worker from a JavaScript
action so it inherits GitHub's short-lived runtime credentials; ordinary shell
steps do not receive them automatically. No pool account, PAT, repository writes,
or separately provisioned service is needed. Admission and finalization do not
use the coordination service.

Each mailbox update has an immutable, opaque key bound to the request, source
revision, run, attempt, platform, and runner. Prefix lookup selects the latest
entry; cached or stale reads never renew a lease. Missing or evicted records
expire through the existing lease handling, and failed helper work returns to
the coordinator. GitHub automatically evicts unused entries after seven days.
The final cache and encrypted helper build payloads remain in the main GHCR
package; no separate `-pool` package is created or accessed. Existing unused pool
packages and credentials are not required by this protocol.

Helpers must not receive the final cache signing key. Coordination records and
results are authenticated and bound to the request, revision, run, attempt, and
platform. Preserve those bindings when embedding the engine. The worker removes
credential environment variables before executing build subprocesses and keeps
private failure details out of its top-level error output.

## Use from Go

Import `github.com/awked-com/nix-ci-worker/worker`. Public entry points include
`Evaluate`, `RunWorker`, `NewRegistry`, `NewFileCacheHandler`, and
`StartCacheServer`. Run `go doc ./worker` for the exported API.
