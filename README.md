# Nix CI worker

## Build and test

Use Go 1.25.8 or newer:

```sh
go build -o bin/nix-ci-worker ./cmd/nix-ci-worker
go test ./...
```

Nix must support derivation JSON version 4 and `nix path-info --json-format 1`.

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

Point a Nix substituter at `http://127.0.0.1:8080` with the public signing key.
GHCR must allow anonymous reads; payloads stay encrypted. The server reloads the
age identity for each decryption.

## Run builds

Use the [CI workflow](https://github.com/awked-com/infra-ci) with Nix on each
runner. Full builds evaluate `hydraJobs.<system>`; put required systems and checks
there. Host/package selections follow NixOS configuration attributes.

The storage owner/package must match `GITHUB_REPOSITORY`. Serialize builds for
that package and retry with the admitted matrices and source revision. Launch
through a JavaScript action to inherit GitHub’s job-scoped cache credentials.
Helpers must not receive the final signing key.

Coordinators publish every 30 seconds, at completion, and before reclaiming disk.
Outputs, generations, results, and helper snapshots are retained permanently;
registry storage grows over time. Publication needs no package Admin access.

Missing or expired coordination messages return work to the coordinator.
Build subprocesses receive no credential environment variables; top-level errors
suppress private failure details.
