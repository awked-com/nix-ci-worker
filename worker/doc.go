// Package worker plans and executes distributed Nix builds, exchanges encrypted
// results through OCI registry storage, and serves signed Nix binary caches.
// RunWorker implements the GitHub Actions environment protocol; lower-level
// operations can be used independently by Go callers.
package worker
