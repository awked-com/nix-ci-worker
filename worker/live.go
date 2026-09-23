package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
)

// PlatformTag names the cumulative cache owned by one platform coordinator.
func PlatformTag(system string) string { return "nixos-cache-" + system }

var ErrResultBindingMismatch = errors.New("build result binding mismatch")

func loadPlatform(storage Storage, repository, system string, identity Secret) (*Snapshot, error) {
	if _, ok := Systems[system]; !ok {
		return nil, errors.New("unsupported cache platform")
	}
	snapshot, err := LoadSnapshot(storage, repository, PlatformTag(system), identity)
	if errors.Is(err, ErrObjectNotFound) {
		// The old aggregate remains the migration base until each platform has
		// published a cumulative head containing all of its inherited outputs.
		snapshot, err = LoadSnapshot(storage, repository, "nixos-cache-latest", identity)
		if errors.Is(err, ErrObjectNotFound) {
			return NewSnapshot(storage, repository), nil
		}
	}
	if err == nil {
		err = snapshot.RequireClosed()
	}
	return snapshot, err
}

// LoadParent reads the cumulative union, including an existing pre-migration cache.
func LoadParent(storage Storage, repository string, identity Secret) (*Snapshot, error) {
	result := NewSnapshot(storage, repository)
	for _, reference := range append([]string{"nixos-cache-latest"}, platformTags()...) {
		snapshot, err := LoadSnapshot(storage, repository, reference, identity)
		if errors.Is(err, ErrObjectNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err = result.Merge(snapshot); err != nil {
			return nil, err
		}
	}
	return result, result.RequireClosed()
}

func platformTags() []string {
	tags := make([]string, 0, len(Systems))
	for _, system := range sortedKeys(Systems) {
		tags = append(tags, PlatformTag(system))
	}
	return tags
}

func resultFile(run, system string, attempt int) (string, error) {
	if !validRetentionRun(run) || attempt < 1 {
		return "", errors.New("invalid build result identity")
	}
	if _, ok := Systems[system]; !ok {
		return "", errors.New("unsupported cache platform")
	}
	return fmt.Sprintf("cache/results/%s/%d/%s.json", run, attempt, system), nil
}

// LoadResult reads an encrypted run result without retaining a manifest per run.
// Existing result tags remain readable during the catalog migration.
func LoadResult(storage Storage, repository, run, system string, attempt int, identity Secret) (*Snapshot, error) {
	name, err := resultFile(run, system, attempt)
	if err != nil {
		return nil, err
	}
	snapshot, err := LoadSnapshot(storage, repository, PlatformTag(system), identity)
	if err == nil && snapshot.HasFile(name) {
		reader, err := snapshot.Read(name, identity)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		raw, err := readLimited(reader, CatalogLimit)
		if err != nil {
			return nil, err
		}
		result := NewSnapshot(storage, repository)
		if err = json.Unmarshal(raw, &result.Metadata); err != nil {
			return nil, err
		}
		if err = validateResult(result.Metadata, run, system, attempt); err != nil {
			return nil, err
		}
		return result, nil
	}
	if err != nil && !errors.Is(err, ErrObjectNotFound) {
		return nil, err
	}
	snapshot, err = LoadSnapshot(storage, repository, ResultTag(run, system, attempt), identity)
	if err == nil {
		err = validateResult(snapshot.Metadata, run, system, attempt)
	}
	return snapshot, err
}

func validateResult(metadata map[string]any, run, system string, attempt int) error {
	binding, ok := metadata["binding"].(map[string]any)
	if !ok || binding["system"] != system || metadata["kind"] != "stage" || metadata["terminal"] != true || String(metadata["run"]) != run || Int(metadata["attempt"]) != attempt {
		return ErrResultBindingMismatch
	}
	return nil
}

func storeResult(snapshot *Snapshot, metadata map[string]any, recipients Secret) error {
	binding, _ := metadata["binding"].(map[string]any)
	run, system, attempt := String(metadata["run"]), String(binding["system"]), Int(metadata["attempt"])
	if err := validateResult(metadata, run, system, attempt); err != nil {
		return err
	}
	name, err := resultFile(run, system, attempt)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	stream, err := EncryptedStream(bytes.NewReader(raw), recipients)
	if err != nil {
		return err
	}
	blob, err := snapshot.Storage.UploadBlob(snapshot.Repository, stream, true)
	stream.Close()
	if err != nil {
		return err
	}
	snapshot.Files[name] = wholeFile(blob)
	return nil
}

func migrateLegacy(storage Storage, repository, run string, attempt int, identity, recipients Secret, retirer *versionRetirer, log io.Writer) error {
	seeds, err := retirer.legacySeeds()
	if err != nil || len(seeds) == 0 {
		return err
	}
	missing := []string{}
	for _, system := range sortedKeys(Systems) {
		if _, err := storage.ManifestDigest(repository, PlatformTag(system)); errors.Is(err, ErrObjectNotFound) {
			missing = append(missing, system)
		} else if err != nil {
			return err
		}
	}
	if len(missing) == 0 {
		// Also finishes cleanup if a previous admission stopped after publishing
		// its final head. Retirement independently checks blob reachability.
		return retirer.retireLegacy(seeds...)
	}
	base := NewSnapshot(storage, repository)
	for _, digest := range seeds {
		seed, err := LoadSnapshot(storage, repository, digest, identity)
		if err != nil {
			return err
		}
		for name, file := range base.Files {
			if next, ok := seed.Files[name]; ok && strings.HasPrefix(name, "cache/plan/") && next.Blob.Digest != file.Blob.Digest {
				base.Files["cache/retained/"+file.Blob.Digest] = file
			}
		}
		if err = base.Merge(seed); err != nil {
			return err
		}
		// Preserve non-cache artifacts too: an old version can only disappear
		// after every one of its payload blobs has another durable reference.
		for name, file := range seed.Files {
			if existing, ok := base.Files[name]; ok && existing.Blob.Digest != file.Blob.Digest {
				base.Files["cache/retained/"+file.Blob.Digest] = file
				continue
			}
			base.Files[name] = file
		}
		if seed.Metadata["kind"] == "stage" && seed.Metadata["terminal"] == true {
			if err = storeResult(base, seed.Metadata, recipients); err != nil {
				return err
			}
		}
	}
	if err := base.RequireClosed(); err != nil {
		return err
	}
	for _, system := range missing {
		base.Metadata = map[string]any{"kind": "live", "system": system, "run": run, "attempt": attempt}
		if _, err := base.Publish(PlatformTag(system), recipients); err != nil {
			return err
		}
	}
	if log != nil {
		fmt.Fprintf(log, "Cache migration: initialized %d platform heads\n", len(missing))
	}
	return retirer.retireLegacy(seeds...)
}

type livePublisher struct {
	snapshot   *Snapshot
	system     string
	run        string
	attempt    int
	recipients Secret
	retire     func(...string) error
	log        io.Writer
	published  int
	failed     error
}

func (p *livePublisher) publish(delta *Snapshot, terminal bool) error {
	if p.failed != nil {
		return p.failed
	}
	p.failed = p.update(delta, terminal)
	return p.failed
}

func (p *livePublisher) update(delta *Snapshot, terminal bool) error {
	if _, ok := Systems[p.system]; !ok || !validRetentionRun(p.run) || p.attempt < 1 {
		return errors.New("invalid cache publication identity")
	}
	if err := p.snapshot.Merge(delta); err != nil {
		return err
	}
	if err := p.snapshot.RequireClosed(); err != nil {
		return err
	}
	if terminal {
		if err := validateResult(delta.Metadata, p.run, p.system, p.attempt); err != nil {
			return err
		}
		if err := storeResult(p.snapshot, delta.Metadata, p.recipients); err != nil {
			return err
		}
	}
	p.snapshot.Metadata = maps.Clone(delta.Metadata)
	p.snapshot.Metadata["kind"] = "live"
	p.snapshot.Metadata["system"] = p.system
	delete(p.snapshot.Metadata, "parent")
	previous := p.snapshot.Digest
	if _, err := p.snapshot.Publish(PlatformTag(p.system), p.recipients); err != nil {
		return err
	}
	p.published++
	if p.log != nil {
		fmt.Fprintf(p.log, "Cache published: %s (%d cached paths)\n", p.system, len(p.snapshot.Narinfos))
	}
	if p.retire != nil && previous != "" && previous != p.snapshot.Digest {
		return p.retire(previous)
	}
	return nil
}
