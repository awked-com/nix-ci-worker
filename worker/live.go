package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
)

// PlatformTag names the cumulative cache owned by one platform coordinator.
func PlatformTag(system string) string { return "nixos-cache-" + system }

// Live generations remain identifiable if GitHub refuses their deletion.
func generationTag(system, run string, attempt, publication int) string {
	return fmt.Sprintf("%s-run-%s-attempt-%d-publication-%d", PlatformTag(system), run, attempt, publication)
}

var ErrResultBindingMismatch = errors.New("build result binding mismatch")

func loadPlatform(storage Storage, repository, system string, identity Secret) (*Snapshot, error) {
	if _, ok := Systems[system]; !ok {
		return nil, errors.New("unsupported cache platform")
	}
	snapshot, err := LoadSnapshot(storage, repository, PlatformTag(system), identity)
	if errors.Is(err, ErrObjectNotFound) {
		return NewSnapshot(storage, repository), nil
	}
	if err == nil {
		err = snapshot.RequireClosed()
	}
	return snapshot, err
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
func LoadResult(storage Storage, repository, run, system string, attempt int, identity Secret) (*Snapshot, error) {
	name, err := resultFile(run, system, attempt)
	if err != nil {
		return nil, err
	}
	snapshot, err := LoadSnapshot(storage, repository, PlatformTag(system), identity)
	if err != nil {
		return nil, err
	}
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
	p.snapshot.Metadata["run"] = p.run
	p.snapshot.Metadata["attempt"] = p.attempt
	p.snapshot.Metadata["publication"] = p.published + 1
	previous := p.snapshot.Digest
	if _, err := p.snapshot.Publish(generationTag(p.system, p.run, p.attempt, p.published+1), p.recipients); err != nil {
		return err
	}
	// Both tags must address the same manifest. Publishing the historical tag
	// first ensures a failed head update leaves an identifiable orphan.
	digest, err := p.snapshot.Storage.PutManifest(p.snapshot.Repository, PlatformTag(p.system), p.snapshot.Manifest)
	if err != nil {
		return err
	}
	if digest != p.snapshot.Digest {
		return errors.New("platform tag manifest digest mismatch")
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
