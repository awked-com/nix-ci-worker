package worker

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// versionRetirer handles artifacts whose ownership and lifecycle the caller
// already knows. Unlike admission recovery, it never scans unrelated manifests
// or workflow runs. GitHub requires a numeric version ID for deletion, so a
// package inventory lookup remains necessary to resolve each digest.
type versionRetirer struct {
	mu         sync.Mutex
	api        GitHubAPI
	storage    Storage
	repository string
	endpoint   string
}

func newVersionRetirer(api GitHubAPI, storage Storage, repository string) *versionRetirer {
	return &versionRetirer{api: api, storage: storage, repository: repository}
}

func (r *versionRetirer) legacySeeds() ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	versions, err := r.inventory()
	if err != nil {
		return nil, err
	}
	inspected, err := inspectVersions(r.storage, r.repository, versions, nil)
	if err != nil {
		return nil, err
	}
	seeds := []string{}
	for i, version := range versions {
		if inspected[i].owned && (inspected[i].record.Kind == "commit" || inspected[i].record.Kind == "stage") {
			seeds = append(seeds, version.Name)
		}
	}
	slices.Sort(seeds)
	return seeds, nil
}

func (r *versionRetirer) retire(digests ...string) error {
	return r.retireVersions(false, digests...)
}

func (r *versionRetirer) retireLegacy(digests ...string) error {
	return r.retireVersions(true, digests...)
}

func (r *versionRetirer) retireVersions(legacy bool, digests ...string) error {
	wanted := map[string]bool{}
	for _, digest := range digests {
		if !digestPattern.MatchString(digest) {
			return errors.New("invalid retirement digest")
		}
		if wanted[digest] {
			return errors.New("duplicate retirement digest")
		}
		wanted[digest] = true
	}
	if len(wanted) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	versions, err := r.inventory()
	if err != nil {
		return err
	}
	candidates := []Version{}
	for _, version := range versions {
		if wanted[version.Name] {
			candidates = append(candidates, version)
			delete(wanted, version.Name)
		}
	}
	for digest := range wanted {
		_, _, err := r.storage.GetManifest(r.repository, digest)
		if errors.Is(err, ErrObjectNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		return errors.New("retirement version is missing from package inventory")
	}
	inspection := candidates
	if legacy {
		inspection = versions
	}
	inspected, err := inspectVersions(r.storage, r.repository, inspection, nil)
	if err != nil {
		return err
	}
	records := map[string]inspectedVersion{}
	protected := map[string]bool{}
	roots := []string{}
	for i, version := range inspection {
		records[version.Name] = inspected[i]
		if legacy {
			for _, tag := range Tags(version) {
				if TagRun(tag) == "" {
					roots = append(roots, version.Name)
				}
			}
		}
	}
	for len(roots) > 0 {
		digest := roots[len(roots)-1]
		roots = roots[:len(roots)-1]
		if protected[digest] {
			continue
		}
		record, ok := records[digest]
		if !ok {
			return errors.New("pinned legacy parent is missing")
		}
		protected[digest] = true
		if record.owned && record.record.Parent != "" {
			roots = append(roots, record.record.Parent)
		}
	}
	retainedBlobs := map[string]bool{}
	if legacy {
		for system := range Systems {
			manifest, _, err := r.storage.GetManifest(r.repository, PlatformTag(system))
			if err != nil {
				return err
			}
			var record retentionRecord
			owned := manifest.Annotations["org.opencontainers.image.source"] == "https://github.com/"+strings.TrimPrefix(r.repository, "ghcr.io/")
			if !owned || json.Unmarshal([]byte(manifest.Annotations[retentionAnnotation]), &record) != nil || record.Kind != "live" || record.System != system || record.validate() != nil {
				return errors.New("legacy retirement requires every platform cache")
			}
			for _, layer := range manifest.Layers {
				retainedBlobs[layer.Digest] = true
			}
		}
	}
	remove := []Version{}
	for _, version := range candidates {
		inspected := records[version.Name]
		record := inspected.record
		allowed := record.Kind == "live" || record.Kind == "pool"
		if legacy {
			allowed = record.Kind == "commit" || record.Kind == "stage"
		}
		if !inspected.owned || !allowed {
			return errors.New("unexpected retirement artifact kind or owner")
		}
		pinned := protected[version.Name]
		for _, tag := range Tags(version) {
			if legacy {
				pinned = pinned || TagRun(tag) == ""
			} else if record.Kind == "live" || !strings.HasPrefix(tag, "nixos-cache-pool-") || TagRun(tag) != record.Run {
				pinned = true
			}
		}
		if pinned {
			continue
		}
		if legacy {
			manifest, _, err := r.storage.GetManifest(r.repository, version.Name)
			if err != nil {
				return err
			}
			for _, layer := range manifest.Layers {
				if layer.Annotations[CatalogTitle] != "files" && !retainedBlobs[layer.Digest] {
					return errors.New("legacy payload is not retained by a platform cache")
				}
			}
		}
		remove = append(remove, version)
	}
	for _, candidate := range remove {
		path := r.endpoint + "/" + strconv.FormatInt(candidate.ID, 10)
		value, err := r.api(path, "GET")
		if errors.Is(err, ErrObjectNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		current, err := decodeVersion(value)
		if err != nil {
			return err
		}
		if Fingerprint([]Version{current}) != Fingerprint([]Version{candidate}) {
			return errors.New("retirement candidate changed")
		}
		if _, err = r.api(path, "DELETE"); err != nil && !errors.Is(err, ErrObjectNotFound) {
			return err
		}
	}
	return nil
}

func (r *versionRetirer) inventory() ([]Version, error) {
	if r.endpoint == "" {
		endpoint, err := EndpointFor(r.api, r.repository)
		if err != nil {
			return nil, err
		}
		r.endpoint = endpoint
	}
	return versionInventory(r.api, r.endpoint)
}
