package worker

import (
	"errors"
	"io"
	"strconv"
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
	log        io.Writer
	endpoint   string
}

func newVersionRetirer(api GitHubAPI, storage Storage, repository string) *versionRetirer {
	return &versionRetirer{api: api, storage: storage, repository: repository}
}

func (r *versionRetirer) retire(digests ...string) error {
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
	inspected, err := inspectVersions(r.storage, r.repository, candidates, nil)
	if err != nil {
		return err
	}
	remove := []Version{}
	for i, version := range candidates {
		record := inspected[i].record
		if !inspected[i].owned {
			return errors.New("unexpected retirement artifact owner")
		}
		pinned := false
		for _, tag := range Tags(version) {
			generation, err := managedGenerationTag(tag, record)
			if err != nil {
				return err
			}
			if generation {
				continue
			}
			if record.Kind == "live" || TagRun(tag) != record.Run {
				pinned = true
			}
		}
		if !pinned {
			remove = append(remove, version)
		}
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
		if _, err = deleteVersion(r.api, path, r.log); err != nil && !errors.Is(err, ErrObjectNotFound) {
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
