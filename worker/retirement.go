package worker

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"sync"
	"time"
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

func (r *versionRetirer) retire(digests ...string) (err error) {
	started := time.Now()
	phase := "validating retirement request"
	defer func() {
		if err == nil || r.log == nil {
			return
		}
		fmt.Fprintf(r.log, "Retention failed while %s", phase)
		var status *githubStatusError
		if errors.As(err, &status) {
			fmt.Fprintf(r.log, ": %s", status)
		}
		fmt.Fprintln(r.log)
	}()
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
	var candidates []Version
	for attempt := range 3 {
		phase = "reading retirement inventory"
		versions, err := r.inventory(wanted)
		if err != nil {
			return err
		}
		remaining := maps.Clone(wanted)
		for _, version := range versions {
			delete(remaining, version.Name)
		}
		phase = "resolving missing retirement versions"
		for digest := range remaining {
			_, _, err := r.storage.GetManifest(r.repository, digest)
			if errors.Is(err, ErrObjectNotFound) {
				delete(remaining, digest)
				delete(wanted, digest)
				continue
			}
			if err != nil {
				return err
			}
		}
		if len(remaining) == 0 {
			candidates = versions
			break
		}
		if attempt == 2 {
			return errors.New("retirement version is missing from package inventory")
		}
		// Offset pagination can skip a version when another runner deletes an
		// earlier row. Retry a fresh inventory only for artifacts still present.
		time.Sleep(time.Duration(attempt+1) * 250 * time.Millisecond)
	}
	phase = "validating retirement manifests"
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
	deleted := 0
	for _, candidate := range remove {
		phase = "rechecking retirement candidate"
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
		phase = "deleting retirement version"
		removed, err := deleteVersion(r.api, path, r.log)
		if err != nil && !errors.Is(err, ErrObjectNotFound) {
			return err
		}
		if removed {
			deleted++
		}
	}
	if r.log != nil {
		fmt.Fprintf(r.log, "Retention: retired %d/%d requested versions (%.1fs)\n", deleted, len(digests), time.Since(started).Seconds())
	}
	return nil
}

func (r *versionRetirer) inventory(wanted map[string]bool) ([]Version, error) {
	if r.endpoint == "" {
		endpoint, err := EndpointFor(r.api, r.repository)
		if err != nil {
			return nil, err
		}
		r.endpoint = endpoint
	}
	// Retirement knows exact digests and rechecks every matched version before
	// deletion. Once they are found, older inventory pages cannot affect the
	// decision; download-protected history need not delay each publication.
	remaining := maps.Clone(wanted)
	versions := []Version{}
	seen := map[int64]string{}
	for page := 1; ; page++ {
		value, err := r.api(fmt.Sprintf("%s?per_page=100&page=%d", r.endpoint, page), "GET")
		if page == 1 && errors.Is(err, ErrObjectNotFound) {
			return versions, nil
		}
		if err != nil {
			return nil, err
		}
		batch, err := objectList(value)
		if err != nil {
			return nil, err
		}
		progress := false
		for _, value := range batch {
			version, err := decodeVersion(value)
			if err != nil {
				return nil, err
			}
			if digest, exists := seen[version.ID]; exists {
				if digest != version.Name {
					return nil, errors.New("package version ID changed digest")
				}
				continue
			}
			seen[version.ID], progress = version.Name, true
			if remaining[version.Name] {
				versions = append(versions, version)
				delete(remaining, version.Name)
			}
		}
		if !progress && len(batch) > 0 {
			return nil, errors.New("package inventory repeated a page without progress")
		}
		if len(remaining) == 0 || len(batch) < 100 {
			return versions, nil
		}
	}
}
