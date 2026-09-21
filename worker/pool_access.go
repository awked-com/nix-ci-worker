package worker

import (
	"errors"
	"strings"
)

func preparePool(api GitHubAPI, storage Storage, repository, run string, recipients Secret, create bool) error {
	endpoint, err := EndpointFor(api, repository+"-pool")
	if err != nil {
		return err
	}
	endpoint = strings.TrimSuffix(endpoint, "/versions")
	value, err := api(endpoint, "GET")
	if errors.Is(err, ErrObjectNotFound) && create {
		// Bootstrap with no runner data: creation visibility depends on GHCR
		// credentials and settings, so verify it before writing coordination records.
		snapshot := NewSnapshot(storage, repository+"-pool")
		snapshot.Metadata = map[string]any{"kind": "control", "run": run}
		if _, err = snapshot.publish("nixos-cache-pool-"+run+"-bootstrap", recipients, repository); err != nil {
			return err
		}
		value, err = api(endpoint, "GET")
	}
	if err != nil {
		return err
	}
	item, err := objectMap(value)
	if err != nil {
		return err
	}
	if poolPackageSource(item) != "" {
		return errors.New("builder pool package must not inherit repository access")
	}
	if item["visibility"] != "private" {
		return errors.New("builder pool package must be private")
	}
	return nil
}

// Keep Actions and cache access on the workflow token; the PAT only manages
// the exact pool package and its versions.
func poolPackageAPI(actions, pool GitHubAPI, endpoint string) GitHubAPI {
	return func(path, method string) (any, error) {
		resource, _, _ := strings.Cut(path, "?")
		if resource == endpoint || strings.HasPrefix(resource, endpoint+"/") {
			return pool(path, method)
		}
		return actions(path, method)
	}
}
