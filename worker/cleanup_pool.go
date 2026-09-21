package worker

import (
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

var poolControlTagPattern = regexp.MustCompile(`^nixos-cache-pool-([1-9][0-9]*)-(?:bootstrap|[1-9][0-9]*-(?:x86_64-linux|aarch64-linux|aarch64-darwin)-(?:coordinator-0|(?:assignment|status)-[1-2]))$`)

type poolPackage struct {
	endpoint, id, name string
	versions           []Version
}

func poolPackageSource(value map[string]any) string {
	repository, _ := value["repository"].(map[string]any)
	return String(repository["full_name"])
}

func planPoolCleanup(api GitHubAPI, storage Storage, repository, versionEndpoint string, active map[string]bool, log io.Writer) (*poolPackage, error) {
	owner, name, err := RepositoryParts(repository)
	if err != nil {
		return nil, err
	}
	// The workflow serializes builds. A known package also lets a later run find
	// cancelled runs' messages without organization-wide package-list access.
	ownerEndpoint, _, _ := strings.Cut(versionEndpoint, "/packages/")
	packageName := name + "-pool"
	endpoint := ownerEndpoint + "/packages/container/" + url.PathEscape(packageName)
	value, err := api(endpoint, "GET")
	if errors.Is(err, ErrObjectNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item, err := objectMap(value)
	if err != nil {
		return nil, err
	}
	if item["name"] != packageName || valueID(item["id"]) == "" || poolPackageSource(item) != "" || item["package_type"] != "container" {
		return nil, nil
	}
	versions, err := versionInventory(api, endpoint+"/versions")
	if err != nil {
		return nil, err
	}
	inspected, err := inspectVersions(storage, "ghcr.io/"+owner+"/"+packageName, repository, versions, log)
	if err != nil {
		return nil, err
	}
	owned := len(versions) > 0
	for i, version := range versions {
		record := inspected[i].record
		if !inspected[i].owned || record.Kind != "control" || active[record.Run] {
			owned = false
			continue
		}
		for _, tag := range Tags(version) {
			match := poolControlTagPattern.FindStringSubmatch(tag)
			if match == nil {
				owned = false
			} else if match[1] != record.Run {
				return nil, errors.New("cannot prune pool package: tag and metadata disagree")
			}
		}
	}
	if !owned {
		return nil, nil
	}
	return &poolPackage{endpoint: endpoint, id: valueID(item["id"]), name: packageName, versions: versions}, nil
}

func deletePoolPackage(api GitHubAPI, candidate poolPackage) error {
	value, err := api(candidate.endpoint, "GET")
	if err != nil {
		return err
	}
	current, err := objectMap(value)
	if err != nil {
		return err
	}
	if valueID(current["id"]) != candidate.id || current["name"] != candidate.name || current["package_type"] != "container" || poolPackageSource(current) != "" {
		return errors.New("pool package changed during retention")
	}
	versions, err := versionInventory(api, candidate.endpoint+"/versions")
	if err != nil {
		return err
	}
	if Fingerprint(versions) != Fingerprint(candidate.versions) {
		return errors.New("pool package inventory changed during retention")
	}
	_, err = api(candidate.endpoint, "DELETE")
	return err
}
