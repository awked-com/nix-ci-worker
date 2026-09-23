package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const retentionAnnotation = "com.awked.infra-ci.retention.v1"
const retentionReaders = 8

// These fields are already public run IDs or opaque registry digests. Keep
// source selections, store paths, commands, and credentials in the catalog.
type retentionRecord struct {
	Kind   string `json:"kind"`
	Run    string `json:"run"`
	Parent string `json:"parent,omitempty"`
	System string `json:"system,omitempty"`
}

func snapshotRetention(metadata map[string]any) retentionRecord {
	record := retentionRecord{Kind: String(metadata["kind"]), Run: valueID(metadata["run"])}
	if record.Kind == "stage" {
		record.Parent = String(metadata["parent"])
	}
	if record.Kind == "live" {
		record.System = String(metadata["system"])
	}
	return record
}

func validRetentionRun(id string) bool {
	number, err := strconv.ParseUint(id, 10, 64)
	return err == nil && number > 0
}

func (r retentionRecord) validate() error {
	if r.Kind != "commit" && r.Kind != "stage" && r.Kind != "pool" && r.Kind != "control" && r.Kind != "live" {
		return errors.New("invalid retention artifact kind")
	}
	if !validRetentionRun(r.Run) {
		return errors.New("missing or invalid retention run ID")
	}
	if r.Parent != "" && (r.Kind != "stage" || !digestPattern.MatchString(r.Parent)) {
		return errors.New("invalid retention parent digest")
	}
	if r.Kind == "live" {
		if _, ok := Systems[r.System]; !ok {
			return errors.New("invalid retention platform")
		}
	} else if r.System != "" {
		return errors.New("unexpected retention platform")
	}
	return nil
}

var runTagPattern = regexp.MustCompile(`^(?:nixos-cache-run-([0-9]+)-[1-9][0-9]*|nixos-cache-stage-([0-9]+)-[1-9][0-9]*-[1-4]-[a-f0-9]{32}|nixos-cache-result-([0-9]+)-[1-9][0-9]*-(?:x86_64-linux|aarch64-linux|aarch64-darwin)|nixos-cache-pool-([0-9]+)-[1-9][0-9]*-(?:x86_64-linux|aarch64-linux|aarch64-darwin)-(?:inputs-[0-2]|result-[1-2]))$`)

type GitHubAPI func(path, method string) (any, error)

type githubStatusError struct {
	method string
	status int
}

func (e *githubStatusError) Error() string {
	return fmt.Sprintf("GitHub %s failed (HTTP %d); check package admin permissions", e.method, e.status)
}

func NewGitHub(token string) GitHubAPI {
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(path, method string) (any, error) {
		if method == "" {
			method = "GET"
		}

		request, err := http.NewRequest(method, "https://api.github.com/"+strings.TrimPrefix(path, "/"), nil)
		if err != nil {
			return nil, err
		}

		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		request.Header.Set("User-Agent", "https://github.com/awked-com/nix-ci-worker")
		response, err := client.Do(request)
		if err != nil {
			return nil, errors.New("GitHub request transport failed")
		}
		defer response.Body.Close()

		body, err := readLimited(response.Body, metadataLimit)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == 404 {
			return nil, ErrObjectNotFound
		}

		expected := 200
		if method == "DELETE" {
			expected = 204
		}

		if response.StatusCode != expected {
			return nil, &githubStatusError{method: method, status: response.StatusCode}
		}
		if len(body) == 0 {
			return nil, nil
		}

		var result any
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.UseNumber()
		err = decoder.Decode(&result)
		return result, err
	}
}

func objectMap(value any) (map[string]any, error) {
	result, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("invalid GitHub object")
	}

	return result, nil
}

func valueID(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func objectList(value any) ([]map[string]any, error) {
	switch values := value.(type) {
	case []map[string]any:
		return values, nil
	case []any:
		result := make([]map[string]any, 0, len(values))
		for _, value := range values {
			item, err := objectMap(value)
			if err != nil {
				return nil, err
			}

			result = append(result, item)
		}

		return result, nil
	default:
		return nil, errors.New("invalid GitHub inventory")
	}
}

func Pages(api GitHubAPI, path, key string) ([]map[string]any, error) {
	values := []map[string]any{}
	seen := map[string]bool{}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	for page := 1; ; page++ {
		result, err := api(fmt.Sprintf("%s%sper_page=100&page=%d", path, separator, page), "GET")
		if err != nil {
			return nil, err
		}

		batchValue := result
		total := 0
		if key != "" {
			mapping, err := objectMap(result)
			if err != nil {
				return nil, err
			}

			total, err = strconv.Atoi(valueID(mapping["total_count"]))
			if err != nil {
				return nil, errors.New("missing Actions inventory total")
			}
			if total >= 1000 {
				return nil, errors.New("Actions inventory is incomplete")
			}

			batchValue = mapping[key]
		}

		batch, err := objectList(batchValue)
		if err != nil {
			return nil, err
		}

		for _, item := range batch {
			id := valueID(item["id"])
			if id == "" {
				return nil, errors.New("inventory item has no ID")
			}
			if seen[id] {
				return nil, errors.New("package inventory changed or repeated a page")
			}

			seen[id] = true
		}

		values = append(values, batch...)
		if len(batch) < 100 {
			if key != "" && len(values) != total {
				return nil, errors.New("package inventory changed during pagination")
			}

			return values, nil
		}
	}
}

type Version struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Metadata  struct {
		Container struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
}

func Tags(version Version) []string { return version.Metadata.Container.Tags }

func EndpointFor(api GitHubAPI, repository string) (string, error) {
	owner, packageName, err := RepositoryParts(repository)
	if err != nil {
		return "", err
	}

	value, err := api("users/"+owner, "GET")
	if err != nil {
		return "", err
	}

	mapping, err := objectMap(value)
	if err != nil {
		return "", err
	}

	prefix := "users"
	switch mapping["type"] {
	case "Organization":
		prefix = "orgs"
	case "User":
	default:
		return "", errors.New("unknown package owner type")
	}

	return prefix + "/" + owner + "/packages/container/" + url.PathEscape(packageName) + "/versions", nil
}

func decodeVersion(value any) (Version, error) {
	var version Version
	raw, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(raw, &version)
	}

	if err == nil && (version.ID == 0 || version.Name == "" || version.Metadata.Container.Tags == nil) {
		err = errors.New("invalid package version")
	}

	return version, err
}

func versionInventory(api GitHubAPI, endpoint string) ([]Version, error) {
	values, err := Pages(api, endpoint, "")
	if err != nil {
		return nil, err
	}

	versions := make([]Version, 0, len(values))
	for _, value := range values {
		version, err := decodeVersion(value)
		if err != nil {
			return nil, err
		}

		versions = append(versions, version)
	}

	return versions, nil
}

func Fingerprint(versions []Version) string {
	type mark struct {
		ID      int64
		Name    string
		Tags    []string
		Updated string
	}
	marks := make([]mark, 0, len(versions))
	for _, version := range versions {
		tags := append([]string{}, Tags(version)...)
		sort.Strings(tags)
		marks = append(marks, mark{version.ID, version.Name, tags, version.UpdatedAt})
	}

	sort.Slice(marks, func(i, j int) bool { return marks[i].ID < marks[j].ID })
	raw, _ := json.Marshal(marks)
	return string(raw)
}

func Inventory(api GitHubAPI, repository string) (string, []Version, error) {
	endpoint, err := EndpointFor(api, repository)
	if err != nil {
		return "", nil, err
	}

	versions, err := versionInventory(api, endpoint)
	if err != nil {
		return "", nil, err
	}

	again, err := versionInventory(api, endpoint)
	if err != nil {
		return "", nil, err
	}
	if Fingerprint(versions) != Fingerprint(again) {
		return "", nil, errors.New("package inventory changed; retry retention")
	}

	return endpoint, versions, nil
}

var activeStates = []string{"queued", "in_progress", "waiting", "pending", "requested"}

func TagRun(tag string) string {
	match := runTagPattern.FindStringSubmatch(tag)
	if match == nil {
		return ""
	}

	for _, part := range match[1:] {
		if part != "" {
			return part
		}
	}

	return ""
}

func latestDigest(storage Storage, repository string) (string, error) {
	digest, err := storage.ManifestDigest(repository, "nixos-cache-latest")
	if errors.Is(err, ErrObjectNotFound) {
		return "", nil
	}

	return digest, err
}

type inspectedVersion struct {
	record retentionRecord
	owned  bool
}

func inspectVersions(storage Storage, repository string, versions []Version, log io.Writer) ([]inspectedVersion, error) {
	// Only immutable manifests are read concurrently. Complete the entire plan
	// before deleting anything; do not turn a failed scan into partial cleanup.
	inspected := make([]inspectedVersion, len(versions))
	var next atomic.Int64
	var failed atomic.Bool
	var scanError error
	var readers sync.WaitGroup
	for range min(retentionReaders, len(versions)) {
		readers.Go(func() {
			for !failed.Load() {
				i := int(next.Add(1) - 1)
				if i >= len(versions) {
					return
				}
				version := versions[i]
				manifest, digest, err := storage.GetManifest(repository, version.Name)
				if err == nil && digest != version.Name {
					err = errors.New("retention manifest digest mismatch")
				}
				raw, marked := manifest.Annotations[retentionAnnotation]
				owned := marked && manifest.Annotations["org.opencontainers.image.source"] == "https://github.com/"+strings.TrimPrefix(repository, "ghcr.io/")
				var record retentionRecord
				if err == nil && owned {
					decoder := json.NewDecoder(strings.NewReader(raw))
					decoder.DisallowUnknownFields()
					err = decoder.Decode(&record)
					if err == nil && decoder.Decode(new(any)) != io.EOF {
						err = errors.New("invalid retention annotation")
					}
					if err == nil {
						err = record.validate()
					}
				}
				if err != nil {
					if failed.CompareAndSwap(false, true) {
						scanError = err
					}
					return
				}
				inspected[i] = inspectedVersion{record, owned}
			}
		})
	}
	readers.Wait()
	if scanError != nil {
		return nil, scanError
	}
	if log != nil {
		fmt.Fprintf(log, "Retention: inspected %d manifests in %s\n", len(versions), repository)
	}

	return inspected, nil
}

type retentionPlan struct {
	endpoint, latest string
	versions         []Version
}

func PlanCleanup(api GitHubAPI, storage Storage, repository, completedRun string, log io.Writer) (*retentionPlan, error) {
	endpoint, versions, err := Inventory(api, repository)
	if err != nil {
		return nil, err
	}

	byDigest := map[string]Version{}
	for _, version := range versions {
		byDigest[version.Name] = version
	}

	if len(byDigest) != len(versions) {
		return nil, errors.New("duplicate version digests")
	}

	latest, err := latestDigest(storage, repository)
	if err != nil {
		return nil, err
	}
	if latest != "" && !slices.Contains(Tags(byDigest[latest]), "nixos-cache-latest") {
		return nil, errors.New("package inventory does not match latest")
	}

	repo := strings.TrimPrefix(repository, "ghcr.io/")
	workflow := "repos/" + repo + "/actions/workflows/build.yml/runs"
	if completedRun != "" && !validRetentionRun(completedRun) {
		return nil, errors.New("cannot prune artifacts: invalid completed run ID")
	}
	activeRuns := map[string]bool{}
	for _, state := range activeStates {
		active, err := Pages(api, workflow+"?status="+state, "workflow_runs")
		if err != nil {
			return nil, err
		}
		for _, run := range active {
			id := valueID(run["id"])
			if !validRetentionRun(id) {
				return nil, errors.New("cannot prune artifacts: a run has an invalid ID")
			}
			activeRuns[id] = true
		}
	}
	if completedRun != "" {
		delete(activeRuns, completedRun)
	}

	inspected, err := inspectVersions(storage, repository, versions, log)
	if err != nil {
		return nil, err
	}

	protected := map[string]bool{}
	parents := map[string]string{}
	roots := []string{}
	for i, version := range versions {
		if !inspected[i].owned {
			protected[version.Name] = true
			continue
		}
		record := inspected[i].record
		parents[version.Name] = record.Parent
		run := record.Run
		pool := record.Kind == "pool"
		// Legacy snapshots are migration inputs, including outputs from failed
		// runs. Only the explicit migration path may retire them after all
		// platform heads durably retain their payloads.
		retain := version.Name == latest || record.Kind == "commit" || record.Kind == "stage"
		for _, tag := range Tags(version) {
			for system := range Systems {
				if tag == PlatformTag(system) && (record.Kind != "live" || record.System != system) {
					return nil, errors.New("platform tag and retention metadata disagree")
				}
			}
			tagRun := TagRun(tag)
			if tag != "nixos-cache-latest" && tagRun == "" {
				retain = true
			}
			if strings.HasPrefix(tag, "nixos-cache-pool-") && tagRun != "" {
				if !pool || tagRun != run {
					return nil, errors.New("cannot prune pool records: tag and metadata disagree")
				}
			} else if activeRuns[tagRun] {
				retain = true
			}
		}
		// Untagged platform generations are cumulative and may be retired even
		// while their publisher is active. Other active artifacts can still have
		// readers holding immutable manifest digests.
		if record.Kind != "live" {
			retain = retain || activeRuns[run]
		}
		if retain {
			protected[version.Name] = true
			roots = append(roots, version.Name)
		}
	}

	// Untagged retained checkpoints need the same parent protection as tagged
	// ones: assignments and recovery can refer to immutable digests directly.
	visited := map[string]bool{}
	for len(roots) > 0 {
		digest := roots[len(roots)-1]
		roots = roots[:len(roots)-1]
		if visited[digest] {
			continue
		}
		visited[digest] = true
		if parent := parents[digest]; parent != "" {
			if _, ok := byDigest[parent]; !ok {
				return nil, errors.New("retained checkpoint parent is missing")
			}
			protected[parent] = true
			roots = append(roots, parent)
		}
	}

	candidates := []Version{}
	for _, version := range versions {
		if !protected[version.Name] {
			candidates = append(candidates, version)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].UpdatedAt == candidates[j].UpdatedAt {
			return candidates[i].ID < candidates[j].ID
		}

		return candidates[i].UpdatedAt < candidates[j].UpdatedAt
	})
	return &retentionPlan{endpoint: endpoint, latest: latest, versions: candidates}, nil
}

func Prune(api GitHubAPI, storage Storage, repository, completedRun string, log io.Writer) (deleted int, err error) {
	started := time.Now()
	phase := "planning cleanup"
	defer func() {
		if err == nil || log == nil {
			return
		}
		// Arbitrary errors can contain credentials or private catalog data. Only
		// expose the operation and the structured HTTP status in public CI logs.
		fmt.Fprintf(log, "Retention failed while %s", phase)
		var status *githubStatusError
		if errors.As(err, &status) {
			fmt.Fprintf(log, ": %s", status)
		}
		fmt.Fprintln(log)
	}()
	plan, err := PlanCleanup(api, storage, repository, completedRun, log)
	if err != nil {
		return 0, err
	}
	if log != nil {
		fmt.Fprintf(log, "Retention: planned %d version deletions (%.1fs)\n", len(plan.versions), time.Since(started).Seconds())
	}
	deletionStarted := time.Now()

	phase = "deleting cache versions"
	for _, candidate := range plan.versions {
		// Overlap independent read checks, but keep deletes serial and wait for
		// both checks before each mutation. No later candidate is prefetched.
		var currentLatest string
		var latestError error
		checked := make(chan struct{})
		go func() {
			defer close(checked)
			currentLatest, latestError = latestDigest(storage, repository)
		}()
		path := plan.endpoint + "/" + strconv.FormatInt(candidate.ID, 10)
		value, err := api(path, "GET")
		<-checked
		if latestError != nil {
			return deleted, latestError
		}
		if currentLatest != plan.latest {
			return deleted, errors.New("latest cache changed during retention")
		}
		if err != nil {
			return deleted, err
		}

		current, err := decodeVersion(value)
		if err != nil {
			return deleted, err
		}
		if Fingerprint([]Version{current}) != Fingerprint([]Version{candidate}) {
			return deleted, errors.New("candidate changed during retention")
		}

		if _, err = api(path, "DELETE"); err != nil {
			return deleted, err
		}

		deleted++
	}

	if log != nil {
		fmt.Fprintf(log, "Retention: deleted %d versions (%.1fs; total %.1fs)\n", deleted, time.Since(deletionStarted).Seconds(), time.Since(started).Seconds())
	}

	return deleted, nil
}
