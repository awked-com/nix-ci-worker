package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const DiskReserve = 8 * 1024 * 1024 * 1024
const DiskStop = 4 * 1024 * 1024 * 1024
const publicationInterval = 30 * time.Second

func BuildEnvironment() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "RUNNER_TRACKING_ID" || key == "NIX_SIGNING_KEY" {
			continue
		}

		private := false
		for _, prefix := range []string{"INPUT_", "CI_", "REGISTRY_", "ACTIONS_", "GITHUB_"} {
			private = private || strings.HasPrefix(key, prefix)
		}

		if !private {
			env = append(env, entry)
		}
	}

	return env
}

func NixRun(source string, log io.Writer, args []string, capture bool, data []byte) ([]byte, error) {
	cmd := exec.Command("nix", append([]string{"--extra-experimental-features", "nix-command flakes"}, args...)...)
	cmd.Dir = source
	cmd.Env = BuildEnvironment()
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = log
	if capture {
		return cmd.Output()
	}

	cmd.Stdout = log
	return nil, cmd.Run()
}

func substituter(storage Storage, snapshot *Snapshot, identity, signingKey Secret, log io.Writer) (*CacheHandler, *http.Server, []string, error) {
	public, e := signingPublicKey(signingKey.Data)
	if e != nil {
		return nil, nil, nil, e
	}

	return publicSubstituter(storage, snapshot, identity, public, log)
}

func publicSubstituter(storage Storage, snapshot *Snapshot, identity Secret, public string, log io.Writer) (*CacheHandler, *http.Server, []string, error) {
	handler := NewCacheHandler(storage, "", "", identity, log)
	handler.SetSnapshot(snapshot)
	server, listener, e := StartCacheServer(handler, 0)
	if e != nil {
		return nil, nil, nil, e
	}

	options := []string{
		"--substituters", "http://" + listener.Addr().String() + "?priority=50 https://cache.nixos.org",
		"--trusted-public-keys", public + " cache.nixos.org-1:" + UpstreamPublicKey,
		"--require-sigs",
		"--option", "fallback", "false",
		"--option", "narinfo-cache-negative-ttl", "0",
	}
	return handler, server, options, nil
}

func diskFree(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if e := syscall.Statfs(path, &stat); e != nil {
		return 0, e
	}

	return stat.Bavail * uint64(stat.Bsize), nil
}

func dedicatedRunner() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted"
}

func BuildBinding(submitted BuildRequest, system string) map[string]any {
	return map[string]any{
		"request": submitted.ID,
		"source":  submitted.Source,
		"system":  system,
		"policy":  Policy,
	}
}

func CacheUnion(parent, delta *Snapshot) (*Snapshot, error) {
	result := NewSnapshot(parent.Storage, parent.Repository)
	if e := result.Merge(parent); e != nil {
		return nil, e
	}

	if e := result.Merge(delta); e != nil {
		return nil, e
	}

	if e := result.RequireClosed(); e != nil {
		return nil, e
	}

	return result, nil
}

func Reclaim(source string, log io.Writer, graph *Plan, durable *Snapshot, roots string) (uint64, error) {
	if !dedicatedRunner() {
		return 0, errors.New("disk reclamation requires a dedicated hosted runner")
	}

	local, e := PublicationRoots(source, log)
	if e != nil {
		return 0, e
	}

	protected := map[string]bool{}
	for p := range graph.Required {
		protected[p] = true
	}

	for _, outputs := range graph.Outputs {
		for _, p := range outputs {
			delete(protected, p)
		}
	}

	entries, e := os.ReadDir(roots)
	if e != nil {
		return 0, e
	}

	for _, entry := range entries {
		if e = os.Remove(filepath.Join(roots, entry.Name())); e != nil {
			return 0, e
		}
	}

	protect, disposable := []string{}, []string{}
	for _, p := range local {
		if protected[p] {
			if !strings.HasSuffix(p, ".drv") {
				protect = append(protect, p)
			}
		} else if durable.Contains(p) {
			disposable = append(disposable, p)
		}
	}

	for offset := 0; offset < len(protect); offset += 128 {
		args := append([]string{"--add-root", filepath.Join(roots, strconv.Itoa(offset)), "--indirect", "--realise"}, protect[offset:min(offset+128, len(protect))]...)
		if _, e = runCommand("", log, "nix-store", args...); e != nil {
			return 0, e
		}
	}

	for offset := 0; offset < len(disposable); offset += 128 {
		runCommand(
			"",
			log,
			"nix-store",
			append([]string{"--delete"}, disposable[offset:min(offset+128, len(disposable))]...)...,
		)
	}

	return diskFree("/nix/store")
}

func BuildCommand(system string, jobs, cores int, options []string) []string {
	sandbox := "true"
	if strings.HasSuffix(system, "-darwin") {
		sandbox = "relaxed"
	}

	return append([]string{
		"--extra-experimental-features", "nix-command flakes",
		"build",
		"--no-link",
		"--print-build-logs",
		"--keep-going",
		"--stdin",
		"--max-jobs", strconv.Itoa(jobs),
		"--cores", strconv.Itoa(cores),
		"--option", "max-substitution-jobs", "8",
		"--option", "min-free", "0",
		"--option", "sandbox", sandbox,
		"--option", "sandbox-fallback", "false",
	}, options...)
}

type DiskGuard struct {
	Paths       []string
	MinimumFree uint64
	Measure     func(string) (uint64, error)
}

func NewDiskGuard(source string) *DiskGuard {
	paths := []string{"/nix/store", source, os.TempDir()}
	for _, key := range []string{"RUNNER_TEMP", "GITHUB_WORKSPACE"} {
		if v := os.Getenv(key); v != "" {
			paths = append(paths, v)
		}
	}

	return &DiskGuard{paths, math.MaxUint64, diskFree}
}

func (g *DiskGuard) Sample() error {
	for _, p := range g.Paths {
		free, e := g.Measure(p)
		if e != nil {
			return e
		}

		g.MinimumFree = min(g.MinimumFree, free)
		if free < DiskStop {
			return errors.New("runner disk safety reserve reached; build cancelled to preserve diagnostics and published outputs")
		}
	}

	return nil
}

func (g *DiskGuard) Run(cmd *exec.Cmd) error {
	if e := cmd.Start(); e != nil {
		return e
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if e := g.Sample(); e != nil {
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
			}

			return e
		}

		select {
		case e := <-done:
			return e
		case <-ticker.C:
		}
	}
}

type buildSecrets struct {
	identity, recipients, signingKey Secret
}

type nativeBuild struct {
	source, system, run string
	attempt             int
	parent, delta       *Snapshot
	secrets             buildSecrets
	log                 io.Writer
	upstream            UpstreamCollector
	pool                *BuildPool
	live                *livePublisher
}

func (b *nativeBuild) publish(required map[string]bool) (int, error) {
	before := len(b.delta.Narinfos) + len(b.delta.Upstream)
	count, err := PublishStore(b.source, required, b.delta, b.parent, b.secrets.signingKey, b.secrets.recipients, b.log, b.upstream)
	if b.live != nil && ((b.live.published == 0 && len(b.delta.Narinfos)+len(b.delta.Upstream) > 0) || before != len(b.delta.Narinfos)+len(b.delta.Upstream)) {
		err = errors.Join(err, b.live.publish(b.delta, false))
	}
	return count, err
}

type buildLog struct {
	mu sync.Mutex
	io.Writer
}

func (l *buildLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Writer.Write(data)
}

type cachePublisher struct {
	updates chan map[string]bool
	stop    chan struct{}
	done    chan struct{}
	err     error
}

func startCachePublisher(required map[string]bool, interval time.Duration, publish func(map[string]bool) error) *cachePublisher {
	p := &cachePublisher{
		updates: make(chan map[string]bool, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	required = maps.Clone(required)
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			if p.err = publish(required); p.err != nil {
				return
			}
			timer := time.NewTimer(interval)
			select {
			case <-p.stop:
				timer.Stop()
				return
			case required = <-p.updates:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
	return p
}

func (p *cachePublisher) update(required map[string]bool) error {
	select {
	case <-p.done:
		return p.err
	default:
	}
	// Only the latest plan is needed; slow publication cannot queue more work.
	select {
	case <-p.updates:
	default:
	}
	p.updates <- maps.Clone(required)
	return nil
}

func (p *cachePublisher) close() error {
	close(p.stop)
	<-p.done
	return p.err
}

func (b nativeBuild) execute() (bool, error) {
	if b.upstream == nil {
		upstream := NewUpstream()
		defer upstream.Close()
		b.upstream = upstream
	}
	started := time.Now()
	if _, ok := b.log.(*buildLog); !ok {
		b.log = &buildLog{Writer: b.log}
	}
	source, system, parent, delta := b.source, b.system, b.parent, b.delta
	signingKey, recipients, log := b.secrets.signingKey, b.secrets.recipients, b.log
	upstream, pool := b.upstream, b.pool
	if b.live == nil {
		b.live = &livePublisher{system: system, run: b.run, attempt: b.attempt,
			recipients: recipients, log: log}
	}
	b.live.log = log
	// The publisher owns mutable cumulative state; the build and its substituter
	// retain their independent views while uploads run in the background.
	durable := NewSnapshot(parent.Storage, parent.Repository)
	if err := durable.Merge(parent); err != nil {
		return false, err
	}
	maps.Copy(durable.Files, parent.Files)
	durable.Digest = parent.Digest
	b.live.snapshot = durable
	fmt.Fprintf(log, "Build capacity: 1 build, %d CPUs\n", runtime.NumCPU())

	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(source, log, args, capture, data)
	}

	selection, e := buildSelection(delta.Metadata)
	if e != nil {
		return false, e
	}

	planKey, e := sourceEvaluationKey(source, system, selection, nix)
	if e != nil {
		return false, e
	}
	graph, e := loadEvaluation(source, system, planKey, parent, b.secrets.identity, signingKey, log)
	if e != nil {
		return false, e
	}
	planFile, reusedPlan := parent.Files[evaluationFile(system)], graph != nil
	if graph == nil {
		graph, e = Evaluate(source, system, nix, selection, log)
		if e != nil {
			return false, e
		}
	}

	fmt.Fprintf(log, "Evaluation finished (%.1fs)\n", time.Since(started).Seconds())
	if graph.Static() {
		parentIndex, err := newSnapshotIndex(parent)
		if err != nil {
			return false, err
		}
		parent = parentIndex.selectPaths(graph.Required)
		b.parent = parent
	}
	unknown := []string{}
	for p := range graph.Required {
		if !parent.Contains(p) && !delta.Contains(p) {
			unknown = append(unknown, p)
		}
	}

	lookupStarted := time.Now()
	found, e := upstream.Collect(unknown)
	if e != nil {
		return false, e
	}

	for p, refs := range found {
		delta.Upstream[p] = refs
	}

	fmt.Fprintf(log, "Upstream cache: checked %d paths (%.1fs)\n", len(unknown), time.Since(lookupStarted).Seconds())
	available, e := CacheUnion(parent, delta)
	if e != nil {
		return false, e
	}
	index, e := newSnapshotIndex(available)
	if e != nil {
		return false, e
	}

	uncachedOutputs := map[string]bool{}
	for _, outputs := range graph.Outputs {
		for _, path := range outputs {
			if path != "" && !available.Contains(path) {
				uncachedOutputs[path] = true
			}
		}
	}
	localPaths, e := localStorePaths(source, log, sortedKeys(uncachedOutputs))
	if e != nil {
		return false, e
	}
	local := map[string]bool{}
	for _, p := range localPaths {
		local[p] = true
	}

	missing := graph.Missing(available, local)

	fmt.Fprintf(
		log,
		"Build plan: %d targets, %d derivations, %d paths, %d output groups to build\n",
		len(graph.Targets),
		len(graph.Derivations),
		len(graph.Required),
		len(missing),
	)
	initialFiles := map[string]bool{}
	for n := range delta.Files {
		initialFiles[n] = true
	}

	minimumFree, e := diskFree("/nix/store")
	if e != nil {
		return false, e
	}

	var failure error
	exitCode := 0
	var publication *cachePublisher
	waitPublication := func() error {
		if publication == nil {
			return nil
		}
		err := publication.close()
		publication = nil
		return err
	}

	build := func() error {
		roots, e := os.MkdirTemp("", "cache-roots-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(roots)

		handler, server, options, e := substituter(parent.Storage, available, b.secrets.identity, signingKey, log)
		if e != nil {
			return e
		}
		defer server.Close()

		batches, e := graph.Batches(missing, 32)
		if e != nil {
			return e
		}

		publish := func(required map[string]bool) error {
			covered := len(delta.Narinfos) + len(delta.Upstream)
			if _, err := b.publish(required); err != nil {
				return err
			}
			if covered == len(delta.Narinfos)+len(delta.Upstream) {
				return nil
			}
			view, err := index.extend(delta)
			if err == nil {
				handler.SetSnapshot(view)
			}
			return err
		}
		startPublication := func() error {
			if publication != nil {
				return publication.update(graph.Required)
			}
			// Only the publisher touches delta until waitPublication returns.
			publication = startCachePublisher(graph.Required, publicationInterval, publish)
			return nil
		}
		reclaimIfNeeded := func() error {
			free, err := diskFree("/nix/store")
			if err != nil {
				return err
			}
			minimumFree = min(minimumFree, free)
			if free >= DiskReserve {
				return nil
			}
			if err = waitPublication(); err != nil {
				return err
			}
			if _, err = b.publish(graph.Required); err != nil {
				return err
			}
			durable, err := CacheUnion(parent, delta)
			if err != nil {
				return err
			}
			handler.SetSnapshot(durable)
			free, err = Reclaim(source, log, graph, durable, roots)
			if err != nil {
				return err
			}
			if free < DiskReserve {
				return errors.New("pending build working set exceeds runner disk capacity")
			}
			return nil
		}

		if pool != nil {
			if graph.Static() {
				err := pool.build(source, system, graph, missing, delta, signingKey, recipients, log, options, func() (*snapshotIndex, error) {
					if err := publish(graph.Required); err != nil {
						return nil, err
					}
					if err := reclaimIfNeeded(); err != nil {
						return nil, err
					}
					return index, nil
				})
				if err == nil && len(handler.Errors()) > 0 {
					return errors.New("inherited cache read failed; refusing a cache fallback")
				}
				return err
			}
			fmt.Fprintln(log, "Building unresolved derivation plan on coordinator")
			pool.Drain()
		}

		for number, batch := range batches {
			if e = startPublication(); e != nil {
				return e
			}
			batchStarted := time.Now()
			fmt.Fprintf(log, "Build batch %d/%d: %d output groups\n", number+1, len(batches), len(batch))
			cmd := exec.Command("nix", BuildCommand(system, 1, runtime.NumCPU(), options)...)
			cmd.Dir = source
			cmd.Env = BuildEnvironment()
			cmd.Stdin = strings.NewReader(strings.Join(batch, "\n") + "\n")
			cmd.Stdout = log
			cmd.Stderr = log
			guard := NewDiskGuard(source)
			err := guard.Run(cmd)
			minimumFree = min(minimumFree, guard.MinimumFree)
			if err != nil {
				var code *exec.ExitError
				if errors.As(err, &code) {
					exitCode = code.ExitCode()
				} else {
					return err
				}
			}

			fmt.Fprintf(log, "Build batch %d/%d: exited with code %d (%.1fs)\n", number+1, len(batches), cmd.ProcessState.ExitCode(), time.Since(batchStarted).Seconds())
			if e = graph.Resolve(nix); e != nil {
				return e
			}
			if e = reclaimIfNeeded(); e != nil {
				return e
			}
		}

		if len(handler.Errors()) > 0 {
			return errors.New("inherited cache read failed; refusing a cache fallback")
		}

		return nil
	}

	failure = build()
	if pool != nil {
		pool.Drain()
	}
	if e = waitPublication(); failure == nil {
		failure = e
	}
	if e = graph.Resolve(nix); failure == nil {
		failure = e
	}

	if _, e = b.publish(graph.Required); failure == nil {
		failure = e
	}
	if reusedPlan {
		delta.Files[evaluationFile(system)] = planFile
	} else if e = saveEvaluation(system, planKey, graph, delta, recipients); failure == nil {
		failure = e
	}

	available, e = CacheUnion(parent, delta)
	if e != nil {
		return false, e
	}

	results := graph.Results(available, system)
	complete := failure == nil && exitCode == 0 && graph.Complete(available)
	for _, r := range results {
		complete = complete && r["status"] == "success"
	}

	status := "failure"
	if complete {
		status = "success"
	}

	newBytes := int64(0)
	for n, d := range delta.Files {
		if !initialFiles[n] {
			newBytes += d.Size
		}
	}

	for k, v := range map[string]any{
		"status":                status,
		"terminal":              true,
		"results":               results,
		"required_hash":         graph.Hash(),
		"seconds":               math.Round(time.Since(started).Seconds()*1000) / 1000,
		"targets":               len(graph.Targets),
		"required_paths":        len(graph.Required),
		"missing_output_groups": len(missing),
		"minimum_free_bytes":    minimumFree,
		"new_ciphertext_bytes":  newBytes,
	} {
		delta.Metadata[k] = v
	}

	if e = b.live.publish(delta, true); e != nil {
		return false, e
	}

	if failure != nil {
		fmt.Fprintf(log, "Build failed: %v\n", failure)
	}

	return complete, nil
}

func RunWorker(log io.Writer) error {
	log = &buildLog{Writer: log}
	request, sourceRevision := os.Getenv("INPUT_REQUEST"), os.Getenv("INPUT_SOURCE")
	mode, system := os.Getenv("INPUT_MODE"), os.Getenv("INPUT_SYSTEM")
	run := os.Getenv("GITHUB_RUN_ID")
	attempt, e := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	validMode := mode == "admit" || mode == "build" || mode == "builder"
	_, native := Systems[system]
	if e != nil || attempt < 1 || !validRetentionRun(run) || !validMode || ((mode == "build" || mode == "builder") && !native) {
		return errors.New("invalid worker inputs")
	}

	submitted, e := NewBuildRequest(request, sourceRevision, os.Getenv("INPUT_HOST"), os.Getenv("INPUT_PACKAGE"))
	if e != nil {
		return e
	}

	var config struct {
		Repository string `json:"repository"`
	}
	if e = json.Unmarshal([]byte(takeEnv("CI_STORAGE")), &config); e != nil {
		return e
	}

	identity := Secret{Data: []byte(takeEnv("CI_IDENTITY"))}
	recipientsText := takeEnv("CI_RECIPIENTS")
	signingKey := Secret{Data: []byte(takeEnv("NIX_SIGNING_KEY"))}
	token, user := takeEnv("REGISTRY_TOKEN"), takeEnv("REGISTRY_USER")
	runtimeToken := Secret{Data: []byte(takeEnv("ACTIONS_RUNTIME_TOKEN"))}
	resultsURL := takeEnv("ACTIONS_RESULTS_URL")
	storage := NewRegistry(RegistryCredential(user, token))
	defer storage.Close()

	repository := config.Repository
	if _, _, err := RepositoryParts(repository); err != nil {
		return err
	}
	if os.Getenv("GITHUB_REPOSITORY") != strings.TrimPrefix(repository, "ghcr.io/") {
		return errors.New("worker repository mismatch")
	}

	api := NewGitHub(token)
	retirer := newVersionRetirer(api, storage, repository)
	retirer.log = log
	workerRecipients, e := IdentityRecipients(identity)
	if e != nil {
		return e
	}
	recipients := Secret{Data: append([]byte(strings.TrimRight(recipientsText, "\r\n")+"\n"), workerRecipients.Data...)}
	source := os.Getenv("INPUT_SOURCE_PATH")
	if source == "" {
		return errors.New("missing source checkout path")
	}
	if mode == "build" {
		if _, err := signingPublicKey(signingKey.Data); err != nil {
			return err
		}
	}
	var bus *poolBus
	if mode == "build" || mode == "builder" {
		control, err := newActionsCache(resultsURL, runtimeToken)
		if err != nil {
			return err
		}
		revision, err := runCommand(source, log, "git", "rev-parse", "HEAD")
		if err != nil {
			return errors.New("resolve builder source commit")
		}
		binding := BuildBinding(submitted, system)
		binding["revision"] = strings.TrimSpace(string(revision))
		bus, err = newPoolBus(storage, control, repository, run, system, attempt, identity, recipients, binding)
		if err != nil {
			return err
		}
	}

	if mode == "builder" {
		runner, err := strconv.Atoi(os.Getenv("INPUT_BUILDER"))
		if err != nil || runner < 1 || runner >= RunnersPerSystem {
			return errors.New("invalid builder runner")
		}
		return RunBuilder(source, runner, bus, log)
	}

	if mode == "admit" {
		matrix, e := AdmissionMatrix(source, submitted.Selection, func(args []string, capture bool, data []byte) ([]byte, error) {
			return NixRun(source, log, args, capture, data)
		})
		if e != nil {
			return e
		}

		f, e := os.OpenFile(os.Getenv("GITHUB_OUTPUT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()

		encoded, e := json.Marshal(matrix)
		if e != nil {
			return e
		}
		helpers, e := matrix.Helpers()
		if e != nil {
			return e
		}
		helperJSON, e := json.Marshal(helpers)
		if e != nil {
			return e
		}
		revision, e := runCommand(source, log, "git", "rev-parse", "HEAD")
		if e != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(strings.TrimSpace(string(revision))) {
			return errors.New("resolve admitted source commit")
		}
		if _, e = Prune(api, storage, repository, log); e != nil {
			return e
		}

		_, e = fmt.Fprintf(f, "matrix=%s\nhelpers=%s\nrevision=%s\n", encoded, helperJSON, strings.TrimSpace(string(revision)))
		if e != nil {
			return e
		}
		for _, row := range matrix.Include {
			fmt.Fprintf(log, "Admitted runner: %s\n", row.System)
		}
		return nil
	}

	parent, e := loadPlatform(storage, repository, system, identity)
	if e != nil {
		return e
	}
	delta := NewSnapshot(storage, repository)
	delta.Metadata = map[string]any{
		"kind": "stage", "binding": BuildBinding(submitted, system),
		"run": run, "attempt": attempt, "request": request, "status": "failure",
	}
	if submitted.Selection != nil {
		delta.Metadata["selection"] = submitted.Selection
	}
	bus.retire = retirer.retire
	pool := StartBuildPool(bus, log)
	defer pool.Close()
	success, e := (nativeBuild{
		source: source, system: system, run: run, attempt: attempt,
		parent: parent, delta: delta, pool: pool, log: log,
		live: &livePublisher{snapshot: parent, system: system, run: run, attempt: attempt,
			recipients: recipients, retire: retirer.retire, log: log},
		secrets: buildSecrets{identity: identity, recipients: recipients, signingKey: signingKey},
	}).execute()
	if e != nil {
		return e
	}
	if !success {
		return errors.New("native build failed")
	}
	return nil
}
