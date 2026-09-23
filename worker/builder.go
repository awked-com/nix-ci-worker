package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

type poolTiming struct{ poll, heartbeat, lease, startup time.Duration }

var productionPoolTiming = poolTiming{poolPoll, poolHeartbeat, poolLease, poolStartupTimeout}

type poolBuildResult struct {
	snapshot string
	err      error
}

func servePoolBuilder(ctx context.Context, bus *poolBus, runner int, features []string, timing poolTiming, execute func(context.Context, poolTask) (string, error), log io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	instance := poolNonce()
	status := poolMessage{Cores: runtime.NumCPU(), Instance: instance, State: "ready", Features: features}
	started := time.Now()
	lastPublished := time.Time{}
	ticker := time.NewTicker(timing.poll)
	defer ticker.Stop()
	var running <-chan poolBuildResult
	defer func() {
		cancel()
		if running != nil {
			<-running
		}
	}()
	stopping := false
	for {
		coordinator, err := bus.read("coordinator", 0)
		if err == nil && poolFresh(coordinator, timing.lease) {
			if status.Session == "" {
				status.Session = coordinator.Session
			}
			if status.Session != coordinator.Session {
				return errors.New("coordinator session changed")
			}
			if coordinator.State == "stop" || len(coordinator.Finish) == RunnersPerSystem && status.Sequence >= coordinator.Finish[runner] {
				stopping = true
			}
		}
		// A reread of an old object cannot renew a lease.
		if status.Session == "" {
			if time.Since(started) >= timing.startup {
				return errors.New("coordinator did not publish its startup lease")
			}
		} else if !poolFresh(coordinator, timing.lease) {
			// Reads may fail temporarily; retain the last verified lease until expiry.
			if time.Since(started) >= timing.lease {
				return errors.New("coordinator heartbeat lease expired")
			}
		} else {
			started = coordinator.Sent
		}

		if status.Session != "" && time.Since(lastPublished) >= timing.heartbeat {
			if err := bus.write("status", runner, status); err == nil {
				lastPublished = time.Now()
			}
		}
		if stopping && running == nil && !lastPublished.IsZero() {
			fmt.Fprintf(log, "Finished builder: %s/%d\n", bus.system, runner)
			return nil
		}
		if status.Session != "" && !stopping && running == nil {
			assignment, err := bus.read("assignment", runner)
			if err == nil && assignment.Session == status.Session && assignment.Instance == instance && assignment.Sequence > status.Sequence {
				if assignment.State != "build" || assignment.Task == nil {
					return errors.New("invalid builder assignment")
				}
				status.Sequence, status.State, status.Snapshot = assignment.Sequence, "busy", ""
				lastPublished = time.Time{}
				result := make(chan poolBuildResult, 1)
				running = result
				go func(task poolTask) {
					snapshot, err := execute(ctx, task)
					result <- poolBuildResult{snapshot, err}
				}(*assignment.Task)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case result := <-running:
			running = nil
			status.State, status.Snapshot = "done", result.snapshot
			if result.err != nil {
				status.State, status.Snapshot = "failed", ""
			}
			lastPublished = time.Time{}
		}
	}
}

func poolFeatures(source string, log io.Writer) ([]string, error) {
	data, err := NixRun(source, log, []string{"config", "show", "--json"}, true, nil)
	if err != nil {
		return nil, err
	}
	var settings map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	var features []string
	if err = json.Unmarshal(data, &settings); err == nil {
		err = json.Unmarshal(settings["system-features"].Value, &features)
	}
	if err != nil || !validFeatures(features) {
		return nil, errors.New("invalid builder system features")
	}
	return features, nil
}

// Hosted runners have passwordless sudo. Apply trust and sandbox settings to
// these commands explicitly instead of changing the runner's global Nix trust.
func poolNixCommand(ctx context.Context, args []string) (*exec.Cmd, error) {
	binary, err := exec.LookPath("nix")
	if err != nil {
		return nil, err
	}
	if dedicatedRunner() {
		return exec.CommandContext(ctx, "sudo", append([]string{"-n", "--", binary}, args...)...), nil
	}
	return exec.CommandContext(ctx, binary, args...), nil
}

func poolCopy(ctx context.Context, source string, snapshot *Snapshot, identity Secret, public string, paths []string, log io.Writer) error {
	handler, server, options, err := publicSubstituter(snapshot.Storage, snapshot, identity, public, log)
	if err != nil {
		return err
	}
	defer server.Close()
	if err = substitutePoolPaths(ctx, source, paths, options, "", log); err != nil {
		return err
	}
	if len(handler.Errors()) != 0 {
		return errors.New("builder cache transfer failed")
	}
	return nil
}

func substitutePoolPaths(ctx context.Context, source string, paths, options []string, root string, log io.Writer) error {
	// A closure can span our encrypted cache and cache.nixos.org. Copying from
	// one store requires every reference there; substitution consults both caches.
	// Bare store paths request the paths themselves, with compilation disabled.
	args := append([]string{
		"--extra-experimental-features", "nix-command flakes",
		"build", "--stdin", "--max-jobs", "0", "--builders", "",
		"--option", "max-substitution-jobs", "8", "--option", "min-free", "0",
	}, options...)
	if root == "" {
		args = append(args, "--no-link")
	} else {
		args = append(args, "--out-link", root)
	}
	cmd, err := poolNixCommand(ctx, args)
	if err != nil {
		return err
	}
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = source, BuildEnvironment(), log, log
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\n") + "\n")
	return NewDiskGuard(source).Run(cmd)
}

func preparePoolInputs(ctx context.Context, source string, inputs, options []string, log io.Writer) (func(), error) {
	started := time.Now()
	roots, err := os.MkdirTemp("", "pool-inputs-")
	if err != nil {
		return nil, err
	}
	release := func() { os.RemoveAll(roots) }
	// Keep inputs rooted through compilation, including while another runner
	// reclaims disk space. Missing inputs must fail before any builder starts.
	if err = substitutePoolPaths(ctx, source, inputs, options, filepath.Join(roots, "input"), log); err != nil {
		release()
		return nil, fmt.Errorf("build input import failed: %w", err)
	}
	fmt.Fprintf(log, "Build inputs imported: %d paths (%.1fs)\n", len(inputs), time.Since(started).Seconds())
	return release, nil
}

func buildPoolDerivation(ctx context.Context, source, system, spec string, cores int, inputs, options []string, log io.Writer) error {
	release, err := preparePoolInputs(ctx, source, inputs, options, log)
	if err != nil {
		return err
	}
	defer release()
	started := time.Now()
	cmd, err := poolNixCommand(ctx, BuildCommand(system, 1, cores, append(slices.Clone(options), "--builders", "")))
	if err != nil {
		return err
	}
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = source, BuildEnvironment(), log, log
	cmd.Stdin = strings.NewReader(spec + "\n")
	if err = NewDiskGuard(source).Run(cmd); err != nil {
		return err
	}
	fmt.Fprintf(log, "Build finished (%.1fs)\n", time.Since(started).Seconds())
	return nil
}

func executePoolBuild(ctx context.Context, bus *poolBus, source string, runner int, task poolTask, upstream UpstreamCollector, log io.Writer) (string, error) {
	started := time.Now()
	if task.Cores < 1 || task.Cores > runtime.NumCPU() {
		return "", errors.New("invalid builder CPU allocation")
	}
	drv, outputs, ok := strings.Cut(task.Installable, "^")
	if !ok || !ValidStorePath(drv) || !strings.HasSuffix(drv, ".drv") || outputs == "" || len(task.Outputs) == 0 || !digestPattern.MatchString(task.Inputs) {
		return "", errors.New("invalid builder task")
	}
	for _, path := range task.Outputs {
		if !ValidStorePath(path) {
			return "", errors.New("invalid builder output")
		}
	}
	if !slices.Contains(task.BuildInputs, drv) {
		return "", errors.New("builder task omits build inputs")
	}
	for _, path := range task.BuildInputs {
		if !ValidStorePath(path) {
			return "", errors.New("invalid builder input")
		}
	}
	inputs, err := LoadSnapshot(bus.storage, bus.repository, task.Inputs, bus.identity)
	if err != nil {
		return "", err
	}
	if err = inputs.RequireClosed(); err != nil {
		return "", err
	}
	fmt.Fprintf(log, "Builder catalog ready: %s/%d (%.1fs)\n", bus.system, runner, time.Since(started).Seconds())
	handler, server, options, err := publicSubstituter(bus.storage, inputs, bus.identity, task.PublicKey, log)
	if err != nil {
		return "", err
	}
	defer server.Close()
	if err = buildPoolDerivation(ctx, source, bus.system, task.Installable, task.Cores, task.BuildInputs, options, log); err != nil {
		return "", err
	}
	if len(handler.Errors()) != 0 {
		return "", errors.New("builder input cache read failed")
	}
	started = time.Now()
	required := map[string]bool{}
	for _, path := range task.Outputs {
		required[path] = true
	}
	delta := NewSnapshot(bus.storage, bus.repository)
	if _, err = PublishStore(source, required, delta, inputs, bus.signingKey(runner), bus.recipients, log, upstream); err != nil {
		return "", err
	}
	result, err := CacheUnion(inputs, delta)
	if err != nil {
		return "", err
	}
	for _, path := range task.Outputs {
		if !result.Contains(path) {
			return "", errors.New("builder did not publish an assigned output")
		}
	}
	index, err := newSnapshotIndex(result)
	if err != nil {
		return "", err
	}
	result = index.selectPaths(required)
	result.Metadata = map[string]any{"kind": "pool", "run": bus.run}
	digest, err := result.Publish(bus.tag("result", runner), bus.recipients)
	if err == nil {
		fmt.Fprintf(log, "Builder result published: %s/%d (%.1fs)\n", bus.system, runner, time.Since(started).Seconds())
	}
	return digest, err
}

func RunBuilder(source string, runner int, bus *poolBus, log io.Writer) error {
	native, err := NativeSystem()
	if err != nil || bus.system != native {
		return errors.New("builder does not match the admitted platform")
	}
	features, err := poolFeatures(source, log)
	if err != nil {
		return err
	}
	upstream := NewUpstream()
	defer upstream.Close()
	log = &buildLog{Writer: log}
	fmt.Fprintf(log, "Ready runner: %s/%d (%d CPUs)\n", bus.system, runner, runtime.NumCPU())
	err = servePoolBuilder(context.Background(), bus, runner, features, productionPoolTiming, func(ctx context.Context, task poolTask) (string, error) {
		return executePoolBuild(ctx, bus, source, runner, task, upstream, log)
	}, log)
	if err != nil {
		fmt.Fprintf(log, "Runner stopped: %s/%d\n", bus.system, runner)
	}
	return err
}
