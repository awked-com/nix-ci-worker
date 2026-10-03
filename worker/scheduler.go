package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dependencies, including transitive dependencies whose outputs are cached, must
// finish before a dependent task is sent to a different store.
func poolDependencies(graph *Plan, drv string, pending map[string]string) []string {
	seen := map[string]bool{}
	result := []string{}
	var visit func(string)
	visit = func(current string) {
		for dep := range graph.Derivations[current].InputDrvs {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			if _, scheduled := pending[dep]; scheduled {
				result = append(result, dep)
			} else {
				visit(dep)
			}
		}
	}
	visit(drv)
	return result
}

func poolCompatible(d Derivation, system string, features []string) bool {
	required := strings.Fields(d.Env["requiredSystemFeatures"])
	preferLocal := d.Env["preferLocalBuild"] == "1"
	if raw := d.Env["__json"]; raw != "" {
		var attrs struct {
			Required []string `json:"requiredSystemFeatures"`
			Local    bool     `json:"preferLocalBuild"`
		}
		if json.Unmarshal([]byte(raw), &attrs) != nil {
			return false
		}
		required = append(required, attrs.Required...)
		preferLocal = preferLocal || attrs.Local
	}
	if d.Dynamic || d.System != "" && d.System != system || preferLocal {
		return false
	}
	for _, output := range d.Outputs {
		if output.Path == "" {
			return false
		}
	}
	for _, feature := range required {
		if !slices.Contains(features, feature) {
			return false
		}
	}
	return true
}

type poolCompletion struct {
	runner   int
	sequence uint64
	drv      string
	released bool
	err      error
}

var errPoolPublication = errors.New("builder result publication failed")

// The coordinator is the only assigner. Runners can start independent work
// while their previous result is published; dependencies wait for publication.
func (p *BuildPool) schedule(ctx context.Context, graph *Plan, missing []string, execute func(context.Context, int, string, poolMessage, func()) error) error {
	if _, err := graph.Batches(missing, 1); err != nil {
		return err
	}
	specs := map[string]string{}
	for _, spec := range missing {
		specs[strings.SplitN(spec, "^", 2)[0]] = spec
	}
	deps := map[string][]string{}
	for drv := range specs {
		deps[drv] = poolDependencies(graph, drv, specs)
	}
	priorities := poolPriorities(deps)
	order := poolOrder(specs, priorities)
	allocated := [RunnersPerSystem]bool{}
	pending := [RunnersPerSystem]int{}
	locality := [RunnersPerSystem]map[string]bool{}
	for runner := range locality {
		locality[runner] = map[string]bool{}
	}
	state := map[string]string{}
	retryLocal := map[string]bool{}
	retired := [RunnersPerSystem]bool{}
	sequences := [RunnersPerSystem]uint64{}
	instances := [RunnersPerSystem]string{}
	ctx, cancel := context.WithCancel(ctx)
	var group sync.WaitGroup
	defer func() { cancel(); group.Wait() }()
	done := make(chan poolCompletion, 2*RunnersPerSystem)
	ticker := time.NewTicker(p.timing.poll)
	defer ticker.Stop()
	deadline := time.Now().Add(p.timing.startup)
	var failure error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Propagate failures so independent branches still finish and get cached.
		changed := true
		for changed {
			changed = false
			for drv := range specs {
				if state[drv] != "" {
					continue
				}
				for _, dep := range deps[drv] {
					if state[dep] == "failed" {
						state[drv] = "failed"
						changed = true
						break
					}
				}
			}
		}
		ready := func(drv string) bool {
			if state[drv] != "" {
				return false
			}
			for _, dep := range deps[drv] {
				if state[dep] != "done" {
					return false
				}
			}
			return true
		}
		delegatable := func(drv string) bool {
			if retryLocal[drv] {
				return false
			}
			for runner := 1; runner < RunnersPerSystem; runner++ {
				message := p.statuses[runner].Load()
				if retired[runner] || !poolFresh(message, p.timing.lease) || message.Instance == "" ||
					instances[runner] != "" && message.Instance != instances[runner] ||
					!validFeatures(message.Features) || message.Cores < 1 || message.Cores > 256 {
					continue
				}
				if poolCompatible(graph.Derivations[drv], p.bus.system, message.Features) {
					return true
				}
			}
			return false
		}
		for runner := range RunnersPerSystem {
			// Keep at most one previous publication beside the current build.
			// A slow registry must not accumulate an unbounded output backlog.
			if allocated[runner] || pending[runner] >= 2 || retired[runner] {
				continue
			}
			remote := poolMessage{Cores: p.cpus}
			if runner > 0 {
				// Helpers may exit after their final assignment. Busy runners still
				// verify their result through execute; idle runners need no more lease.
				if p.finish.Load() != nil {
					continue
				}
				message := p.statuses[runner].Load()
				if !poolFresh(message, p.timing.lease) || message.Instance == "" || !validFeatures(message.Features) || message.Cores < 1 || message.Cores > 256 {
					if time.Now().After(deadline) {
						retired[runner] = true
						fmt.Fprintf(p.log, "warning: builder %s/%d did not register; continuing with available builders\n", p.bus.system, runner)
					}
					continue
				}
				if instances[runner] != "" && message.Instance != instances[runner] {
					retired[runner] = true
					continue
				}
				if message.State != "ready" && message.State != "done" && message.State != "failed" {
					continue
				}
				if instances[runner] == "" {
					fmt.Fprintf(p.log, "Registered builder: %s/%d\n", p.bus.system, runner)
				}
				remote = *message
				instances[runner] = message.Instance
			}
			selected := ""
			warmest := -1
			selectedLocal := false
			for _, drv := range order {
				if !ready(drv) {
					continue
				}
				if runner > 0 && (retryLocal[drv] || !poolCompatible(graph.Derivations[drv], p.bus.system, remote.Features)) {
					continue
				}
				warm := 0
				for dep := range graph.Derivations[drv].InputDrvs {
					if locality[runner][dep] {
						warm++
					}
				}
				// Keep the coordinator available for work that no live helper can
				// accept. Otherwise compatible work can strand local-only branches.
				local := runner == 0 && !delegatable(drv)
				if selected == "" || local && !selectedLocal || local == selectedLocal && priorities[drv] == priorities[selected] && warm > warmest {
					selected, warmest = drv, warm
					selectedLocal = local
				}
			}
			if selected == "" {
				continue
			}
			allocated[runner] = true
			pending[runner]++
			state[selected] = "running"
			sequences[runner]++
			remote.Sequence = sequences[runner]
			fmt.Fprintf(p.log, "Assigned build: %s/%d task %d (%d cores)\n", p.bus.system, runner, remote.Sequence, remote.Cores)
			drv := selected
			group.Go(func() {
				send := func(event poolCompletion) {
					select {
					case done <- event:
					case <-ctx.Done():
					}
				}
				release := sync.OnceFunc(func() {
					send(poolCompletion{runner: runner, sequence: remote.Sequence, drv: drv, released: true})
				})
				err := execute(ctx, runner, specs[drv], remote, release)
				send(poolCompletion{runner: runner, sequence: remote.Sequence, drv: drv, err: err})
			})
		}
		unassigned, active := false, false
		for drv := range specs {
			unassigned = unassigned || state[drv] == ""
			active = active || state[drv] == "running"
		}
		if !unassigned && p.finish.Load() == nil {
			copy := sequences
			p.finish.Store(&copy)
			p.notify()
		}
		if !active && !unassigned {
			p.Drain()
			return failure
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case result := <-done:
			if result.sequence == sequences[result.runner] {
				allocated[result.runner] = false
			}
			if result.released {
				continue
			}
			pending[result.runner]--
			if errors.Is(result.err, errPoolPublication) {
				return result.err
			}
			if result.err != nil && result.runner > 0 {
				// Retire this incarnation before reassigning. Late results cannot complete
				// the new local attempt, and helpers stop when their coordinator lease ends.
				retired[result.runner], retryLocal[result.drv], state[result.drv] = true, true, ""
				fmt.Fprintf(p.log, "warning: builder %s/%d failed; retrying its task on coordinator\n", p.bus.system, result.runner)
			} else {
				state[result.drv] = "done"
				if result.err == nil {
					warm := locality[result.runner]
					warm[result.drv] = true
					for dep := range graph.Derivations[result.drv].InputDrvs {
						warm[dep] = true
					}
					fmt.Fprintf(p.log, "Finished build: %s/%d task %d\n", p.bus.system, result.runner, result.sequence)
				}
				if result.err != nil {
					state[result.drv], failure = "failed", errors.New("coordinator build failed")
				}
			}
		}
	}
}

func (p *BuildPool) remoteTask(ctx context.Context, runner int, remote poolMessage, task poolTask) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	assignment := poolMessage{Session: p.session, Instance: remote.Instance, Sequence: remote.Sequence, State: "build", Task: &task}
	if err := p.bus.write("assignment", runner, assignment); err != nil {
		return nil, err
	}
	assigned := time.Now()
	acknowledged := false
	ticker := time.NewTicker(p.timing.poll)
	defer ticker.Stop()
	for {
		status := p.statuses[runner].Load()
		if !poolFresh(status, p.timing.lease) || status.Instance != remote.Instance {
			return nil, errors.New("builder lease expired or instance changed")
		}
		if status.Sequence > remote.Sequence {
			return nil, errors.New("builder assignment sequence changed")
		}
		if status.Sequence == remote.Sequence {
			if status.State == "busy" {
				acknowledged = true
			}
			if status.State == "failed" {
				return nil, errors.New("builder task failed")
			}
			if status.State == "done" {
				if !digestPattern.MatchString(status.Snapshot) {
					return nil, errors.New("invalid builder result digest")
				}
				snapshot, err := LoadSnapshot(p.bus.storage, p.bus.repository, status.Snapshot, p.bus.identity)
				if err != nil {
					return nil, err
				}
				if err = snapshot.RequireClosed(); err != nil {
					return nil, err
				}
				for name := range snapshot.Files {
					if !strings.HasPrefix(name, "cache/") || !archivePattern.MatchString(strings.TrimPrefix(name, "cache/")) {
						return nil, errors.New("builder result contains a non-archive file")
					}
				}
				for _, path := range task.Outputs {
					if !snapshot.Contains(path) {
						return nil, errors.New("builder result omitted an output")
					}
				}
				return snapshot, nil
			}
		}
		// An evicted assignment must not wait forever on a helper that keeps
		// publishing ready heartbeats without ever receiving the task.
		if !acknowledged && time.Since(assigned) >= p.timing.lease {
			return nil, errors.New("builder did not acknowledge assignment")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		case <-p.changed[runner]:
		}
	}
}

func (p *BuildPool) build(source, system string, graph *Plan, missing []string, delta *Snapshot, signingKey, recipients Secret, log io.Writer, options []string, after func(bool) (*snapshotIndex, error)) error {
	public, err := signingPublicKey(signingKey.Data)
	if err != nil {
		return err
	}
	var inputs atomic.Pointer[snapshotIndex]
	refresh := func(force bool) error {
		index, err := after(force)
		if err != nil {
			return err
		}
		// extend replaces the index's maps; active assignments keep this view.
		view := *index
		inputs.Store(&view)
		return nil
	}
	if err = refresh(false); err != nil {
		return fmt.Errorf("%w: %w", errPoolPublication, err)
	}

	// Publication owns mutable cache state. Runners can compile their next
	// independent task while the preceding result waits for this lock.
	var publication sync.Mutex
	ctx, cancel := context.WithCancelCause(p.ctx)
	defer cancel(nil)
	periodic := make(chan struct{})
	go func() {
		defer close(periodic)
		ticker := time.NewTicker(publicationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				publication.Lock()
				if ctx.Err() == nil {
					if err := refresh(false); err != nil {
						cancel(fmt.Errorf("%w: %w", errPoolPublication, err))
					}
				}
				publication.Unlock()
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	execute := func(ctx context.Context, runner int, spec string, remote poolMessage) (*Snapshot, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		drv := strings.SplitN(spec, "^", 2)[0]
		buildInputs, err := graph.BuildInputs(drv)
		if err != nil {
			return nil, err
		}
		if runner == 0 {
			return nil, buildPoolDerivation(ctx, source, spec, remote.Cores, buildInputs, options, log)
		}
		paths := []string{}
		for _, path := range graph.Outputs[drv] {
			paths = append(paths, path)
		}
		required := map[string]bool{}
		for _, path := range buildInputs {
			required[path] = true
		}
		input := inputs.Load().selectPaths(required)
		input.Metadata = map[string]any{"kind": "pool", "run": p.bus.run}
		digest, err := input.Publish(p.bus.artifactTag("inputs", runner, remote.Sequence), recipients)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errPoolPublication, err)
		}
		task := poolTask{Cores: remote.Cores, Installable: spec, BuildInputs: buildInputs, Inputs: digest, PublicKey: public, Outputs: paths}
		result, err := p.remoteTask(ctx, runner, remote, task)
		if err != nil {
			return nil, err
		}
		transportKey := p.bus.signingKey(runner)
		transportPublic, err := signingPublicKey(transportKey.Data)
		if err != nil {
			return nil, err
		}
		if err = poolCopy(ctx, source, result, p.bus.identity, public+" "+transportPublic, paths, log); err != nil {
			return nil, err
		}
		return result, nil
	}
	err = p.schedule(ctx, graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage, release func()) error {
		result, buildError := execute(ctx, runner, spec, remote)
		if errors.Is(buildError, errPoolPublication) {
			cancel(buildError)
			return buildError
		}
		if buildError == nil {
			release()
		}
		waiting := time.Now()
		publication.Lock()
		defer publication.Unlock()
		started := time.Now()
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reuse verified ciphertext archives. PublishStore recomputes NAR metadata
		// locally and signs it with the final key, which helpers never receive.
		if result != nil {
			for name, file := range result.Files {
				if _, exists := delta.Files[name]; !exists {
					delta.Files[name] = file
				}
			}
		}
		if err := refresh(false); err != nil {
			failure := fmt.Errorf("%w: %w", errPoolPublication, err)
			cancel(failure)
			return failure
		}
		fmt.Fprintf(log, "Build result processed: %s/%d (%.1fs; waited %.1fs)\n", system, runner, time.Since(started).Seconds(), started.Sub(waiting).Seconds())
		return buildError
	})
	cancel(nil)
	<-periodic
	if cause := context.Cause(ctx); errors.Is(cause, errPoolPublication) {
		return cause
	}
	if errors.Is(err, errPoolPublication) || p.ctx.Err() != nil {
		return err
	}
	// Flush every signed result, including partial failures, before completion.
	if flushError := refresh(true); flushError != nil {
		return fmt.Errorf("%w: %w", errPoolPublication, flushError)
	}
	return err
}
