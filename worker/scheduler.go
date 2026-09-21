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
	runner int
	drv    string
	err    error
}

var errPoolPublication = errors.New("builder result publication failed")

// The coordinator is the only assigner. No registry tag is used as a lock, and
// a runner remains busy through result publication, not just compilation.
func (p *BuildPool) schedule(graph *Plan, missing []string, execute func(context.Context, int, string, poolMessage) error) error {
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
	locality := [RunnersPerSystem]map[string]bool{}
	for runner := range locality {
		locality[runner] = map[string]bool{}
	}
	state := map[string]string{}
	retryLocal := map[string]bool{}
	retired := [RunnersPerSystem]bool{}
	sequences := [RunnersPerSystem]uint64{}
	instances := [RunnersPerSystem]string{}
	ctx, cancel := context.WithCancel(p.ctx)
	var group sync.WaitGroup
	defer func() { cancel(); group.Wait() }()
	done := make(chan poolCompletion, RunnersPerSystem)
	ticker := time.NewTicker(p.timing.poll)
	defer ticker.Stop()
	deadline := time.Now().Add(p.timing.startup)
	var failure error
	for {
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
		for runner := range RunnersPerSystem {
			if allocated[runner] || retired[runner] {
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
				if selected == "" || priorities[drv] == priorities[selected] && warm > warmest {
					selected, warmest = drv, warm
				}
			}
			if selected == "" {
				continue
			}
			allocated[runner] = true
			state[selected] = "running"
			sequences[runner]++
			remote.Sequence = sequences[runner]
			fmt.Fprintf(p.log, "Assigned build: %s/%d task %d (%d cores)\n", p.bus.system, runner, remote.Sequence, remote.Cores)
			group.Add(1)
			go func(runner int, drv string, remote poolMessage) {
				defer group.Done()
				err := execute(ctx, runner, specs[drv], remote)
				done <- poolCompletion{runner, drv, err}
			}(runner, selected, remote)
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
			allocated[result.runner] = false
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
					fmt.Fprintf(p.log, "Finished build: %s/%d task %d\n", p.bus.system, result.runner, sequences[result.runner])
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		case <-p.changed[runner]:
		}
	}
}

func (p *BuildPool) build(source, system string, graph *Plan, missing []string, delta *Snapshot, signingKey, recipients Secret, log io.Writer, options []string, after func() (*snapshotIndex, error)) error {
	public, err := signingPublicKey(signingKey.Data)
	if err != nil {
		return err
	}
	var inputs atomic.Pointer[snapshotIndex]
	refresh := func() error {
		index, err := after()
		if err != nil {
			return err
		}
		// extend replaces the index's maps; active assignments keep this view.
		view := *index
		inputs.Store(&view)
		return nil
	}
	if err = refresh(); err != nil {
		return err
	}

	// Publishing is serialized, while the scheduler keeps assigning independent
	// tasks to other free runners. A runner is free only after its output is durable.
	var publication sync.Mutex
	execute := func(ctx context.Context, runner int, spec string, remote poolMessage) (*Snapshot, error) {
		drv := strings.SplitN(spec, "^", 2)[0]
		buildInputs, err := graph.BuildInputs(drv)
		if err != nil {
			return nil, err
		}
		if runner == 0 {
			return nil, buildPoolDerivation(ctx, source, system, spec, remote.Cores, buildInputs, options, log)
		}
		paths := []string{}
		for _, path := range graph.Outputs[drv] {
			paths = append(paths, path)
		}
		required, _ := graph.TargetPaths(drv)
		input := inputs.Load().selectPaths(required)
		input.Metadata = map[string]any{"kind": "pool", "run": p.bus.run}
		digest, err := input.Publish(p.bus.tag("inputs", 0), recipients)
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
	return p.schedule(graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
		result, buildError := execute(ctx, runner, spec, remote)
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
		if err := refresh(); err != nil {
			return fmt.Errorf("%w: %w", errPoolPublication, err)
		}
		fmt.Fprintf(log, "Build result processed: %s/%d (%.1fs; waited %.1fs)\n", system, runner, time.Since(started).Seconds(), started.Sub(waiting).Seconds())
		return buildError
	})
}
