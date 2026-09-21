package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSchedulerUsesWholeRunnerForNarrowGraphs(t *testing.T) {
	pool := schedulerFixture(t)
	pool.cpus = 3
	for runner := 1; runner < RunnersPerSystem; runner++ {
		status := *pool.statuses[runner].Load()
		status.Cores = 3
		pool.statuses[runner].Store(&status)
	}
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "b": derivation("b-out", "a"), "c": derivation("c-out", "b")}}
	if err := pool.schedule(graph, []string{"a^out", "b^out", "c^out"}, func(ctx context.Context, runner int, spec string, budget poolMessage) error {
		if budget.Cores != 3 {
			t.Errorf("serial build %s received %d of 3 cores", spec, budget.Cores)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerRunsOneFullCPUCapacityBuildPerRunner(t *testing.T) {
	pool := schedulerFixture(t)
	pool.cpus = 3
	for runner := 1; runner < RunnersPerSystem; runner++ {
		status := *pool.statuses[runner].Load()
		status.Cores = 3
		pool.statuses[runner].Store(&status)
	}
	graph := &Plan{Derivations: map[string]Derivation{}}
	missing := []string{}
	for n := range 12 {
		drv := fmt.Sprint(n)
		graph.Derivations[drv] = derivation(drv + "-out")
		missing = append(missing, drv+"^out")
	}
	var mu sync.Mutex
	used := [RunnersPerSystem]bool{}
	err := pool.schedule(graph, missing, func(ctx context.Context, runner int, spec string, budget poolMessage) error {
		mu.Lock()
		if used[runner] || budget.Cores != 3 {
			t.Errorf("runner %d has overlapping work or %d cores", runner, budget.Cores)
		}
		used[runner] = true
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		used[runner] = false
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerPrioritizesLongDependencyChains(t *testing.T) {
	pool := schedulerFixture(t)
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "z": derivation("z-out"), "y": derivation("y-out", "z"), "x": derivation("x-out", "y")}}
	var mu sync.Mutex
	first := ""
	err := pool.schedule(graph, []string{"a^out", "z^out", "y^out", "x^out"}, func(ctx context.Context, runner int, spec string, budget poolMessage) error {
		// The coordinator is allocated synchronously before any helper, independent
		// of which execution goroutine happens to start first.
		if runner == 0 {
			mu.Lock()
			if first == "" {
				first = spec
			}
			mu.Unlock()
		}
		return nil
	})
	if err != nil || first != "z^out" {
		t.Fatal("longest chain did not start on the coordinator", first, err)
	}
}
