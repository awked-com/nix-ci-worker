package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

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
