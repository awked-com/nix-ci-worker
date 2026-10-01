package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
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
	err := pool.schedule(pool.ctx, graph, missing, func(ctx context.Context, runner int, spec string, budget poolMessage, releaseRunner func()) error {
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

func TestSchedulerReservesCoordinatorForRestrictedWork(t *testing.T) {
	for _, env := range []map[string]string{{"preferLocalBuild": "1"}, {"requiredSystemFeatures": "kvm"}} {
		t.Run(fmt.Sprint(env), func(t *testing.T) {
			pool := schedulerFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			pool.ctx = ctx
			graph := &Plan{Derivations: map[string]Derivation{
				"a": derivation("a-out"), "b": derivation("b-out"),
				"c": derivation("c-out", "a"), "d": derivation("d-out"), "z": derivation("z-out"),
			}}
			restricted := graph.Derivations["z"]
			restricted.Env = env
			graph.Derivations["z"] = restricted
			started := make(chan string, len(graph.Derivations))
			builds := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- pool.schedule(pool.ctx, graph, []string{"a^out", "b^out", "c^out", "d^out", "z^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage, releaseRunner func()) error {
					started <- fmt.Sprintf("%d:%s", runner, spec)
					select {
					case <-builds:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			seen := map[string]bool{}
			for range RunnersPerSystem {
				select {
				case event := <-started:
					seen[event] = true
				case <-ctx.Done():
					t.Fatal("available runners were not filled", seen)
				}
			}
			close(builds)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !seen["0:z^out"] || !seen["1:a^out"] || !seen["2:b^out"] {
				t.Fatal("local-only work waited behind compatible work", seen)
			}
		})
	}
}

func TestSchedulerPipelinesBuildsWithoutReleasingDependencies(t *testing.T) {
	pool := schedulerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool.ctx = ctx
	graph := &Plan{Derivations: map[string]Derivation{
		"a": derivation("a-out"), "b": derivation("b-out"), "c": derivation("c-out"),
		"d": derivation("d-out"), "e": derivation("e-out"), "f": derivation("f-out"), "z": derivation("z-out", "a"),
	}}
	started := make(chan string, len(graph.Derivations))
	published := make(chan struct{})
	builds := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pool.schedule(pool.ctx, graph, []string{"a^out", "b^out", "c^out", "d^out", "e^out", "f^out", "z^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage, releaseRunner func()) error {
			started <- fmt.Sprintf("%d:%s", runner, spec)
			if spec == "a^out" || spec == "e^out" {
				releaseRunner()
				releaseRunner()
				select {
				case <-published:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			select {
			case <-builds:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	seen := map[string]bool{}
	for len(seen) < RunnersPerSystem+1 {
		select {
		case event := <-started:
			seen[event] = true
		case <-ctx.Done():
			t.Fatal("runner waited for its previous publication", seen)
		}
	}
	if !seen["0:a^out"] || !seen["0:e^out"] || !seen["1:b^out"] || !seen["2:c^out"] || !seen["3:d^out"] {
		t.Fatal("unexpected pipeline assignments", seen)
	}
	select {
	case event := <-started:
		t.Fatal("unpublished results released a dependency or exceeded the backlog bound", event)
	case <-time.After(30 * time.Millisecond):
	}
	close(published)
	select {
	case event := <-started:
		if event != "0:f^out" && event != "0:z^out" {
			t.Fatal("unexpected assignment after publication", event)
		}
	case <-ctx.Done():
		t.Fatal("published results did not release pending work")
	}
	close(builds)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerOlderPublicationCannotReleaseCurrentBuild(t *testing.T) {
	pool := schedulerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool.ctx = ctx
	graph := &Plan{Derivations: map[string]Derivation{}}
	missing := []string{}
	for _, drv := range []string{"a", "b", "c", "d", "e", "f"} {
		graph.Derivations[drv] = derivation(drv + "-out")
		missing = append(missing, drv+"^out")
	}
	started := make(chan string, len(missing))
	published := make(chan struct{})
	builds := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pool.schedule(pool.ctx, graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage, releaseRunner func()) error {
			started <- fmt.Sprintf("%d:%s", runner, spec)
			if spec == "a^out" {
				releaseRunner()
				select {
				case <-published:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			select {
			case <-builds:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	for range RunnersPerSystem + 1 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("runner did not overlap its previous publication")
		}
	}
	close(published)
	select {
	case event := <-started:
		t.Fatal("older publication freed a runner whose next build was still active", event)
	case <-time.After(30 * time.Millisecond):
	}
	close(builds)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerPublicationFailureCancelsPipelinedBuilds(t *testing.T) {
	pool := schedulerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool.ctx = ctx
	graph := &Plan{Derivations: map[string]Derivation{}}
	missing := []string{}
	for _, drv := range []string{"a", "b", "c", "d"} {
		graph.Derivations[drv] = derivation(drv + "-out")
		missing = append(missing, drv+"^out")
	}
	started := make(chan string, len(missing))
	published := make(chan struct{})
	done := make(chan error, 1)
	var joined atomic.Int32
	go func() {
		done <- pool.schedule(pool.ctx, graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage, releaseRunner func()) error {
			started <- spec
			if spec == "a^out" {
				releaseRunner()
				select {
				case <-published:
					return errPoolPublication
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			<-ctx.Done()
			joined.Add(1)
			return ctx.Err()
		})
	}()
	for range len(missing) {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("runner did not overlap its previous publication")
		}
	}
	close(published)
	if err := <-done; !errors.Is(err, errPoolPublication) || joined.Load() != 3 {
		t.Fatal("publication failure did not cancel and join all builds", err, joined.Load())
	}
}

func TestPoolForcesPendingHeadBeforeReturning(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%v", fail), func(t *testing.T) {
			pool := schedulerFixture(t)
			delta := NewSnapshot(pool.bus.storage, pool.bus.repository)
			index, err := newSnapshotIndex(delta)
			if err != nil {
				t.Fatal(err)
			}
			forced := false
			publicationError := errors.New("head upload failed")
			err = pool.build("", pool.bus.system, &Plan{Derivations: map[string]Derivation{}}, nil, delta,
				pool.bus.signingKey(0), pool.bus.recipients, io.Discard, nil,
				func(force bool) (*snapshotIndex, error) {
					if force {
						forced = true
						if fail {
							return nil, publicationError
						}
					}
					return index, nil
				})
			if !forced || fail && (!errors.Is(err, publicationError) || !errors.Is(err, errPoolPublication)) || !fail && err != nil {
				t.Fatal("pool returned without a successful final head or its publication error", forced, err)
			}
		})
	}
}

func BenchmarkSchedulerPublicationPipeline(b *testing.B) {
	for _, pipelined := range []bool{false, true} {
		b.Run(fmt.Sprintf("pipelined=%v", pipelined), func(b *testing.B) {
			for b.Loop() {
				pool := &BuildPool{cpus: 1, timing: poolTiming{poll: time.Hour}, bus: &poolBus{system: "x86_64-linux"}, ctx: context.Background(), log: io.Discard}
				graph := &Plan{Derivations: map[string]Derivation{}}
				missing := []string{}
				for n := range 8 {
					drv := fmt.Sprint(n)
					graph.Derivations[drv] = derivation(drv + "-out")
					missing = append(missing, drv+"^out")
				}
				var publication sync.Mutex
				if err := pool.schedule(pool.ctx, graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage, releaseRunner func()) error {
					if runner != 0 || !strings.HasSuffix(spec, "^out") {
						b.Fatal("invalid benchmark assignment", runner, spec)
					}
					time.Sleep(10 * time.Millisecond)
					if pipelined {
						releaseRunner()
					}
					publication.Lock()
					defer publication.Unlock()
					time.Sleep(15 * time.Millisecond)
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
