package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionHasTwoHelpersPerPlatform(t *testing.T) {
	matrix := allBuildRunners(t)
	helpers, err := matrix.Helpers()
	if err != nil || len(helpers["include"]) != 6 {
		t.Fatal(helpers, err)
	}
	for _, row := range matrix.Include {
		count := 0
		for _, helper := range helpers["include"] {
			if helper.System == row.System {
				count++
				if helper.Runner != row.Runner || helper.Builder < 1 || helper.Builder > 2 {
					t.Fatal(helper)
				}
			}
		}
		if count != 2 {
			t.Fatal(row, count)
		}
	}
	one, err := (BuildMatrix{Include: matrix.Include[:1]}).Helpers()
	if err != nil || len(one["include"]) != 2 {
		t.Fatal(one, err)
	}
}

func poolFixture(t *testing.T) *poolBus {
	t.Helper()
	identity, recipients := cacheKeys(t)
	bus, err := newPoolBus(newMemoryCache(), newMemoryCoordination(), cacheTestRepository, "12", "x86_64-linux", 1, identity, recipients, "source-commit")
	if err != nil {
		t.Fatal(err)
	}
	return bus
}

func awaitPool(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("pool did not make progress")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolMessagesAreEncryptedAndBoundToRequestAndRecord(t *testing.T) {
	bus := poolFixture(t)
	message := poolMessage{Session: "session", Instance: "instance", Sequence: 7, State: "build", Task: &poolTask{Installable: "private-derivation"}}
	if err := bus.write("assignment", 2, message); err != nil {
		t.Fatal(err)
	}
	received, err := bus.read("assignment", 2)
	if err != nil || received.Task.Installable != "private-derivation" || received.Sequence != 7 {
		t.Fatal(received, err)
	}
	control := bus.control.(*memoryCoordination)
	original := control.latest[bus.prefix("assignment", 2)]
	encrypted := control.objects[original]
	if bytes.Contains(encrypted, []byte("private-derivation")) {
		t.Fatal("plaintext assignment")
	}

	for _, change := range []string{"runner", "run", "system", "attempt", "repository", "source", "request"} {
		t.Run(change, func(t *testing.T) {
			repository, run, system, attempt, binding, runner := bus.repository, bus.run, bus.system, bus.attempt, "source-commit", 2
			switch change {
			case "runner":
				runner = 1
			case "run":
				run = "13"
			case "system":
				system = "aarch64-linux"
			case "attempt":
				attempt++
			case "repository":
				repository = "ghcr.io/test/other"
			default:
				binding = change
			}
			other, err := newPoolBus(bus.storage, control, repository, run, system, attempt, bus.identity, bus.recipients, binding)
			if err != nil {
				t.Fatal(err)
			}
			if other.prefix("assignment", runner) == bus.prefix("assignment", 2) {
				t.Fatal("mailbox binding collision")
			}
			key := other.prefix("assignment", runner) + poolNonce()
			control.Write(key, encrypted)
			if _, err := other.read("assignment", runner); err == nil {
				t.Fatal("accepted replay into another binding")
			}
		})
	}
	// Copying even a valid message to a newer entry must not reset the mailbox.
	control.Write(bus.prefix("assignment", 2)+poolNonce(), encrypted)
	if _, err := bus.read("assignment", 2); err == nil {
		t.Fatal("accepted message under a different record key")
	}
	// Possession of the public age recipient is insufficient to forge commands.
	key := bus.prefix("assignment", 2) + poolNonce()
	raw, _ := json.Marshal(message)
	envelope, _ := json.Marshal(poolEnvelope{raw, strings.Repeat("0", 64)})
	stream, err := EncryptedStream(bytes.NewReader(envelope), bus.controlRecipients)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := io.ReadAll(stream)
	stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	control.Write(key, forged)
	if _, err := bus.read("assignment", 2); err == nil {
		t.Fatal("accepted forged assignment")
	}
}

func TestPoolRejectsExpiredAndFutureLeases(t *testing.T) {
	old := &poolMessage{Sent: time.Now().Add(-poolLease - time.Second)}
	if poolFresh(old, poolLease) {
		t.Fatal("expired lease accepted")
	}
	if poolFresh(&poolMessage{Sent: time.Now().Add(2 * time.Minute)}, poolLease) {
		t.Fatal("future lease accepted")
	}
}

func TestPoolCachedReadsPreserveLeaseAndIgnoreStaleEntries(t *testing.T) {
	bus := poolFixture(t)
	control := bus.control.(*memoryCoordination)
	if err := bus.write("status", 2, poolMessage{State: "ready"}); err != nil {
		t.Fatal(err)
	}
	first, err := bus.read("status", 2)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := control.latest[bus.prefix("status", 2)]
	sent := first.Sent
	first.State = "changed by caller"
	for range 3 {
		cached, err := bus.read("status", 2)
		if err != nil || cached.State != "ready" || cached.Sent != sent {
			t.Fatal("cached record or lease changed", cached, err)
		}
	}
	if control.downloads != 1 {
		t.Fatal("unchanged record downloaded again", control.downloads)
	}
	if err := bus.write("status", 2, poolMessage{State: "done"}); err != nil {
		t.Fatal(err)
	}
	updated, err := bus.read("status", 2)
	if err != nil || updated.State != "done" {
		t.Fatal(updated, err)
	}
	control.latest[bus.prefix("status", 2)] = oldKey
	stale, err := bus.read("status", 2)
	if err != nil || stale.State != "done" || stale.Sent != updated.Sent {
		t.Fatal("stale entry rolled back mailbox", stale, err)
	}
	// Missing entries cannot become a new lease, including after cache eviction.
	delete(control.latest, bus.prefix("status", 2))
	if _, err := bus.read("status", 2); !errors.Is(err, ErrObjectNotFound) {
		t.Fatal(err)
	}
}

func TestRunnerBuildsOneTaskAndJoinsCancellation(t *testing.T) {
	for runner := 1; runner < RunnersPerSystem; runner++ {
		t.Run(fmt.Sprint(runner), func(t *testing.T) {
			bus := poolFixture(t)
			if err := bus.write("coordinator", 0, poolMessage{Session: "session", State: "running"}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, stopped := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- servePoolBuilder(ctx, bus, runner, nil, poolTiming{5 * time.Millisecond, 20 * time.Millisecond, time.Second, time.Second}, func(ctx context.Context, task poolTask) (string, error) {
					close(started)
					<-ctx.Done()
					close(stopped)
					return "", ctx.Err()
				}, io.Discard)
			}()
			var status *poolMessage
			awaitPool(t, func() bool { status, _ = bus.read("status", runner); return status != nil })
			if err := bus.write("assignment", runner, poolMessage{Session: "session", Instance: status.Instance, Sequence: 1, State: "build", Task: &poolTask{}}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("runner did not start its task")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("runner returned before joining its task", err)
				}
				<-stopped
			case <-time.After(3 * time.Second):
				t.Fatal("runner did not cancel its task")
			}
		})
	}
}

func TestHelperPublishesCompletionWithoutWaitingForPoll(t *testing.T) {
	bus := poolFixture(t)
	if err := bus.write("coordinator", 0, poolMessage{Session: "session", State: "running"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- servePoolBuilder(ctx, bus, 2, nil, poolTiming{time.Second, time.Minute, time.Minute, time.Minute}, func(ctx context.Context, task poolTask) (string, error) {
			close(started)
			select {
			case <-release:
				return "sha256:" + strings.Repeat("a", 64), nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}, io.Discard)
	}()
	var status *poolMessage
	awaitPool(t, func() bool { status, _ = bus.read("status", 2); return status != nil })
	if err := bus.write("assignment", 2, poolMessage{Session: "session", Instance: status.Instance, Sequence: 1, State: "build", Task: &poolTask{}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not start")
	}
	close(release)
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		status, err := bus.read("status", 2)
		if err == nil && status.State == "done" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finished task waited for the next poll")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestHelperAcknowledgesOnceAndExitsAfterUploading(t *testing.T) {
	bus := poolFixture(t)
	coordinator := poolMessage{Session: "session", State: "running"}
	if err := bus.write("coordinator", 0, coordinator); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var builds atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- servePoolBuilder(ctx, bus, 2, []string{"big-parallel"}, poolTiming{5 * time.Millisecond, 20 * time.Millisecond, 2 * time.Second, 2 * time.Second}, func(ctx context.Context, task poolTask) (string, error) {
			builds.Add(1)
			select {
			case <-release:
				return "sha256:" + strings.Repeat("a", 64), nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}, io.Discard)
	}()
	var status *poolMessage
	awaitPool(t, func() bool { status, _ = bus.read("status", 2); return status != nil && status.State == "ready" })
	assignment := poolMessage{Session: "session", Instance: status.Instance, Sequence: 1, State: "build", Task: &poolTask{Installable: "task"}}
	if err := bus.write("assignment", 2, assignment); err != nil {
		t.Fatal(err)
	}
	awaitPool(t, func() bool { return builds.Load() == 1 })
	if err := bus.write("assignment", 2, assignment); err != nil {
		t.Fatal(err)
	}
	coordinator.State = "stop"
	if err := bus.write("coordinator", 0, coordinator); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatal("helper exited during output upload", err)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not exit")
	}
	status, err := bus.read("status", 2)
	if err != nil || status.State != "done" || status.Sequence != 1 || status.Snapshot == "" || builds.Load() != 1 {
		t.Fatal(status, builds.Load(), err)
	}
}

func TestHelperCancelsBuildAfterCoordinatorLeaseExpires(t *testing.T) {
	bus := poolFixture(t)
	if err := bus.write("coordinator", 0, poolMessage{Session: "session", State: "running"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, cancelled := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- servePoolBuilder(ctx, bus, 2, nil, poolTiming{5 * time.Millisecond, 20 * time.Millisecond, 300 * time.Millisecond, time.Second}, func(ctx context.Context, task poolTask) (string, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return "", ctx.Err()
		}, io.Discard)
	}()
	var status *poolMessage
	awaitPool(t, func() bool { status, _ = bus.read("status", 2); return status != nil })
	if err := bus.write("assignment", 2, poolMessage{Session: "session", Instance: status.Instance, Sequence: 1, State: "build", Task: &poolTask{}}); err != nil {
		t.Fatal(err)
	}
	<-started
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired lease succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lease did not expire")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("abandoned build did not cancel")
	}
}

type failingPoolStatusStorage struct {
	coordinationStore
	tag       string
	failed    chan struct{}
	once      sync.Once
	recovered atomic.Bool
}

func (s *failingPoolStatusStorage) Write(key string, data []byte) error {
	if strings.HasPrefix(key, s.tag) && !s.recovered.Load() {
		s.once.Do(func() { close(s.failed) })
		return errors.New("status upload unavailable")
	}
	return s.coordinationStore.Write(key, data)
}

func TestHelperCanCancelWhileFinalStatusUploadFails(t *testing.T) {
	bus := poolFixture(t)
	if err := bus.write("coordinator", 0, poolMessage{Session: "session", State: "stop"}); err != nil {
		t.Fatal(err)
	}
	storage := &failingPoolStatusStorage{coordinationStore: bus.control, tag: bus.prefix("status", 2), failed: make(chan struct{})}
	bus.control = storage
	defer storage.recovered.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- servePoolBuilder(ctx, bus, 2, nil, poolTiming{10 * time.Millisecond, time.Millisecond, time.Second, time.Second}, func(context.Context, poolTask) (string, error) {
			return "", errors.New("unexpected assignment")
		}, io.Discard)
	}()
	select {
	case <-storage.failed:
	case <-time.After(time.Second):
		t.Fatal("helper did not attempt final status upload")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed status uploads prevented cancellation")
	}
}

func schedulerFixture(t *testing.T) *BuildPool {
	t.Helper()
	p := &BuildPool{cpus: 4, timing: poolTiming{time.Millisecond, poolHeartbeat, poolLease, time.Second}, bus: poolFixture(t), session: "session", ctx: context.Background(), log: io.Discard}
	for runner := 1; runner < RunnersPerSystem; runner++ {
		p.statuses[runner].Store(&poolMessage{Session: p.session, Instance: fmt.Sprint(runner), State: "ready", Cores: 4, Sent: time.Now(), Features: []string{"big-parallel"}})
	}
	return p
}

func TestSchedulerUsesEveryRunnerAndUnlocksDependenciesImmediately(t *testing.T) {
	p := schedulerFixture(t)
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "b": derivation("b-out"), "c": derivation("c-out"), "d": derivation("d-out"), "e": derivation("e-out"), "f": derivation("f-out"), "g": derivation("g-out", "cached"), "cached": derivation("cached-out", "a")}}
	started := make(chan string, 7)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		done <- p.schedule(graph, []string{"a^out", "b^out", "c^out", "d^out", "e^out", "f^out", "g^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
			started <- fmt.Sprintf("%d:%s", runner, spec)
			if spec == "a^out" {
				time.Sleep(30 * time.Millisecond)
				return nil
			}
			if spec == "g^out" {
				return nil
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	seen := map[string]bool{}
	for len(seen) < 4 {
		select {
		case event := <-started:
			seen[event] = true
		case <-time.After(3 * time.Second):
			t.Fatal("dependency waited behind unrelated large builds", seen)
		}
	}
	for _, event := range []string{"0:a^out", "1:b^out", "2:c^out", "0:d^out"} {
		if !seen[event] {
			t.Fatal(seen)
		}
	}
	once.Do(func() { close(release) })
	for len(seen) < 7 {
		seen[<-started] = true
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !p.stop.Load() {
		t.Fatal("helpers were not drained")
	}
}

func TestSchedulerRetriesRemoteFailureLocallyAndKeepsOtherWork(t *testing.T) {
	p := schedulerFixture(t)
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "b": derivation("b-out"), "c": derivation("c-out"), "d": derivation("d-out", "c")}}
	var mu sync.Mutex
	type attempts struct{ local, remote int }
	counts := map[string]attempts{}
	err := p.schedule(graph, []string{"a^out", "b^out", "c^out", "d^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
		mu.Lock()
		defer mu.Unlock()
		count := counts[spec]
		if runner > 0 {
			count.remote++
			counts[spec] = count
			return errors.New("lost helper")
		}
		count.local++
		counts[spec] = count
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := 0
	for drv := range graph.Derivations {
		count := counts[drv+"^out"]
		if count.local != 1 || count.remote > 1 {
			t.Fatalf("%s: expected one local completion and at most one helper attempt, got %+v", drv, count)
		}
		remote += count.remote
	}
	if remote == 0 {
		t.Fatal("no helper attempted a build", counts)
	}
}

func TestPoolHonorsFeaturesAndLocalBuildPreference(t *testing.T) {
	d := derivation("out")
	d.System = "x86_64-linux"
	d.Env = map[string]string{"requiredSystemFeatures": "kvm big-parallel"}
	if poolCompatible(d, "x86_64-linux", []string{"big-parallel"}) {
		t.Fatal("missing features accepted")
	}
	if !poolCompatible(d, "x86_64-linux", []string{"big-parallel", "kvm"}) {
		t.Fatal("compatible helper rejected")
	}
	d.Env = map[string]string{"__json": `{"requiredSystemFeatures":["kvm"],"preferLocalBuild":false}`}
	if poolCompatible(d, "x86_64-linux", nil) {
		t.Fatal("structured feature requirement ignored")
	}
	if !poolCompatible(d, "x86_64-linux", []string{"kvm"}) {
		t.Fatal("structured compatible build rejected")
	}
	d.Env["preferLocalBuild"] = "1"
	if poolCompatible(d, "x86_64-linux", []string{"big-parallel", "kvm"}) {
		t.Fatal("local preference ignored")
	}
}

func TestHelperWaitsForItsFinalAssignmentBeforeDraining(t *testing.T) {
	bus := poolFixture(t)
	if err := bus.write("coordinator", 0, poolMessage{Session: "session", State: "running", Finish: []uint64{0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var built atomic.Int32
	go func() {
		done <- servePoolBuilder(ctx, bus, 2, nil, poolTiming{5 * time.Millisecond, 10 * time.Millisecond, 2 * time.Second, 2 * time.Second}, func(context.Context, poolTask) (string, error) {
			built.Add(1)
			return "sha256:" + strings.Repeat("a", 64), nil
		}, io.Discard)
	}()
	var status *poolMessage
	awaitPool(t, func() bool { status, _ = bus.read("status", 2); return status != nil })
	select {
	case err := <-done:
		t.Fatal("helper exited before receiving its last assignment", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := bus.write("assignment", 2, poolMessage{Session: "session", Instance: status.Instance, Sequence: 1, State: "build", Task: &poolTask{}}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not drain after final assignment")
	}
	if built.Load() != 1 {
		t.Fatal("last assignment not built")
	}
}

func TestCoordinatorRejectsStaleResultAndReplacedHelper(t *testing.T) {
	p := schedulerFixture(t)
	remote := *p.statuses[2].Load()
	remote.Sequence = 2
	p.statuses[2].Store(&poolMessage{Session: p.session, Instance: remote.Instance, Sequence: 1, State: "done", Snapshot: "sha256:" + strings.Repeat("a", 64), Sent: time.Now()})
	p.timing.poll = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.remoteTask(ctx, 2, remote, poolTask{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("old result completed a new assignment")
	}
	changed := remote
	changed.Instance = "replacement"
	changed.Sent = time.Now()
	p.statuses[2].Store(&changed)
	if _, err := p.remoteTask(context.Background(), 2, remote, poolTask{}); err == nil {
		t.Fatal("replaced helper completed prior assignment")
	}
}

func TestCoordinatorAcceptsResultWhenStatusArrives(t *testing.T) {
	p := schedulerFixture(t)
	p.timing.poll = time.Hour
	p.changed[2] = make(chan struct{}, 1)
	remote := *p.statuses[2].Load()
	remote.Sequence = 1
	result := NewSnapshot(p.bus.storage, p.bus.repository)
	result.Metadata = map[string]any{"kind": "pool", "run": p.bus.run}
	digest, err := result.Publish(p.bus.tag("result", 2), p.bus.recipients)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		snapshot, err := p.remoteTask(ctx, 2, remote, poolTask{})
		if err == nil && snapshot.Digest != digest {
			err = errors.New("wrong result snapshot")
		}
		done <- err
	}()
	awaitPool(t, func() bool { _, err := p.bus.read("assignment", 2); return err == nil })
	completed := remote
	completed.State, completed.Snapshot = "done", digest
	p.statuses[2].Store(&completed)
	p.changed[2] <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("coordinator waited for a poll after receiving the result")
	}
}

func TestCoordinatorRejectsHelperEvaluationPlans(t *testing.T) {
	p := schedulerFixture(t)
	result := NewSnapshot(p.bus.storage, p.bus.repository)
	if err := cacheAdd(result, evaluationFile(p.bus.system), strings.NewReader("forged plan"), p.bus.recipients); err != nil {
		t.Fatal(err)
	}
	result.Metadata = map[string]any{"kind": "pool", "run": p.bus.run}
	digest, err := result.Publish(p.bus.tag("result", 2), p.bus.recipients)
	if err != nil {
		t.Fatal(err)
	}
	remote := *p.statuses[2].Load()
	remote.Sequence = 1
	completed := remote
	completed.State, completed.Snapshot = "done", digest
	p.statuses[2].Store(&completed)
	if _, err := p.remoteTask(context.Background(), 2, remote, poolTask{}); err == nil {
		t.Fatal("helper injected a coordinator evaluation plan")
	}
}

func TestSchedulerKeepsHelpersWhileDependenciesCanUnlockWork(t *testing.T) {
	p := schedulerFixture(t)
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "b": derivation("b-out", "a")}}
	err := p.schedule(graph, []string{"a^out", "b^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
		if spec == "a^out" && p.finish.Load() != nil {
			return errors.New("helpers drained with unassigned dependent work")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerAllowsHelpersToExitAfterFinalAssignment(t *testing.T) {
	tasks := 3
	t.Run(fmt.Sprintf("%d tasks", tasks), func(t *testing.T) {
		p := schedulerFixture(t)
		p.timing.startup = 0
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		p.ctx = ctx
		var log bytes.Buffer
		p.log = &log
		graph := &Plan{Derivations: map[string]Derivation{}}
		missing := []string{}
		for i := 0; i < tasks; i++ {
			drv := fmt.Sprint(i)
			graph.Derivations[drv] = derivation(drv + "-out")
			missing = append(missing, drv+"^out")
		}
		finished := make(chan struct{})
		var builds [RunnersPerSystem]atomic.Int32
		err := p.schedule(graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
			builds[runner].Add(1)
			if runner != 2 {
				select {
				case <-finished:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			for p.finish.Load() == nil {
				select {
				case <-time.After(time.Millisecond):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			// A finished helper stops its heartbeat while the other tasks finish.
			status := *p.statuses[2].Load()
			status.State, status.Sequence = "done", remote.Sequence
			status.Sent = time.Now().Add(-p.timing.lease - time.Second)
			p.statuses[2].Store(&status)
			close(finished)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(log.String(), "warning:") {
			t.Fatalf("successful helper exit produced a warning:\n%s", &log)
		}
		for runner := range RunnersPerSystem {
			if builds[runner].Load() != 1 {
				t.Fatalf("runner %d built %d tasks", runner, builds[runner].Load())
			}
		}
	})
}

func TestSchedulerRetriesExpiredFinalAssignmentOnCoordinator(t *testing.T) {
	p := schedulerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p.ctx = ctx
	graph := &Plan{Derivations: map[string]Derivation{"a": derivation("a-out"), "b": derivation("b-out"), "c": derivation("c-out")}}
	var attempts [RunnersPerSystem]atomic.Int32
	err := p.schedule(graph, []string{"a^out", "b^out", "c^out"}, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
		attempts[runner].Add(1)
		if runner == 0 {
			return nil
		}
		for p.finish.Load() == nil {
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		status := remote
		status.State, status.Sent = "busy", time.Now().Add(-p.timing.lease-time.Second)
		p.statuses[runner].Store(&status)
		_, err := p.remoteTask(ctx, runner, remote, poolTask{Installable: spec})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts[0].Load() != 3 || attempts[1].Load()+attempts[2].Load() != 2 {
		t.Fatalf("unfinished helper task was not retried locally: %d/%d/%d", attempts[0].Load(), attempts[1].Load(), attempts[2].Load())
	}
}

func TestSchedulerStopsAssignmentsWhenRetirementFails(t *testing.T) {
	p := schedulerFixture(t)
	graph := &Plan{Derivations: map[string]Derivation{}}
	missing := []string{}
	for i := range 30 {
		drv := fmt.Sprint(i)
		graph.Derivations[drv] = derivation(drv + "-out")
		missing = append(missing, drv+"^out")
	}
	var started atomic.Int32
	err := p.schedule(graph, missing, func(ctx context.Context, runner int, spec string, remote poolMessage) error {
		started.Add(1)
		return fmt.Errorf("%w: retirement failed", errPoolPublication)
	})
	if !errors.Is(err, errPoolPublication) || started.Load() != RunnersPerSystem {
		t.Fatal("retirement backlog admitted more work", started.Load(), err)
	}
}
