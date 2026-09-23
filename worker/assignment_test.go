package worker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvictedAssignmentHasBoundedAcknowledgement(t *testing.T) {
	for _, state := range []string{"ready", "busy"} {
		t.Run(state, func(t *testing.T) {
			p := schedulerFixture(t)
			p.timing.poll, p.timing.lease = 5*time.Millisecond, 200*time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			remote := *p.statuses[2].Load()
			remote.Sequence = 1
			result := make(chan error, 1)
			go func() {
				_, err := p.remoteTask(ctx, 2, remote, poolTask{})
				result <- err
			}()

			control := p.bus.control.(*memoryCoordination)
			prefix := p.bus.prefix("assignment", 2)
			awaitPool(t, func() bool {
				control.Lock()
				defer control.Unlock()
				key := control.latest[prefix]
				if key == "" {
					return false
				}
				delete(control.latest, prefix)
				delete(control.objects, key)
				return true
			})
			status := *p.statuses[2].Load()
			status.State = state
			if state == "busy" {
				status.Sequence = remote.Sequence
			}
			ticker := time.NewTicker(p.timing.poll)
			defer ticker.Stop()
			deadline := time.NewTimer(3 * p.timing.lease)
			defer deadline.Stop()
			for {
				status.Sent = time.Now()
				copy := status
				p.statuses[2].Store(&copy)
				select {
				case err := <-result:
					if state != "ready" || err == nil || err.Error() != "builder did not acknowledge assignment" {
						t.Fatalf("unexpected assignment outcome with fresh %s statuses: %v", state, err)
					}
					return
				case <-deadline.C:
					if state == "ready" {
						t.Fatal("fresh ready heartbeats kept an evicted assignment pending")
					}
					cancel()
					if err := <-result; !errors.Is(err, context.Canceled) {
						t.Fatalf("acknowledged long build stopped before cancellation: %v", err)
					}
					return
				case <-ticker.C:
				}
			}
		})
	}
}
