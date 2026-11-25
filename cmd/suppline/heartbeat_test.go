package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

type fakeRecorder struct {
	mu       sync.Mutex
	beats    int
	statuses []string
	removed  string
	err      error
}

func (f *fakeRecorder) Heartbeat(_ context.Context, in statestore.Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	f.statuses = append(f.statuses, in.Status)
	return f.err
}

func (f *fakeRecorder) RemoveInstance(_ context.Context, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = holder
	return nil
}

func TestHeartbeatBeatsUntilStoppedThenRemovesItself(t *testing.T) {
	rec := &fakeRecorder{err: errors.New("database briefly away")}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		var n atomic.Int32
		status := func() string {
			if n.Add(1) == 1 {
				return "unhealthy"
			}
			return "healthy"
		}
		runHeartbeat(ctx, rec, statestore.Instance{Holder: "h"}, status, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	time.Sleep(55 * time.Millisecond)
	cancel()
	<-done

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.beats < 3 {
		t.Fatalf("%d heartbeats in 55 ms at 10 ms; a failed beat must not stop the loop", rec.beats)
	}
	if rec.statuses[0] != "unhealthy" || rec.statuses[len(rec.statuses)-1] != "healthy" {
		t.Fatalf("statuses %v; each heartbeat must carry the current health", rec.statuses)
	}
	if rec.removed != "h" {
		t.Fatalf("removed %q on stop, want h", rec.removed)
	}
}
