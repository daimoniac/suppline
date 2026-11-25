package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

type fakeRecorder struct {
	mu      sync.Mutex
	beats   int
	removed string
	err     error
}

func (f *fakeRecorder) Heartbeat(context.Context, statestore.Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
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
		runHeartbeat(ctx, rec, statestore.Instance{Holder: "h"}, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	if rec.removed != "h" {
		t.Fatalf("removed %q on stop, want h", rec.removed)
	}
}
