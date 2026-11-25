package leader

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type fakeLock struct {
	mu         sync.Mutex
	free       bool
	held       bool
	advertised string
	advertErr  error
	checkErr   error
	released   int
}

func (f *fakeLock) TryAcquire(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.free {
		return false, nil
	}
	f.free, f.held = false, true
	return true, nil
}

func (f *fakeLock) Check(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkErr
}

func (f *fakeLock) Advertise(_ context.Context, holder, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.advertErr != nil {
		return f.advertErr
	}
	f.advertised = holder + "@" + address
	return nil
}

func (f *fakeLock) Release(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held {
		f.held, f.free = false, true
	}
	f.released++
	return nil
}

func (f *fakeLock) set(fn func(*fakeLock)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func newTestElector(t *testing.T, lock *fakeLock, onElected func(context.Context), exit func(int)) *Elector {
	t.Helper()
	e, err := New(Config{
		Lock:          lock,
		Holder:        "pod-a",
		Address:       "http://10.0.0.1:8080",
		OnElected:     onElected,
		RetryInterval: 10 * time.Millisecond,
		CheckInterval: 10 * time.Millisecond,
		CheckTimeout:  time.Second,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Exit:          exit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestStandbyWaitsUntilLockIsFree(t *testing.T) {
	lock := &fakeLock{}
	started := make(chan struct{})
	e := newTestElector(t, lock, func(context.Context) { close(started) }, func(int) { t.Error("exit called") })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	select {
	case <-started:
		t.Fatal("elected while another instance held the lock")
	case <-time.After(100 * time.Millisecond):
	}

	lock.set(func(f *fakeLock) { f.free = true })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("not elected after the lock became free")
	}
	<-e.Elected()
	lock.set(func(f *fakeLock) {
		if f.advertised != "pod-a@http://10.0.0.1:8080" {
			t.Errorf("advertised %q", f.advertised)
		}
	})
}

func TestLeaderExitsWhenLockIsLost(t *testing.T) {
	lock := &fakeLock{free: true}
	exited := make(chan int, 1)
	var leaderCtx context.Context
	elected := make(chan struct{})
	e := newTestElector(t, lock, func(ctx context.Context) { leaderCtx = ctx; close(elected) }, func(code int) { exited <- code })

	done := make(chan error, 1)
	go func() { done <- e.Run(t.Context()) }()
	<-elected
	if leaderCtx.Err() != nil {
		t.Fatal("leader context ended while the lock was held")
	}

	lock.set(func(f *fakeLock) { f.checkErr = errors.New("session gone") })
	select {
	case code := <-exited:
		if code != 1 {
			t.Fatalf("exit code %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not exit after losing the lock")
	}
	if err := <-done; err == nil {
		t.Fatal("Run returned nil after losing the lock")
	}
}

func TestFailedAdvertiseGivesTheLockBack(t *testing.T) {
	lock := &fakeLock{free: true, advertErr: errors.New("write failed")}
	elected := make(chan struct{})
	e := newTestElector(t, lock, func(context.Context) { close(elected) }, func(int) {})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	lock.set(func(f *fakeLock) {
		if f.held || f.released == 0 {
			t.Errorf("lock held=%v released=%d after failed advertise; want given back", f.held, f.released)
		}
		f.advertErr = nil
	})
	select {
	case <-elected:
	case <-time.After(2 * time.Second):
		t.Fatal("not elected once advertising worked")
	}
}

func TestShutdownDoesNotExitOrRelease(t *testing.T) {
	lock := &fakeLock{free: true}
	elected := make(chan struct{})
	e := newTestElector(t, lock, func(context.Context) { close(elected) }, func(int) { t.Error("exit called on shutdown") })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	<-elected
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	lock.set(func(f *fakeLock) {
		if !f.held {
			t.Error("Run released the lock; the caller releases it after components stop")
		}
	})
	if err := e.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewHolderIDIsUnique(t *testing.T) {
	if a, b := NewHolderID(), NewHolderID(); a == b {
		t.Fatalf("NewHolderID returned %q twice", a)
	}
}
