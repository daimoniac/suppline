package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fastRetry() retryPolicy {
	return retryPolicy{MaxWait: 200 * time.Millisecond, Initial: time.Millisecond, Max: 4 * time.Millisecond}
}

// A PostgreSQL switchover refuses connections for a few seconds. Starting
// suppline then must wait for the new primary instead of exiting.
func TestRetryOpenWaitsForTheDatabase(t *testing.T) {
	calls, failures := 0, 0
	got, err := retryOpen(t.Context(), fastRetry(), func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("connect: connection refused")
		}
		return "store", nil
	}, func(error, time.Duration) { failures++ })
	if err != nil || got != "store" {
		t.Fatalf("retryOpen = %q, %v; want the store after two refusals", got, err)
	}
	if calls != 3 || failures != 2 {
		t.Fatalf("calls=%d failures reported=%d, want 3 and 2", calls, failures)
	}
}

func TestRetryOpenGivesUpAfterMaxWait(t *testing.T) {
	start := time.Now()
	_, err := retryOpen(t.Context(), fastRetry(), func() (string, error) {
		return "", errors.New("still down")
	}, func(error, time.Duration) {})
	if err == nil || err.Error() != "still down" {
		t.Fatalf("err = %v, want the last error", err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("gave up after %v, want about MaxWait", elapsed)
	}
}

func TestRetryOpenStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	policy := retryPolicy{MaxWait: time.Minute, Initial: 10 * time.Second, Max: 10 * time.Second}
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	_, err := retryOpen(ctx, policy, func() (string, error) { return "", errors.New("down") }, func(error, time.Duration) {})
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v, want context.Canceled promptly", err, time.Since(start))
	}
}
