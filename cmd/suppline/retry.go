package main

import (
	"context"
	"time"
)

// retryPolicy bounds how long startup waits for a dependency.
type retryPolicy struct {
	// MaxWait is the total time to keep trying.
	MaxWait time.Duration
	// Initial is the first delay; it doubles up to Max.
	Initial, Max time.Duration
}

// startupDBRetry rides out a PostgreSQL switchover, which refuses
// connections for a few seconds, and stays below the liveness probe's
// budget (about 90 s) so the pod is not killed while it waits.
var startupDBRetry = retryPolicy{MaxWait: 60 * time.Second, Initial: time.Second, Max: 15 * time.Second}

// retryOpen calls open until it succeeds, MaxWait has passed, or ctx ends.
// onFailure hears every failed attempt and the delay before the next one.
// It returns the last error when it gives up.
func retryOpen[T any](ctx context.Context, policy retryPolicy, open func() (T, error), onFailure func(err error, next time.Duration)) (T, error) {
	deadline := time.Now().Add(policy.MaxWait)
	delay := policy.Initial
	for {
		v, err := open()
		if err == nil {
			return v, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return v, err
		}
		wait := min(delay, remaining)
		onFailure(err, wait)
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case <-time.After(wait):
		}
		delay = min(delay*2, policy.Max)
	}
}
