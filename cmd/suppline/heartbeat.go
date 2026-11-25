package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// heartbeatInterval is how often every instance refreshes its row in the
// instances table; the cluster API lists rows newer than 30 s.
const heartbeatInterval = 10 * time.Second

type instanceRecorder interface {
	Heartbeat(ctx context.Context, in statestore.Instance) error
	RemoveInstance(ctx context.Context, holder string) error
}

// runHeartbeat records the instance now and every interval until ctx ends,
// then removes its row so the dashboard drops it at once.
func runHeartbeat(ctx context.Context, rec instanceRecorder, in statestore.Instance, every time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if err := rec.Heartbeat(ctx, in); err != nil && ctx.Err() == nil {
			logger.Warn("failed to record instance heartbeat", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			removeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if err := rec.RemoveInstance(removeCtx, in.Holder); err != nil {
				logger.Warn("failed to remove instance row; it ages out", "error", err.Error())
			}
			return
		case <-ticker.C:
		}
	}
}
