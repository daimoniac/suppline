// Package configreload watches the suppline.yml file and applies a new parse
// when its contents change. Kubernetes updates a ConfigMap volume by swapping
// the data directory, so the check reads the file instead of trusting an
// inotify event on the path.
package configreload

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"time"

	"github.com/daimoniac/suppline/internal/config"
)

// Interval is how often the mounted config file is checked.
const Interval = 15 * time.Second

// Run checks path until ctx is done. The first contents are the config already
// loaded at startup and are not applied. A later change that parses replaces
// the running catalog through apply. A file that no longer parses is left
// unused and tried again on the next check.
func Run(ctx context.Context, logger *slog.Logger, path string, interval time.Duration, apply func(*config.RegsyncConfig)) {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = Interval
	}
	body, err := os.ReadFile(path)
	if err != nil {
		logger.Error("config reload cannot read the config file", "path", path, "error", err)
		return
	}
	sum := sha256.Sum256(body)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			parsed, next, err := readChange(path, sum)
			if err != nil {
				logger.Error("config reload rejected", "path", path, "error", err)
				continue
			}
			if parsed == nil {
				continue
			}
			apply(parsed)
			sum = next
		}
	}
}

// readChange parses path when its contents differ from sum. A nil config and a
// nil error means the file is unchanged. A parse or read error keeps sum so
// the next check tries the file again.
func readChange(path string, sum [32]byte) (*config.RegsyncConfig, [32]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, sum, err
	}
	next := sha256.Sum256(body)
	if next == sum {
		return nil, sum, nil
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		return nil, sum, err
	}
	return parsed, next, nil
}
