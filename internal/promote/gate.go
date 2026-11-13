// Package promote decides when a mirrored tag may move onto a new digest.
// The digest is copied first. The tag stays on the previous digest until that
// new digest has a passing SCAI attestation, so a cluster pulling the tag
// never resolves an image Kyverno cannot verify.
package promote

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/statestore"
)

// Scanner is the scan lookup the gate needs.
type Scanner interface {
	GetLastRepositoryScan(ctx context.Context, repository, digest string) (*statestore.ScanRecord, error)
}

// Gate implements mirror.TagGate.
type Gate struct {
	Store          Scanner
	Enqueue        func(ctx context.Context, repository, tag, digest string) error
	RescanInterval func(repository string) time.Duration
	Now            func() time.Time
	Log            *slog.Logger
}

// Ready reports whether tag in repository may move to digest.
// A false result leaves the tag in place. A digest that is not yet acceptable
// is enqueued when its retry window has elapsed.
func (g *Gate) Ready(ctx context.Context, repository, tag, digest string) (bool, error) {
	if g == nil || g.Store == nil {
		return false, nil
	}
	rec, err := g.Store.GetLastRepositoryScan(ctx, repository, digest)
	if err != nil && !errors.Is(err, statestore.ErrScanNotFound) {
		return false, err
	}
	if errors.Is(err, statestore.ErrScanNotFound) {
		rec = nil
	}
	if acceptable(rec) {
		return true, nil
	}
	if !due(rec, g.now(), g.rescan(repository)) {
		g.logger().Info("holding tag; scan is not ready to retry",
			"repository", repository,
			"tag", tag,
			"digest", digest,
			"policy_status", statusOf(rec))
		return false, nil
	}
	if g.Enqueue == nil {
		return false, nil
	}
	if err := g.Enqueue(ctx, repository, tag, digest); err != nil {
		return false, err
	}
	g.logger().Info("queued scan before tag move",
		"repository", repository,
		"tag", tag,
		"digest", digest)
	return false, nil
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) rescan(repository string) time.Duration {
	if g.RescanInterval == nil {
		return 7 * 24 * time.Hour
	}
	interval := g.RescanInterval(repository)
	if interval <= 0 {
		return 7 * 24 * time.Hour
	}
	return interval
}

func (g *Gate) logger() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

func acceptable(rec *statestore.ScanRecord) bool {
	return rec != nil && rec.PolicyPassed && rec.SCAIAttested && rec.ErrorMessage == ""
}

// due reports whether a digest that is not acceptable should be scanned again.
func due(rec *statestore.ScanRecord, now time.Time, rescan time.Duration) bool {
	if rec == nil {
		return true
	}
	age := now.Sub(time.Unix(rec.CreatedAt, 0))
	if rec.PolicyStatus == policy.PolicyStatusPending {
		wait := time.Duration(rec.MinimumReleaseAgeSeconds-rec.ReleaseAgeSeconds) * time.Second
		if wait < 0 {
			wait = 0
		}
		return age >= wait
	}
	if rec.PolicyPassed && !rec.SCAIAttested {
		return true
	}
	return age >= rescan
}

func statusOf(rec *statestore.ScanRecord) string {
	if rec == nil {
		return ""
	}
	return rec.PolicyStatus
}
