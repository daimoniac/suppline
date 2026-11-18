package worker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/registry"
)

type fixedClock struct{ at *time.Time }

func (c fixedClock) FirstSeen(context.Context, string, string) (*time.Time, error) { return c.at, nil }

func TestCooldownFirstSeen(t *testing.T) {
	logger := observability.NewLogger("error")
	cfg := &config.RegsyncConfig{Sync: []config.SyncEntry{{
		Target: "myorg/app", Type: "repository",
		CooldownReleases: []config.CooldownRelease{{Digest: "sha256:released"}},
	}}}
	w := NewImageWorker(newMockQueue(1), nil, nil, nil, nil, nil, DefaultConfig(), logger, cfg)
	ctx := context.Background()

	// Without the runway, a Cooldown release stops the artifact clock.
	got, err := w.pipeline.cooldownFirstSeen(ctx, &queue.ScanTask{Repository: "myorg/app", Digest: "sha256:released"}, time.Now())
	if err != nil || got != nil {
		t.Fatalf("released digest: FirstSeen = %v, %v; want no clock", got, err)
	}

	// The runway's clock wins when it is set.
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	w.SetCooldownClock(fixedClock{at: &at})
	got, err = w.pipeline.cooldownFirstSeen(ctx, &queue.ScanTask{Repository: "myorg/app", Digest: "sha256:held"}, time.Now())
	if err != nil || got == nil || !got.Equal(at) {
		t.Fatalf("runway clock: FirstSeen = %v, %v; want %v", got, err, at)
	}
}

// missingTagRegistry reports every tag as missing, like a new tag the runway
// has not created yet.
type missingTagRegistry struct{ registry.Client }

func (missingTagRegistry) GetDigest(context.Context, string, string) (string, error) {
	return "", errors.NewManifestNotFoundf("tag not found")
}

// A Held digest of a new tag is scanned under a tag the registry does not
// have yet. The scan keeps that tag instead of cleaning the digest up.
func TestRetargetKeepsTagOfHeldDigest(t *testing.T) {
	logger := observability.NewLogger("error")
	w := NewImageWorker(newMockQueue(1), nil, nil, nil, missingTagRegistry{}, nil, DefaultConfig(), logger, &config.RegsyncConfig{})
	w.SetHeldDigests(func(string) []string { return []string{"sha256:held"} })
	task := &queue.ScanTask{Repository: "myorg/app", Digest: "sha256:held", Tag: "1.2.4"}

	if err := w.pipeline.retargetTaskTag(context.Background(), task, task.Repository, task.Digest, map[string]struct{}{}); err != nil {
		t.Fatalf("retargetTaskTag() error = %v, want the held tag kept", err)
	}
	if task.Tag != "1.2.4" {
		t.Errorf("task tag = %q, want 1.2.4", task.Tag)
	}

	other := &queue.ScanTask{Repository: "myorg/app", Digest: "sha256:gone", Tag: "1.2.4"}
	if err := w.pipeline.retargetTaskTag(context.Background(), other, other.Repository, other.Digest, map[string]struct{}{}); !errors.IsManifestNotFound(err) {
		t.Errorf("retargetTaskTag() for a digest no tag names = %v, want manifest not found", err)
	}
}

// A scan pending for its cooldown did not fail: it must not be reported as a
// policy failure, while a real failure still is.
func TestCheckPolicyFailuresIgnoresPendingCooldown(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	w := NewImageWorker(newMockQueue(1), nil, nil, nil, nil, nil, DefaultConfig(), logger, &config.RegsyncConfig{})
	task := &queue.ScanTask{Repository: "myorg/app", Digest: "sha256:held", Tag: "1.2.4", IsRescan: true}

	w.pipeline.checkPolicyFailures(context.Background(), task, &policy.PolicyDecision{
		Status: policy.PolicyStatusPending, Reason: "policy pending: cooldown 120h0m0s not over",
	})
	if strings.Contains(buf.String(), "failed policy") || strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("pending scan logged as a failure: %s", buf.String())
	}

	task.IsRescan = false
	w.pipeline.checkPolicyFailures(context.Background(), task, &policy.PolicyDecision{
		Status: policy.PolicyStatusFailed, Reason: "critical vulnerabilities found",
	})
	if !strings.Contains(buf.String(), "image failed policy evaluation") {
		t.Fatalf("failed scan not logged: %s", buf.String())
	}
}
