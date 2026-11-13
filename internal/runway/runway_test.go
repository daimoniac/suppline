package runway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

const (
	repo    = "example/app"
	tag     = "1.0"
	oldDig  = "sha256:old"
	newDig  = "sha256:new"
	failErr = "db down"
)

// fakeRegistry is the registry tag table plus the scan state the runway reads.
type fakeRegistry struct {
	tags     map[string]string
	rec      *statestore.ScanRecord
	storeErr error
	bindings []string
	queued   []scanenqueue.DiscoveryKind
}

func (f *fakeRegistry) GetLastRepositoryScan(context.Context, string, string) (*statestore.ScanRecord, error) {
	if f.storeErr != nil {
		return nil, f.storeErr
	}
	if f.rec == nil {
		return nil, statestore.ErrScanNotFound
	}
	return f.rec, nil
}

func (f *fakeRegistry) EnsureArtifactTagBinding(_ context.Context, repository, digest, tag string) (bool, error) {
	f.bindings = append(f.bindings, repository+":"+tag+"@"+digest)
	return false, nil
}

func (f *fakeRegistry) MoveTag(_ context.Context, _, tag, digest string) error {
	f.tags[tag] = digest
	return nil
}

func (f *fakeRegistry) EnqueueDiscovery(_ context.Context, _ scanenqueue.Image, kind scanenqueue.DiscoveryKind) (*queue.ScanTask, error) {
	f.queued = append(f.queued, kind)
	return &queue.ScanTask{}, nil
}

func newRunway(f *fakeRegistry, now time.Time) *Runway {
	return New(Config{
		Store:          f,
		Tagger:         f,
		Scheduler:      f,
		RescanInterval: func(string) time.Duration { return 7 * 24 * time.Hour },
		Now:            func() time.Time { return now },
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestOffer_ExistingTag(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		rec           *statestore.ScanRecord
		wantPublished bool
		wantQueued    bool
	}{
		{name: "unscanned", wantQueued: true},
		{
			name: "passed and attested",
			rec: &statestore.ScanRecord{
				PolicyPassed: true, SCAIAttested: true,
				PolicyStatus: policy.PolicyStatusPassed, CreatedAt: now.Unix(),
			},
			wantPublished: true,
		},
		{
			name: "passed without attestation",
			rec: &statestore.ScanRecord{
				PolicyPassed: true, PolicyStatus: policy.PolicyStatusPassed, CreatedAt: now.Unix(),
			},
			wantQueued: true,
		},
		{
			name: "scan error",
			rec: &statestore.ScanRecord{
				PolicyPassed: true, SCAIAttested: true, ErrorMessage: "trivy failed",
				PolicyStatus: policy.PolicyStatusPassed, CreatedAt: now.Unix(),
			},
		},
		{
			name: "recent failure",
			rec: &statestore.ScanRecord{
				PolicyStatus: policy.PolicyStatusFailed, CreatedAt: now.Add(-time.Hour).Unix(),
			},
		},
		{
			name: "failure past rescan interval",
			rec: &statestore.ScanRecord{
				PolicyStatus: policy.PolicyStatusFailed, CreatedAt: now.Add(-8 * 24 * time.Hour).Unix(),
			},
			wantQueued: true,
		},
		{
			name: "pending inside release age",
			rec: &statestore.ScanRecord{
				PolicyStatus:             policy.PolicyStatusPending,
				MinimumReleaseAgeSeconds: int64((48 * time.Hour).Seconds()),
				ReleaseAgeSeconds:        int64(time.Hour.Seconds()),
				CreatedAt:                now.Unix(),
			},
		},
		{
			name: "pending after release age",
			rec: &statestore.ScanRecord{
				PolicyStatus:             policy.PolicyStatusPending,
				MinimumReleaseAgeSeconds: int64((48 * time.Hour).Seconds()),
				ReleaseAgeSeconds:        int64(time.Hour.Seconds()),
				CreatedAt:                now.Add(-48 * time.Hour).Unix(),
			},
			wantQueued: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeRegistry{tags: map[string]string{tag: oldDig}, rec: tt.rec}
			published, err := newRunway(f, now).Offer(context.Background(), Candidate{
				Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig,
			})
			if err != nil {
				t.Fatal(err)
			}
			if published != tt.wantPublished {
				t.Fatalf("published = %t, want %t", published, tt.wantPublished)
			}
			wantTag := oldDig
			if tt.wantPublished {
				wantTag = newDig
			}
			if f.tags[tag] != wantTag {
				t.Fatalf("tag names %s, want %s", f.tags[tag], wantTag)
			}
			if got := len(f.queued) > 0; got != tt.wantQueued {
				t.Fatalf("queued = %t, want %t", got, tt.wantQueued)
			}
			if tt.wantPublished != (len(f.bindings) == 1) {
				t.Fatalf("bindings = %v, want one binding only after a move", f.bindings)
			}
		})
	}
}

func TestOffer_NewTagPublishesWithoutScan(t *testing.T) {
	f := &fakeRegistry{tags: map[string]string{}}
	published, err := newRunway(f, time.Now()).Offer(context.Background(), Candidate{
		Repository: repo, Tag: tag, Digest: newDig,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !published || f.tags[tag] != newDig {
		t.Fatalf("new tag not published: published=%t tags=%v", published, f.tags)
	}
	if len(f.queued) != 0 || len(f.bindings) != 0 {
		t.Fatalf("new tag queued=%v bindings=%v, want neither", f.queued, f.bindings)
	}
}

func TestScanned_MovesHeldTagOnceAttested(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	f := &fakeRegistry{tags: map[string]string{tag: oldDig}}
	r := newRunway(f, now)

	if published, err := r.Offer(ctx, Candidate{Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig}); err != nil || published {
		t.Fatalf("offer: published=%t err=%v", published, err)
	}

	f.rec = &statestore.ScanRecord{PolicyStatus: policy.PolicyStatusFailed, CreatedAt: now.Unix()}
	r.Scanned(ctx, repo, newDig)
	if f.tags[tag] != oldDig {
		t.Fatalf("failed scan moved tag to %s", f.tags[tag])
	}

	f.rec = &statestore.ScanRecord{PolicyPassed: true, SCAIAttested: true, PolicyStatus: policy.PolicyStatusPassed, CreatedAt: now.Unix()}
	r.Scanned(ctx, repo, "sha256:other")
	if f.tags[tag] != oldDig {
		t.Fatalf("scan of another digest moved tag to %s", f.tags[tag])
	}
	r.Scanned(ctx, repo, newDig)
	if f.tags[tag] != newDig {
		t.Fatalf("attested scan left tag on %s", f.tags[tag])
	}
	if len(f.bindings) != 1 || f.bindings[0] != repo+":"+tag+"@"+newDig {
		t.Fatalf("bindings = %v", f.bindings)
	}

	f.bindings = nil
	r.Scanned(ctx, repo, newDig)
	if len(f.bindings) != 0 {
		t.Fatal("released candidate published twice")
	}
}

func TestOffer_StoreError(t *testing.T) {
	f := &fakeRegistry{tags: map[string]string{tag: oldDig}, storeErr: errors.New(failErr)}
	if _, err := newRunway(f, time.Now()).Offer(context.Background(), Candidate{
		Repository: repo, Tag: tag, Digest: newDig, Previous: oldDig,
	}); err == nil {
		t.Fatal("expected error")
	}
	if f.tags[tag] != oldDig {
		t.Fatal("store error moved tag")
	}
}
