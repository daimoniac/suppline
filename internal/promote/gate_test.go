package promote

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/statestore"
)

type memStore struct {
	rec *statestore.ScanRecord
	err error
}

func (m memStore) GetLastRepositoryScan(context.Context, string, string) (*statestore.ScanRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.rec == nil {
		return nil, statestore.ErrScanNotFound
	}
	return m.rec, nil
}

func TestReady(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	rescan := 7 * 24 * time.Hour

	tests := []struct {
		name       string
		rec        *statestore.ScanRecord
		wantReady  bool
		wantQueued bool
	}{
		{name: "unscanned", wantQueued: true},
		{
			name: "passed and attested",
			rec: &statestore.ScanRecord{
				PolicyPassed: true,
				SCAIAttested: true,
				PolicyStatus: policy.PolicyStatusPassed,
				CreatedAt:    now.Unix(),
			},
			wantReady: true,
		},
		{
			name: "passed without attestation",
			rec: &statestore.ScanRecord{
				PolicyPassed: true,
				PolicyStatus: policy.PolicyStatusPassed,
				CreatedAt:    now.Unix(),
			},
			wantQueued: true,
		},
		{
			name: "recent failure",
			rec: &statestore.ScanRecord{
				PolicyStatus: policy.PolicyStatusFailed,
				CreatedAt:    now.Add(-time.Hour).Unix(),
			},
		},
		{
			name: "failure past rescan interval",
			rec: &statestore.ScanRecord{
				PolicyStatus: policy.PolicyStatusFailed,
				CreatedAt:    now.Add(-8 * 24 * time.Hour).Unix(),
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
			var queued int
			g := &Gate{
				Store: memStore{rec: tt.rec},
				Enqueue: func(context.Context, string, string, string) error {
					queued++
					return nil
				},
				RescanInterval: func(string) time.Duration { return rescan },
				Now:            func() time.Time { return now },
				Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			ready, err := g.Ready(context.Background(), "example/app", "1.0", "sha256:abc")
			if err != nil {
				t.Fatal(err)
			}
			if ready != tt.wantReady {
				t.Fatalf("ready = %t, want %t", ready, tt.wantReady)
			}
			gotQueued := queued > 0
			if gotQueued != tt.wantQueued {
				t.Fatalf("queued = %t, want %t", gotQueued, tt.wantQueued)
			}
		})
	}
}

func TestReady_StoreError(t *testing.T) {
	g := &Gate{Store: memStore{err: errors.New("db down")}}
	_, err := g.Ready(context.Background(), "example/app", "1.0", "sha256:abc")
	if err == nil {
		t.Fatal("expected error")
	}
}
