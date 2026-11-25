package triage

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	suppErrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/statestore"
)

// flakyScans fails ListScans with a transient error while down is set.
type flakyScans struct {
	statestore.StateStoreQuery
	down  atomic.Bool
	calls atomic.Int32
}

func (f *flakyScans) ListScans(context.Context, statestore.ScanFilter) ([]*statestore.ScanRecord, error) {
	f.calls.Add(1)
	if f.down.Load() {
		return nil, suppErrors.NewTransientf("failed to query scans: FATAL: terminating connection due to administrator command (SQLSTATE 57P01)")
	}
	return nil, nil
}

// countingRuns counts recorded triage runs.
type countingRuns struct {
	stubRuns
	mu       sync.Mutex
	inserted int
}

func (c *countingRuns) InsertTriageRun(context.Context, *statestore.TriageRun) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inserted++
	return nil
}

func (c *countingRuns) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inserted
}

func outageService(scans *flakyScans, runs *countingRuns) *Service {
	return &Service{
		settings:   Settings{Enabled: true},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		jobs:       make(chan Job, 64),
		pending:    map[string]ActiveJob{},
		scans:      scans,
		runs:       runs,
		retryMin:   10 * time.Millisecond,
		retryMax:   20 * time.Millisecond,
		pullAll:    func(context.Context) ([]gitops.Checkout, Roots, error) { return nil, Roots{}, nil },
		budgetWait: make(chan struct{}),
	}
}

// A PostgreSQL switchover must not turn the whole triage backlog into
// recorded errors: the batch stops and its jobs stay queued.
func TestProcessBatchKeepsJobsWhenTheDatabaseIsDown(t *testing.T) {
	scans := &flakyScans{}
	scans.down.Store(true)
	runs := &countingRuns{}
	svc := outageService(scans, runs)

	for _, repo := range []string{"app", "db"} {
		for _, cve := range []string{"CVE-1", "CVE-2", "CVE-3"} {
			svc.Retry(context.Background(), repo, cve)
		}
	}
	var batch []Job
	for len(svc.jobs) > 0 {
		batch = append(batch, <-svc.jobs)
	}

	retry := svc.processBatch(context.Background(), batch)
	if len(retry) != len(batch) {
		t.Fatalf("retry %d jobs, want all %d", len(retry), len(batch))
	}
	if scans.calls.Load() != 1 {
		t.Fatalf("ListScans called %d times; the batch must stop at the first outage error", scans.calls.Load())
	}
	if runs.count() != 0 {
		t.Fatalf("recorded %d triage runs as errors during the outage", runs.count())
	}
	if svc.Pending() != len(batch) {
		t.Fatalf("pending = %d, want the %d jobs kept", svc.Pending(), len(batch))
	}
}

// Once the database is back the kept jobs run.
func TestStartRetriesJobsAfterTheDatabaseReturns(t *testing.T) {
	scans := &flakyScans{}
	scans.down.Store(true)
	svc := outageService(scans, &countingRuns{})
	svc.Retry(context.Background(), "app", "CVE-1")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = svc.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for scans.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("job was not retried while the database was down")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if svc.Pending() != 1 {
		t.Fatalf("pending = %d during the outage, want 1", svc.Pending())
	}
	scans.down.Store(false)
	for svc.Pending() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("job still pending after the database came back")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
