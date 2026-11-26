package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	suppErrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
)

const (
	ciRepo   = "ci.local/group/app"
	ciTag    = "sha1a2b3c4d"
	ciDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

type scanRequestStore struct {
	mockStateStore
	mu      sync.Mutex
	records map[string]*statestore.ScanRecord
	// failRead, when set, fails the n-th read (1-based) with a transient
	// error, as a PostgreSQL switchover does.
	failRead func(n int) bool
	reads    int
}

func (s *scanRequestStore) GetLastRepositoryScan(_ context.Context, repository, digest string) (*statestore.ScanRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.failRead != nil && s.failRead(s.reads) {
		return nil, suppErrors.NewTransientf("query: FATAL: terminating connection due to administrator command (SQLSTATE 57P01)")
	}
	if record, ok := s.records[repository+"@"+digest]; ok {
		copied := *record
		return &copied, nil
	}
	return nil, statestore.ErrScanNotFound
}

func (s *scanRequestStore) put(record *statestore.ScanRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = map[string]*statestore.ScanRecord{}
	}
	s.records[record.Repository+"@"+record.Digest] = record
}

type fakeResolver map[string]string

func (f fakeResolver) GetDigest(_ context.Context, repo, tag string) (string, error) {
	if digest, ok := f[repo+":"+tag]; ok {
		return digest, nil
	}
	return "", errors.New("MANIFEST_UNKNOWN")
}

type scanRequestFixture struct {
	server *APIServer
	store  *scanRequestStore
	queue  *queue.InMemoryQueue
	waiter *ScanRequestWaiter
}

func newScanRequestFixture(t *testing.T, apiKey string) *scanRequestFixture {
	t.Helper()
	cfg := &config.RegsyncConfig{Sync: []config.SyncEntry{
		{Source: "upstream/app", Target: "mirror.local/app", Type: "repository"},
		{
			Source: ciRepo, Target: ciRepo, Type: "repository", InPlace: true,
			ScanRequesters: []string{"group/app"},
			Tags:           &config.TagFilter{Allow: []string{"sha[0-9a-f]{8,}"}},
		},
	}}
	store := &scanRequestStore{}
	taskQueue := queue.NewInMemoryQueue(100)
	server := NewAPIServerWithEnqueuer(&config.APIConfig{Port: 8080, APIKey: apiKey}, mockAttestationConfig(), store, taskQueue, scanenqueue.New(taskQueue, nil), cfg, observability.NewLogger("error"))
	waiter := NewScanRequestWaiter()
	server.SetScanRequests(fakeResolver{ciRepo + ":" + ciTag: ciDigest, ciRepo + ":latest": ciDigest}, waiter)
	return &scanRequestFixture{server: server, store: store, queue: taskQueue, waiter: waiter}
}

func (f *scanRequestFixture) do(method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.server.router.ServeHTTP(w, req)
	return w
}

// finishNextTask plays the worker: it takes the queued task, persists a scan
// record when record is set, and reports the task finished.
func (f *scanRequestFixture) finishNextTask(t *testing.T, record *statestore.ScanRecord, err error) *queue.ScanTask {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	task, dequeueErr := f.queue.Dequeue(ctx)
	if dequeueErr != nil {
		t.Fatalf("no task was queued: %v", dequeueErr)
	}
	if record != nil {
		f.store.put(record)
	}
	f.waiter.Finished(ctx, task, err)
	return task
}

func decodeResult(t *testing.T, w *httptest.ResponseRecorder) ScanRequestResult {
	t.Helper()
	var result ScanRequestResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return result
}

func TestScanRequest_RejectsBadRequests(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	other := "sha256:" + strings.Repeat("2", 64)
	cases := []struct {
		name   string
		body   string
		token  string
		status int
	}{
		{"no credentials", `{"image":"` + ciRepo + `:` + ciTag + `"}`, "", http.StatusUnauthorized},
		{"wrong key", `{"image":"` + ciRepo + `:` + ciTag + `"}`, "nope", http.StatusUnauthorized},
		{"no tag", `{"image":"` + ciRepo + `"}`, "secret", http.StatusBadRequest},
		{"unknown field", `{"image":"` + ciRepo + `:` + ciTag + `","x":1}`, "secret", http.StatusBadRequest},
		{"not configured", `{"image":"ci.local/other:` + ciTag + `"}`, "secret", http.StatusNotFound},
		{"mirrored", `{"image":"mirror.local/app:1.0"}`, "secret", http.StatusUnprocessableEntity},
		{"tag filtered", `{"image":"` + ciRepo + `:latest"}`, "secret", http.StatusUnprocessableEntity},
		{"unknown tag", `{"image":"` + ciRepo + `:sha99999999"}`, "secret", http.StatusNotFound},
		{"digest mismatch", `{"image":"` + ciRepo + `:` + ciTag + `@` + other + `"}`, "secret", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do(http.MethodPost, "/api/v1/scan-requests", tc.body, tc.token)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
	if depth, _ := f.queue.GetQueueDepth(context.Background()); depth != 0 {
		t.Fatalf("rejected requests queued %d tasks", depth)
	}
}

func TestScanRequest_WaitsForVerdict(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	// An older scan exists; the request must wait for a newer one.
	f.store.put(&statestore.ScanRecord{ID: 7, Repository: ciRepo, Digest: ciDigest, Tag: ciTag, PolicyStatus: "failed"})

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.do(http.MethodPost, "/api/v1/scan-requests?wait=5s", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	}()
	task := f.finishNextTask(t, &statestore.ScanRecord{
		ID: 8, Repository: ciRepo, Digest: ciDigest, Tag: ciTag,
		PolicyStatus: "passed", SCAIAttested: true, SBOMAttested: true, HighVulnCount: 2,
	}, nil)
	if task.Priority != queue.PriorityUrgent || task.Tag != ciTag {
		t.Fatalf("queued task = %+v, want an urgent task for %s", task, ciTag)
	}

	w := <-done
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", w.Code, w.Body.String())
	}
	result := decodeResult(t, w)
	if result.State != "done" || result.Verdict == nil || result.Verdict.ScanID != 8 || result.Verdict.Status != "passed" ||
		!result.Verdict.Attested.SCAI || result.Verdict.Counts.High != 2 || result.After != 7 {
		t.Fatalf("result = %+v verdict = %+v", result, result.Verdict)
	}
	if result.URL != "/scans/"+ciDigest {
		t.Fatalf("url = %q", result.URL)
	}
}

func TestScanRequest_TimesOutThenPolls(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	w := f.do(http.MethodPost, "/api/v1/scan-requests?wait=10ms", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d; body %s", w.Code, w.Body.String())
	}
	queued := decodeResult(t, w)
	if queued.State != "queued" || !strings.HasPrefix(queued.Poll, "/api/v1/scan-requests/"+ciDigest+"?") {
		t.Fatalf("queued = %+v", queued)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.do(http.MethodGet, queued.Poll+"&wait=5s", "", "secret") }()
	f.finishNextTask(t, &statestore.ScanRecord{ID: 1, Repository: ciRepo, Digest: ciDigest, Tag: ciTag, PolicyStatus: "failed", PolicyReason: "critical vulnerabilities found"}, nil)

	w = <-done
	if w.Code != http.StatusOK {
		t.Fatalf("poll status = %d; body %s", w.Code, w.Body.String())
	}
	result := decodeResult(t, w)
	if result.State != "done" || result.Verdict.Status != "failed" || result.Verdict.Reason == "" {
		t.Fatalf("poll result = %+v", result)
	}

	// The scan is done and nothing is queued any more: a poll past it is a 404.
	w = f.do(http.MethodGet, fmt.Sprintf("/api/v1/scan-requests/%s?repository=%s&after=1", ciDigest, ciRepo), "", "secret")
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale poll status = %d; body %s", w.Code, w.Body.String())
	}
}

func TestScanRequest_ReportsTaskFailureWithoutRecord(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.do(http.MethodPost, "/api/v1/scan-requests?wait=5s", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	}()
	f.finishNextTask(t, nil, errors.New("failed to create SBOM attestation: denied"))

	w := <-done
	result := decodeResult(t, w)
	if w.Code != http.StatusOK || result.State != "error" || !strings.Contains(result.Error, "SBOM attestation") {
		t.Fatalf("status = %d result = %+v", w.Code, result)
	}
}

func TestScanRequest_ShutdownAnswersQueued(t *testing.T) {
	f := newScanRequestFixture(t, "")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.do(http.MethodPost, "/api/v1/scan-requests?wait=1m", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "")
	}()
	// Let the request start waiting, then shut down.
	time.Sleep(50 * time.Millisecond)
	f.waiter.Close()
	select {
	case w := <-done:
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d; body %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request kept waiting after shutdown")
	}
}

func TestScanRequest_ReadOnlyRefusesNewRequests(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	f.server.config.ReadOnly = true
	w := f.do(http.MethodPost, "/api/v1/scan-requests", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
}

func (f *scanRequestFixture) failReads(fn func(n int) bool) {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	f.store.failRead = fn
}

// A CI job waiting for its verdict must not fail because PostgreSQL
// switched over while the scan ran: the wait re-reads until the verdict.
func TestScanRequest_LongPollRidesOutDatabaseBlip(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	f.server.storeRetryEvery = 10 * time.Millisecond
	// Read 1 is POST's "latest scan" lookup; reads 2-4 fail mid-wait.
	f.failReads(func(n int) bool { return n >= 2 && n <= 4 })

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.do(http.MethodPost, "/api/v1/scan-requests?wait=5s", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	task, err := f.queue.Dequeue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Let the wait hit the failing reads before the scan finishes.
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.store.mu.Lock()
		reads := f.store.reads
		f.store.mu.Unlock()
		if reads >= 5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.store.put(&statestore.ScanRecord{ID: 9, Repository: ciRepo, Digest: ciDigest, Tag: ciTag, PolicyStatus: "passed"})
	f.waiter.Finished(ctx, task, nil)

	w := <-done
	result := decodeResult(t, w)
	if w.Code != http.StatusOK || result.State != "done" || result.Verdict == nil || result.Verdict.ScanID != 9 {
		t.Fatalf("status %d result %+v; want the verdict despite the failed reads", w.Code, result)
	}
}

// POST reads the latest scan before queuing; a brief outage is retried.
func TestScanRequest_PostRetriesDatabaseRead(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	f.server.storeRetryEvery = 10 * time.Millisecond
	f.failReads(func(n int) bool { return n <= 2 })

	w := f.do(http.MethodPost, "/api/v1/scan-requests?wait=0s", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d body %s; want the scan queued after two failed reads", w.Code, w.Body.String())
	}
	if depth, _ := f.queue.GetQueueDepth(context.Background()); depth != 1 {
		t.Fatalf("queue depth %d, want 1", depth)
	}
}

func TestScanRequest_PostGivesUpAfterRetryBudget(t *testing.T) {
	f := newScanRequestFixture(t, "secret")
	f.server.storeRetryEvery = 10 * time.Millisecond
	f.server.storeRetryFor = 50 * time.Millisecond
	f.failReads(func(int) bool { return true })

	w := f.do(http.MethodPost, "/api/v1/scan-requests?wait=0s", `{"image":"`+ciRepo+`:`+ciTag+`"}`, "secret")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d Retry-After %q; want 503 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if depth, _ := f.queue.GetQueueDepth(context.Background()); depth != 0 {
		t.Fatalf("queue depth %d, want nothing queued", depth)
	}
}
