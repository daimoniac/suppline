package triage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/worker"
)

type stubLLM struct {
	body string
}

func (s stubLLM) Complete(context.Context, []chatMessage, []toolDef) (completion, error) {
	return completion{Content: s.body, Tokens: 4}, nil
}

func TestProcessWritesLocalAutoVEX(t *testing.T) {
	t.Setenv("SUPPLINE_LLM_API_KEY", "test-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
`), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Triage = &config.TriageConfig{
		Enabled: true,
		Mode:    config.TriageModeEnforce,
		LLM:     config.TriageLLMConfig{BaseURL: "http://llm.example/v1", Model: "stub"},
	}
	cat := catalog.NewConfigCatalog(parsed)
	store, err := statestore.NewSQLiteStore(filepath.Join(dir, "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	svc, err := New(parsed.Triage, path, cat, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.yaml"), []byte("ingress: internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	t.Cleanup(kev.Close)
	svc.kev = &KEVCache{URL: kev.URL, TTL: time.Hour}
	svc.llm = stubLLM{body: `{"verdict":"not_affected","justification":"protected_at_perimeter","confidence":0.95,"evidence":[{"repo":"infra","path":"app.yaml","line":1,"quote":"ingress: internal"}],"reasoning":"only an internal ingress is exposed"}`}
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: root}}}
	checkouts := []gitops.Checkout{{Name: "infra", Dir: root, SHA: "abc123"}}
	job := Job{Repository: "registry.local/app", CVEID: "CVE-2026-1", PackageName: "nginx", Description: "overflow", Severity: "CRITICAL"}
	svc.process(context.Background(), job, checkouts, roots)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "x-vex-auto") || !strings.Contains(string(body), "CVE-2026-1") {
		t.Fatalf("file was not updated:\n%s", body)
	}
	if _, err := os.Stat(path + ".bak.1"); err != nil {
		t.Fatal(err)
	}
	evidence := cat.ResolveEvidence(job.Repository)
	if len(evidence.VEXStatements) != 1 || evidence.VEXStatements[0].Source != types.VEXSourceAuto || evidence.VEXStatements[0].State != types.VEXStateNotAffected {
		t.Fatalf("effective vex = %+v", evidence.VEXStatements)
	}
	run, err := store.LatestTriageRun(context.Background(), job.Repository, job.CVEID)
	if err != nil || run == nil || run.Status != StatusWritten {
		t.Fatalf("run = %+v err=%v", run, err)
	}
}

func TestSessionWritesEveryCVEOnce(t *testing.T) {
	t.Setenv("SUPPLINE_LLM_API_KEY", "test-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
`), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Triage = &config.TriageConfig{
		Enabled: true,
		Mode:    config.TriageModeEnforce,
		LLM:     config.TriageLLMConfig{BaseURL: "http://llm.example/v1", Model: "stub"},
	}
	cat := catalog.NewConfigCatalog(parsed)
	store, err := statestore.NewSQLiteStore(filepath.Join(dir, "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	svc, err := New(parsed.Triage, path, cat, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.yaml"), []byte("ingress: internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	t.Cleanup(kev.Close)
	svc.kev = &KEVCache{URL: kev.URL, TTL: time.Hour}
	verdict := `{"verdict":"not_affected","justification":"protected_at_perimeter","confidence":0.95,"evidence":[{"repo":"infra","path":"app.yaml","line":1,"quote":"ingress: internal"}],"reasoning":"only an internal ingress is exposed"}`
	svc.llm = &seqLLM{bodies: []string{"context ready", verdict, "not-json"}}
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: root}}}
	checkouts := []gitops.Checkout{{Name: "infra", Dir: root, SHA: "abc123"}}
	jobs := []Job{
		{Repository: "registry.local/app", CVEID: "CVE-2026-1", PackageName: "nginx", Severity: "HIGH"},
		{Repository: "registry.local/app", CVEID: "CVE-2026-2", PackageName: "openssl", Severity: "HIGH"},
	}
	svc.executeSession(context.Background(), jobs, checkouts, roots)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CVE-2026-1") || strings.Contains(string(body), "CVE-2026-2") {
		t.Fatalf("file:\n%s", body)
	}
	backup, err := os.ReadFile(path + ".bak.1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(backup), "x-vex-auto") {
		t.Fatal("backup was taken after the first statement")
	}
	first, err := store.LatestTriageRun(context.Background(), jobs[0].Repository, "CVE-2026-1")
	if err != nil || first == nil || first.Status != StatusWritten || first.SessionID == "" {
		t.Fatalf("first = %+v err=%v", first, err)
	}
	second, err := store.LatestTriageRun(context.Background(), jobs[0].Repository, "CVE-2026-2")
	if err != nil || second == nil || second.Status != StatusError || second.SessionID != first.SessionID {
		t.Fatalf("second = %+v err=%v", second, err)
	}
	if first.Tokens == 0 || second.Tokens == 0 {
		t.Fatalf("tokens first=%d second=%d", first.Tokens, second.Tokens)
	}
}

type seqLLM struct {
	bodies []string
	i      int
}

func (s *seqLLM) Complete(context.Context, []chatMessage, []toolDef) (completion, error) {
	body := s.bodies[s.i]
	if s.i+1 < len(s.bodies) {
		s.i++
	}
	return completion{Content: body, Tokens: 4}, nil
}

func TestPromoteManualWritesXVEX(t *testing.T) {
	t.Setenv("SUPPLINE_LLM_API_KEY", "test-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
sync:
  - source: example.com/app
    target: registry.local/app
    type: repository
    x-vex-auto:
      - id: CVE-2026-1
        state: not_affected
        justification: code_not_reachable
        detail: auto
`), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Triage = &config.TriageConfig{
		Enabled: true,
		Mode:    config.TriageModeDryRun,
		LLM:     config.TriageLLMConfig{BaseURL: "http://llm.example/v1", Model: "stub"},
	}
	cat := catalog.NewConfigCatalog(parsed)
	store, err := statestore.NewSQLiteStore(filepath.Join(dir, "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	svc, err := New(parsed.Triage, path, cat, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC).Unix()
	commit, err := svc.PromoteManual(context.Background(), "registry.local/app", types.VEXStatement{
		ID:            "CVE-2026-1",
		State:         types.VEXStateNotAffected,
		Justification: types.VEXJustProtectedAtPerimeter,
		Detail:        "accepted by a person",
		ExpiresAt:     &expires,
	})
	if err != nil || commit != "" {
		t.Fatalf("commit %q err %v", commit, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "protected_at_perimeter") || !strings.Contains(string(body), "x-vex-auto") {
		t.Fatalf("file:\n%s", body)
	}
	evidence := cat.ResolveEvidence("registry.local/app")
	if len(evidence.VEXStatements) != 1 || evidence.VEXStatements[0].Source != types.VEXSourceManual || evidence.VEXStatements[0].Justification != types.VEXJustProtectedAtPerimeter {
		t.Fatalf("effective = %+v", evidence.VEXStatements)
	}
}

func TestActiveListsPendingJob(t *testing.T) {
	svc := &Service{
		settings: Settings{Enabled: true},
		logger:   slog.Default(),
		jobs:     make(chan Job, 1),
		pending:  map[string]ActiveJob{},
	}
	if !svc.enqueue(Job{Repository: "app", CVEID: "CVE-1", ImageRef: "app:1"}) {
		t.Fatal("enqueue")
	}
	queued := svc.Queued()
	if len(queued) != 1 || queued[0].CVEID != "CVE-1" || queued[0].Image != "app:1" || len(svc.Sessions()) != 0 || svc.Pending() != 1 {
		t.Fatalf("queued = %+v sessions = %+v pending %d", queued, svc.Sessions(), svc.Pending())
	}
}

func TestRetryQueuesAndMarksRunning(t *testing.T) {
	svc := &Service{
		settings: Settings{Enabled: true},
		logger:   slog.Default(),
		jobs:     make(chan Job, 2),
		pending:  map[string]ActiveJob{},
	}
	if svc.Retry(context.Background(), "app", "CVE-1") != 1 {
		t.Fatal("retry")
	}
	queued := svc.Queued()
	if len(queued) != 1 || queued[0].CVEID != "CVE-1" || len(svc.Sessions()) != 0 {
		t.Fatalf("queued = %+v", queued)
	}
	svc.beginSession([]Job{{Repository: "app", CVEID: "CVE-1"}}, "s1", "app:1")
	sessions := svc.Sessions()
	if len(sessions) != 1 || sessions[0].Phase != "context" || sessions[0].CurrentCVE != "" || len(svc.Queued()) != 0 {
		t.Fatalf("session = %+v", sessions)
	}
	svc.focusCVE("app", "CVE-1")
	sessions = svc.Sessions()
	if len(sessions) != 1 || sessions[0].CurrentCVE != "CVE-1" || sessions[0].CVEs[0].Status != "running" {
		t.Fatalf("running = %+v", sessions)
	}
	if svc.Retry(context.Background(), "app", "CVE-1") != 0 {
		t.Fatal("duplicate retry was queued")
	}
}

type stubRuntime struct {
	used bool
}

func (s stubRuntime) GetRuntimeUsageForScan(context.Context, string, string, string) (*statestore.RuntimeUsage, error) {
	return &statestore.RuntimeUsage{RuntimeUsed: s.used}, nil
}

func (s stubRuntime) RepositoryInUse(context.Context, string) (bool, error) {
	return s.used, nil
}

func TestNotifyPolicyFailureRespectsInUse(t *testing.T) {
	notice := worker.PolicyFailureNotice{
		Repository: "example/nginx",
		Digest:     "sha256:abc",
		Tag:        "1.2.3",
		Findings:   []types.PolicyFailureFinding{{CVEID: "CVE-1", PackageName: "nginx"}},
	}
	notRunning := &Service{
		settings: Settings{Enabled: true, OnlyInUse: true},
		runtime:  stubRuntime{used: false},
		logger:   slog.Default(),
		jobs:     make(chan Job, 1),
		pending:  map[string]ActiveJob{},
	}
	notRunning.NotifyPolicyFailure(context.Background(), notice)
	select {
	case job := <-notRunning.jobs:
		t.Fatalf("queued unused image %s", job.CVEID)
	default:
	}

	running := &Service{
		settings: Settings{Enabled: true, OnlyInUse: true},
		runtime:  stubRuntime{used: true},
		logger:   slog.Default(),
		jobs:     make(chan Job, 1),
		pending:  map[string]ActiveJob{},
	}
	running.NotifyPolicyFailure(context.Background(), notice)
	select {
	case job := <-running.jobs:
		if job.CVEID != "CVE-1" {
			t.Fatalf("cve = %s", job.CVEID)
		}
	default:
		t.Fatal("in-use image was not queued")
	}

	allImages := &Service{
		settings: Settings{Enabled: true, OnlyInUse: false},
		runtime:  stubRuntime{used: false},
		logger:   slog.Default(),
		jobs:     make(chan Job, 1),
		pending:  map[string]ActiveJob{},
	}
	allImages.NotifyPolicyFailure(context.Background(), notice)
	select {
	case job := <-allImages.jobs:
		if job.Force {
			t.Fatal("automatic triage should not force a rerun")
		}
	default:
		t.Fatal("only_in_use false still skipped the image")
	}
}

func TestQueuePolicyFailureForcesRun(t *testing.T) {
	svc := &Service{
		settings: Settings{Enabled: true, OnlyInUse: false},
		logger:   slog.Default(),
		jobs:     make(chan Job, 2),
		pending:  map[string]ActiveJob{},
	}
	notice := worker.PolicyFailureNotice{
		Repository: "example/nginx",
		Digest:     "sha256:abc",
		Tag:        "1.2.3",
		Findings: []types.PolicyFailureFinding{
			{CVEID: "CVE-1", PackageName: "nginx"},
			{CVEID: "CVE-2", PackageName: "openssl"},
		},
	}
	queued := svc.QueuePolicyFailure(context.Background(), notice)
	if queued != 2 {
		t.Fatalf("queued = %d", queued)
	}
	for i := 0; i < 2; i++ {
		job := <-svc.jobs
		if !job.Force {
			t.Fatalf("job %s was not forced", job.CVEID)
		}
	}
	if again := svc.QueuePolicyFailure(context.Background(), notice); again != 0 {
		t.Fatalf("duplicate queue = %d", again)
	}
}

type stubRuns struct {
	commit *statestore.TriageRun
}

func (s stubRuns) InsertTriageRun(context.Context, *statestore.TriageRun) error { return nil }
func (s stubRuns) LatestTriageRun(context.Context, string, string) (*statestore.TriageRun, error) {
	return nil, nil
}
func (s stubRuns) LatestTriageCommit(context.Context) (*statestore.TriageRun, error) {
	return s.commit, nil
}
func (s stubRuns) ListTriageRuns(context.Context, statestore.TriageFilter) ([]statestore.TriageRun, error) {
	return nil, nil
}
func (s stubRuns) TriageTokensSince(context.Context, time.Time) (int, error) { return 0, nil }
func (s stubRuns) BudgetResetAt(context.Context) (time.Time, error)          { return time.Time{}, nil }
func (s stubRuns) SetBudgetResetAt(context.Context, time.Time) error         { return nil }

type budgetRuns struct {
	mu     sync.Mutex
	tokens int
	reset  time.Time
}

func (b *budgetRuns) InsertTriageRun(context.Context, *statestore.TriageRun) error { return nil }
func (b *budgetRuns) LatestTriageRun(context.Context, string, string) (*statestore.TriageRun, error) {
	return nil, nil
}
func (b *budgetRuns) LatestTriageCommit(context.Context) (*statestore.TriageRun, error) {
	return nil, nil
}
func (b *budgetRuns) ListTriageRuns(context.Context, statestore.TriageFilter) ([]statestore.TriageRun, error) {
	return nil, nil
}
func (b *budgetRuns) TriageTokensSince(_ context.Context, since time.Time) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.reset.IsZero() && since.After(b.reset) {
		return 0, nil
	}
	return b.tokens, nil
}
func (b *budgetRuns) BudgetResetAt(context.Context) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reset, nil
}
func (b *budgetRuns) SetBudgetResetAt(_ context.Context, at time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reset = at
	return nil
}

func TestResetDailyBudgetClearsSpendAndWakesWaiter(t *testing.T) {
	svc := &Service{
		settings: Settings{DailyTokenBudget: 10},
		runs:     &budgetRuns{tokens: 10},
		now:      func() time.Time { return time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC) },
		logger:   slog.Default(),
	}
	if !svc.overBudget(context.Background()) {
		t.Fatal("expected the budget to be exhausted")
	}
	done := make(chan struct{})
	go func() {
		svc.waitForBudget(context.Background())
		close(done)
	}()
	if err := svc.ResetDailyBudget(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("budget wait did not return")
	}
	status := svc.BudgetStatus(context.Background())
	if status.Exhausted || status.Used != 0 || status.Limit != 10 {
		t.Fatalf("budget = %+v", status)
	}
}

func TestGitopsStatusMergesSharedRepo(t *testing.T) {
	when := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	svc := &Service{
		settings: Settings{
			Context: []config.GitRepoConfig{
				{Name: "infra", URL: "https://example.com/infra.git", Branch: "main"},
				{Name: "apps", URL: "https://example.com/apps.git"},
			},
			ConfigRepo: &config.ConfigRepoConfig{URL: "https://example.com/infra.git", Branch: "main"},
		},
		runs: stubRuns{commit: &statestore.TriageRun{CommitSHA: "deadbeef", CreatedAt: when}},
	}
	repos, err := svc.GitopsStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("repos = %+v", repos)
	}
	if repos[0].Name != "infra" || len(repos[0].Roles) != 2 || repos[0].LastSupplineSHA != "deadbeef" || !repos[0].LastSupplineAt.Equal(when) {
		t.Fatalf("config repo = %+v", repos[0])
	}
	if repos[1].Name != "apps" || repos[1].LastSupplineSHA != "" || len(repos[1].Roles) != 1 {
		t.Fatalf("context repo = %+v", repos[1])
	}
}

func TestAutoCommitSkipsGitLabCI(t *testing.T) {
	message := autoCommitMessage("hostingmaloonde/elasticsearch_kibana", []string{"GHSA-cg2g-xh64-v4q7 not_affected"})
	if !strings.Contains(message, "chore(vex): auto-triage 1 CVE for hostingmaloonde/elasticsearch_kibana [skip ci]\n") {
		t.Fatalf("message = %q", message)
	}
	if !strings.Contains(message, "GHSA-cg2g-xh64-v4q7 not_affected") {
		t.Fatalf("message = %q", message)
	}
}

type imageAccessStub struct{}

func (imageAccessStub) ImageLabels(context.Context, string, string) (map[string]string, error) {
	return map[string]string{"org.opencontainers.image.source": "https://github.com/acme/app"}, nil
}

func (imageAccessStub) UnpackImage(context.Context, string, string, string) error {
	return nil
}

func TestSetImageLabelsKeepsUnpack(t *testing.T) {
	svc := &Service{}
	svc.SetImageLabels(imageAccessStub{})
	if svc.images == nil || svc.unpack == nil {
		t.Fatal("labels and unpack are one seam")
	}
}

func TestResolveKeepsConfigRepoWhenDisabled(t *testing.T) {
	settings, err := Resolve(&config.TriageConfig{
		Enabled:         false,
		CheckoutDir:     "/tmp/checkouts",
		BackupRetention: 3,
		ConfigRepo:      &config.ConfigRepoConfig{URL: "https://example.com/cfg.git", Path: "suppline.yml"},
	}, "/tmp/suppline.yml")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Enabled {
		t.Fatal("disabled triage became enabled")
	}
	if settings.ConfigRepo == nil || settings.ConfigRepo.Path != "suppline.yml" {
		t.Fatalf("config repo = %+v", settings.ConfigRepo)
	}
	if settings.BackupRetention != 3 || settings.CheckoutDir != "/tmp/checkouts" || settings.ConfigPath != "/tmp/suppline.yml" {
		t.Fatalf("settings = %+v", settings)
	}
}

func TestCommitConfigWritesLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := New(nil, path, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mode, err := svc.ConfigWriteMode()
	if err != nil || mode != "local" {
		t.Fatalf("mode %q err %v", mode, err)
	}
	commit, err := svc.CommitConfig(context.Background(), "chore(config): test [skip ci]", func(current []byte) ([]byte, error) {
		return append(current, []byte("sync: []\n")...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if commit != "" {
		t.Fatalf("local write returned commit %q", commit)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "sync: []") {
		t.Fatalf("file = %s", body)
	}
	if _, err := os.Stat(path + ".bak.1"); err != nil {
		t.Fatal(err)
	}
}
