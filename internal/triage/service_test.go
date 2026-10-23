package triage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		w.Write([]byte(`{"vulnerabilities":[]}`))
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
		pending:  map[string]struct{}{},
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
		pending:  map[string]struct{}{},
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
		pending:  map[string]struct{}{},
	}
	allImages.NotifyPolicyFailure(context.Background(), notice)
	select {
	case <-allImages.jobs:
	default:
		t.Fatal("only_in_use false still skipped the image")
	}
}
