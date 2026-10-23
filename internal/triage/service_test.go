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

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
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
