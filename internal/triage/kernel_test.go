package triage

import (
	"context"
	"errors"
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

func TestKernelHeaderPackage(t *testing.T) {
	for _, name := range []string{"linux-libc-dev", "Linux-Headers", "linux-headers-6.1.0-28-amd64", "kernel-headers", "linux-api-headers", "linux-uapi-headers"} {
		if !kernelHeaderPackage(name) || !kernelPackage(name) {
			t.Errorf("%s should be a kernel header package", name)
		}
	}
	for _, name := range []string{"linux", "kernel", "linux-image-amd64", "kernel-modules", "linux-lts", "libc6"} {
		if kernelHeaderPackage(name) {
			t.Errorf("%s should not be a kernel header package", name)
		}
	}
	if !kernelPackage("linux") || !kernelPackage("kernel") || kernelPackage("libc6") {
		t.Error("kernelPackage mismatch")
	}
}

func TestHeaderOnly(t *testing.T) {
	cases := []struct {
		name string
		job  Job
		want bool
	}{
		{"headers", Job{PackageName: "linux-libc-dev", Packages: []PackageFact{{Name: "linux-libc-dev"}, {Name: "linux-headers-6.1.0-28-amd64"}}}, true},
		{"package name only", Job{PackageName: "linux-libc-dev"}, true},
		{"no packages", Job{}, false},
		{"real kernel", Job{PackageName: "linux-libc-dev", Packages: []PackageFact{{Name: "linux-libc-dev"}, {Name: "linux-image-amd64"}}}, false},
		{"in-use digest has other package", Job{
			PackageName: "linux-libc-dev",
			Packages:    []PackageFact{{Name: "linux-libc-dev"}},
			InUse:       []DigestFact{{Digest: "sha256:a", Packages: []PackageFact{{Name: "kernel"}}}},
		}, false},
	}
	for _, tc := range cases {
		if got := headerOnly(tc.job); got != tc.want {
			t.Errorf("%s: headerOnly = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDecideHeader(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	settings := Settings{BlockKEV: true, Expiry: time.Hour, Model: "stub"}
	job := Job{Repository: "r/falco-driver-loader", CVEID: "CVE-2026-99083", PackageName: "linux-libc-dev", Packages: []PackageFact{{Name: "linux-libc-dev"}}}

	got := decideHeader(settings, job, false, nil, nil, nil, "ts-1", now)
	if got.Action != outcomeNotAffected || got.Statement.Justification != types.VEXJustCodeNotPresent || got.Statement.Source != types.VEXSourceAuto {
		t.Fatalf("decision = %+v", got)
	}
	if !strings.Contains(got.Statement.Detail, headerRule) || !strings.Contains(got.Statement.Detail, "linux-libc-dev ships kernel headers only") {
		t.Fatalf("detail = %q", got.Statement.Detail)
	}
	if got.Statement.ExpiresAt == nil || *got.Statement.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("expires = %v", got.Statement.ExpiresAt)
	}

	if got := decideHeader(settings, job, true, nil, nil, nil, "ts-1", now); got.Action != outcomeReject || !strings.Contains(got.Reason, "Known Exploited") {
		t.Fatalf("kev decision = %+v", got)
	}
	if got := decideHeader(settings, job, false, errors.New("down"), nil, nil, "ts-1", now); got.Action != outcomeReject {
		t.Fatalf("kev error decision = %+v", got)
	}
	settings.BlockKEV = false
	if got := decideHeader(settings, job, true, nil, nil, nil, "ts-1", now); got.Action != outcomeNotAffected {
		t.Fatalf("kev off decision = %+v", got)
	}
}

type failLLM struct{ t *testing.T }

func (f failLLM) Complete(context.Context, []chatMessage, []toolDef) (completion, error) {
	f.t.Error("model was called for a header-only kernel finding")
	return completion{}, errors.New("unexpected call")
}

func TestProcessWritesHeaderVEXWithoutModel(t *testing.T) {
	t.Setenv("SUPPLINE_LLM_API_KEY", "test-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
sync:
  - source: example.com/driver-loader
    target: registry.local/driver-loader
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
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	t.Cleanup(kev.Close)
	svc.kev = &KEVCache{URL: kev.URL, TTL: time.Hour}
	svc.llm = failLLM{t: t}
	root := t.TempDir()
	roots := Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: root}}}
	checkouts := []gitops.Checkout{{Name: "infra", Dir: root, SHA: "abc123"}}
	job := Job{
		Repository:  "registry.local/driver-loader",
		CVEID:       "CVE-2026-99083",
		PackageName: "linux-libc-dev",
		Severity:    "CRITICAL",
		Packages:    []PackageFact{{Name: "linux-libc-dev", Installed: "6.1.190-1", Fixed: "6.1.192-1"}},
	}
	svc.process(context.Background(), job, checkouts, roots)

	evidence := cat.ResolveEvidence(job.Repository)
	if len(evidence.VEXStatements) != 1 {
		t.Fatalf("effective vex = %+v", evidence.VEXStatements)
	}
	got := evidence.VEXStatements[0]
	if got.Source != types.VEXSourceAuto || got.State != types.VEXStateNotAffected || got.Justification != types.VEXJustCodeNotPresent {
		t.Fatalf("statement = %+v", got)
	}
	run, err := store.LatestTriageRun(context.Background(), job.Repository, job.CVEID)
	if err != nil || run == nil || run.Status != StatusWritten || run.Tokens != 0 || run.Justification != string(types.VEXJustCodeNotPresent) || run.WrittenState != string(types.VEXStateNotAffected) {
		t.Fatalf("run = %+v err=%v", run, err)
	}
}
