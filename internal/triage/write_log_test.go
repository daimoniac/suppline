package triage

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/statestore/storetest"
	"github.com/daimoniac/suppline/internal/types"
)

// countingRequeuer is called from the editor's background requeues.
type countingRequeuer struct {
	mu           sync.Mutex
	repositories []string
}

func (c *countingRequeuer) RequeueRepositories(_ context.Context, repositories []string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.repositories = append(c.repositories, repositories...)
	return 2 * len(repositories), nil
}

// internal-1, 2026-11-16: a triage re-add of CVE-2026-119618 on snipe_snipe-it
// queued its rescans, which waited 23 minutes behind other work. Nothing in the
// log showed that they had been queued.
func TestTriageWritesLogTheirRequeue(t *testing.T) {
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
		Mode:    config.TriageModeDryRun,
		LLM:     config.TriageLLMConfig{BaseURL: "http://llm.example/v1", Model: "stub"},
	}
	cat := catalog.NewConfigCatalog(parsed)
	store, err := statestore.NewPostgresStore(storetest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	requeue := &countingRequeuer{}
	editor := configedit.New(configedit.Target{LocalPath: path, Retention: 1}, cat, requeue, logger)
	svc, err := New(parsed.Triage, path, cat, store, editor, logger)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.applyStatements(context.Background(), "registry.local/app", []types.VEXStatement{{
		ID: "CVE-2026-2", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable,
	}}, "chore(vex): auto-triage 1 CVE for registry.local/app [skip ci]"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PromoteManual(context.Background(), "registry.local/app", types.VEXStatement{
		ID: "CVE-2026-3", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotReachable,
	}); err != nil {
		t.Fatal(err)
	}

	editor.WaitRequeues()
	out := logs.String()
	for _, want := range []string{
		`msg="wrote vex-auto statements" repository=registry.local/app ids=[CVE-2026-2] mode=local commit="" requeue=[registry.local/app]`,
		`msg="wrote vex statement" repository=registry.local/app ids=[CVE-2026-3] mode=local commit="" requeue=[registry.local/app]`,
		`msg="config edit requeued images" repositories=[registry.local/app] queued=2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q\n%s", want, out)
		}
	}
}
