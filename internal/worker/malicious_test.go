package worker

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/statestore/storetest"
	"github.com/daimoniac/suppline/internal/types"
)

type fakeMaliciousChecker struct {
	check    *types.MaliciousCheck
	packages []types.PackageRef
	err      error
	calls    int
}

func (f *fakeMaliciousChecker) Check([]byte) (*types.MaliciousCheck, []types.PackageRef, error) {
	f.calls++
	return f.check, f.packages, f.err
}

func newMaliciousPipeline(t *testing.T, checker MaliciousChecker) (*Pipeline, *statestore.SQLiteStore) {
	t.Helper()
	store, err := statestore.NewPostgresStore(storetest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	w := &ImageWorker{stateStore: store, logger: slog.Default()}
	if checker != nil {
		w.SetMaliciousChecker(checker, true)
	}
	return NewPipeline(w, slog.Default()), store
}

func TestMaliciousPhaseRecordsCheckAndInventory(t *testing.T) {
	checker := &fakeMaliciousChecker{
		check:    &types.MaliciousCheck{Status: types.MaliciousCheckOK, Findings: []types.MaliciousFinding{{ID: "MAL-1", PackageName: "evil"}}},
		packages: []types.PackageRef{{Ecosystem: "npm", Name: "evil", Version: "1.0.0", PURL: "pkg:npm/evil@1.0.0"}},
	}
	pipeline, store := newMaliciousPipeline(t, checker)
	task := &queue.ScanTask{Repository: "library/app", Digest: "sha256:abc"}
	result := &scanner.ScanResult{}

	pipeline.maliciousPhase(context.Background(), task, "library/app@sha256:abc", &scanner.SBOM{Data: []byte("{}")}, result)

	if result.Malicious == nil || len(result.Malicious.Findings) != 1 {
		t.Fatalf("expected check on scan result, got %+v", result.Malicious)
	}
	inventory, err := store.ListPackageInventory(context.Background(), "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 1 || inventory[0].PURL != "pkg:npm/evil@1.0.0" {
		t.Fatalf("inventory not recorded: %+v", inventory)
	}
}

func TestMaliciousPhaseFailsOpen(t *testing.T) {
	checker := &fakeMaliciousChecker{
		check: &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable},
		err:   errors.New("bad sbom"),
	}
	pipeline, _ := newMaliciousPipeline(t, checker)
	result := &scanner.ScanResult{}
	pipeline.maliciousPhase(context.Background(), &queue.ScanTask{Digest: "sha256:abc"}, "img", &scanner.SBOM{Data: []byte("x")}, result)
	if result.Malicious == nil || result.Malicious.Status != types.MaliciousCheckUnavailable {
		t.Fatalf("expected unavailable check, got %+v", result.Malicious)
	}

	// No SBOM at all: unavailable, checker not called.
	result = &scanner.ScanResult{}
	pipeline.maliciousPhase(context.Background(), &queue.ScanTask{Digest: "sha256:abc"}, "img", nil, result)
	if result.Malicious == nil || result.Malicious.Status != types.MaliciousCheckUnavailable || checker.calls != 1 {
		t.Fatalf("expected unavailable without calling the checker, got %+v calls=%d", result.Malicious, checker.calls)
	}
}

func TestMaliciousPhaseDisabled(t *testing.T) {
	pipeline, _ := newMaliciousPipeline(t, nil)
	result := &scanner.ScanResult{}
	pipeline.maliciousPhase(context.Background(), &queue.ScanTask{Digest: "sha256:abc"}, "img", &scanner.SBOM{Data: []byte("{}")}, result)
	if result.Malicious != nil {
		t.Fatalf("disabled check must leave the result alone, got %+v", result.Malicious)
	}
}
