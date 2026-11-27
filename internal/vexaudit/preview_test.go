package vexaudit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	supplineerrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

func previewAuditor(statements []types.VEXStatement) *Auditor {
	now := time.Now().Unix()
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fakeCatalog{statements: statements},
		fakeScans{
			records: []*statestore.ScanRecord{
				{ID: 1, Repository: "registry.local/clean", Digest: "sha256:clean", Tag: "1", CreatedAt: now, PolicyPassed: true, PolicyStatus: "passed"},
				{ID: 2, Repository: "registry.local/highs", Digest: "sha256:highs", Tag: "2", CreatedAt: now, PolicyPassed: true, PolicyStatus: "passed"},
				{ID: 3, Repository: "registry.local/broken", Digest: "sha256:broken", Tag: "3", CreatedAt: now, PolicyPassed: false, PolicyStatus: "failed"},
				{ID: 4, Repository: "registry.local/held", Digest: "sha256:held", Tag: "4", CreatedAt: now, PolicyStatus: "pending"},
			},
			vulns: map[int64][]types.VulnerabilityRecord{
				2: {
					{CVEID: "CVE-HIGH-1", Severity: "HIGH", PackageName: "openssl"},
					{CVEID: "CVE-HIGH-2", Severity: "HIGH", PackageName: "zlib"},
				},
				3: {{CVEID: "CVE-CRIT", Severity: "CRITICAL", PackageName: "libc"}},
				4: {{CVEID: "CVE-HELD", Severity: "CRITICAL", PackageName: "libc"}},
			},
		},
		engineFor,
	)
}

// The default policy admits an image with ordinary highs;
// would block it (as does any critical). The image that already fails stays a failure, and a held
// (pending) scan is not part of the replay.
func TestPreviewNamesNewlyBlockedImages(t *testing.T) {
	result, err := previewAuditor(nil).Preview(context.Background(), "criticalCount == 0 && highCount == 0", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 3 || result.WouldPass != 1 || result.WouldFail != 2 {
		t.Fatalf("counts = %+v, want 3 evaluated, 1 pass, 2 fail", result)
	}
	if result.CurrentlyFailing != 1 {
		t.Fatalf("CurrentlyFailing = %d, want 1", result.CurrentlyFailing)
	}
	if result.NewlyBlocked != 1 || len(result.Images) != 1 {
		t.Fatalf("newly blocked = %d / %+v, want only the highs image", result.NewlyBlocked, result.Images)
	}
	image := result.Images[0]
	if image.Repository != "registry.local/highs" || image.Tag != "2" || image.Digest != "sha256:highs" {
		t.Fatalf("image = %+v", image)
	}
}

// An empty expression previews the built-in default, and VEX statements still
// exempt findings.
func TestPreviewAppliesTheRepositorysVEX(t *testing.T) {
	exempt := []types.VEXStatement{{ID: "CVE-CRIT", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent}}
	result, err := previewAuditor(exempt).Preview(context.Background(), policy.DefaultExpression, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.WouldFail != 0 || result.NewlyBlocked != 0 {
		t.Fatalf("result = %+v, want nothing failing once CVE-CRIT is exempted", result)
	}
}

func TestPreviewRejectsAnExpressionThatDoesNotCompile(t *testing.T) {
	_, err := previewAuditor(nil).Preview(context.Background(), "criticalCount ==", true)
	var permanent *supplineerrors.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("err = %v, want a permanent (caller's) error", err)
	}
}
