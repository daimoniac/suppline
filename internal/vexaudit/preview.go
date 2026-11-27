package vexaudit

import (
	"context"
	"fmt"
	"sort"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/statestore"
)

const (
	// maxPreviewImages caps the images a preview lists; the counts stay exact.
	maxPreviewImages = 100
	// maxPreviewCVEs caps the findings listed for one image.
	maxPreviewCVEs = 10
)

// PreviewImage is an image a candidate policy blocks and the current one
// admits.
type PreviewImage struct {
	Repository string
	Tag        string
	Digest     string
	Reason     string
	// CVEs are the findings that fail the candidate policy, capped.
	CVEs []string
}

// PreviewResult says what a candidate policy would decide about the latest
// scan of each image, next to what the policies in force decided.
type PreviewResult struct {
	// Evaluated counts the latest completed scans, one per digest.
	Evaluated int
	// WouldPass and WouldFail split Evaluated by the candidate policy.
	WouldPass int
	WouldFail int
	// CurrentlyFailing counts the scans that fail the policies in force.
	CurrentlyFailing int
	// NewlyBlocked counts the scans the candidate fails and the current policy
	// admits. Images lists them, capped.
	NewlyBlocked int
	Images       []PreviewImage
}

// Preview replays the latest scan of every image against expression, with
// each repository's own VEX statements applied, and compares the result with
// the decisions on record. Nothing is stored. A malicious-package finding
// fails an image whatever the expression says, so it is not part of the
// comparison. inUseOnly limits the replay to images a cluster runs.
func (a *Auditor) Preview(ctx context.Context, expression string, inUseOnly bool) (*PreviewResult, error) {
	engine, err := a.engines(policy.PolicyConfig{Expression: expression})
	if err != nil {
		return nil, fmt.Errorf("build policy engine: %w", err)
	}

	filter := statestore.ScanFilter{}
	if inUseOnly {
		filter.ImageUsage = statestore.ImageUsageInUse
	}
	listed, err := a.scans.ListScans(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	scans := completedScans(listed)
	if err := a.attachVulnerabilities(ctx, scans); err != nil {
		return nil, err
	}

	result := &PreviewResult{Evaluated: len(scans)}
	for _, scan := range scans {
		if !scan.PolicyPassed {
			result.CurrentlyFailing++
		}
		scanned := scanResult(scan)
		decision, err := engine.Evaluate(ctx, scan.Digest, &scanned, a.catalog.ResolveEvidence(scan.Repository).VEXStatements)
		if err != nil {
			return nil, fmt.Errorf("evaluate policy for %s: %w", scan.Digest, err)
		}
		if decision.Passed {
			result.WouldPass++
			continue
		}
		result.WouldFail++
		if !scan.PolicyPassed {
			continue
		}
		result.NewlyBlocked++
		if len(result.Images) < maxPreviewImages {
			result.Images = append(result.Images, PreviewImage{
				Repository: scan.Repository,
				Tag:        scan.Tag,
				Digest:     scan.Digest,
				Reason:     decision.Reason,
				CVEs:       failingCVEs(decision),
			})
		}
	}
	sort.Slice(result.Images, func(i, j int) bool {
		if result.Images[i].Repository != result.Images[j].Repository {
			return result.Images[i].Repository < result.Images[j].Repository
		}
		return result.Images[i].Tag < result.Images[j].Tag
	})
	return result, nil
}

func failingCVEs(decision *policy.PolicyDecision) []string {
	seen := make(map[string]struct{}, len(decision.PolicyFailureFindings))
	var out []string
	for _, finding := range decision.PolicyFailureFindings {
		if _, dup := seen[finding.CVEID]; dup {
			continue
		}
		seen[finding.CVEID] = struct{}{}
		out = append(out, finding.CVEID)
	}
	sort.Strings(out)
	if len(out) > maxPreviewCVEs {
		out = out[:maxPreviewCVEs]
	}
	return out
}
