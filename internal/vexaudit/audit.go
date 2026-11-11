// Package vexaudit finds sync-entry VEX statements that no current policy
// decision depends on. The audit runs in the background and the Tasks API only
// reads its last result, so requests never evaluate policy themselves.
package vexaudit

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/policy"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/scanner"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

const refreshInterval = time.Hour

// Catalog is the configuration view the audit reads.
type Catalog interface {
	Repositories() []string
	ResolvePolicy(repository string) (policy.PolicyConfig, error)
	ResolveEvidence(repository string) catalog.Evidence
	SyncVEX(repository string) []types.VEXStatement
}

// ScanStore is the scan read model the audit reads.
type ScanStore interface {
	ListScans(ctx context.Context, filter statestore.ScanFilter) ([]*statestore.ScanRecord, error)
	LoadVulnerabilitiesByScanIDs(ctx context.Context, scanIDs []int64) (map[int64][]types.VulnerabilityRecord, error)
}

// EngineFactory returns the policy engine for an effective repository policy.
type EngineFactory func(cfg policy.PolicyConfig) (policy.PolicyEngine, error)

// Finding is a sync-entry statement whose removal leaves every latest scan's
// policy outcome unchanged.
type Finding struct {
	Repository    string
	CVEID         string
	Source        string
	State         string
	Justification string
	Detail        string
	ExpiresAt     *int64
}

// Auditor computes findings and keeps the last result for readers.
type Auditor struct {
	logger  *slog.Logger
	catalog Catalog
	scans   ScanStore
	engines EngineFactory

	mu         sync.RWMutex
	findings   []Finding
	computedAt time.Time
}

// New creates an auditor. It does not compute anything until Run is called.
func New(logger *slog.Logger, catalog Catalog, scans ScanStore, engines EngineFactory) *Auditor {
	return &Auditor{logger: logger, catalog: catalog, scans: scans, engines: engines}
}

// Run computes the audit now and then once per hour until ctx is done.
func (a *Auditor) Run(ctx context.Context) {
	a.refresh(ctx)
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refresh(ctx)
		}
	}
}

func (a *Auditor) refresh(ctx context.Context) {
	findings, err := a.Audit(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.logger.Error("vex audit failed", "error", err)
		}
		return
	}
	a.mu.Lock()
	a.findings = findings
	a.computedAt = time.Now()
	a.mu.Unlock()
	a.logger.Info("vex audit refreshed", "ineffective_statements", len(findings))
}

// Snapshot returns the last computed findings and when they were computed.
// The zero time means no audit has finished yet.
func (a *Auditor) Snapshot() ([]Finding, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]Finding(nil), a.findings...), a.computedAt
}

// Forget drops a statement that was just removed from config, so it does not
// stay listed until the next refresh.
func (a *Auditor) Forget(repository, cveID, source string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.findings[:0]
	for _, finding := range a.findings {
		if finding.Repository == repository && finding.CVEID == cveID && finding.Source == source {
			continue
		}
		kept = append(kept, finding)
	}
	a.findings = kept
}

// Audit evaluates every repository with sync-entry statements against the
// latest scan of each of its artifacts.
func (a *Auditor) Audit(ctx context.Context) ([]Finding, error) {
	listed, err := a.scans.ListScans(ctx, statestore.ScanFilter{})
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	a.logger.Info("vex audit started", "scans", len(listed))
	if err := a.attachVulnerabilities(ctx, listed); err != nil {
		return nil, err
	}
	byRepository := make(map[string][]*statestore.ScanRecord)
	for _, record := range listed {
		byRepository[record.Repository] = append(byRepository[record.Repository], record)
	}

	now := time.Now()
	var findings []Finding
	for _, repository := range a.catalog.Repositories() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		found, err := a.auditRepository(ctx, repository, byRepository[repository], now)
		if err != nil {
			a.logger.Warn("skipped repository in vex audit", "repository", repository, "error", err)
			continue
		}
		findings = append(findings, found...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Repository != findings[j].Repository {
			return findings[i].Repository < findings[j].Repository
		}
		return findings[i].CVEID < findings[j].CVEID
	})
	return findings, nil
}

func (a *Auditor) auditRepository(ctx context.Context, repository string, records []*statestore.ScanRecord, now time.Time) ([]Finding, error) {
	candidates := candidateStatements(a.catalog.SyncVEX(repository), now)
	if len(candidates) == 0 {
		return nil, nil
	}
	cfg, err := a.catalog.ResolvePolicy(repository)
	if err != nil {
		return nil, err
	}
	if cfg.MinimumReleaseAge > 0 {
		// Release-age gating depends on the current time, so stored scans do
		// not show whether a statement matters now. Nothing is offered here.
		return nil, nil
	}
	if strings.Contains(cfg.Expression, "description") {
		// Descriptions are not loaded with the findings. A policy that reads
		// them cannot be checked from this cache.
		return nil, nil
	}
	engine, err := a.engines(cfg)
	if err != nil {
		return nil, fmt.Errorf("build policy engine: %w", err)
	}
	scans := completedScans(records)
	// A finding recorded before severity lived on the row has only the shared
	// catalog value. That value may already belong to a different image, so
	// the statement is kept until a scan records its own severity.
	unrecorded := cveIDsWithUnrecordedSeverity(scans)
	for _, scan := range scans {
		scan.Vulnerabilities = narrowFindings(cfg.Expression, scan.Vulnerabilities)
	}
	scans = scansWithCandidate(scans, candidates)
	if len(scans) == 0 {
		return findingsForUnseen(repository, candidates, unrecorded), nil
	}

	evidence := a.catalog.ResolveEvidence(repository).VEXStatements
	baseline := make([]bool, len(scans))
	for i, scan := range scans {
		passed, err := evaluate(ctx, engine, scan, evidence)
		if err != nil {
			return nil, err
		}
		baseline[i] = passed
	}

	var findings []Finding
	for _, candidate := range candidates {
		if _, skip := unrecorded[candidate.ID]; skip {
			continue
		}
		without := withoutStatement(evidence, candidate.ID)
		if changesOutcome(ctx, a.logger, engine, scans, baseline, without, candidate.ID) {
			continue
		}
		findings = append(findings, Finding{
			Repository:    repository,
			CVEID:         candidate.ID,
			Source:        candidate.Source,
			State:         string(candidate.State),
			Justification: string(candidate.Justification),
			Detail:        candidate.Detail,
			ExpiresAt:     candidate.ExpiresAt,
		})
	}
	return findings, nil
}

// narrowFindings drops vulnerabilities a severity gate cannot see. Policies
// that mention another severity, a package, or a description keep the full list.
func narrowFindings(expression string, vulns []types.VulnerabilityRecord) []types.VulnerabilityRecord {
	for _, word := range []string{"HIGH", "MEDIUM", "LOW", "highCount", "mediumCount", "lowCount", "packageName", "description"} {
		if strings.Contains(expression, word) {
			return vulns
		}
	}
	out := make([]types.VulnerabilityRecord, 0)
	for _, vuln := range vulns {
		if vuln.Severity == "CRITICAL" {
			out = append(out, vuln)
		}
	}
	return out
}

// scansWithCandidate keeps scans that still contain one of the candidate CVEs
// after narrowing. Any other scan is unchanged by removing those statements.
func scansWithCandidate(scans []*statestore.ScanRecord, candidates []types.VEXStatement) []*statestore.ScanRecord {
	ids := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		ids[candidate.ID] = struct{}{}
	}
	var out []*statestore.ScanRecord
	for _, scan := range scans {
		for _, vuln := range scan.Vulnerabilities {
			if _, ok := ids[vuln.CVEID]; ok {
				out = append(out, scan)
				break
			}
		}
	}
	return out
}

// findingsForUnseen reports every candidate when no current scan still contains
// it. Removing the statement cannot change a result. skip holds CVE ids whose
// severity was not recorded on the finding; those stay in place.
func findingsForUnseen(repository string, candidates []types.VEXStatement, skip map[string]struct{}) []Finding {
	out := make([]Finding, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := skip[candidate.ID]; ok {
			continue
		}
		out = append(out, Finding{
			Repository:    repository,
			CVEID:         candidate.ID,
			Source:        candidate.Source,
			State:         string(candidate.State),
			Justification: string(candidate.Justification),
			Detail:        candidate.Detail,
			ExpiresAt:     candidate.ExpiresAt,
		})
	}
	return out
}

// cveIDsWithUnrecordedSeverity collects CVEs present on a scan whose severity
// was not stored with the finding. An empty severity is not evidence that the
// statement has no effect.
func cveIDsWithUnrecordedSeverity(scans []*statestore.ScanRecord) map[string]struct{} {
	unknown := make(map[string]struct{})
	for _, scan := range scans {
		for _, vuln := range scan.Vulnerabilities {
			if strings.TrimSpace(vuln.CVEID) == "" || strings.TrimSpace(vuln.Severity) != "" {
				continue
			}
			unknown[vuln.CVEID] = struct{}{}
		}
	}
	return unknown
}

// candidateStatements keeps statements that could exempt a CVE right now:
// not_affected and not yet expired. Other states never exempt, and expired
// statements are already reported by the expiry task.
func candidateStatements(statements []types.VEXStatement, now time.Time) []types.VEXStatement {
	var out []types.VEXStatement
	for _, statement := range statements {
		if statement.State != types.VEXStateNotAffected {
			continue
		}
		if statement.ExpiresAt != nil && *statement.ExpiresAt <= now.Unix() {
			continue
		}
		out = append(out, statement)
	}
	return out
}

// attachVulnerabilities fills the findings of every listed scan in bulk.
func (a *Auditor) attachVulnerabilities(ctx context.Context, records []*statestore.ScanRecord) error {
	ids := make([]int64, 0, len(records))
	seen := make(map[int64]struct{}, len(records))
	for _, record := range records {
		if record.ID == 0 {
			continue
		}
		if _, ok := seen[record.ID]; ok {
			continue
		}
		seen[record.ID] = struct{}{}
		ids = append(ids, record.ID)
	}
	byScan, err := a.scans.LoadVulnerabilitiesByScanIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("load vulnerabilities: %w", err)
	}
	for _, record := range records {
		record.Vulnerabilities = byScan[record.ID]
	}
	return nil
}

// completedScans keeps one finished scan per digest. Pending and failed scans
// cannot show whether a statement changes the policy outcome.
func completedScans(records []*statestore.ScanRecord) []*statestore.ScanRecord {
	seen := make(map[string]struct{}, len(records))
	var out []*statestore.ScanRecord
	for _, record := range records {
		if _, dup := seen[record.Digest]; dup {
			continue
		}
		seen[record.Digest] = struct{}{}
		if record.ErrorMessage != "" || record.PolicyStatus == "pending" {
			continue
		}
		out = append(out, record)
	}
	return out
}

// changesOutcome reports whether removing evidence changes the pass/fail result
// of any scan. An evaluation error counts as a change, so nothing is offered
// for removal when the answer is unknown.
func changesOutcome(ctx context.Context, logger *slog.Logger, engine policy.PolicyEngine, scans []*statestore.ScanRecord, baseline []bool, without []types.VEXStatement, cveID string) bool {
	for i, scan := range scans {
		if !scanHasCVE(scan, cveID) {
			continue
		}
		passed, err := evaluate(ctx, engine, scan, without)
		if err != nil {
			logger.Warn("vex audit evaluation failed", "digest", scan.Digest, "error", err)
			return true
		}
		if passed != baseline[i] {
			return true
		}
	}
	return false
}

func scanHasCVE(scan *statestore.ScanRecord, cveID string) bool {
	for _, vuln := range scan.Vulnerabilities {
		if vuln.CVEID == cveID {
			return true
		}
	}
	return false
}

func evaluate(ctx context.Context, engine policy.PolicyEngine, scan *statestore.ScanRecord, statements []types.VEXStatement) (bool, error) {
	result := scanResult(scan)
	decision, err := engine.Evaluate(ctx, scan.Digest, &result, statements)
	if err != nil {
		return false, fmt.Errorf("evaluate policy: %w", err)
	}
	return decision.Passed, nil
}

func scanResult(scan *statestore.ScanRecord) scanner.ScanResult {
	result := scanner.ScanResult{
		ImageRef:        scan.Digest,
		ScannedAt:       time.Unix(scan.CreatedAt, 0).UTC(),
		Vulnerabilities: make([]types.Vulnerability, 0, len(scan.Vulnerabilities)),
	}
	if scan.ImageCreatedAt > 0 {
		created := time.Unix(scan.ImageCreatedAt, 0).UTC()
		result.ImageCreatedAt = &created
	}
	for _, vuln := range scan.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, types.Vulnerability{
			ID:           vuln.CVEID,
			Severity:     vuln.Severity,
			PackageName:  vuln.PackageName,
			Version:      vuln.InstalledVersion,
			FixedVersion: vuln.FixedVersion,
			Title:        vuln.Title,
			Description:  vuln.Description,
			PrimaryURL:   vuln.PrimaryURL,
		})
	}
	return result
}

func withoutStatement(statements []types.VEXStatement, id string) []types.VEXStatement {
	out := make([]types.VEXStatement, 0, len(statements))
	for _, statement := range statements {
		if statement.ID == id {
			continue
		}
		out = append(out, statement)
	}
	return out
}
