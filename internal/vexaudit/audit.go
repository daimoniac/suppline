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
	ShadowedSyncVEX(repository string) []types.VEXStatement
}

// ScanStore is the scan read model the audit reads.
type ScanStore interface {
	ListScans(ctx context.Context, filter statestore.ScanFilter) ([]*statestore.ScanRecord, error)
	LoadVulnerabilitiesByScanIDs(ctx context.Context, scanIDs []int64) (map[int64][]types.VulnerabilityRecord, error)
}

// EngineFactory returns the policy engine for an effective repository policy.
type EngineFactory func(cfg policy.PolicyConfig) (policy.PolicyEngine, error)

// Reasons a sync-entry statement has no effect.
const (
	// ReasonNoEffect: removing the statement leaves every latest scan's
	// policy outcome unchanged.
	ReasonNoEffect = "no_effect"
	// ReasonShadowedByDefaults: defaults.vex has the same id, and defaults
	// win, so the statement never applies.
	ReasonShadowedByDefaults = "shadowed_by_defaults"
)

// Finding is a sync-entry statement that can be removed without changing any
// policy outcome. Reason says why.
type Finding struct {
	Repository    string
	CVEID         string
	Source        string
	State         string
	Justification string
	Detail        string
	ExpiresAt     *int64
	Reason        string
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
			// Statements shadowed by defaults do not depend on the policy
			// check, so they are still reported.
			a.logger.Warn("skipped repository in vex audit", "repository", repository, "error", err)
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
	shadowed := shadowedStatements(repository, a.catalog.ShadowedSyncVEX(repository))
	malicious := unusedMaliciousStatements(repository, a.catalog.SyncVEX(repository), completedScans(records), now)
	findings, err := a.auditCVEStatements(ctx, repository, records, now)
	if err != nil {
		return shadowed, err
	}
	findings = append(findings, malicious...)
	return append(findings, shadowed...), nil
}

// shadowedStatements reports sync-entry statements that defaults.vex
// overrides. They never apply, so state, expiry and scans do not matter.
func shadowedStatements(repository string, statements []types.VEXStatement) []Finding {
	out := make([]Finding, 0, len(statements))
	for _, statement := range statements {
		out = append(out, Finding{
			Repository:    repository,
			CVEID:         statement.ID,
			Source:        statement.Source,
			State:         string(statement.State),
			Justification: string(statement.Justification),
			Detail:        statement.Detail,
			ExpiresAt:     statement.ExpiresAt,
			Reason:        ReasonShadowedByDefaults,
		})
	}
	return out
}

// unusedMaliciousStatements reports false_positive statements for
// malicious-package advisories that no current scan of the repository still
// matches. They are judged on presence, not by replaying policy: an active
// malicious finding fails the image, so a statement covering one always
// matters. Without a scan that ran the check there is no evidence either way.
func unusedMaliciousStatements(repository string, statements []types.VEXStatement, scans []*statestore.ScanRecord, now time.Time) []Finding {
	present := make(map[string]bool)
	checked := false
	for _, scan := range scans {
		if scan.Malicious == nil || scan.Malicious.Status == types.MaliciousCheckUnavailable {
			continue
		}
		checked = true
		for _, finding := range scan.Malicious.Findings {
			present[finding.ID] = true
		}
	}
	if !checked {
		return nil
	}
	var out []Finding
	for _, statement := range statements {
		if !types.IsMaliciousID(statement.ID) || statement.State != types.VEXStateFalsePositive {
			continue
		}
		if statement.ExpiresAt != nil && *statement.ExpiresAt <= now.Unix() {
			continue
		}
		if present[statement.ID] {
			continue
		}
		out = append(out, Finding{
			Repository: repository,
			CVEID:      statement.ID,
			Source:     statement.Source,
			State:      string(statement.State),
			Detail:     statement.Detail,
			ExpiresAt:  statement.ExpiresAt,
			Reason:     ReasonNoEffect,
		})
	}
	return out
}

func (a *Auditor) auditCVEStatements(ctx context.Context, repository string, records []*statestore.ScanRecord, now time.Time) ([]Finding, error) {
	candidates := candidateStatements(a.catalog.SyncVEX(repository), now)
	if len(candidates) == 0 {
		return nil, nil
	}
	cfg, err := a.catalog.ResolvePolicy(repository)
	if err != nil {
		return nil, err
	}
	// A cooldown only holds a passing scan back. It never turns on a VEX
	// statement, so the audit compares pass/fail without it.
	cfg.Cooldown = 0
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
		if changesOutcome(ctx, a.logger, engine, scans, baseline, evidence, without, candidate.ID) {
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
			Reason:        ReasonNoEffect,
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
			Reason:        ReasonNoEffect,
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
// not_affected or false_positive and not yet expired. Other states never
// exempt, malicious-package statements are audited separately, and expired
// statements are already reported by the expiry task.
func candidateStatements(statements []types.VEXStatement, now time.Time) []types.VEXStatement {
	var out []types.VEXStatement
	for _, statement := range statements {
		if !statement.State.ExemptsVulnerability() || types.IsMaliciousID(statement.ID) {
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
//
// A scan that already fails for another CVE hides the statement's effect, so
// each scan is also evaluated with every other CVE exempted. The statement is
// kept when either comparison changes the result.
func changesOutcome(ctx context.Context, logger *slog.Logger, engine policy.PolicyEngine, scans []*statestore.ScanRecord, baseline []bool, evidence, without []types.VEXStatement, cveID string) bool {
	now := time.Now()
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
		others := exemptOthers(scan, evidence, cveID, now)
		isolatedWith, err := evaluate(ctx, engine, scan, append(append([]types.VEXStatement(nil), evidence...), others...))
		if err != nil {
			logger.Warn("vex audit evaluation failed", "digest", scan.Digest, "error", err)
			return true
		}
		isolatedWithout, err := evaluate(ctx, engine, scan, append(append([]types.VEXStatement(nil), without...), others...))
		if err != nil {
			logger.Warn("vex audit evaluation failed", "digest", scan.Digest, "error", err)
			return true
		}
		if isolatedWith != isolatedWithout {
			return true
		}
	}
	return false
}

// exemptOthers returns a not_affected statement for every CVE on the scan
// except cveID that evidence does not already exempt. With them applied, only
// cveID can still decide the policy outcome.
func exemptOthers(scan *statestore.ScanRecord, evidence []types.VEXStatement, cveID string, now time.Time) []types.VEXStatement {
	exempted := make(map[string]struct{}, len(evidence))
	for _, statement := range candidateStatements(evidence, now) {
		exempted[statement.ID] = struct{}{}
	}
	var out []types.VEXStatement
	for _, vuln := range scan.Vulnerabilities {
		if vuln.CVEID == cveID {
			continue
		}
		if _, ok := exempted[vuln.CVEID]; ok {
			continue
		}
		exempted[vuln.CVEID] = struct{}{}
		out = append(out, types.VEXStatement{ID: vuln.CVEID, State: types.VEXStateNotAffected})
	}
	return out
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

// scanResult rebuilds what the policy saw. Malicious-package findings are left
// out on purpose: the audit asks whether a CVE statement changes the outcome,
// and a malicious package fails the image whatever the CVE statements say, so
// including it would make every statement on such an image look unused.
// Statements about malicious advisories are judged separately, on presence.
func scanResult(scan *statestore.ScanRecord) scanner.ScanResult {
	result := scanner.ScanResult{
		ImageRef:        scan.Digest,
		ScannedAt:       time.Unix(scan.CreatedAt, 0).UTC(),
		OSEndOfLife:     scan.OSEndOfLife,
		Vulnerabilities: make([]types.Vulnerability, 0, len(scan.Vulnerabilities)),
	}
	if scan.ImageCreatedAt > 0 {
		created := time.Unix(scan.ImageCreatedAt, 0).UTC()
		result.ImageCreatedAt = &created
	}
	for _, vuln := range scan.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, types.Vulnerability{
			ID:             vuln.CVEID,
			Severity:       vuln.Severity,
			PackageName:    vuln.PackageName,
			Version:        vuln.InstalledVersion,
			FixedVersion:   vuln.FixedVersion,
			Title:          vuln.Title,
			Description:    vuln.Description,
			PrimaryURL:     vuln.PrimaryURL,
			VendorStatus:   vuln.VendorStatus,
			VendorSeverity: vuln.VendorSeverity,
			AttackVector:   vuln.AttackVector,
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
