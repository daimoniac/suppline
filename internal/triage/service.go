package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/gitops"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/scanenqueue"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/triage/yamledit"
	"github.com/daimoniac/suppline/internal/types"
	"github.com/daimoniac/suppline/internal/worker"
)

// Service pulls gitops context, asks the LLM whether a policy exception
// applies, and records the guarded result.
type Service struct {
	settings Settings
	catalog  *catalog.ConfigCatalog
	runs     statestore.TriageStore
	scans    statestore.StateStoreQuery
	runtime  runtimeLookup
	clusters clusterQuerier
	enqueuer *scanenqueue.Enqueuer
	logger   *slog.Logger
	llm      completer
	git      *gitops.Manager
	kev      *KEVCache
	now      func() time.Time

	jobs      chan Job
	pending   map[string]struct{}
	pendingMu sync.Mutex

	// pullAll and apply are replaceable in tests.
	pullAll func(ctx context.Context) ([]gitops.Checkout, Roots, error)
	apply   func(ctx context.Context, repository string, statement types.VEXStatement, message string) (string, error)
}

type runtimeLookup interface {
	GetRuntimeUsageForScan(ctx context.Context, digest, repository, tag string) (*statestore.RuntimeUsage, error)
	RepositoryInUse(ctx context.Context, repository string) (bool, error)
}

// New builds a triage service. A missing API key disables the feature.
func New(cfg *config.TriageConfig, configPath string, cat *catalog.ConfigCatalog, store statestore.StateStoreQuery, enqueuer *scanenqueue.Enqueuer, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	settings, err := Resolve(cfg, configPath)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.Enabled && !settings.Enabled {
		logger.Error("triage disabled: SUPPLINE_LLM_API_KEY is unset")
	}
	var runs statestore.TriageStore
	if settings.Enabled {
		var ok bool
		runs, ok = store.(statestore.TriageStore)
		if !ok {
			return nil, fmt.Errorf("state store does not support triage runs")
		}
	}
	var runtime runtimeLookup
	if lookup, ok := store.(runtimeLookup); ok {
		runtime = lookup
	}
	var clusters clusterQuerier
	if lookup, ok := store.(clusterRuntimeStore); ok {
		clusters = runtimeTool{store: lookup}
	}
	svc := &Service{
		settings: settings,
		catalog:  cat,
		runs:     runs,
		scans:    store,
		runtime:  runtime,
		clusters: clusters,
		enqueuer: enqueuer,
		logger:   logger,
		llm: &Client{
			BaseURL: settings.BaseURL,
			Model:   settings.Model,
			APIKey:  settings.APIKey,
		},
		git:     &gitops.Manager{Base: settings.CheckoutDir},
		kev:     &KEVCache{URL: settings.KEVFeedURL, TTL: settings.KEVCacheTTL},
		now:     func() time.Time { return time.Now().UTC() },
		jobs:    make(chan Job, 256),
		pending: make(map[string]struct{}),
	}
	svc.pullAll = svc.pullCheckouts
	svc.apply = svc.applyStatement
	return svc, nil
}

// ValidateStartup fails when enforce mode would have nowhere writable to put x-vex-auto.
func (s *Service) ValidateStartup() error {
	if s == nil || !s.settings.Enabled {
		return nil
	}
	if _, err := s.settings.contextSpecs(); err != nil {
		return fmt.Errorf("triage context repositories: %w", err)
	}
	if s.settings.ConfigRepo != nil {
		if _, err := s.settings.configSpec(); err != nil {
			return fmt.Errorf("triage config repository: %w", err)
		}
	} else if s.settings.Mode == config.TriageModeEnforce {
		if err := Writable(s.settings.ConfigPath); err != nil {
			return fmt.Errorf("triage enforce mode writes suppline.yml locally: %w", err)
		}
	}
	return nil
}

// Start runs the queue and the renewal sweep until ctx is cancelled.
func (s *Service) Start(ctx context.Context) error {
	if s == nil || !s.settings.Enabled {
		<-ctx.Done()
		return nil
	}
	go s.sweepLoop(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case job := <-s.jobs:
			batch := []Job{job}
		drain:
			for len(batch) < 32 {
				select {
				case extra := <-s.jobs:
					batch = append(batch, extra)
				default:
					break drain
				}
			}
			s.processBatch(ctx, batch)
		}
	}
}

// Enabled reports whether triage accepts work.
func (s *Service) Enabled() bool {
	return s != nil && s.settings.Enabled
}

// Mode is dry-run or enforce.
func (s *Service) Mode() string {
	if s == nil {
		return ""
	}
	return s.settings.Mode
}

// OnlyInUse reports whether triage is limited to images running in a cluster.
func (s *Service) OnlyInUse() bool {
	return s == nil || s.settings.OnlyInUse
}

// Pending is the number of jobs waiting or in flight.
func (s *Service) Pending() int {
	if s == nil {
		return 0
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return len(s.pending)
}

// NotifyPolicyFailure queues one job per finding that has no active exemption.
func (s *Service) NotifyPolicyFailure(ctx context.Context, notice worker.PolicyFailureNotice) {
	s.queuePolicyFailure(ctx, notice, false)
}

// QueuePolicyFailure queues the same work as a policy failure and runs it
// again even when a cached decision exists. It returns how many findings were queued.
func (s *Service) QueuePolicyFailure(ctx context.Context, notice worker.PolicyFailureNotice) int {
	return s.queuePolicyFailure(ctx, notice, true)
}

func (s *Service) queuePolicyFailure(ctx context.Context, notice worker.PolicyFailureNotice, force bool) int {
	if s == nil || !s.settings.Enabled {
		return 0
	}
	if s.settings.OnlyInUse {
		used, err := s.imageInUse(ctx, notice.Digest, notice.Repository, notice.Tag)
		if err != nil {
			s.logger.Error("triage in-use lookup failed", "repository", notice.Repository, "digest", notice.Digest, "error", err)
			return 0
		}
		if !used {
			s.logger.Debug("triage skipped, image not in use", "repository", notice.Repository, "tag", notice.Tag, "digest", notice.Digest)
			return 0
		}
	}
	queued := 0
	for _, finding := range notice.Findings {
		if s.exempt(notice.Repository, finding.CVEID) {
			continue
		}
		job := Job{
			Repository:  notice.Repository,
			CVEID:       finding.CVEID,
			PackageName: finding.PackageName,
			ImageRef:    notice.Repository,
			Tag:         notice.Tag,
			Digest:      notice.Digest,
		}
		if notice.Tag != "" {
			job.ImageRef = notice.Repository + ":" + notice.Tag
		}
		for _, vuln := range notice.Vulnerabilities {
			if vuln.ID != finding.CVEID {
				continue
			}
			if finding.PackageName != "" && vuln.PackageName != finding.PackageName {
				continue
			}
			job.PackageName = vuln.PackageName
			job.Version = vuln.Version
			job.FixedVersion = vuln.FixedVersion
			job.Severity = vuln.Severity
			job.Description = vuln.Description
			break
		}
		job.Force = force
		if s.enqueue(job) {
			queued++
		}
	}
	return queued
}

func (s *Service) exempt(repository, cve string) bool {
	if s.catalog == nil {
		return false
	}
	now := s.now()
	for _, statement := range s.catalog.ResolveEvidence(repository).VEXStatements {
		if statement.ID != cve || statement.State != types.VEXStateNotAffected {
			continue
		}
		if statement.ExpiresAt != nil && time.Unix(*statement.ExpiresAt, 0).Before(now) {
			continue
		}
		return true
	}
	return false
}

func (s *Service) enqueue(job Job) bool {
	if job.Repository == "" || job.CVEID == "" {
		return false
	}
	s.pendingMu.Lock()
	if _, exists := s.pending[job.key()]; exists {
		s.pendingMu.Unlock()
		return false
	}
	s.pending[job.key()] = struct{}{}
	s.pendingMu.Unlock()
	select {
	case s.jobs <- job:
		return true
	default:
		s.finish(job)
		s.logger.Error("triage queue full", "repository", job.Repository, "cve", job.CVEID)
		return false
	}
}

func (s *Service) finish(job Job) {
	s.pendingMu.Lock()
	delete(s.pending, job.key())
	s.pendingMu.Unlock()
}

func (s *Service) sweepLoop(ctx context.Context) {
	s.sweep(ctx)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

func (s *Service) sweep(ctx context.Context) {
	if s.catalog == nil {
		return
	}
	now := s.now()
	for _, repository := range s.catalog.Repositories() {
		if s.settings.OnlyInUse {
			used, err := s.repositoryInUse(ctx, repository)
			if err != nil {
				s.logger.Error("triage in-use lookup failed", "repository", repository, "error", err)
				continue
			}
			if !used {
				continue
			}
		}
		for _, statement := range s.catalog.AutoVEX(repository) {
			if statement.ExpiresAt == nil {
				continue
			}
			if time.Unix(*statement.ExpiresAt, 0).Sub(now) > s.settings.RenewBefore {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.enqueue(Job{
				Repository:  repository,
				CVEID:       statement.ID,
				Renewal:     true,
				Description: statement.Detail,
			})
		}
	}
}

func (s *Service) processBatch(ctx context.Context, batch []Job) {
	defer func() {
		for _, job := range batch {
			s.finish(job)
		}
	}()
	if s.overBudget(ctx) {
		observability.GetMetrics().TriageBudgetExhausted.Set(1)
		s.logger.Warn("triage daily token budget exhausted")
		s.waitForBudget(ctx)
		if ctx.Err() != nil {
			return
		}
	}
	observability.GetMetrics().TriageBudgetExhausted.Set(0)

	checkouts, roots, err := s.pullAll(ctx)
	if err != nil {
		for _, job := range batch {
			s.record(ctx, job, modelVerdict{}, 0, StatusError, "", shaKey(checkouts), err.Error())
		}
		s.logger.Error("triage gitops pull failed", "error", err)
		return
	}
	for _, job := range batch {
		if ctx.Err() != nil {
			return
		}
		s.process(ctx, job, checkouts, roots)
	}
}

func (s *Service) process(ctx context.Context, job Job, checkouts []gitops.Checkout, roots Roots) {
	shas := shaKey(checkouts)
	last, err := s.runs.LatestTriageRun(ctx, job.Repository, job.CVEID)
	if err != nil {
		s.logger.Error("triage lookup failed", "repository", job.Repository, "cve", job.CVEID, "error", err)
		return
	}
	if !job.Force && ShouldSkip(last, job.Renewal, shas, job.cveHash(), s.settings.RetriageInterval, s.now()) {
		s.logger.Debug("triage skipped", "repository", job.Repository, "cve", job.CVEID, "renewal", job.Renewal)
		return
	}
	if s.overBudget(ctx) {
		observability.GetMetrics().TriageBudgetExhausted.Set(1)
		s.logger.Warn("triage daily token budget exhausted", "repository", job.Repository, "cve", job.CVEID)
		return
	}

	var existing *types.VEXStatement
	if s.catalog != nil {
		for _, statement := range s.catalog.AutoVEX(job.Repository) {
			if statement.ID == job.CVEID {
				copied := statement
				existing = &copied
				break
			}
		}
	}
	names := make([]string, len(checkouts))
	for i, checkout := range checkouts {
		names[i] = checkout.Name
	}
	verdict, tokens, err := runAgent(ctx, s.llm, roots, s.clusters, newPublicSource(), allowedNames(s.settings), job, s.placements(ctx, job), names, existing, s.settings.MaxSteps)
	if err != nil {
		s.record(ctx, job, verdict, tokens, StatusError, "", shas, err.Error())
		s.logger.Error("triage agent failed", "repository", job.Repository, "cve", job.CVEID, "error", err)
		return
	}
	evidenceErr := ""
	if err := verifyEvidence(roots, verdict); err != nil {
		evidenceErr = err.Error()
	}
	kevHit, kevErr := s.kev.Contains(ctx, job.CVEID)
	if !s.settings.BlockKEV {
		kevHit, kevErr = false, nil
	}
	decision := decide(s.settings, job, verdict, evidenceErr, kevHit, kevErr, existing, checkouts, fmt.Sprintf("tr-%d", s.now().UnixNano()), s.now())
	switch decision.Action {
	case outcomeNotAffected, outcomeAffected:
		if s.settings.Mode == config.TriageModeDryRun {
			s.record(ctx, job, verdict, tokens, StatusDryRun, "", shas, decision.Statement.Detail)
			return
		}
		message := fmt.Sprintf("chore(vex): auto-triage %s for %s\n\ntriage verdict: %s\n%s", job.CVEID, job.Repository, decision.Statement.State, decision.Reason)
		commit, err := s.apply(ctx, job.Repository, decision.Statement, message)
		if err != nil {
			status := StatusError
			var pushErr *gitops.PushError
			if errors.As(err, &pushErr) {
				status = StatusPushFailed
				observability.GetMetrics().TriagePushFailures.Inc()
			}
			s.record(ctx, job, verdict, tokens, status, "", shas, err.Error())
			s.logger.Error("triage apply failed", "repository", job.Repository, "cve", job.CVEID, "error", err)
			return
		}
		if s.catalog != nil {
			next := upsertStatement(s.catalog.AutoVEX(job.Repository), decision.Statement)
			if err := s.catalog.ReplaceAutoVEX(job.Repository, next); err != nil {
				s.logger.Error("triage hot-swap failed", "repository", job.Repository, "error", err)
			}
		}
		s.reevaluate(ctx, job.Repository)
		status := StatusWritten
		if s.settings.ConfigRepo != nil {
			status = StatusCommitted
		}
		s.record(ctx, job, verdict, tokens, status, commit, shas, decision.Statement.Detail)
	default:
		s.record(ctx, job, verdict, tokens, StatusRejected, "", shas, decision.Reason)
	}
}

func (s *Service) record(ctx context.Context, job Job, verdict modelVerdict, tokens int, status, commit, shas, reasoning string) {
	if tokens > 0 {
		observability.GetMetrics().TriageTokens.Add(float64(tokens))
	}
	observability.GetMetrics().TriageRuns.WithLabelValues(status).Inc()
	if s.runs == nil {
		return
	}
	evidence, _ := json.Marshal(verdict.Evidence)
	text := reasoning
	if text == "" {
		text = verdict.Reasoning
	}
	err := s.runs.InsertTriageRun(ctx, &statestore.TriageRun{
		Repository:    job.Repository,
		CVEID:         job.CVEID,
		Verdict:       verdict.Verdict,
		Justification: verdict.Justification,
		Confidence:    verdict.Confidence,
		EvidenceJSON:  string(evidence),
		Reasoning:     text,
		Model:         s.settings.Model,
		RepoSHAsJSON:  shas,
		CVEHash:       job.cveHash(),
		Tokens:        tokens,
		Status:        status,
		CommitSHA:     commit,
		CreatedAt:     s.now(),
	})
	if err != nil {
		s.logger.Error("record triage run", "repository", job.Repository, "cve", job.CVEID, "error", err)
	}
}

func (s *Service) overBudget(ctx context.Context) bool {
	if s.runs == nil || s.settings.DailyTokenBudget <= 0 {
		return false
	}
	now := s.now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	used, err := s.runs.TriageTokensSince(ctx, start)
	if err != nil {
		s.logger.Error("triage token budget lookup failed", "error", err)
		return false
	}
	return used >= s.settings.DailyTokenBudget
}

func (s *Service) waitForBudget(ctx context.Context) {
	now := s.now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (s *Service) pullCheckouts(ctx context.Context) ([]gitops.Checkout, Roots, error) {
	specs, err := s.settings.contextSpecs()
	if err != nil {
		return nil, Roots{}, err
	}
	checkouts := make([]gitops.Checkout, 0, len(specs))
	roots := Roots{MaxFileBytes: s.settings.MaxFileBytes}
	for i, spec := range specs {
		checkout, err := s.git.Pull(ctx, spec)
		if err != nil {
			return nil, Roots{}, err
		}
		checkouts = append(checkouts, checkout)
		roots.Checkouts = append(roots.Checkouts, CheckoutRoot{
			Name:    checkout.Name,
			Dir:     checkout.Dir,
			Include: s.settings.Context[i].Include,
			Exclude: s.settings.Context[i].Exclude,
		})
	}
	return checkouts, roots, nil
}

func (s *Service) applyStatement(ctx context.Context, repository string, statement types.VEXStatement, message string) (string, error) {
	if s.settings.ConfigRepo != nil {
		spec, err := s.settings.configSpec()
		if err != nil {
			return "", err
		}
		return s.git.CommitFile(ctx, spec, s.settings.ConfigRepo.Path, func(current []byte) ([]byte, error) {
			return yamledit.Upsert(current, repository, statement)
		}, message)
	}
	return "", writeLocalStatement(s.settings.ConfigPath, s.settings.BackupRetention, repository, statement)
}

func writeLocalStatement(path string, retention int, repository string, statement types.VEXStatement) error {
	current, err := readFile(path)
	if err != nil {
		return err
	}
	updated, err := yamledit.Upsert(current, repository, statement)
	if err != nil {
		return err
	}
	return WriteLocal(path, retention, updated)
}

func (s *Service) reevaluate(ctx context.Context, repository string) {
	if s.enqueuer == nil || s.scans == nil {
		return
	}
	scans, err := s.scans.ListScans(ctx, statestore.ScanFilter{Repository: repository, Limit: 1000})
	if err != nil {
		s.logger.Error("triage reevaluate list failed", "repository", repository, "error", err)
		return
	}
	seen := make(map[string]struct{})
	for _, scan := range scans {
		key := scan.Repository + "@" + scan.Digest
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, err := s.enqueuer.EnqueueRescan(ctx, scanenqueue.Image{
			Repository: scan.Repository,
			Digest:     scan.Digest,
			Tag:        scan.Tag,
		}); err != nil {
			s.logger.Error("triage reevaluate enqueue failed", "repository", scan.Repository, "digest", scan.Digest, "error", err)
		}
	}
}

func (s *Service) imageInUse(ctx context.Context, digest, repository, tag string) (bool, error) {
	if s.runtime == nil {
		return false, nil
	}
	usage, err := s.runtime.GetRuntimeUsageForScan(ctx, digest, repository, tag)
	if err != nil || usage == nil {
		return false, err
	}
	return usage.RuntimeUsed, nil
}

func (s *Service) repositoryInUse(ctx context.Context, repository string) (bool, error) {
	if s.runtime == nil {
		return false, nil
	}
	return s.runtime.RepositoryInUse(ctx, repository)
}

func (s *Service) placements(ctx context.Context, job Job) string {
	if s.runtime == nil || job.Digest == "" {
		return ""
	}
	usage, err := s.runtime.GetRuntimeUsageForScan(ctx, job.Digest, job.Repository, job.Tag)
	if err != nil || usage == nil || !usage.RuntimeUsed {
		return ""
	}
	var b strings.Builder
	count := 0
	for cluster, namespaces := range usage.Runtime {
		for namespace, images := range namespaces {
			for _, image := range images {
				fmt.Fprintf(&b, "%s/%s %s:%s %s\n", cluster, namespace, image.ImageRef, image.Tag, image.Digest)
				count++
				if count >= 20 {
					return b.String()
				}
			}
		}
	}
	return b.String()
}

func upsertStatement(list []types.VEXStatement, statement types.VEXStatement) []types.VEXStatement {
	for i := range list {
		if list[i].ID == statement.ID {
			list[i] = statement
			return list
		}
	}
	return append(list, statement)
}

func allowedNames(settings Settings) []string {
	names := make([]string, 0, len(settings.Allowed))
	for justification := range settings.Allowed {
		names = append(names, string(justification))
	}
	sort.Strings(names)
	return names
}

func shaKey(checkouts []gitops.Checkout) string {
	type item struct {
		Name string `json:"name"`
		SHA  string `json:"sha"`
	}
	items := make([]item, len(checkouts))
	for i, checkout := range checkouts {
		items[i] = item{Name: checkout.Name, SHA: checkout.SHA}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	raw, _ := json.Marshal(items)
	return string(raw)
}
