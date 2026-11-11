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
	images   imageLabeler
	unpack   imageUnpacker
	enqueuer *scanenqueue.Enqueuer
	logger   *slog.Logger
	llm      completer
	git      *gitops.Manager
	kev      *KEVCache
	now      func() time.Time

	jobs      chan Job
	pending   map[string]ActiveJob
	pendingMu sync.Mutex

	budgetMu   sync.Mutex
	budgetWait chan struct{}

	// pullAll and apply are replaceable in tests.
	pullAll func(ctx context.Context) ([]gitops.Checkout, Roots, error)
	apply   func(ctx context.Context, repository string, statements []types.VEXStatement, message string) (string, error)
}

type runtimeLookup interface {
	GetRuntimeUsageForScan(ctx context.Context, digest, repository, tag string) (*statestore.RuntimeUsage, error)
	RepositoryInUse(ctx context.Context, repository string) (bool, error)
}

// SetImageLabels supplies label reads and image unpack for the image being triaged.
func (s *Service) SetImageLabels(src imageAccess) {
	if s != nil {
		s.images = src
		s.unpack = src
	}
}

type imageAccess interface {
	imageLabeler
	imageUnpacker
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
		pending: make(map[string]ActiveJob),
	}
	svc.pullAll = svc.pullCheckouts
	svc.apply = svc.applyStatements
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

// ActiveJob is one CVE waiting or inside a session.
type ActiveJob struct {
	Repository string
	CVEID      string
	Image      string
	SessionID  string
	Phase      string
	Current    bool
}

// SessionStatus is one repository session in flight.
type SessionStatus struct {
	SessionID  string
	Repository string
	Image      string
	Phase      string
	CurrentCVE string
	CVEs       []SessionCVE
}

// SessionCVE is one CVE inside a session.
type SessionCVE struct {
	CVEID  string
	Status string
}

// QueuedJob is one CVE accepted onto the queue and not yet in a session.
type QueuedJob struct {
	Repository string
	CVEID      string
	Image      string
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

// Sessions lists sessions in flight. Only the CVE being decided is running.
func (s *Service) Sessions() []SessionStatus {
	if s == nil {
		return nil
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	byID := map[string]*SessionStatus{}
	var order []string
	for _, job := range s.pending {
		if job.SessionID == "" {
			continue
		}
		session, ok := byID[job.SessionID]
		if !ok {
			session = &SessionStatus{
				SessionID:  job.SessionID,
				Repository: job.Repository,
				Image:      job.Image,
				Phase:      job.Phase,
			}
			byID[job.SessionID] = session
			order = append(order, job.SessionID)
		}
		status := "waiting"
		if job.Current {
			status = "running"
			session.CurrentCVE = job.CVEID
			session.Phase = job.Phase
		}
		session.CVEs = append(session.CVEs, SessionCVE{CVEID: job.CVEID, Status: status})
	}
	out := make([]SessionStatus, 0, len(order))
	for _, id := range order {
		session := *byID[id]
		sort.Slice(session.CVEs, func(i, j int) bool { return session.CVEs[i].CVEID < session.CVEs[j].CVEID })
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repository == out[j].Repository {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].Repository < out[j].Repository
	})
	return out
}

// Queued lists jobs accepted but not yet in a session.
func (s *Service) Queued() []QueuedJob {
	if s == nil {
		return nil
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	out := make([]QueuedJob, 0, len(s.pending))
	for _, job := range s.pending {
		if job.SessionID != "" {
			continue
		}
		out = append(out, QueuedJob{Repository: job.Repository, CVEID: job.CVEID, Image: job.Image})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repository == out[j].Repository {
			return out[i].CVEID < out[j].CVEID
		}
		return out[i].Repository < out[j].Repository
	})
	return out
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
		used, err := s.repositoryInUse(ctx, notice.Repository)
		if err != nil {
			s.logger.Error("triage in-use lookup failed", "repository", notice.Repository, "error", err)
			return 0
		}
		if !used {
			s.logger.Debug("triage skipped, repository not in use", "repository", notice.Repository)
			return 0
		}
	}
	queued := 0
	for _, finding := range notice.Findings {
		if s.exempt(notice.Repository, finding.CVEID) {
			continue
		}
		job := Job{
			Repository: notice.Repository,
			CVEID:      finding.CVEID,
			ImageRef:   notice.Repository,
			Force:      force,
		}
		if notice.Tag != "" {
			job.ImageRef = notice.Repository + ":" + notice.Tag
		}
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

// Retry queues one finished decision again, even when an exemption already exists.
// only_in_use still applies. It returns 1 when the job was accepted.
func (s *Service) Retry(ctx context.Context, repository, cve string) int {
	if s == nil || !s.settings.Enabled {
		return 0
	}
	repository = strings.TrimSpace(repository)
	cve = strings.TrimSpace(cve)
	if repository == "" || cve == "" {
		return 0
	}
	if s.settings.OnlyInUse {
		used, err := s.repositoryInUse(ctx, repository)
		if err != nil {
			s.logger.Error("triage in-use lookup failed", "repository", repository, "cve", cve, "error", err)
			return 0
		}
		if !used {
			return 0
		}
	}
	job := Job{Repository: repository, CVEID: cve, ImageRef: repository, Force: true}
	if s.enqueue(job) {
		return 1
	}
	return 0
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
	s.pending[job.key()] = ActiveJob{Repository: job.Repository, CVEID: job.CVEID, Image: job.ImageRef}
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

func (s *Service) beginSession(jobs []Job, sessionID, image string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for _, job := range jobs {
		current, ok := s.pending[job.key()]
		if !ok {
			continue
		}
		current.SessionID = sessionID
		current.Phase = phaseContext
		current.Current = false
		if image != "" {
			current.Image = image
		}
		s.pending[job.key()] = current
	}
}

func (s *Service) focusCVE(repository, cve string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for key, job := range s.pending {
		if job.SessionID == "" || job.Repository != repository {
			continue
		}
		job.Phase = "deciding"
		job.Current = job.CVEID == cve
		s.pending[key] = job
	}
}

func (s *Service) processBatch(ctx context.Context, batch []Job) {
	defer func() {
		for _, job := range batch {
			s.finish(job)
		}
	}()
	for s.overBudget(ctx) {
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
			s.record(ctx, job, modelVerdict{}, 0, StatusError, "", "", shaKey(checkouts), err.Error())
		}
		s.logger.Error("triage gitops pull failed", "error", err)
		return
	}
	maxGroup := s.settings.MaxGroup
	if maxGroup < 1 {
		maxGroup = 8
	}
	for _, jobs := range groupByRepository(batch) {
		for start := 0; start < len(jobs); start += maxGroup {
			if ctx.Err() != nil {
				return
			}
			end := start + maxGroup
			if end > len(jobs) {
				end = len(jobs)
			}
			chunk := jobs[start:end]
			resolved, err := s.resolveJobs(ctx, chunk)
			if err != nil {
				for _, job := range chunk {
					s.record(ctx, job, modelVerdict{}, 0, StatusError, "", "", shaKey(checkouts), err.Error())
				}
				s.logger.Error("triage resolve failed", "repository", chunk[0].Repository, "error", err)
				continue
			}
			kept := map[string]struct{}{}
			for _, job := range resolved {
				kept[job.key()] = struct{}{}
			}
			for _, job := range chunk {
				if _, ok := kept[job.key()]; ok {
					continue
				}
				s.finish(job)
				s.logger.Debug("triage skipped, cve not in current scans", "repository", job.Repository, "cve", job.CVEID)
			}
			s.executeSession(ctx, resolved, checkouts, roots)
		}
	}
}

func groupByRepository(batch []Job) [][]Job {
	index := map[string]int{}
	var groups [][]Job
	for _, job := range batch {
		at, ok := index[job.Repository]
		if !ok {
			index[job.Repository] = len(groups)
			groups = append(groups, nil)
			at = len(groups) - 1
		}
		groups[at] = append(groups[at], job)
	}
	return groups
}

func (s *Service) resolveJobs(ctx context.Context, jobs []Job) ([]Job, error) {
	if len(jobs) == 0 || s.scans == nil {
		return jobs, nil
	}
	records, err := s.scans.ListScans(ctx, statestore.ScanFilter{Repository: jobs[0].Repository})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		if jobsHaveFacts(jobs) {
			return jobs, nil
		}
		return nil, nil
	}
	if err := s.loadFindings(ctx, jobs[0].Repository, records); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(jobs))
	flags := make(map[string]Job, len(jobs))
	for _, job := range jobs {
		ids = append(ids, job.CVEID)
		flags[job.CVEID] = job
	}
	resolved := resolveGroup(records, jobs[0].Repository, ids, s.settings.OnlyInUse)
	for i := range resolved {
		src := flags[resolved[i].CVEID]
		resolved[i].Force = src.Force
		resolved[i].Renewal = src.Renewal
	}
	return resolved, nil
}

// loadFindings fills vulnerability rows that ListScans leaves out.
func (s *Service) loadFindings(ctx context.Context, repository string, records []*statestore.ScanRecord) error {
	full := map[string][]types.VulnerabilityRecord{}
	for _, record := range records {
		if record == nil || record.Repository != repository || record.Digest == "" || len(record.Vulnerabilities) > 0 {
			continue
		}
		vulns, ok := full[record.Digest]
		if !ok {
			scan, err := s.scans.GetLastRepositoryScan(ctx, repository, record.Digest)
			if err != nil && !errors.Is(err, statestore.ErrScanNotFound) {
				return fmt.Errorf("load findings for %s@%s: %w", repository, record.Digest, err)
			}
			if scan != nil {
				vulns = scan.Vulnerabilities
			}
			full[record.Digest] = vulns
		}
		record.Vulnerabilities = vulns
	}
	return nil
}

func jobsHaveFacts(jobs []Job) bool {
	for _, job := range jobs {
		if job.PackageName != "" || job.Description != "" || len(job.Packages) > 0 || job.Digest != "" {
			return true
		}
	}
	return false
}

func (s *Service) process(ctx context.Context, job Job, checkouts []gitops.Checkout, roots Roots) {
	s.executeSession(ctx, []Job{job}, checkouts, roots)
}

func (s *Service) executeSession(ctx context.Context, jobs []Job, checkouts []gitops.Checkout, roots Roots) {
	if len(jobs) == 0 {
		return
	}
	shas := shaKey(checkouts)
	runnable := make([]Job, 0, len(jobs))
	for _, job := range jobs {
		if s.catalog != nil {
			if source, platform, ok := s.catalog.Upstream(job.Repository); ok {
				job.Upstream = source
				job.Platform = platform
			}
		}
		var last *statestore.TriageRun
		if s.runs != nil {
			found, err := s.runs.LatestTriageRun(ctx, job.Repository, job.CVEID)
			if err != nil {
				s.logger.Error("triage lookup failed", "repository", job.Repository, "cve", job.CVEID, "error", err)
				s.finish(job)
				continue
			}
			last = found
		}
		if !job.Force && ShouldSkip(last, job.Renewal, shas, job.cveHash(), s.settings.RetriageInterval, s.now()) {
			s.logger.Debug("triage skipped", "repository", job.Repository, "cve", job.CVEID, "renewal", job.Renewal)
			s.finish(job)
			continue
		}
		if s.overBudget(ctx) {
			observability.GetMetrics().TriageBudgetExhausted.Set(1)
			s.logger.Warn("triage daily token budget exhausted", "repository", job.Repository, "cve", job.CVEID)
			break
		}
		runnable = append(runnable, job)
	}
	if len(runnable) == 0 {
		return
	}
	if runnable[0].PlacementText == "" {
		text := s.placements(ctx, runnable[0])
		for i := range runnable {
			runnable[i].PlacementText = text
		}
	}
	sessionID := fmt.Sprintf("ts-%d", s.now().UnixNano())
	s.beginSession(runnable, sessionID, runnable[0].ImageRef)

	names := make([]string, len(checkouts))
	for i, checkout := range checkouts {
		names[i] = checkout.Name
	}
	jobRoots := roots
	jobRoots.Checkouts = append([]CheckoutRoot(nil), roots.Checkouts...)
	jobRoots.Image = newImageFS(s.unpack, runnable[0].Repository, runnable[0].Digest)
	pub := newPublicSource()
	upstream := &publicCheckouts{base: s.settings.CheckoutDir, pub: pub}
	existing := map[string]*types.VEXStatement{}
	if s.catalog != nil {
		for _, statement := range s.catalog.AutoVEX(runnable[0].Repository) {
			for _, job := range runnable {
				if statement.ID != job.CVEID {
					continue
				}
				copied := statement
				existing[job.CVEID] = &copied
			}
		}
	}
	result := runSession(ctx, s.llm, &jobRoots, s.clusters, pub, upstream, s.images, ociManifests{}, allowedNames(s.settings), s.settings.Prompt, s.settings.MinConfidence, runnable, names, existing, s.settings.MaxSteps, func() bool {
		return !s.overBudget(ctx)
	}, sessionHooks{
		onContext: func() {},
		onCVE:     func(cve string) { s.focusCVE(runnable[0].Repository, cve) },
	})
	if result.Err != nil {
		shares := splitContextTokens(result.ContextTokens, errorTurns(runnable, result.Err))
		for i, job := range runnable {
			tokens := shares[i]
			s.record(ctx, job, modelVerdict{}, tokens, StatusError, sessionID, "", shas, sessionFailure(result.Err))
		}
		s.logger.Error("triage session failed", "repository", runnable[0].Repository, "error", result.Err)
		return
	}
	shares := splitContextTokens(result.ContextTokens, result.Turns)
	type pendingWrite struct {
		turn     sessionTurn
		decision verdictDecision
		tokens   int
	}
	var writing []pendingWrite
	var rejected []pendingWrite
	for i, turn := range result.Turns {
		tokens := turn.Tokens + shares[i]
		if turn.Err != nil {
			s.record(ctx, turn.Job, modelVerdict{}, tokens, StatusError, sessionID, "", shas, turn.Err.Error())
			s.logger.Error("triage cve failed", "repository", turn.Job.Repository, "cve", turn.Job.CVEID, "error", turn.Err)
			continue
		}
		evidenceErr := ""
		if err := verifyEvidence(jobRoots, pub, turn.Job, &turn.Verdict); err != nil {
			evidenceErr = err.Error()
		}
		var kevHit bool
		var kevErr error
		if s.settings.BlockKEV && s.kev != nil {
			kevHit, kevErr = s.kev.Contains(ctx, turn.Job.CVEID)
		}
		decision := decide(s.settings, turn.Job, turn.Verdict, evidenceErr, kevHit, kevErr, existing[turn.Job.CVEID], checkouts, sessionID, s.now())
		row := pendingWrite{turn: turn, decision: decision, tokens: tokens}
		if decision.Action == outcomeNotAffected || decision.Action == outcomeAffected {
			writing = append(writing, row)
			continue
		}
		rejected = append(rejected, row)
	}
	for _, row := range rejected {
		s.record(ctx, row.turn.Job, row.turn.Verdict, row.tokens, StatusRejected, sessionID, "", shas, row.decision.Reason)
	}
	if len(writing) == 0 {
		return
	}
	if s.settings.Mode == config.TriageModeDryRun {
		for _, row := range writing {
			s.record(ctx, row.turn.Job, row.turn.Verdict, row.tokens, StatusDryRun, sessionID, "", shas, row.decision.Statement.Detail)
		}
		return
	}
	statements := make([]types.VEXStatement, 0, len(writing))
	lines := make([]string, 0, len(writing))
	for _, row := range writing {
		statements = append(statements, row.decision.Statement)
		lines = append(lines, fmt.Sprintf("%s %s", row.turn.Job.CVEID, row.decision.Statement.State))
	}
	message := autoCommitMessage(runnable[0].Repository, lines)
	commit, err := s.apply(ctx, runnable[0].Repository, statements, message)
	if err != nil {
		status := StatusError
		var pushErr *gitops.PushError
		if errors.As(err, &pushErr) {
			status = StatusPushFailed
			observability.GetMetrics().TriagePushFailures.Inc()
		}
		for _, row := range writing {
			s.record(ctx, row.turn.Job, row.turn.Verdict, row.tokens, status, sessionID, "", shas, err.Error())
		}
		s.logger.Error("triage apply failed", "repository", runnable[0].Repository, "error", err)
		return
	}
	if s.catalog != nil {
		next := s.catalog.AutoVEX(runnable[0].Repository)
		for _, statement := range statements {
			next = upsertStatement(next, statement)
		}
		if err := s.catalog.ReplaceAutoVEX(runnable[0].Repository, next); err != nil {
			s.logger.Error("triage hot-swap failed", "repository", runnable[0].Repository, "error", err)
		}
	}
	s.reevaluate(ctx, runnable[0].Repository)
	status := StatusWritten
	if s.settings.ConfigRepo != nil {
		status = StatusCommitted
	}
	for _, row := range writing {
		s.record(ctx, row.turn.Job, row.turn.Verdict, row.tokens, status, sessionID, commit, shas, row.decision.Statement.Detail)
	}
}

func errorTurns(jobs []Job, err error) []sessionTurn {
	turns := make([]sessionTurn, len(jobs))
	for i, job := range jobs {
		turns[i] = sessionTurn{Job: job, Err: err}
	}
	return turns
}

func (s *Service) record(ctx context.Context, job Job, verdict modelVerdict, tokens int, status, sessionID, commit, shas, reasoning string) {
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
		SessionID:     sessionID,
		CommitSHA:     commit,
		CreatedAt:     s.now(),
	})
	if err != nil {
		s.logger.Error("record triage run", "repository", job.Repository, "cve", job.CVEID, "error", err)
	}
}

// Budget is today's token spend against the configured limit.
type Budget struct {
	Used      int
	Limit     int
	Exhausted bool
}

func (s *Service) BudgetStatus(ctx context.Context) Budget {
	if s == nil {
		return Budget{}
	}
	limit := s.settings.DailyTokenBudget
	if s.runs == nil || limit <= 0 {
		return Budget{Limit: limit}
	}
	start, err := s.budgetStart(ctx)
	if err != nil {
		s.logger.Error("triage token budget lookup failed", "error", err)
		return Budget{Limit: limit}
	}
	used, err := s.runs.TriageTokensSince(ctx, start)
	if err != nil {
		s.logger.Error("triage token budget lookup failed", "error", err)
		return Budget{Limit: limit}
	}
	return Budget{Used: used, Limit: limit, Exhausted: used >= limit}
}

// ResetDailyBudget starts a new token window at the current time and wakes a worker parked until midnight.
func (s *Service) ResetDailyBudget(ctx context.Context) error {
	if s == nil || s.runs == nil {
		return fmt.Errorf("triage store unavailable")
	}
	if err := s.runs.SetBudgetResetAt(ctx, s.now()); err != nil {
		return err
	}
	observability.GetMetrics().TriageBudgetExhausted.Set(0)
	s.wakeBudgetWait()
	s.logger.Info("triage daily token budget reset")
	return nil
}

func (s *Service) overBudget(ctx context.Context) bool {
	return s.BudgetStatus(ctx).Exhausted
}

func (s *Service) budgetStart(ctx context.Context) (time.Time, error) {
	now := s.now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	reset, err := s.runs.BudgetResetAt(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !reset.IsZero() && !reset.Before(start) {
		start = time.Unix(reset.Unix()+1, 0).UTC()
	}
	return start, nil
}

func (s *Service) waitForBudget(ctx context.Context) {
	wait := s.budgetSignal()
	if !s.overBudget(ctx) {
		return
	}
	now := s.now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	case <-wait:
	}
}

func (s *Service) budgetSignal() <-chan struct{} {
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if s.budgetWait == nil {
		s.budgetWait = make(chan struct{})
	}
	return s.budgetWait
}

func (s *Service) wakeBudgetWait() {
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if s.budgetWait != nil {
		close(s.budgetWait)
		s.budgetWait = nil
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

// autoCommitMessage is the GitLab commit for one x-vex-auto write.
// [skip ci] keeps that push from starting a pipeline. lines are "CVE state".
func autoCommitMessage(repository string, lines []string) string {
	n := len(lines)
	label := "CVEs"
	if n == 1 {
		label = "CVE"
	}
	return fmt.Sprintf("chore(vex): auto-triage %d %s for %s [skip ci]\n\n%s", n, label, repository, strings.Join(lines, "\n"))
}

func (s *Service) applyStatements(ctx context.Context, repository string, statements []types.VEXStatement, message string) (string, error) {
	if len(statements) == 0 {
		return "", nil
	}
	if s.settings.ConfigRepo != nil {
		spec, err := s.settings.configSpec()
		if err != nil {
			return "", err
		}
		return s.git.CommitFile(ctx, spec, s.settings.ConfigRepo.Path, func(current []byte) ([]byte, error) {
			return yamledit.UpsertMany(current, repository, statements)
		}, message)
	}
	return "", writeLocalStatements(s.settings.ConfigPath, s.settings.BackupRetention, repository, statements)
}

func writeLocalStatements(path string, retention int, repository string, statements []types.VEXStatement) error {
	current, err := readFile(path)
	if err != nil {
		return err
	}
	updated, err := yamledit.UpsertMany(current, repository, statements)
	if err != nil {
		return err
	}
	return WriteLocal(path, retention, updated)
}

// PromoteManual writes a hand-written x-vex statement and makes it effective
// immediately. It runs even when triage mode is dry-run, because a person
// asked for the override. x-vex-auto is left in place and loses on the same id.
func (s *Service) PromoteManual(ctx context.Context, repository string, statement types.VEXStatement) (string, error) {
	if s == nil || !s.settings.Enabled {
		return "", fmt.Errorf("triage is not enabled")
	}
	repository = strings.TrimSpace(repository)
	statement.ID = strings.TrimSpace(statement.ID)
	statement.Source = ""
	statement.Justification = types.NormalizeVEXJustification(statement.Justification)
	if statement.State != types.VEXStateNotAffected {
		statement.Justification = ""
	}
	if repository == "" || statement.ID == "" {
		return "", fmt.Errorf("repository and id are required")
	}
	if err := types.ValidateVEXStatement(statement); err != nil {
		return "", err
	}
	message := fmt.Sprintf("chore(vex): accept %s for %s\n\nhuman override of triage", statement.ID, repository)
	commit, err := s.writeStatement(ctx, repository, statement, message, yamledit.UpsertManual)
	if err != nil {
		return "", err
	}
	if s.catalog != nil {
		if err := s.catalog.UpsertManualVEX(repository, statement); err != nil {
			return commit, err
		}
	}
	s.reevaluate(ctx, repository)
	return commit, nil
}

// ConfigWriteMode reports where housekeeping edits are written.
// "git" commits the configured config repository. "local" updates the file
// suppline was started with.
func (s *Service) ConfigWriteMode() (string, error) {
	if s == nil {
		return "", fmt.Errorf("config editing is unavailable")
	}
	if s.settings.ConfigRepo != nil {
		return "git", nil
	}
	if strings.TrimSpace(s.settings.ConfigPath) == "" {
		return "", fmt.Errorf("suppline config path is not set")
	}
	if err := Writable(s.settings.ConfigPath); err != nil {
		return "", err
	}
	return "local", nil
}

// CommitConfig applies mutate to suppline.yaml and either pushes a commit or
// writes the local file. An unchanged document is not written.
func (s *Service) CommitConfig(ctx context.Context, message string, mutate func([]byte) ([]byte, error)) (string, error) {
	if s == nil {
		return "", fmt.Errorf("config editing is unavailable")
	}
	if strings.TrimSpace(message) == "" {
		return "", fmt.Errorf("commit message is required")
	}
	if s.settings.ConfigRepo != nil {
		spec, err := s.settings.configSpec()
		if err != nil {
			return "", err
		}
		return s.git.CommitFile(ctx, spec, s.settings.ConfigRepo.Path, mutate, message)
	}
	if strings.TrimSpace(s.settings.ConfigPath) == "" {
		return "", fmt.Errorf("suppline config path is not set")
	}
	current, err := readFile(s.settings.ConfigPath)
	if err != nil {
		return "", err
	}
	updated, err := mutate(current)
	if err != nil {
		return "", err
	}
	if string(updated) == string(current) {
		return "", nil
	}
	if err := WriteLocal(s.settings.ConfigPath, s.settings.BackupRetention, updated); err != nil {
		return "", err
	}
	return "", nil
}

func (s *Service) writeStatement(ctx context.Context, repository string, statement types.VEXStatement, message string, edit func([]byte, string, types.VEXStatement) ([]byte, error)) (string, error) {
	if s.settings.ConfigRepo != nil {
		spec, err := s.settings.configSpec()
		if err != nil {
			return "", err
		}
		return s.git.CommitFile(ctx, spec, s.settings.ConfigRepo.Path, func(current []byte) ([]byte, error) {
			return edit(current, repository, statement)
		}, message)
	}
	return "", writeLocalStatement(s.settings.ConfigPath, s.settings.BackupRetention, repository, statement, edit)
}

func writeLocalStatement(path string, retention int, repository string, statement types.VEXStatement, edit func([]byte, string, types.VEXStatement) ([]byte, error)) error {
	current, err := readFile(path)
	if err != nil {
		return err
	}
	updated, err := edit(current, repository, statement)
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
