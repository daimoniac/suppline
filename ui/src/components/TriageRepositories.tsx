import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ChevronDown, ChevronRight, Clock, Copy, Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { buildOpenTriagePrompt } from '../lib/policyComplianceData';
import { copyToClipboard, formatDate, formatRelativeTime } from '../lib/utils';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { ErrorState, LoadingState, PageFiltersBar } from './ui';
import { EditModal } from './TriageEditModal';
import { ExpirationBadge } from './TriagePills';
import { TriageBudgetBanner, type TriageBudgetState } from './TriageBudgetBanner';
import { STATUS_LABELS, VEX_STATES, type StatementRow } from '../lib/triageRows';
import type { TriagePhase, TriageRepository, TriageRepositoryCVE, TriageRun } from '../lib/api';

const PHASE_LABELS: Record<TriagePhase, string> = {
  uncertain: 'Uncertain',
  error: 'Failed',
  not_triaged: 'Not triaged',
  running: 'Running',
  queued: 'Queued',
  decided: 'Decided',
  exempt: 'Exempt',
};

const PHASE_STYLES: Record<TriagePhase, string> = {
  uncertain: 'bg-warning-bg text-warning',
  error: 'bg-danger-bg text-danger',
  not_triaged: 'bg-danger-bg text-danger',
  running: 'bg-info-bg text-info',
  queued: 'bg-info-bg text-info',
  decided: 'bg-success-bg text-success',
  exempt: 'bg-bg-tertiary text-text-secondary',
};

const ATTENTION: TriagePhase[] = ['uncertain', 'error', 'not_triaged'];

function pairKey(repository: string, cve: string) {
  return `${repository}\n${cve}`;
}

function needsAttention(cve: TriageRepositoryCVE) {
  return ATTENTION.includes(cve.Phase);
}

function isBusy(cve: TriageRepositoryCVE) {
  return cve.Phase === 'running' || cve.Phase === 'queued';
}

function modalRow(repository: string, cve: TriageRepositoryCVE): StatementRow {
  const run = cve.Run;
  const verdictIsState = !!run && VEX_STATES.some(([value]) => value === run.Verdict);
  return {
    key: pairKey(repository, cve.CVEID),
    cve: cve.CVEID,
    repository,
    state: cve.State || (verdictIsState && run ? run.Verdict : ''),
    justification: cve.Justification || run?.Justification || '',
    detail: cve.Detail || run?.Reasoning || '',
    expiresAt: cve.ExpiresAt || 0,
    triagedAt: run?.CreatedAt || 0,
    affectedImages: cve.Tags.length,
    source: cve.Origin ?? 'open',
    needsFix: cve.Phase === 'uncertain' || cve.Phase === 'error',
    run,
  };
}

function PhasePill({ cve }: { cve: TriageRepositoryCVE }) {
  const label = cve.Phase === 'exempt' ? `Exempt · ${cve.Origin ?? 'manual'}` : PHASE_LABELS[cve.Phase];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap ${PHASE_STYLES[cve.Phase]}`}>
      {cve.Phase === 'running' && <Loader2 className="w-3 h-3 animate-spin" />}
      {cve.Phase === 'queued' && <Clock className="w-3 h-3" />}
      {label}
    </span>
  );
}

function CountChip({ count, label, tone }: { count: number; label: string; tone: 'warn' | 'info' | 'ok' | 'muted' }) {
  if (count === 0) return null;
  const styles = {
    warn: 'bg-warning-bg text-warning',
    info: 'bg-info-bg text-info',
    ok: 'bg-success-bg text-success',
    muted: 'bg-bg-tertiary text-text-secondary',
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap ${styles[tone]}`}>{count} {label}</span>;
}

function RunLine({ run }: { run: TriageRun }) {
  const confidence = run.Confidence > 0 ? ` · ${run.Confidence.toFixed(2)} confidence` : '';
  return (
    <span>
      Last run: {STATUS_LABELS[run.Status] || run.Status}{confidence} · {formatRelativeTime(run.CreatedAt)}
    </span>
  );
}

export function TriageRepositories() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [repositories, setRepositories] = useState<TriageRepository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [budget, setBudget] = useState<TriageBudgetState>({ used: 0, limit: 0, exhausted: false });
  const [resettingBudget, setResettingBudget] = useState(false);
  const [search, setSearch] = useState('');
  const [view, setView] = useState<'attention' | 'failing' | 'all'>('attention');
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [showExempt, setShowExempt] = useState<Record<string, boolean>>({});
  const [retrying, setRetrying] = useState<Set<string>>(new Set());
  const [copying, setCopying] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ repository: string; cve: TriageRepositoryCVE; withCVEs: string[] } | null>(null);

  const refresh = useCallback(async (quiet: boolean) => {
    if (!quiet) setLoading(true);
    try {
      const [cards, status] = await Promise.all([
        apiClient.getTriageRepositories(),
        apiClient.getTriageStatus().catch(() => null),
      ]);
      setRepositories(cards || []);
      setBudget({
        used: status?.BudgetUsed ?? 0,
        limit: status?.BudgetLimit ?? 0,
        exhausted: status?.BudgetExhausted ?? false,
      });
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load triage');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { scheduleEffectLoad(() => refresh(false)); }, [refresh]);

  const inProgress = repositories.some(card => card.Counts.InProgress > 0);
  useEffect(() => {
    if (!inProgress && !budget.exhausted) return;
    const id = window.setInterval(() => { refresh(true); }, 3000);
    return () => window.clearInterval(id);
  }, [inProgress, budget.exhausted, refresh]);

  const resetBudget = async () => {
    if (!window.confirm("Reset today's triage token budget? Queued triage will start.")) return;
    setResettingBudget(true);
    try {
      await apiClient.resetTriageBudget();
      toast('Daily triage limit reset', 'success');
      await refresh(true);
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to reset the daily limit', 'error');
    } finally {
      setResettingBudget(false);
    }
  };

  const runAgain = async (repository: string, cves: TriageRepositoryCVE[]) => {
    const keys = cves.map(cve => pairKey(repository, cve.CVEID));
    setRetrying(prev => new Set([...prev, ...keys]));
    setNotice(null);
    try {
      const results = await Promise.all(cves.map(cve => apiClient.retryTriage({ Repository: repository, CVEID: cve.CVEID })));
      const queued = results.reduce((sum, result) => sum + result.Queued, 0);
      if (queued === 0) setNotice('Triage was not queued. It may already be waiting, or the image is not running in a cluster.');
      await refresh(true);
    } catch (e: unknown) {
      setNotice(e instanceof Error ? e.message : 'Failed to queue triage');
    } finally {
      setRetrying(prev => {
        const next = new Set(prev);
        keys.forEach(key => next.delete(key));
        return next;
      });
    }
  };

  const copyPrompt = async (runs: TriageRun[], key: string) => {
    setCopying(key);
    try {
      const prompt = buildOpenTriagePrompt(runs);
      if (!prompt) {
        toast('No open findings to copy', 'warning');
        return;
      }
      const ok = await copyToClipboard(prompt);
      toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error');
    } finally {
      setCopying(null);
    }
  };

  if (loading && repositories.length === 0) return <LoadingState message="Loading triage..." />;
  if (error && repositories.length === 0) return <ErrorState message={error} onRetry={() => refresh(false)} />;

  const query = search.trim().toLowerCase();
  const visible = repositories.filter(card => {
    if (view === 'attention' && card.Counts.NeedsAttention + card.Counts.InProgress === 0) return false;
    if (view === 'failing' && card.PolicyPassed) return false;
    if (!query) return true;
    return card.Repository.toLowerCase().includes(query) || card.CVEs.some(cve => cve.CVEID.toLowerCase().includes(query));
  });
  const totals = repositories.reduce((sum, card) => ({
    attention: sum.attention + card.Counts.NeedsAttention,
    progress: sum.progress + card.Counts.InProgress,
  }), { attention: 0, progress: 0 });

  return (
    <div>
      <TriageBudgetBanner budget={budget} resetting={resettingBudget} onReset={resetBudget} />
      <PageFiltersBar>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search repository or CVE ID…"
          className="w-full sm:flex-1 sm:max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <select value={view} onChange={e => setView(e.target.value as typeof view)}
          className="w-full sm:w-auto px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
          <option value="attention">Needs attention</option>
          <option value="failing">Failing policy</option>
          <option value="all">All running repositories</option>
        </select>
      </PageFiltersBar>
      <p className="text-xs text-text-muted mb-3">
        {totals.attention} CVE{totals.attention === 1 ? '' : 's'} need attention
        {totals.progress > 0 ? ` · ${totals.progress} in progress` : ''}
        {' · '}{repositories.length} running {repositories.length === 1 ? 'repository' : 'repositories'}
      </p>
      {error && <p className="text-sm text-danger mb-3">{error}</p>}
      {notice && <p className="text-sm text-text-secondary mb-3">{notice}</p>}
      {visible.length === 0 ? (
        <div className="bg-bg-primary border border-border rounded-xl p-8 sm:p-12 text-center text-text-secondary text-sm">
          {view === 'attention' ? 'Nothing needs attention. Every CVE blocking a running image is handled.' : 'No repositories match.'}
        </div>
      ) : (
        <div className="space-y-3">
          {visible.map(card => {
            const counts = card.Counts;
            const expanded = open[card.Repository] ?? (counts.NeedsAttention + counts.InProgress > 0);
            const blocking = card.CVEs.filter(cve => cve.Phase !== 'exempt');
            const exempt = card.CVEs.filter(cve => cve.Phase === 'exempt');
            const attention = blocking.filter(needsAttention);
            const fixable = blocking.filter(cve => (cve.Phase === 'uncertain' || cve.Phase === 'error') && cve.Run);
            const exemptShown = showExempt[card.Repository] ?? false;
            const rows = exemptShown ? [...blocking, ...exempt] : blocking;
            const exemptCount = counts.ExemptAuto + counts.ExemptManual;
            return (
              <div key={card.Repository} className="bg-bg-primary border border-border rounded-xl overflow-hidden">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
                  <button type="button" onClick={() => setOpen(prev => ({ ...prev, [card.Repository]: !expanded }))}
                    className="flex items-center gap-2 min-w-0 text-left" aria-expanded={expanded}>
                    {expanded ? <ChevronDown className="w-4 h-4 shrink-0 text-text-muted" /> : <ChevronRight className="w-4 h-4 shrink-0 text-text-muted" />}
                    <span className="text-sm font-medium break-all">{card.Repository}</span>
                  </button>
                  <Link to={`/repositories/${encodeURIComponent(card.Repository)}`} className="text-xs text-accent hover:text-accent-hover">Open</Link>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {card.Tags.map(tag => (
                      <span key={tag.Digest || tag.Tag}
                        title={`${tag.Tag}: policy ${tag.PolicyStatus || (tag.PolicyPassed ? 'passed' : 'failed')}`}
                        className={`px-1.5 py-0.5 rounded text-xs font-mono ${tag.PolicyPassed ? 'bg-success-bg text-success' : 'bg-danger-bg text-danger'}`}>
                        {tag.Tag || tag.Digest.slice(7, 19)}
                      </span>
                    ))}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 ml-auto">
                    <CountChip count={counts.NeedsAttention} label="need attention" tone="warn" />
                    <CountChip count={counts.InProgress} label="in progress" tone="info" />
                    <CountChip count={counts.Decided} label="decided" tone="ok" />
                    <CountChip count={exemptCount} label={`exempt (${counts.ExemptAuto} auto, ${counts.ExemptManual} manual)`} tone="muted" />
                    {card.PolicyPassed && blocking.length === 0 && <span className="text-xs text-success">Passing</span>}
                  </div>
                </div>
                {expanded && (
                  <div className="border-t border-border">
                    {(attention.length > 0 || fixable.length > 0) && (
                      <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-bg-secondary">
                        {attention.length > 0 && (
                          <button type="button" onClick={() => runAgain(card.Repository, attention.filter(cve => !retrying.has(pairKey(card.Repository, cve.CVEID))))}
                            disabled={attention.every(cve => retrying.has(pairKey(card.Repository, cve.CVEID)))}
                            className="px-2.5 py-1 text-xs rounded-md border border-border text-text-primary hover:bg-bg-tertiary disabled:opacity-50">
                            Run again for {attention.length} that need attention
                          </button>
                        )}
                        {fixable.length > 0 && (
                          <button type="button" onClick={() => copyPrompt(fixable.map(cve => cve.Run as TriageRun), card.Repository)}
                            disabled={copying === card.Repository}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md border border-accent/30 text-text-secondary hover:bg-bg-tertiary disabled:opacity-50">
                            <Copy className="w-3 h-3" />
                            {copying === card.Repository ? 'Copying…' : `Fix ${fixable.length} using coding assistant`}
                          </button>
                        )}
                      </div>
                    )}
                    {rows.length === 0 ? (
                      <p className="px-4 py-3 text-sm text-text-muted">No CVEs block this repository.</p>
                    ) : (
                      <div className="divide-y divide-border">
                        {rows.map(cve => {
                          const key = pairKey(card.Repository, cve.CVEID);
                          const session = cve.Run?.SessionID;
                          return (
                            <div key={key} className="px-4 py-3 hover:bg-bg-secondary transition-colors md:flex md:items-start md:gap-4">
                              <button type="button" className="min-w-0 flex-1 text-left"
                                onClick={() => setEditing({
                                  repository: card.Repository,
                                  cve,
                                  withCVEs: session
                                    ? card.CVEs.filter(other => other.CVEID !== cve.CVEID && other.Run?.SessionID === session).map(other => other.CVEID)
                                    : [],
                                })}>
                                <div className="flex flex-wrap items-center gap-2">
                                  <PhasePill cve={cve} />
                                  <span className="text-sm font-mono font-medium break-all">{cve.CVEID}</span>
                                  {cve.Packages && cve.Packages.length > 0 && (
                                    <span className="text-xs text-text-muted">{cve.Packages.slice(0, 2).join(', ')}{cve.Packages.length > 2 ? ` +${cve.Packages.length - 2}` : ''}</span>
                                  )}
                                  {cve.Phase === 'exempt' && <ExpirationBadge expiresAt={cve.ExpiresAt} />}
                                </div>
                                <p className="text-sm text-text-secondary mt-1">{cve.Reason}</p>
                                <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 mt-1 text-xs text-text-muted">
                                  {cve.Tags.length > 0 && <span>On {cve.Tags.join(', ')}</span>}
                                  {cve.Run && cve.Phase !== 'exempt' && <RunLine run={cve.Run} />}
                                  {cve.ReasonCode && cve.ReasonAt ? <span title={formatDate(cve.ReasonAt)}>Noted {formatRelativeTime(cve.ReasonAt)}</span> : null}
                                  {cve.Phase === 'exempt' && cve.ExpiresAt ? <span>Expires {formatDate(cve.ExpiresAt)}</span> : null}
                                </div>
                                {(cve.Phase === 'uncertain' || cve.Phase === 'error') && cve.Run?.Reasoning && (
                                  <p className="text-xs text-text-muted mt-1 line-clamp-2 whitespace-pre-wrap">{cve.Run.Reasoning}</p>
                                )}
                              </button>
                              {cve.Phase !== 'exempt' && (
                                <div className="mt-2 md:mt-0 flex flex-wrap items-center gap-2 md:justify-end shrink-0">
                                  <button type="button" onClick={() => runAgain(card.Repository, [cve])}
                                    disabled={retrying.has(key) || isBusy(cve)}
                                    className="px-2 py-1 text-xs rounded-md border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-50">
                                    {isBusy(cve) ? 'In progress' : retrying.has(key) ? 'Queuing…' : cve.Phase === 'not_triaged' ? 'Triage now' : 'Run again'}
                                  </button>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    {exempt.length > 0 && (
                      <button type="button" onClick={() => setShowExempt(prev => ({ ...prev, [card.Repository]: !exemptShown }))}
                        className="w-full px-4 py-2 text-xs text-left text-text-secondary hover:bg-bg-secondary border-t border-border transition-colors">
                        {exemptShown ? 'Hide' : 'Show'} {exempt.length} exempt CVE{exempt.length === 1 ? '' : 's'}
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {editing && (
        <EditModal
          key={pairKey(editing.repository, editing.cve.CVEID)}
          row={modalRow(editing.repository, editing.cve)}
          withCVEs={editing.withCVEs}
          onClose={() => setEditing(null)}
          onSave={async body => {
            await apiClient.acceptTriage(body);
            setEditing(null);
            await refresh(true);
          }}
        />
      )}
    </div>
  );
}
