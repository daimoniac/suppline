import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ArrowDown, ArrowUp, ArrowUpDown, Clock, Copy, Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { buildOpenTriagePrompt } from '../lib/policyComplianceData';
import { copyToClipboard, formatDate, isPast, isWithinDays } from '../lib/utils';
import { ErrorState, FilterActionButton, LoadingState, PageFiltersBar, Pagination } from './ui';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { usePageSizePreference } from '../lib/pageSizePreference';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';
import { EditModal } from './TriageEditModal';
import { TriageBudgetBanner } from './TriageBudgetBanner';
import { ExpirationBadge, StatePill, StatusPill } from './TriagePills';
import type { StatementRow } from '../lib/triageRows';
import type { TriageQueued, TriageRun, TriageSession, TriageStatement } from '../lib/api';

function statementRow(item: TriageStatement): StatementRow {
  return {
    key: `${item.Repository}\n${item.CVEID}`,
    cve: item.CVEID,
    repository: item.Repository,
    state: item.State || '',
    justification: item.Justification || '',
    detail: item.Detail || '',
    expiresAt: item.ExpiresAt || 0,
    triagedAt: item.TriagedAt || item.Run?.CreatedAt || 0,
    affectedImages: item.AffectedImageCount || 0,
    source: item.Source,
    needsFix: item.NeedsFix,
    run: item.Run,
  };
}

function companions(rows: StatementRow[], row: StatementRow) {
  const session = row.run?.SessionID;
  if (!session) return [];
  return rows.filter(item => item.key !== row.key && item.run?.SessionID === session);
}

function needsManualTriage(row: StatementRow) {
  if (row.source === 'manual' || !row.needsFix || !row.run || row.run.Superseded) return false;
  return row.run.Status === 'rejected_by_guardrail'
    || row.run.Status === 'error'
    || row.run.Status === 'push_failed'
    || row.run.Verdict === 'uncertain';
}

function affectsImages(row: StatementRow) {
  return row.affectedImages > 0;
}

function pairKey(repository: string, cve: string) {
  return `${repository}\n${cve}`;
}

function matchesOrigin(row: StatementRow, origin: string) {
  if (origin === 'all') return true;
  if (origin === 'manual') return row.source === 'manual';
  return row.source === 'auto' || row.source === 'open';
}

function openRuns(rows: StatementRow[]): TriageRun[] {
  return rows.flatMap(row => (row.needsFix && row.run ? [row.run] : []));
}

export function TriageBoard({
  mode,
  refreshToken = 0,
}: {
  mode: 'full' | 'attention';
  refreshToken?: number;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();
  const { pageSize, setPageSize, options: pageSizeOptions } = usePageSizePreference();
  const [copying, setCopying] = useState(false);
  const [copyingKey, setCopyingKey] = useState<string | null>(null);
  const [rows, setRows] = useState<StatementRow[]>([]);
  const [sessions, setSessions] = useState<TriageSession[]>([]);
  const [queued, setQueued] = useState<TriageQueued[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState(mode === 'full' ? (searchParams.get('cve_id') || searchParams.get('repository') || '') : '');
  const [stateFilter, setStateFilter] = useState(mode === 'full' ? (searchParams.get('state') || 'all') : 'all');
  const [expirationFilter, setExpirationFilter] = useState(mode === 'full' ? (searchParams.get('expiration_status') || 'all') : 'all');
  const [origin, setOrigin] = useState('auto');
  const [editing, setEditing] = useState<StatementRow | null>(null);
  const [retryingKey, setRetryingKey] = useState<string | null>(null);
  const [resettingBudget, setResettingBudget] = useState(false);
  const [budget, setBudget] = useState({ used: 0, limit: 0, exhausted: false });
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async (quiet: boolean) => {
    if (!quiet) setLoading(true);
    try {
      const [statements, triageStatus] = await Promise.all([
        apiClient.getTriageStatements(),
        apiClient.getTriageStatus().catch(() => null),
      ]);
      setRows((statements || []).map(statementRow));
      setSessions(triageStatus?.Sessions ?? []);
      setQueued(triageStatus?.Queued ?? []);
      setBudget({
        used: triageStatus?.BudgetUsed ?? 0,
        limit: triageStatus?.BudgetLimit ?? 0,
        exhausted: triageStatus?.BudgetExhausted ?? false,
      });
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load triage');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { scheduleEffectLoad(() => refresh(false)); }, [refresh]);

  useEffect(() => {
    if (refreshToken === 0) return;
    scheduleEffectLoad(() => refresh(true));
  }, [refreshToken, refresh]);

  useEffect(() => {
    if (sessions.length + queued.length === 0 && !budget.exhausted) return;
    const id = window.setInterval(() => { refresh(true); }, 3000);
    return () => window.clearInterval(id);
  }, [sessions.length, queued.length, budget.exhausted, refresh]);

  let pool = mode === 'attention' ? rows.filter(needsManualTriage) : rows.filter(row => matchesOrigin(row, origin));
  pool = pool.filter(affectsImages);
  if (search) {
    const query = search.toLowerCase();
    pool = pool.filter(row => row.cve.toLowerCase().includes(query) || row.repository.toLowerCase().includes(query));
  }
  if (mode === 'full' && stateFilter !== 'all') pool = pool.filter(row => row.state === stateFilter);
  if (mode === 'full' && expirationFilter !== 'all') {
    pool = pool.filter(row => {
      if (expirationFilter === 'active') return !row.expiresAt || !isPast(row.expiresAt);
      if (expirationFilter === 'expired') return row.expiresAt > 0 && isPast(row.expiresAt);
      if (expirationFilter === 'expiring') return row.expiresAt > 0 && !isPast(row.expiresAt) && isWithinDays(row.expiresAt, 7);
      return true;
    });
  }

  const { sortColumn: sortBy, sortDirection: sortDir, toggleSort, page, setPage, totalPages, offset } = useSortablePaginationState({
    initialSortColumn: 'triagedAt',
    initialSortDirection: 'desc',
    resolveNewColumnDirection: col => (col === 'affectedImages' || col === 'expiresAt' || col === 'triagedAt' ? 'desc' : 'asc'),
    pageSize,
    totalItems: pool.length,
  });

  const sorted = [...pool].sort((a, b) => {
    const value = (row: StatementRow) => {
      if (sortBy === 'affectedImages') return row.affectedImages;
      if (sortBy === 'expiresAt') return row.expiresAt;
      return row.triagedAt;
    };
    const diff = value(a) - value(b);
    if (diff !== 0) return sortDir === 'asc' ? diff : -diff;
    if (a.repository !== b.repository) return a.repository < b.repository ? -1 : 1;
    return a.cve < b.cve ? -1 : a.cve > b.cve ? 1 : 0;
  });
  const paged = sorted.slice(offset, offset + pageSize);

  const busyKey = new Set<string>();
  for (const session of sessions) {
    for (const cve of session.CVEs) busyKey.add(pairKey(session.Repository, cve.CVEID));
  }
  for (const job of queued) busyKey.add(pairKey(job.Repository, job.CVEID));
  const queuedByImage = new Map<string, TriageQueued[]>();
  for (const job of queued) {
    const key = job.Image || job.Repository;
    queuedByImage.set(key, [...(queuedByImage.get(key) ?? []), job]);
  }

  const copyRuns = async (runs: TriageRun[], key?: string) => {
    if (key) setCopyingKey(key);
    else setCopying(true);
    try {
      const prompt = buildOpenTriagePrompt(runs);
      if (!prompt) {
        toast('No open findings to copy', 'warning');
        return;
      }
      const ok = await copyToClipboard(prompt);
      toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error');
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to build the coding-assistant prompt', 'error');
    } finally {
      if (key) setCopyingKey(null);
      else setCopying(false);
    }
  };

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

  const retry = async (row: StatementRow) => {
    setRetryingKey(row.key);
    setNotice(null);
    try {
      const result = await apiClient.retryTriage({ Repository: row.repository, CVEID: row.cve });
      if (result.Queued > 0) {
        await refresh(true);
      } else {
        setNotice('Triage was not queued. It may already be waiting, or the image is not running in a cluster.');
      }
    } catch (e: unknown) {
      setNotice(e instanceof Error ? e.message : 'Failed to queue triage');
    } finally {
      setRetryingKey(null);
    }
  };

  const sortColumns = [
    { col: 'affectedImages', label: 'Affected Images' },
    { col: 'expiresAt', label: 'Expiry' },
    { col: 'triagedAt', label: 'Triaged' },
  ] as const;

  if (loading && rows.length === 0 && sessions.length === 0 && queued.length === 0) return <LoadingState message="Loading triage..." />;
  if (error && rows.length === 0) return <ErrorState message={error} onRetry={() => refresh(false)} />;

  const promptRows = (mode === 'attention' ? rows.filter(needsManualTriage) : rows).filter(affectsImages);

  return (
    <div>
      <TriageBudgetBanner budget={budget} resetting={resettingBudget} onReset={resetBudget} />
      {sessions.map(session => (
        <div key={session.SessionID} className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">
            {session.Phase === 'deciding' ? `Deciding ${session.CurrentCVE}` : 'Gathering image context'}
            <span className="text-text-muted"> · {session.Image || session.Repository}</span>
          </div>
          {session.CVEs.map(cve => (
            <div key={cve.CVEID} className="flex items-center gap-3 px-4 py-3">
              {cve.Status === 'running'
                ? <Loader2 className="w-4 h-4 animate-spin text-accent shrink-0" />
                : <Clock className="w-4 h-4 text-text-muted shrink-0" />}
              <div className="min-w-0">
                <div className="text-sm font-mono font-medium">{cve.CVEID}</div>
                <div className="text-xs text-text-muted truncate">{cve.Status === 'running' ? 'In progress' : 'Waiting in this session'}</div>
              </div>
            </div>
          ))}
        </div>
      ))}
      {queued.length > 0 && (
        <div className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">Queued</div>
          {[...queuedByImage.entries()].map(([image, jobs]) => (
            <div key={image} className="px-4 py-3">
              <div className="text-xs text-text-muted truncate mb-2">{image}</div>
              <div className="flex flex-wrap gap-2">
                {jobs.map(job => (
                  <span key={pairKey(job.Repository, job.CVEID)} className="inline-flex items-center gap-1.5 text-sm font-mono">
                    <Clock className="w-3.5 h-3.5 text-text-muted" />
                    {job.CVEID}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      {mode === 'full' ? (
        <PageFiltersBar>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE ID or repository…"
            className="w-full sm:flex-1 sm:max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
          <select value={stateFilter} onChange={e => { setStateFilter(e.target.value); setPage(1); }}
            className="w-full sm:w-auto px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="all">All VEX States</option>
            <option value="not_affected">Not Affected</option>
            <option value="affected">Affected</option>
            <option value="in_triage">In Triage</option>
            <option value="fixed">Fixed</option>
            <option value="false_positive">False Positive</option>
            <option value="resolved">Resolved</option>
          </select>
          <select value={expirationFilter} onChange={e => { setExpirationFilter(e.target.value); setPage(1); }}
            className="w-full sm:w-auto px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="all">All Expirations</option>
            <option value="active">Active</option>
            <option value="expiring">Expiring Soon</option>
            <option value="expired">Expired</option>
          </select>
          <select value={origin} onChange={e => { setOrigin(e.target.value); setPage(1); }}
            className="w-full sm:w-auto px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="auto">Auto</option>
            <option value="manual">Manual</option>
            <option value="all">All</option>
          </select>
          <FilterActionButton onClick={() => setPage(1)}>Filter</FilterActionButton>
          <FilterActionButton variant="secondary" onClick={() => { setSearch(''); setStateFilter('all'); setExpirationFilter('all'); setOrigin('auto'); setPage(1); }}>Clear</FilterActionButton>
          <button type="button" onClick={() => copyRuns(openRuns(promptRows))} disabled={copying}
            title="Fix all open using coding assistant"
            className="inline-flex w-full sm:w-auto items-center justify-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-accent/30 text-text-primary bg-bg-secondary hover:bg-bg-tertiary disabled:opacity-50 transition-colors">
            <Copy className="w-3.5 h-3.5 shrink-0" />
            {copying ? 'Copying…' : 'Fix all open using coding assistant'}
          </button>
        </PageFiltersBar>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <p className="text-xs text-text-muted">
            {pool.length} current rejected or unresolved auto {pool.length === 1 ? 'triage needs' : 'triages need'} a manual decision.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/triage" className="text-xs text-accent hover:text-accent-hover">Open triage</Link>
            <button type="button" onClick={() => copyRuns(openRuns(promptRows))} disabled={copying || pool.length === 0}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-accent/30 text-text-primary bg-bg-primary/70 hover:bg-bg-primary disabled:opacity-50 transition-colors">
              <Copy className="w-3 h-3" />
              {copying ? 'Copying…' : 'Fix all open using coding assistant'}
            </button>
          </div>
        </div>
      )}
      {error && <p className="text-sm text-danger mb-3">{error}</p>}
      {notice && <p className="text-sm text-text-secondary mb-3">{notice}</p>}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="flex flex-wrap items-center gap-1 px-3 py-2 border-b border-border bg-bg-secondary text-xs font-medium text-text-secondary uppercase md:grid md:grid-cols-[minmax(0,1fr)_6.5rem_5.5rem_11.5rem_auto] md:items-center md:gap-x-3 md:px-4">
          <span className="pl-1 mr-auto md:mr-0">Statement</span>
          {sortColumns.map(({ col, label }) => {
            const activeSort = sortBy === col;
            const Icon = activeSort ? (sortDir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
            return (
              <button key={col} type="button" onClick={() => { setPage(1); toggleSort(col); }}
                className={`flex items-center gap-1 px-2 py-1 rounded hover:bg-bg-tertiary transition-colors select-none md:justify-end ${activeSort ? 'text-accent' : ''}`}>
                {label} <Icon className="w-3 h-3" />
              </button>
            );
          })}
          <span className="hidden md:block" />
        </div>
        {paged.length === 0 ? (
          <div className="p-8 sm:p-12 text-center text-text-secondary text-sm">
            {mode === 'attention' ? 'No rejected or unresolved auto-triages need manual review.' : 'No statements match filters'}
          </div>
        ) : (
          <div className="divide-y divide-border">
            {paged.map(row => (
              <div key={row.key} className="px-3 py-3 hover:bg-bg-secondary transition-colors md:grid md:grid-cols-[minmax(0,1fr)_6.5rem_5.5rem_11.5rem_auto] md:items-center md:gap-x-3 md:px-4">
                <button type="button" onClick={() => setEditing(row)} className="min-w-0 text-left">
                  <div className="flex flex-wrap items-center gap-2">
                    {row.source === 'open' && row.run ? <StatusPill status={row.run.Status} /> : <StatePill state={row.state} />}
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-bg-tertiary text-text-secondary">
                      {row.source === 'open' ? 'open' : row.source}
                    </span>
                    <span className="text-sm font-mono font-medium break-all">{row.cve}</span>
                  </div>
                  <div className="text-xs text-text-muted truncate mt-1">
                    {row.repository}{row.justification ? ` · ${row.justification}` : ''}
                  </div>
                </button>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 md:contents">
                  <span className="text-xs text-text-muted md:mt-0 md:text-right">{row.affectedImages} image{row.affectedImages === 1 ? '' : 's'}</span>
                  <span className="md:text-right"><ExpirationBadge expiresAt={row.expiresAt} /></span>
                  <span className="text-xs text-text-muted md:text-right whitespace-nowrap">
                    <span className="md:hidden">Triaged </span>{row.triagedAt ? formatDate(row.triagedAt) : '—'}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2 md:mt-0 md:justify-end">
                  {row.needsFix && row.run && (
                    <button type="button" onClick={() => copyRuns([row.run as TriageRun], row.key)}
                      disabled={copyingKey === row.key}
                      title="Fix this using coding assistant"
                      className="px-2 py-1 text-xs rounded-md border border-accent/30 text-text-secondary hover:bg-bg-tertiary disabled:opacity-50 max-w-full">
                      {copyingKey === row.key ? 'Copying…' : 'Fix this using coding assistant'}
                    </button>
                  )}
                  <button type="button" onClick={() => retry(row)}
                    disabled={retryingKey === row.key || busyKey.has(row.key)}
                    className="px-2 py-1 text-xs rounded-md border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-50">
                    {busyKey.has(row.key) ? 'Queued' : retryingKey === row.key ? 'Queuing…' : 'Requeue'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
        <Pagination
          currentPage={page}
          totalPages={totalPages}
          total={pool.length}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={size => { setPageSize(size); setPage(1); }}
          pageSizeOptions={pageSizeOptions}
          itemLabel="statements"
        />
      </div>
      {editing && (
        <EditModal
          key={editing.key}
          row={editing}
          withCVEs={companions(rows, editing).map(item => item.cve)}
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
