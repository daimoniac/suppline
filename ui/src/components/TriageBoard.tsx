import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ArrowDown, ArrowUp, ArrowUpDown, Clock, Copy, Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { buildOpenTriagePrompt } from '../lib/policyComplianceData';
import { copyToClipboard, daysUntil, formatDate, isPast, isWithinDays } from '../lib/utils';
import { ErrorState, FilterActionButton, LoadingState, PageFiltersBar, Pagination, SeverityBadge } from './ui';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { usePageSizePreference } from '../lib/pageSizePreference';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';
import type { TriageAccept, TriageActive, TriageRun, TriageStatement, VulnerabilityGroup } from '../lib/api';

const STATUS_LABELS: Record<string, string> = {
  dry_run: 'Dry run',
  committed: 'Committed',
  written: 'Written',
  push_failed: 'Push failed',
  rejected_by_guardrail: 'Rejected',
  error: 'Error',
};

const VEX_STATES = [
  ['not_affected', 'Not affected'],
  ['affected', 'Affected'],
  ['in_triage', 'In triage'],
  ['false_positive', 'False positive'],
  ['resolved', 'Resolved'],
  ['resolved_with_pedigree', 'Resolved with pedigree'],
] as const;

const VEX_STATE_LABELS: Record<string, string> = {
  not_affected: 'Not affected',
  affected: 'Affected',
  in_triage: 'In triage',
  fixed: 'Fixed',
  false_positive: 'False positive',
  resolved: 'Resolved',
  resolved_with_pedigree: 'Resolved with pedigree',
};

const VEX_JUSTIFICATIONS = [
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment',
  'protected_by_compiler',
  'protected_at_runtime',
  'protected_at_perimeter',
  'protected_by_mitigations',
];

type StatementRow = {
  key: string;
  cve: string;
  repository: string;
  state: string;
  justification: string;
  detail: string;
  expiresAt: number;
  createdAt: number;
  affectedImages: number;
  source: 'auto' | 'manual' | 'open';
  needsFix: boolean;
  run?: TriageStatement['Run'];
};

function statementRow(item: TriageStatement): StatementRow {
  return {
    key: `${item.Repository}\n${item.CVEID}`,
    cve: item.CVEID,
    repository: item.Repository,
    state: item.State || '',
    justification: item.Justification || '',
    detail: item.Detail || '',
    expiresAt: item.ExpiresAt || 0,
    createdAt: item.CreatedAt || 0,
    affectedImages: item.AffectedImageCount || 0,
    source: item.Source,
    needsFix: item.NeedsFix,
    run: item.Run,
  };
}

function needsManualTriage(row: StatementRow) {
  if (row.source === 'manual' || !row.needsFix || !row.run || row.run.Superseded) return false;
  return row.run.Status === 'rejected_by_guardrail'
    || row.run.Status === 'error'
    || row.run.Status === 'push_failed'
    || row.run.Verdict === 'uncertain';
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    dry_run: 'bg-info-bg text-info',
    committed: 'bg-success-bg text-success',
    written: 'bg-success-bg text-success',
    push_failed: 'bg-danger-bg text-danger',
    rejected_by_guardrail: 'bg-warning-bg text-warning',
    error: 'bg-danger-bg text-danger',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] || 'bg-bg-tertiary text-text-secondary'}`}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

function StatePill({ state }: { state: string }) {
  const styles: Record<string, string> = {
    not_affected: 'bg-success-bg text-success',
    affected: 'bg-danger-bg text-danger',
    in_triage: 'bg-warning-bg text-warning',
    fixed: 'bg-info-bg text-info',
    false_positive: 'bg-bg-tertiary text-text-secondary',
    resolved: 'bg-success-bg text-success',
    resolved_with_pedigree: 'bg-success-bg text-success',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[state] || 'bg-bg-tertiary text-text-secondary'}`}>
      {VEX_STATE_LABELS[state] || state || 'Open'}
    </span>
  );
}

function ExpirationBadge({ expiresAt }: { expiresAt?: number }) {
  if (!expiresAt) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">Active</span>;
  const expired = isPast(expiresAt);
  const expiringSoon = !expired && isWithinDays(expiresAt, 7);
  const days = daysUntil(expiresAt);
  if (expired) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-danger-bg text-danger">Expired</span>;
  if (expiringSoon) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">{days}d left</span>;
  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">Active</span>;
}

function fromLocalInput(value: string) {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000);
}

function toLocalInput(unix?: number) {
  if (!unix) return '';
  const date = new Date(unix * 1000);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
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

function EditModal({
  row,
  onClose,
  onSave,
}: {
  row: StatementRow;
  onClose: () => void;
  onSave: (body: TriageAccept) => Promise<void>;
}) {
  const { apiClient } = useAuth();
  const knownState = VEX_STATES.some(([value]) => value === row.state);
  const [state, setState] = useState(knownState ? row.state : 'not_affected');
  const [justification, setJustification] = useState(row.justification || 'code_not_reachable');
  const [detail, setDetail] = useState(row.detail);
  const [expires, setExpires] = useState(toLocalInput(row.expiresAt));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [vuln, setVuln] = useState<VulnerabilityGroup | null>(null);
  const [vulnState, setVulnState] = useState<'loading' | 'ready' | 'missing'>('loading');

  useEffect(() => {
    let cancelled = false;
    scheduleEffectLoad(async () => {
      try {
        const details = await apiClient.getVulnerabilityDetails(row.cve, { max_digests: 20 });
        if (cancelled) return;
        setVuln(details);
        setVulnState(details?.CVEID ? 'ready' : 'missing');
      } catch {
        if (!cancelled) setVulnState('missing');
      }
    });
    return () => { cancelled = true; };
  }, [apiClient, row.cve]);

  const packages = [...new Set(
    (vuln?.affected || []).flatMap(image => (image.digests || []).map(digest => digest.packageName).filter(Boolean)),
  )];

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await onSave({
        Repository: row.repository,
        CVEID: row.cve,
        State: state,
        Justification: state === 'not_affected' ? justification : undefined,
        Detail: detail.trim() || undefined,
        ExpiresAt: fromLocalInput(expires),
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save');
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="bg-bg-secondary border border-border rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-6 pt-5 pb-4 border-b border-border shrink-0">
          <h3 className="text-lg font-semibold font-mono">{row.cve}</h3>
          {vuln?.Severity && <SeverityBadge severity={vuln.Severity} />}
          <p className="text-xs text-text-muted truncate ml-auto">{row.repository}</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 min-h-0 overflow-y-auto md:overflow-hidden md:flex-1">
          <div className="px-6 py-5 space-y-4 border-b md:border-b-0 md:border-r border-border md:overflow-y-auto">
            {vulnState === 'loading' && <p className="text-sm text-text-muted">Loading vulnerability…</p>}
            {vulnState === 'missing' && (
              <p className="text-sm text-text-secondary">This CVE has no vulnerability record in the current scans.</p>
            )}
            {vuln && (
              <div className="space-y-2 text-sm">
                {vuln.Title && <p className="font-medium text-text-primary">{vuln.Title}</p>}
                {vuln.Description && <p className="text-text-secondary whitespace-pre-wrap">{vuln.Description}</p>}
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
                  <span>{vuln.affectedImageCount || row.affectedImages} affected image{(vuln.affectedImageCount || row.affectedImages) === 1 ? '' : 's'}</span>
                  {packages.length > 0 && <span>Package: {packages.slice(0, 3).join(', ')}{packages.length > 3 ? ` +${packages.length - 3}` : ''}</span>}
                </div>
                {vuln.PrimaryURL && (
                  <a href={vuln.PrimaryURL} target="_blank" rel="noreferrer" className="text-xs text-accent hover:text-accent-hover break-all">
                    {vuln.PrimaryURL}
                  </a>
                )}
              </div>
            )}
            <div className="text-sm border-t border-border pt-4">
              <p className="text-xs text-text-muted mb-2">
                Automated triage
                {row.run ? ` · ${STATUS_LABELS[row.run.Status] || row.run.Status} · ${row.run.Confidence.toFixed(2)} confidence` : ''}
              </p>
              {row.run?.Reasoning ? (
                <p className="text-text-secondary whitespace-pre-wrap">{row.run.Reasoning}</p>
              ) : (
                <p className="text-text-muted">No automated triage notes for this statement.</p>
              )}
            </div>
          </div>
          <div className="px-6 py-5 md:overflow-y-auto">
            <div className="space-y-3">
              <label className="block text-xs text-text-secondary">
                Outcome
                <select value={state} onChange={e => setState(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
                  {VEX_STATES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              {state === 'not_affected' && (
                <label className="block text-xs text-text-secondary">
                  Justification
                  <select value={justification} onChange={e => setJustification(e.target.value)}
                    className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
                    {VEX_JUSTIFICATIONS.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
              )}
              <label className="block text-xs text-text-secondary">
                Detail
                <textarea value={detail} onChange={e => setDetail(e.target.value)} rows={8}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
              </label>
              <label className="block text-xs text-text-secondary">
                Expires
                <input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
              </label>
              {expires && <p className="text-xs text-text-muted">Expires {formatDate(fromLocalInput(expires) || 0)}</p>}
              {error && <p className="text-sm text-danger">{error}</p>}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary transition-colors">Cancel</button>
              <button type="button" onClick={save} disabled={saving} className="px-4 py-2 text-sm rounded-lg bg-accent text-bg-primary font-medium hover:bg-accent-hover transition-colors disabled:opacity-50">
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
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
  const [active, setActive] = useState<TriageActive[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState(mode === 'full' ? (searchParams.get('cve_id') || searchParams.get('repository') || '') : '');
  const [stateFilter, setStateFilter] = useState(mode === 'full' ? (searchParams.get('state') || 'all') : 'all');
  const [expirationFilter, setExpirationFilter] = useState(mode === 'full' ? (searchParams.get('expiration_status') || 'all') : 'all');
  const [origin, setOrigin] = useState('auto');
  const [editing, setEditing] = useState<StatementRow | null>(null);
  const [retryingKey, setRetryingKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async (quiet: boolean) => {
    if (!quiet) setLoading(true);
    try {
      const [statements, triageStatus] = await Promise.all([
        apiClient.getTriageStatements(),
        apiClient.getTriageStatus().catch(() => null),
      ]);
      setRows((statements || []).map(statementRow));
      setActive(triageStatus?.Active ?? []);
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
    if (active.length === 0) return;
    const id = window.setInterval(() => { refresh(true); }, 3000);
    return () => window.clearInterval(id);
  }, [active.length, refresh]);

  let pool = mode === 'attention' ? rows.filter(needsManualTriage) : rows.filter(row => matchesOrigin(row, origin));
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
    initialSortColumn: 'affectedImages',
    initialSortDirection: 'desc',
    resolveNewColumnDirection: col => (col === 'affectedImages' || col === 'createdAt' ? 'desc' : 'asc'),
    pageSize,
    totalItems: pool.length,
  });

  const sorted = [...pool].sort((a, b) => {
    const value = (row: StatementRow) => {
      if (sortBy === 'affectedImages') return row.affectedImages;
      if (sortBy === 'expiresAt') return row.expiresAt;
      return row.createdAt;
    };
    const diff = value(a) - value(b);
    return sortDir === 'asc' ? diff : -diff;
  });
  const paged = sorted.slice(offset, offset + pageSize);

  const running = active.filter(job => job.Running);
  const queued = active.filter(job => !job.Running);
  const busyKey = new Set(active.map(job => pairKey(job.Repository, job.CVEID)));

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
    { col: 'createdAt', label: 'Created' },
  ] as const;

  if (loading && rows.length === 0 && active.length === 0) return <LoadingState message="Loading triage..." />;
  if (error && rows.length === 0) return <ErrorState message={error} onRetry={() => refresh(false)} />;

  const promptRows = mode === 'attention' ? rows.filter(needsManualTriage) : rows;

  return (
    <div>
      {running.length > 0 && (
        <div className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">Currently running</div>
          {running.map(job => (
            <div key={pairKey(job.Repository, job.CVEID)} className="flex items-center gap-3 px-4 py-3">
              <Loader2 className="w-4 h-4 animate-spin text-accent shrink-0" />
              <div className="min-w-0">
                <div className="text-sm font-mono font-medium">{job.CVEID}</div>
                <div className="text-xs text-text-muted truncate">{job.Image || job.Repository}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {queued.length > 0 && (
        <div className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">Queued</div>
          {queued.map(job => (
            <div key={pairKey(job.Repository, job.CVEID)} className="flex items-center gap-3 px-4 py-3">
              <Clock className="w-4 h-4 text-text-muted shrink-0" />
              <div className="min-w-0">
                <div className="text-sm font-mono font-medium">{job.CVEID}</div>
                <div className="text-xs text-text-muted truncate">{job.Image || job.Repository}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {mode === 'full' ? (
        <PageFiltersBar>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE ID or repository…"
            className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
          <select value={stateFilter} onChange={e => { setStateFilter(e.target.value); setPage(1); }}
            className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="all">All VEX States</option>
            <option value="not_affected">Not Affected</option>
            <option value="affected">Affected</option>
            <option value="in_triage">In Triage</option>
            <option value="fixed">Fixed</option>
            <option value="false_positive">False Positive</option>
            <option value="resolved">Resolved</option>
          </select>
          <select value={expirationFilter} onChange={e => { setExpirationFilter(e.target.value); setPage(1); }}
            className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="all">All Expirations</option>
            <option value="active">Active</option>
            <option value="expiring">Expiring Soon</option>
            <option value="expired">Expired</option>
          </select>
          <select value={origin} onChange={e => { setOrigin(e.target.value); setPage(1); }}
            className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
            <option value="auto">Auto</option>
            <option value="manual">Manual</option>
            <option value="all">All</option>
          </select>
          <FilterActionButton onClick={() => setPage(1)}>Filter</FilterActionButton>
          <FilterActionButton variant="secondary" onClick={() => { setSearch(''); setStateFilter('all'); setExpirationFilter('all'); setOrigin('auto'); setPage(1); }}>Clear</FilterActionButton>
          <button type="button" onClick={() => copyRuns(openRuns(promptRows))} disabled={copying}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-accent/30 text-text-primary bg-bg-secondary hover:bg-bg-tertiary disabled:opacity-50 transition-colors">
            <Copy className="w-3.5 h-3.5" />
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
        <div className="flex items-center gap-1 px-4 py-2 border-b border-border bg-bg-secondary text-xs font-medium text-text-secondary uppercase">
          <span className="flex-1 pl-2">Statement</span>
          {sortColumns.map(({ col, label }) => {
            const activeSort = sortBy === col;
            const Icon = activeSort ? (sortDir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
            return (
              <button key={col} type="button" onClick={() => { setPage(1); toggleSort(col); }}
                className={`flex items-center gap-1 px-2 py-1 rounded hover:bg-bg-tertiary transition-colors select-none ${activeSort ? 'text-accent' : ''}`}>
                {label} <Icon className="w-3 h-3" />
              </button>
            );
          })}
        </div>
        {paged.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">
            {mode === 'attention' ? 'No rejected or unresolved auto-triages need manual review.' : 'No statements match filters'}
          </div>
        ) : (
          <div className="divide-y divide-border">
            {paged.map(row => (
              <div key={row.key} className="flex items-center gap-3 px-4 py-3 hover:bg-bg-secondary transition-colors">
                <button type="button" onClick={() => setEditing(row)} className="flex-1 min-w-0 flex items-center gap-3 text-left">
                  {row.source === 'open' && row.run ? <StatusPill status={row.run.Status} /> : <StatePill state={row.state} />}
                  <span className="px-2 py-0.5 rounded text-xs font-medium bg-bg-tertiary text-text-secondary shrink-0">
                    {row.source === 'open' ? 'open' : row.source}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-mono font-medium">{row.cve}</div>
                    <div className="text-xs text-text-muted truncate">
                      {row.repository}{row.justification ? ` · ${row.justification}` : ''}
                    </div>
                  </div>
                  <ExpirationBadge expiresAt={row.expiresAt} />
                  <span className="text-xs text-text-muted shrink-0 w-16 text-right">{row.affectedImages} image{row.affectedImages === 1 ? '' : 's'}</span>
                  <span className="text-xs text-text-muted shrink-0 w-28 text-right">{row.createdAt ? formatDate(row.createdAt) : '—'}</span>
                </button>
                <div className="flex items-center gap-2 shrink-0">
                  {row.needsFix && row.run && (
                    <button type="button" onClick={() => copyRuns([row.run as TriageRun], row.key)}
                      disabled={copyingKey === row.key}
                      title="Fix this using coding assistant"
                      className="px-2 py-1 text-xs rounded-md border border-accent/30 text-text-secondary hover:bg-bg-tertiary disabled:opacity-50">
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
