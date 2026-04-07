import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatDate, isPast, isWithinDays, daysUntil } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, Pagination, PageFiltersBar, FilterActionButton } from '../components/ui';
import type { VEXSummary } from '../lib/api';
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';

const VEX_STATE_LABELS: Record<string, string> = {
  not_affected: 'Not Affected',
  affected: 'Affected',
  in_triage: 'In Triage',
  fixed: 'Fixed',
  false_positive: 'False Positive',
  resolved: 'Resolved',
  resolved_with_pedigree: 'Resolved (Pedigree)',
};

function VEXStateBadge({ state }: { state: string }) {
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
      {VEX_STATE_LABELS[state] || state}
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

export default function VEXPage() {
  const { apiClient } = useAuth();
  const [searchParams] = useSearchParams();
  const [statements, setStatements] = useState<VEXSummary[]>([]);
  const [inactive, setInactive] = useState<VEXSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState(searchParams.get('cve_id') || searchParams.get('repository') || '');
  const [stateFilter, setStateFilter] = useState(searchParams.get('state') || 'all');
  const [expirationFilter, setExpirationFilter] = useState(searchParams.get('expiration_status') || 'all');
  const pageSize = 20;

  // Combine, filter, sort
  let combined = [...statements, ...inactive];
  if (search) {
    const q = search.toLowerCase();
    combined = combined.filter(t =>
      t.CVEID.toLowerCase().includes(q) ||
      t.Repositories?.some(r => r.Repository.toLowerCase().includes(q))
    );
  }
  if (stateFilter !== 'all') combined = combined.filter(t => t.State === stateFilter);
  if (expirationFilter !== 'all') {
    combined = combined.filter(t => {
      if (expirationFilter === 'active') return !t.ExpiresAt || !isPast(t.ExpiresAt);
      if (expirationFilter === 'expired') return t.ExpiresAt && isPast(t.ExpiresAt);
      if (expirationFilter === 'expiring') return t.ExpiresAt && !isPast(t.ExpiresAt) && isWithinDays(t.ExpiresAt, 7);
      return true;
    });
  }

  const { sortColumn: sortBy, sortDirection: sortDir, toggleSort, page, setPage, totalPages, offset } = useSortablePaginationState({
    initialSortColumn: 'affectedImages',
    initialSortDirection: 'desc',
    resolveNewColumnDirection: (col) => (col === 'affectedImages' ? 'desc' : 'asc'),
    pageSize,
    totalItems: combined.length,
  });

  const handleSort = (col: string) => {
    setPage(1);
    toggleSort(col);
  };

  combined.sort((a, b) => {
    let aVal: string | number;
    let bVal: string | number;
    switch (sortBy) {
      case 'affectedImages': aVal = a.AffectedImageCount || 0; bVal = b.AffectedImageCount || 0; break;
      case 'expiresAt': aVal = a.ExpiresAt || 0; bVal = b.ExpiresAt || 0; break;
      default: aVal = a.CVEID; bVal = b.CVEID;
    }
    if (typeof aVal === 'number' && typeof bVal === 'number') return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
    return sortDir === 'asc' ? String(aVal).localeCompare(String(bVal)) : String(bVal).localeCompare(String(aVal));
  });

  const paged = combined.slice(offset, offset + pageSize);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [active, inact] = await Promise.all([
        apiClient.getVEXStatements({}),
        apiClient.getInactiveVEXStatements(),
      ]);
      setStatements(active);
      setInactive(inact);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const sortColumns = [
    { col: 'affectedImages', label: 'Affected Images' },
    { col: 'expiresAt', label: 'Expires' },
    { col: 'cveId', label: 'CVE ID' },
  ] as const;

  return (
    <div>
      <PageHeader
        title="VEX Statements"
        subtitle="Manage and monitor vulnerability analysis statements"
        showImageUsage={false}
      />
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
        <FilterActionButton onClick={() => setPage(1)}>Filter</FilterActionButton>
        <FilterActionButton variant="secondary" onClick={() => { setSearch(''); setStateFilter('all'); setExpirationFilter('all'); setPage(1); }}>Clear</FilterActionButton>
      </PageFiltersBar>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {/* Sort bar */}
        <div className="flex items-center gap-1 px-4 py-2 border-b border-border bg-bg-secondary text-xs font-medium text-text-secondary uppercase">
          <span className="flex-1 pl-2">VEX Statement</span>
          {sortColumns.map(({ col, label }) => {
            const active = sortBy === col;
            const Icon = active ? (sortDir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
            return (
              <button key={col} onClick={() => handleSort(col)}
                className={`flex items-center gap-1 px-2 py-1 rounded hover:bg-bg-tertiary transition-colors select-none ${active ? 'text-accent' : ''}`}>
                {label} <Icon className="w-3 h-3" />
              </button>
            );
          })}
        </div>
        {paged.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No VEX statements match filters</div>
        ) : (
          <div className="divide-y divide-border">
            {paged.map(t => {
              const repos = t.Repositories || [];
              return (
                <Link key={t.CVEID} to={`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-bg-secondary transition-colors">
                  <VEXStateBadge state={t.State} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono font-medium">{t.CVEID}</span>
                      <ExpirationBadge expiresAt={t.ExpiresAt} />
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      {t.Justification && <span className="text-xs text-text-secondary truncate">{t.Justification}</span>}
                      {t.Justification && t.Detail && <span className="text-xs text-text-muted">·</span>}
                      {t.Detail && <span className="text-xs text-text-muted truncate">{t.Detail}</span>}
                    </div>
                    {repos.length > 0 && (
                      <div className="text-xs text-text-muted mt-0.5 truncate">
                        {repos.slice(0, 3).map(r => r.Repository).join(', ')}{repos.length > 3 ? ` +${repos.length - 3}` : ''}
                      </div>
                    )}
                  </div>
                  <span className="text-xs text-text-muted shrink-0">{t.AffectedImageCount || 0} image{(t.AffectedImageCount || 0) !== 1 ? 's' : ''}</span>
                  {t.ExpiresAt ? (
                    <span className="text-xs text-text-muted shrink-0 w-24 text-right">{formatDate(t.ExpiresAt)}</span>
                  ) : (
                    <span className="text-xs text-text-muted shrink-0 w-24 text-right">No expiry</span>
                  )}
                </Link>
              );
            })}
          </div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={combined.length} pageSize={pageSize} onPageChange={setPage} itemLabel="vex statements" />
      </div>
    </div>
  );
}
