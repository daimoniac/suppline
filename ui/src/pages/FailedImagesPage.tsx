import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatRelativeTime, formatDate, daysUntilReleaseAge, formatRemainingDays } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination } from '../components/ui';
import type { Scan } from '../lib/api';
import { AlertTriangle } from 'lucide-react';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';
import { DigestLinkWithCopy } from '../components/DigestLinkWithCopy';
import { RuntimeUsageBadge } from '../components/RuntimeUsageBadge';
import { PageFiltersBar, FilterActionButton } from '../components/PageFiltersBar';

export default function FailedImagesPage() {
  const { apiClient } = useAuth();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams] = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [repositoryInput, setRepositoryInput] = useState(searchParams.get('repository') || '');
  const [repository, setRepository] = useState(searchParams.get('repository') || '');
  const pageSize = 25;

  const { sortColumn: sortCol, sortDirection: sortDir, toggleSort, page, setPage, totalPages, offset } = useSortablePaginationState({
    initialSortColumn: 'scanned_at',
    initialSortDirection: 'desc',
    resolveNewColumnDirection: () => 'desc',
    pageSize,
    totalItems: totalScans,
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const sortKey = `${sortCol}_${sortDir}`;
      const filters: Record<string, unknown> = {
        policy_passed: false,
        sort_by: sortKey,
        limit: pageSize,
        offset,
      };
      if (repository) filters.repository = repository;
      if (inUseQuery !== undefined) filters.in_use = inUseQuery;

      const result = await apiClient.getScansPage(filters);
      setScans(result.scans);
      setTotalScans(result.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, inUseQuery, offset, pageSize, repository, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    setPage(1);
    toggleSort(col);
  };

  if (loading && scans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const pendingCount = scans.filter(s => s.PolicyStatus === 'pending').length;
  const failedCount = scans.length - pendingCount;

  return (
    <div>
      <PageHeader title="Policy Exceptions" subtitle="Images that are policy-failed or pending release maturity" />

      {totalScans > 0 && (
        <div className="flex items-center gap-3 p-4 mb-4 rounded-xl border border-warning/30 bg-warning-bg/20">
          <AlertTriangle className="w-5 h-5 text-danger flex-shrink-0" />
          <div>
            <div className="text-sm font-medium text-text-primary">Policy Exceptions Detected</div>
            <div className="text-xs text-text-secondary flex items-center gap-3 flex-wrap">
              <span>{totalScans} image{totalScans !== 1 ? 's' : ''} require attention.</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-danger-bg text-danger">{failedCount} Failed</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-warning-bg text-warning">{pendingCount} Pending Maturity</span>
            </div>
          </div>
        </div>
      )}

      <PageFiltersBar>
        <input value={repositoryInput} onChange={e => setRepositoryInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setRepository(repositoryInput.trim()), setPage(1))}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <FilterActionButton onClick={() => { setRepository(repositoryInput.trim()); setPage(1); }}>Filter</FilterActionButton>
        <FilterActionButton variant="secondary" onClick={() => { setRepositoryInput(''); setRepository(''); setPage(1); }}>Clear</FilterActionButton>
      </PageFiltersBar>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {scans.length === 0 ? (
          <div className="p-12 text-center">
            <div className="text-3xl mb-2">✅</div>
            <h3 className="font-semibold text-accent">No Policy Exceptions</h3>
            <p className="text-sm text-text-secondary">All images are policy compliant</p>
          </div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="repository" label="Repository" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="tag" label="Tag" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Digest</th>
            <SortHeader column="scanned_at" label="Scanned" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Status</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Failure Reasons</th>
          </tr></thead><tbody>
            {scans.map((s, idx) => (
              <tr key={`${s.Repository}:${s.Tag}:${s.Digest}:${idx}`} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                <td className="px-4 py-3 text-sm">
                  <Link to={`/repositories/${encodeURIComponent(s.Repository)}`} className="text-accent hover:underline">
                    {s.Repository || 'N/A'}
                  </Link>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">{s.Tag || 'N/A'}</td>
                <td className="px-4 py-3 text-sm">
                  <DigestLinkWithCopy digest={s.Digest} to={`/scans/${s.Digest}`} wrap />
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary" title={formatDate(s.ScannedAt ?? s.CreatedAt)}>{formatRelativeTime(s.ScannedAt ?? s.CreatedAt)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge passed={s.PolicyPassed} status={s.PolicyStatus} label={s.PolicyStatus === 'pending' ? 'Pending Maturity' : undefined} />
                    <RuntimeUsageBadge inUse={!!s.RuntimeUsed} clusters={s.RuntimeClusters} />
                  </div>
                </td>
                <td className="px-4 py-3"><VulnCounts critical={s.CriticalVulnCount} high={s.HighVulnCount} medium={s.MediumVulnCount} low={s.LowVulnCount} /></td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {s.PolicyStatus === 'pending' && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-warning-bg text-warning">
                        {formatRemainingDays(daysUntilReleaseAge(s.ReleaseAgeSeconds, s.MinimumReleaseAgeSeconds))}
                      </span>
                    )}
                    {s.CriticalVulnCount > 0 && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-severity-critical/20 text-severity-critical">{s.CriticalVulnCount} Critical</span>}
                    {s.HighVulnCount > 0 && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-severity-high/20 text-severity-high">{s.HighVulnCount} High</span>}
                    {!s.VulnAttested && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-warning-bg text-warning">No Attestation</span>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={totalScans} pageSize={pageSize} onPageChange={setPage} itemLabel="images" />
      </div>
    </div>
  );
}
