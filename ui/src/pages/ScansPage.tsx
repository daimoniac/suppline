import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatRelativeTime, formatDate } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination, DigestLinkWithCopy, RuntimeUsageBadge, PageFiltersBar, FilterActionButton, PolicyStatusSelect } from '../components/ui';
import type { Scan } from '../lib/api';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';

export default function ScansPage() {
  const { apiClient } = useAuth();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams] = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [repositoryInput, setRepositoryInput] = useState(searchParams.get('repository') || '');
  const [repository, setRepository] = useState(searchParams.get('repository') || '');
  const [policyFilter, setPolicyFilter] = useState(searchParams.get('policy_passed') || 'all');
  const pageSize = 50;

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
        limit: pageSize,
        offset,
        sort_by: sortKey,
      };
      if (repository) filters.repository = repository;
      if (policyFilter !== 'all') filters.policy_status = policyFilter;
      if (inUseQuery !== undefined) filters.in_use = inUseQuery;

      const result = await apiClient.getScansPage(filters);
      setScans(result.scans);
      setTotalScans(result.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, inUseQuery, offset, pageSize, policyFilter, repository, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    setPage(1);
    toggleSort(col);
  };

  if (loading && scans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Image Scans" subtitle="View and manage container image security scans" />
      <PageFiltersBar>
        <input value={repositoryInput} onChange={e => setRepositoryInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setRepository(repositoryInput.trim()), setPage(1))}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <PolicyStatusSelect value={policyFilter} onChange={v => { setPolicyFilter(v); setPage(1); }} />
        <FilterActionButton onClick={() => { setRepository(repositoryInput.trim()); setPage(1); }}>Filter</FilterActionButton>
        <FilterActionButton variant="secondary" onClick={() => { setRepositoryInput(''); setRepository(''); setPolicyFilter('all'); setPage(1); }}>Clear</FilterActionButton>      </PageFiltersBar>
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {scans.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No scans found</div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="repository" label="Repository" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="tag" label="Tag" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="digest" label="Digest" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="scanned_at" label="Scanned" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="policy_passed" label="Status" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
          </tr></thead><tbody>
            {scans.map((s, idx) => (
              <tr key={`${s.Repository}:${s.Tag}:${s.Digest}:${idx}`} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                <td className="px-4 py-3 text-sm text-text-primary">
                  <Link to={`/repositories/${encodeURIComponent(s.Repository)}`} className="text-accent hover:underline">{s.Repository || 'N/A'}</Link>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">{s.Tag || 'N/A'}</td>
                <td className="px-4 py-3 text-sm">
                  <DigestLinkWithCopy digest={s.Digest} to={`/scans/${s.Digest}`} wrap />
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary" title={formatDate(s.ScannedAt ?? s.CreatedAt)}>{formatRelativeTime(s.ScannedAt ?? s.CreatedAt)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge passed={s.PolicyPassed} status={s.PolicyStatus} />
                    <RuntimeUsageBadge inUse={!!s.RuntimeUsed} clusters={s.RuntimeClusters} />
                  </div>
                </td>
                <td className="px-4 py-3"><VulnCounts critical={s.CriticalVulnCount} high={s.HighVulnCount} medium={s.MediumVulnCount} low={s.LowVulnCount} /></td>
              </tr>
            ))}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={totalScans} pageSize={pageSize} onPageChange={setPage} itemLabel="scans" />
      </div>
    </div>
  );
}
