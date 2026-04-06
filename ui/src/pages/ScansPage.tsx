import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatRelativeTime, formatDate } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination, DigestLinkWithCopy, RuntimeUsageBadge, PageFiltersBar, FilterActionButton, PolicyStatusSelect } from '../components/ui';
import type { Scan } from '../lib/api';
import { useSortablePaginationState, type SortDirection } from '../lib/useSortablePaginationState';
import { useScanPageFilters } from '../lib/useScanPageFilters';

export default function ScansPage() {
  const { apiClient } = useAuth();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams, setSearchParams] = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const pageSize = 50;
  const defaultSortColumn = 'scanned_at';
  const defaultSortDirection: SortDirection = 'desc';
  const initialSortDirection = (searchParams.get('order') as SortDirection) || defaultSortDirection;
  const initialPage = Number(searchParams.get('page')) || 1;

  const { sortColumn: sortCol, sortDirection: sortDir, toggleSort, page, setPage, totalPages, offset } = useSortablePaginationState({
    initialSortColumn: searchParams.get('sort') || defaultSortColumn,
    initialSortDirection,
    resolveNewColumnDirection: () => 'desc',
    initialPage,
    pageSize,
    totalItems: totalScans,
  });

  const {
    repository,
    policyFilter,
    handleRepositoryInputChange,
    applyRepositoryFilter,
    handlePolicyFilterChange,
    clearFilters,
    handlePageChange,
    handleSortChange,
  } = useScanPageFilters({
    initialRepository: searchParams.get('repository') || '',
    initialPolicyFilter: searchParams.get('policy_status') || 'all',
    page,
    sortColumn: sortCol,
    sortDirection: sortDir,
    defaultSortColumn,
    defaultSortDirection,
    setPage,
    setSearchParams,
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
    const nextDir = col === sortCol ? (sortDir === 'asc' ? 'desc' : 'asc') : 'desc';
    toggleSort(col);
    handleSortChange(col, nextDir);
  };

  if (loading && scans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Image Scans" subtitle="View and manage container image security scans" />
      <PageFiltersBar>
        <input value={repository} onChange={e => handleRepositoryInputChange(e.target.value)} onKeyDown={e => e.key === 'Enter' && applyRepositoryFilter()}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <PolicyStatusSelect value={policyFilter} onChange={handlePolicyFilterChange} />
        <FilterActionButton onClick={applyRepositoryFilter}>Filter</FilterActionButton>
        <FilterActionButton variant="secondary" onClick={clearFilters}>Clear</FilterActionButton>      </PageFiltersBar>
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
        <Pagination currentPage={page} totalPages={totalPages} total={totalScans} pageSize={pageSize} onPageChange={handlePageChange} itemLabel="scans" />
      </div>
    </div>
  );
}
