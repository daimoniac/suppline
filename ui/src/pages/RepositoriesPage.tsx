import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination, ConfirmModal, RuntimeUsageBadge, PageFiltersBar, FilterActionButton, PolicyStatusSelect } from '../components/ui';
import type { Repository } from '../lib/api';
import { RefreshCw } from 'lucide-react';
import { useSortablePaginationState, type SortDirection } from '../lib/useSortablePaginationState';
import { useScanPageFilters } from '../lib/useScanPageFilters';

export default function RepositoriesPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams, setSearchParams] = useSearchParams();

  const [repos, setRepos] = useState<Repository[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const pageSize = 10;
  const [confirmRescan, setConfirmRescan] = useState('');

  const defaultSortColumn = 'lastScanTime';
  const defaultSortDirection: SortDirection = 'desc';
  const initialSortDir = (searchParams.get('order') as SortDirection) || defaultSortDirection;
  const initialPage = Number(searchParams.get('page')) || 1;

  const { sortColumn: sortCol, sortDirection: sortDir, toggleSort, page, setPage, totalPages, offset } = useSortablePaginationState({
    initialSortColumn: searchParams.get('sort') || defaultSortColumn,
    initialSortDirection: initialSortDir,
    resolveNewColumnDirection: () => 'asc',
    initialPage,
    pageSize,
    totalItems: total,
  });

  const {
    repositoryInput,
    repository,
    policyFilter,
    handleRepositoryInputChange,
    applyRepositoryFilter,
    handlePolicyFilterChange,
    clearFilters,
    handlePageChange,
    handleSortChange,
  } = useScanPageFilters({
    initialRepository: searchParams.get('search') || '',
    initialPolicyFilter: searchParams.get('policy_status') || 'all',
    searchParamName: 'search',
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
      let sortBy = 'age_desc';
      switch (sortCol) {
        case 'name':
          sortBy = sortDir === 'asc' ? 'name_asc' : 'name_desc';
          break;
        case 'artifactCount':
          sortBy = sortDir === 'asc' ? 'artifacts_asc' : 'artifacts_desc';
          break;
        case 'lastScanTime':
          sortBy = sortDir === 'asc' ? 'age_asc' : 'age_desc';
          break;
        case 'status':
          sortBy = sortDir === 'asc' ? 'status_asc' : 'status_desc';
          break;
      }

      const resp = await apiClient.getRepositories({
        limit: pageSize, offset,
        ...(repository && { search: repository }),
        ...(inUseQuery !== undefined && { in_use: inUseQuery }),
        ...(policyFilter !== 'all' && { policy_status: policyFilter }),
        sort_by: sortBy,
      });
      if (resp && resp.Repositories) {
        setRepos(resp.Repositories);
        setTotal(resp.Total || resp.Repositories.length);
      } else {
        setRepos([]);
        setTotal(0);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [apiClient, inUseQuery, offset, pageSize, policyFilter, repository, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    const nextDir = col === sortCol ? (sortDir === 'asc' ? 'desc' : 'asc') : 'asc';
    toggleSort(col);
    handleSortChange(col, nextDir);
  };

  const handleRescan = async (name: string) => {
    setConfirmRescan('');
    try {
      const resp = await apiClient.triggerRepositoryRescan(name);
      toast(resp.message || 'Rescan triggered', 'success');
      setTimeout(load, 2000);
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed', 'error');
    }
  };

  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Repositories" subtitle="View all repositories and their scanning status" />
      <PageFiltersBar>
        <input value={repositoryInput} onChange={e => handleRepositoryInputChange(e.target.value)} onKeyDown={e => e.key === 'Enter' && applyRepositoryFilter()}
          placeholder="Filter by name…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <PolicyStatusSelect value={policyFilter} onChange={handlePolicyFilterChange} />
        <FilterActionButton onClick={applyRepositoryFilter}>Filter</FilterActionButton>
        <FilterActionButton variant="secondary" onClick={clearFilters}>Clear</FilterActionButton>
      </PageFiltersBar>
      {loading && repos.length === 0 ? <LoadingState /> : <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {repos.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No repositories found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border">
                <SortHeader column="name" label="Name" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
                <SortHeader column="artifactCount" label="Artifacts" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
                <SortHeader column="lastScanTime" label="Last Scan" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
                <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
                <SortHeader column="status" label="Status" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
                <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Action</th>
              </tr></thead>
              <tbody>
                {repos.map(r => (
                  <tr key={r.Name} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                    <td className="px-4 py-3 text-sm"><Link className="text-accent hover:underline" to={`/repositories/${encodeURIComponent(r.Name)}`}>{r.Name}</Link></td>
                    <td className="px-4 py-3 text-sm text-text-secondary">{r.ArtifactCount || 0}</td>
                    <td className="px-4 py-3 text-sm text-text-secondary">{r.LastScanTime ? formatRelativeTime(r.LastScanTime) : 'Never'}</td>
                    <td className="px-4 py-3"><VulnCounts critical={r.VulnerabilityCount?.Critical} high={r.VulnerabilityCount?.High} medium={r.VulnerabilityCount?.Medium} low={r.VulnerabilityCount?.Low} exempted={r.VulnerabilityCount?.Exempted} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <StatusBadge passed={r.PolicyPassed} status={r.PolicyStatus} />
                        <RuntimeUsageBadge inUse={!!r.RuntimeUsed} whitelisted={!!r.Whitelisted} />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={e => { e.stopPropagation(); setConfirmRescan(r.Name); }} className="px-3 py-1 text-xs rounded border border-warning/30 text-warning hover:bg-warning-bg transition-colors flex items-center gap-1">
                        <RefreshCw className="w-3 h-3" /> Rescan
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={handlePageChange} itemLabel="repos" />
      </div>}
      <ConfirmModal open={!!confirmRescan} title="Rescan Repository" message={`Trigger rescan for all images in "${confirmRescan}"?`} onConfirm={() => handleRescan(confirmRescan)} onCancel={() => setConfirmRescan('')} />
    </div>
  );
}
