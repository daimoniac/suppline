import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination, ConfirmModal } from '../components/ui';
import type { Repository } from '../lib/api';
import { RefreshCw } from 'lucide-react';

export default function RepositoriesPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams, setSearchParams] = useSearchParams();

  const [repos, setRepos] = useState<Repository[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [sortCol, setSortCol] = useState(searchParams.get('sort') || 'lastScanTime');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>((searchParams.get('order') as 'asc' | 'desc') || 'desc');
  const [page, setPage] = useState(Number(searchParams.get('page')) || 1);
  const pageSize = 10;
  const [confirmRescan, setConfirmRescan] = useState('');

  const sortMap: Record<string, string> = {
    name: sortDir === 'asc' ? 'name_asc' : 'name_desc',
    artifactCount: sortDir === 'asc' ? 'artifacts_asc' : 'artifacts_desc',
    lastScanTime: sortDir === 'asc' ? 'age_asc' : 'age_desc',
    status: sortDir === 'asc' ? 'status_asc' : 'status_desc',
  };

  const load = useCallback(async (opts?: { page?: number; search?: string }) => {
    setLoading(true);
    setError('');
    try {
      const effectivePage = opts?.page ?? page;
      const effectiveSearch = opts?.search ?? search;
      const resp = await apiClient.getRepositories({
        limit: pageSize, offset: (effectivePage - 1) * pageSize,
        ...(effectiveSearch && { search: effectiveSearch }),
        ...(inUseQuery !== undefined && { in_use: inUseQuery }),
        sort_by: sortMap[sortCol] || 'age_desc',
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
  }, [apiClient, inUseQuery, page, search, sortCol, sortDir]); // eslint-disable-line

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    const nextDir = col === sortCol ? (sortDir === 'asc' ? 'desc' : 'asc') : 'asc';
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
    updateURL(col, nextDir, search, page);
  };

  const updateURL = (s: string, d: string, q: string, p: number) => {
    const params: Record<string, string> = {};
    if (q) params.search = q;
    if (p > 1) params.page = String(p);
    if (s !== 'lastScanTime' || d !== 'desc') { params.sort = s; params.order = d; }
    setSearchParams(params, { replace: true });
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

  const totalPages = Math.ceil(total / pageSize);

  const applySearch = (nextSearch: string) => {
    setPage(1);
    updateURL(sortCol, sortDir, nextSearch, 1);
    void load({ page: 1, search: nextSearch });
  };

  const handleSearchInputChange = (nextSearch: string) => {
    setSearch(nextSearch);
    if (page !== 1) {
      setPage(1);
      updateURL(sortCol, sortDir, nextSearch, 1);
    }
  };

  if (loading && repos.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Repositories" subtitle="View all repositories and their scanning status" />
      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <input value={search} onChange={e => handleSearchInputChange(e.target.value)} onKeyDown={e => e.key === 'Enter' && applySearch(search)}
          placeholder="Filter by name…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <button onClick={() => applySearch(search)} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
        <button onClick={() => { setSearch(''); applySearch(''); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>
      {/* Table */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
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
                    <td className="px-4 py-3"><VulnCounts critical={r.VulnerabilityCount?.Critical} high={r.VulnerabilityCount?.High} medium={r.VulnerabilityCount?.Medium} low={r.VulnerabilityCount?.Low} tolerated={r.VulnerabilityCount?.Tolerated} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <StatusBadge passed={r.PolicyPassed} status={r.PolicyStatus} />
                        {r.RuntimeUsed && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-success-bg text-success">In use</span>}
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
        <Pagination currentPage={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={p => { setPage(p); updateURL(sortCol, sortDir, search, p); }} itemLabel="repos" />
      </div>
      <ConfirmModal open={!!confirmRescan} title="Rescan Repository" message={`Trigger rescan for all images in "${confirmRescan}"?`} onConfirm={() => handleRescan(confirmRescan)} onCancel={() => setConfirmRescan('')} />
    </div>
  );
}
