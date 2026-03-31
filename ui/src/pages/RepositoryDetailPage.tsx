import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime } from '../lib/utils';
import { LoadingState, ErrorState, StatusBadge, VulnCounts, SortHeader, Pagination, ConfirmModal } from '../components/ui';
import type { RepositoryTag } from '../lib/api';
import { ArrowLeft, RefreshCw } from 'lucide-react';

export default function RepositoryDetailPage() {
  const { name } = useParams<{ name: string }>();
  const decodedName = decodeURIComponent(name || '');
  const { apiClient } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  const [tags, setTags] = useState<RepositoryTag[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [sortCol, setSortCol] = useState('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const [confirmRescan, setConfirmRescan] = useState<{type: 'repo' | 'tag'; name: string} | null>(null);

  const load = useCallback(async () => {
    if (!decodedName) return;
    setLoading(true);
    setError('');
    try {
      const resp = await apiClient.getRepository(decodedName, { limit: pageSize, offset: (page - 1) * pageSize, ...(search && { search }) });
      const t = resp?.Tags || [];
      // Client-side sort
      const colMap: Record<string, keyof RepositoryTag> = { name: 'Name', lastScanTime: 'LastScanTime', status: 'PolicyPassed' };
      const apiCol = colMap[sortCol] || 'Name';
      t.sort((a, b) => {
        const av = a[apiCol as keyof RepositoryTag] as any;
        const bv = b[apiCol as keyof RepositoryTag] as any;
        if (typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? av - bv : bv - av;
        return sortDir === 'asc' ? String(av || '').localeCompare(String(bv || '')) : String(bv || '').localeCompare(String(av || ''));
      });
      setTags(t);
      setTotal(resp?.Total || t.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [apiClient, decodedName, page, search, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
    setPage(1);
  };

  const handleRescan = async (type: 'repo' | 'tag', n: string) => {
    setConfirmRescan(null);
    try {
      const resp = type === 'repo'
        ? await apiClient.triggerRepositoryRescan(decodedName)
        : await apiClient.triggerTagRescan(decodedName, n);
      toast(resp.message || 'Rescan triggered', 'success');
      setTimeout(load, 2000);
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed', 'error');
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  if (loading && tags.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <button onClick={() => navigate('/repositories')} className="p-2 rounded-lg border border-border hover:bg-bg-tertiary transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{decodedName}</h1>
          <p className="text-sm text-text-secondary">{total} tag{total !== 1 ? 's' : ''}</p>
        </div>
        <button onClick={() => setConfirmRescan({ type: 'repo', name: decodedName })} className="px-4 py-2 text-sm rounded-lg border border-warning/30 text-warning hover:bg-warning-bg flex items-center gap-2 transition-colors">
          <RefreshCw className="w-4 h-4" /> Rescan All
        </button>
      </div>
      {/* Search */}
      <div className="flex gap-3 mb-4">
        <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(); } }}
          placeholder="Filter tags…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <button onClick={() => { setPage(1); load(); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
      </div>
      {/* Table */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {tags.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No tags found</div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="name" label="Tag" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="lastScanTime" label="Last Scan" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
            <SortHeader column="status" label="Status" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Action</th>
          </tr></thead><tbody>
            {tags.map(tag => (
              <tr key={tag.Name} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                <td className="px-4 py-3 text-sm text-accent cursor-pointer hover:underline" onClick={() => tag.Digest && navigate(`/repositories/${encodeURIComponent(decodedName)}/tags/${encodeURIComponent(tag.Digest)}`)}>{tag.Name}</td>
                <td className="px-4 py-3 text-sm text-text-secondary">{tag.LastScanTime ? formatRelativeTime(tag.LastScanTime) : 'Never'}</td>
                <td className="px-4 py-3"><VulnCounts critical={tag.VulnerabilityCount?.Critical} high={tag.VulnerabilityCount?.High} medium={tag.VulnerabilityCount?.Medium} low={tag.VulnerabilityCount?.Low} tolerated={tag.VulnerabilityCount?.Tolerated} /></td>
                <td className="px-4 py-3">{tag.ScanError ? <span className="text-xs text-danger" title={tag.ScanError}>Error</span> : <StatusBadge passed={tag.PolicyPassed} />}</td>
                <td className="px-4 py-3">
                  <button onClick={() => setConfirmRescan({ type: 'tag', name: tag.Name })} className="px-3 py-1 text-xs rounded border border-warning/30 text-warning hover:bg-warning-bg flex items-center gap-1 transition-colors">
                    <RefreshCw className="w-3 h-3" /> Rescan
                  </button>
                </td>
              </tr>
            ))}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="tags" />
      </div>
      <ConfirmModal open={!!confirmRescan} title={`Rescan ${confirmRescan?.type === 'repo' ? 'Repository' : 'Tag'}`}
        message={confirmRescan?.type === 'repo' ? `Rescan all images in "${decodedName}"?` : `Rescan tag "${confirmRescan?.name}" in "${decodedName}"?`}
        onConfirm={() => confirmRescan && handleRescan(confirmRescan.type, confirmRescan.name)} onCancel={() => setConfirmRescan(null)} />
    </div>
  );
}
