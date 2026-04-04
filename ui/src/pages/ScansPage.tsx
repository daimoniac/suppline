import { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, formatDate, truncateDigest, copyToClipboard } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination } from '../components/ui';
import type { Scan } from '../lib/api';
import { Copy } from 'lucide-react';

export default function ScansPage() {
  const { apiClient } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams] = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [repositoryInput, setRepositoryInput] = useState(searchParams.get('repository') || '');
  const [repository, setRepository] = useState(searchParams.get('repository') || '');
  const [policyFilter, setPolicyFilter] = useState(searchParams.get('policy_passed') || 'all');
  const [sortCol, setSortCol] = useState('scanned_at');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const sortKey = `${sortCol}_${sortDir}`;
      const filters: Record<string, unknown> = {
        limit: pageSize,
        offset: (page - 1) * pageSize,
        sort_by: sortKey,
      };
      if (repository) filters.repository = repository;
      if (policyFilter !== 'all') filters.policy_passed = policyFilter === 'passed';
      if (inUseQuery !== undefined) filters.in_use = inUseQuery;

      const result = await apiClient.getScansPage(filters);
      setScans(result.scans);
      setTotalScans(result.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, inUseQuery, page, pageSize, policyFilter, repository, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(totalScans / pageSize));
    if (page > totalPages) setPage(totalPages);
  }, [page, pageSize, totalScans]);

  const handleSort = (col: string) => {
    setPage(1);
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  if (loading && scans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const totalPages = Math.max(1, Math.ceil(totalScans / pageSize));

  return (
    <div>
      <PageHeader title="Image Scans" subtitle="View and manage container image security scans" />
      <div className="flex gap-3 mb-4 flex-wrap">
        <input value={repositoryInput} onChange={e => setRepositoryInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setRepository(repositoryInput.trim()), setPage(1))}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <select value={policyFilter} onChange={e => { setPolicyFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
          <option value="all">All Statuses</option>
          <option value="passed">Passed</option>
          <option value="failed">Failed</option>
        </select>
        <button onClick={() => { setRepository(repositoryInput.trim()); setPage(1); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
        <button onClick={() => { setRepositoryInput(''); setRepository(''); setPolicyFilter('all'); setPage(1); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>
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
              <tr key={`${s.Repository}:${s.Tag}:${s.Digest}:${idx}`} className="border-b border-border/50 hover:bg-bg-secondary cursor-pointer transition-colors" onClick={() => navigate(`/scans/${s.Digest}`)}>
                <td className="px-4 py-3 text-sm text-text-primary">{s.Repository || 'N/A'}</td>
                <td className="px-4 py-3 text-sm text-text-secondary">{s.Tag || 'N/A'}</td>
                <td className="px-4 py-3 text-sm">
                  <div className="flex items-center gap-1 flex-wrap"><code className="text-xs text-text-muted font-mono">{truncateDigest(s.Digest)}</code>
                    <button className="text-text-muted hover:text-text-primary p-0.5" onClick={e => { e.stopPropagation(); copyToClipboard(s.Digest).then(ok => toast(ok ? 'Copied!' : 'Failed', ok ? 'success' : 'error')); }}>
                      <Copy className="w-3 h-3" /></button></div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary" title={formatDate(s.ScannedAt ?? s.CreatedAt)}>{formatRelativeTime(s.ScannedAt ?? s.CreatedAt)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge passed={s.PolicyPassed} status={s.PolicyStatus} />
                    {s.RuntimeUsed && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-success-bg text-success" title={s.RuntimeClusters && s.RuntimeClusters.length > 0 ? `Running on: ${s.RuntimeClusters.join(', ')}` : 'In use'}>
                        In use
                      </span>
                    )}
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
