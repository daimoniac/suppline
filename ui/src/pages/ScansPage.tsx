import { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, truncateDigest, copyToClipboard } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, StatusBadge, VulnCounts, SortHeader, Pagination } from '../components/ui';
import type { Scan } from '../lib/api';
import { Copy } from 'lucide-react';

export default function ScansPage() {
  const { apiClient } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  const [allScans, setAllScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
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
      const fetchSize = 200;
      let offset = 0;
      const collected: Scan[] = [];

      while (true) {
        const filters: Record<string, unknown> = { limit: fetchSize, offset };
        if (repository) filters.repository = repository;
        if (policyFilter !== 'all') filters.policy_passed = policyFilter === 'passed';

        const batch = await apiClient.getScans(filters);
        collected.push(...batch);

        if (batch.length < fetchSize) break;
        offset += batch.length;
      }

      setAllScans(collected);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, repository, policyFilter]);

  const sortedScans = useMemo(() => {
    const colMap: Record<string, keyof Scan> = {
      scanned_at: 'ScannedAt',
      policy_passed: 'PolicyPassed',
      repository: 'Repository',
      tag: 'Tag',
      digest: 'Digest',
    };
    const apiCol = colMap[sortCol] || 'ScannedAt';

    return [...allScans].sort((a, b) => {
      const av = a[apiCol as keyof Scan] as unknown;
      const bv = b[apiCol as keyof Scan] as unknown;
      if (typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? av - bv : bv - av;
      if (typeof av === 'boolean' && typeof bv === 'boolean') {
        const an = av ? 1 : 0;
        const bn = bv ? 1 : 0;
        return sortDir === 'asc' ? an - bn : bn - an;
      }
      return sortDir === 'asc'
        ? String(av || '').localeCompare(String(bv || ''))
        : String(bv || '').localeCompare(String(av || ''));
    });
  }, [allScans, sortCol, sortDir]);

  const scans = useMemo(() => {
    const start = (page - 1) * pageSize;
    return sortedScans.slice(start, start + pageSize);
  }, [sortedScans, page]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(sortedScans.length / pageSize));
    if (page > totalPages) setPage(totalPages);
  }, [page, sortedScans.length]);

  const handleSort = (col: string) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  if (loading && allScans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const totalPages = Math.ceil(sortedScans.length / pageSize);

  return (
    <div>
      <PageHeader title="Image Scans" subtitle="View and manage container image security scans" />
      <div className="flex gap-3 mb-4 flex-wrap">
        <input value={repository} onChange={e => setRepository(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setPage(1), load())}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <select value={policyFilter} onChange={e => { setPolicyFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
          <option value="all">All Statuses</option>
          <option value="passed">Passed</option>
          <option value="failed">Failed</option>
        </select>
        <button onClick={() => { setPage(1); load(); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
        <button onClick={() => { setRepository(''); setPolicyFilter('all'); setPage(1); load(); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {sortedScans.length === 0 ? (
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
            {scans.map(s => (
              <tr key={s.Digest} className="border-b border-border/50 hover:bg-bg-secondary cursor-pointer transition-colors" onClick={() => navigate(`/scans/${s.Digest}`)}>
                <td className="px-4 py-3 text-sm text-text-primary">{s.Repository || 'N/A'}</td>
                <td className="px-4 py-3 text-sm text-text-secondary">{s.Tag || 'N/A'}</td>
                <td className="px-4 py-3 text-sm">
                  <div className="flex items-center gap-1"><code className="text-xs text-text-muted font-mono">{truncateDigest(s.Digest)}</code>
                    <button className="text-text-muted hover:text-text-primary p-0.5" onClick={e => { e.stopPropagation(); copyToClipboard(s.Digest).then(ok => toast(ok ? 'Copied!' : 'Failed', ok ? 'success' : 'error')); }}>
                      <Copy className="w-3 h-3" /></button></div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">{formatRelativeTime(s.ScannedAt)}</td>
                <td className="px-4 py-3"><StatusBadge passed={s.PolicyPassed} /></td>
                <td className="px-4 py-3"><VulnCounts critical={s.CriticalVulnCount} high={s.HighVulnCount} medium={s.MediumVulnCount} low={s.LowVulnCount} /></td>
              </tr>
            ))}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={sortedScans.length} pageSize={pageSize} onPageChange={setPage} itemLabel="scans" />
      </div>
    </div>
  );
}
