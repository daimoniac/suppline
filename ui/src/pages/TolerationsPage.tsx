import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatDate, isPast, isWithinDays, daysUntil } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, SortHeader, Pagination } from '../components/ui';
import type { Toleration } from '../lib/api';

export default function TolerationsPage() {
  const { apiClient } = useAuth();
  const [searchParams] = useSearchParams();
  const [tolerations, setTolerations] = useState<Toleration[]>([]);
  const [inactive, setInactive] = useState<Toleration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [cveFilter, setCveFilter] = useState(searchParams.get('cve_id') || '');
  const [repoFilter, setRepoFilter] = useState(searchParams.get('repository') || '');
  const [expirationFilter, setExpirationFilter] = useState(searchParams.get('expiration_status') || 'all');
  const [sortCol, setSortCol] = useState('cveId');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [active, inact] = await Promise.all([
        apiClient.getTolerations({}),
        apiClient.getInactiveTolerations(),
      ]);
      setTolerations(active);
      setInactive(inact);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
  };

  // Combine active + inactive
  let combined = [...tolerations, ...inactive];

  // Filter
  if (cveFilter) combined = combined.filter(t => t.CVEID.toLowerCase().includes(cveFilter.toLowerCase()));
  if (repoFilter) combined = combined.filter(t => t.Repositories?.some(r => r.Repository.toLowerCase().includes(repoFilter.toLowerCase())));
  if (expirationFilter !== 'all') {
    combined = combined.filter(t => {
      if (expirationFilter === 'active') return !t.ExpiresAt || !isPast(t.ExpiresAt);
      if (expirationFilter === 'expired') return t.ExpiresAt && isPast(t.ExpiresAt);
      if (expirationFilter === 'expiring') return t.ExpiresAt && !isPast(t.ExpiresAt) && isWithinDays(t.ExpiresAt, 7);
      return true;
    });
  }

  // Sort
  combined.sort((a, b) => {
    const aVal = sortCol === 'cveId' ? a.CVEID : sortCol === 'expiresAt' ? (a.ExpiresAt || 0) : a.CVEID;
    const bVal = sortCol === 'cveId' ? b.CVEID : sortCol === 'expiresAt' ? (b.ExpiresAt || 0) : b.CVEID;
    if (typeof aVal === 'number' && typeof bVal === 'number') return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
    return sortDir === 'asc' ? String(aVal).localeCompare(String(bVal)) : String(bVal).localeCompare(String(aVal));
  });

  const paged = combined.slice((page - 1) * pageSize, page * pageSize);
  const totalPages = Math.ceil(combined.length / pageSize);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="CVE Tolerations" subtitle="Manage and monitor CVE exception policies" />
      <div className="flex gap-3 mb-4 flex-wrap">
        <input value={cveFilter} onChange={e => setCveFilter(e.target.value)} placeholder="CVE ID…"
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors w-44" />
        <input value={repoFilter} onChange={e => setRepoFilter(e.target.value)} placeholder="Repository…"
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors w-44" />
        <select value={expirationFilter} onChange={e => { setExpirationFilter(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="expiring">Expiring Soon</option>
          <option value="expired">Expired</option>
        </select>
        <button onClick={() => setPage(1)} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
        <button onClick={() => { setCveFilter(''); setRepoFilter(''); setExpirationFilter('all'); setPage(1); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {paged.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No tolerations match filters</div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="cveId" label="CVE ID" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Statement</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Repositories</th>
            <SortHeader column="expiresAt" label="Expires" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Status</th>
          </tr></thead><tbody>
            {paged.map(t => {
              const expired = t.ExpiresAt && isPast(t.ExpiresAt);
              const expiringSoon = t.ExpiresAt && !expired && isWithinDays(t.ExpiresAt, 7);
              const days = daysUntil(t.ExpiresAt);
              return (
                <tr key={t.CVEID} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                  <td className="px-4 py-3 text-sm font-mono font-medium text-accent"><Link className="hover:underline" to={`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`}>{t.CVEID}</Link></td>
                  <td className="px-4 py-3 text-sm text-text-secondary max-w-xs truncate">{t.Statement || '—'}</td>
                  <td className="px-4 py-3 text-sm text-text-muted">
                    {(t.Repositories || []).length > 0
                      ? (t.Repositories || []).slice(0, 2).map(r => r.Repository).join(', ') + ((t.Repositories || []).length > 2 ? ` +${(t.Repositories || []).length - 2}` : '')
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">{t.ExpiresAt ? formatDate(t.ExpiresAt) : 'Never'}</td>
                  <td className="px-4 py-3">
                    {expired
                      ? <span className="px-2 py-0.5 rounded text-xs font-medium bg-danger-bg text-danger">Expired</span>
                      : expiringSoon
                        ? <span className="px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">{days}d left</span>
                        : <span className="px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">Active</span>
                    }
                  </td>
                </tr>
              );
            })}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={combined.length} pageSize={pageSize} onPageChange={setPage} itemLabel="tolerations" />
      </div>
    </div>
  );
}
