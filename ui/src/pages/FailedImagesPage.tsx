import { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, truncateDigest, copyToClipboard } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, VulnCounts, SortHeader, Pagination } from '../components/ui';
import type { Scan } from '../lib/api';
import { AlertTriangle, Copy } from 'lucide-react';

export default function FailedImagesPage() {
  const { apiClient } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [repositoryInput, setRepositoryInput] = useState(searchParams.get('repository') || '');
  const [repository, setRepository] = useState(searchParams.get('repository') || '');
  const [sortCol, setSortCol] = useState('scanned_at');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const sortKey = `${sortCol}_${sortDir}`;
      const filters: Record<string, unknown> = {
        policy_passed: false,
        sort_by: sortKey,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      };
      if (repository) filters.repository = repository;

      const result = await apiClient.getScansPage(filters);
      setScans(result.scans);
      setTotalScans(result.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, page, pageSize, repository, sortCol, sortDir]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    setPage(1);
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const totalPages = Math.max(1, Math.ceil(totalScans / pageSize));

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(totalScans / pageSize));
    if (page > maxPage) setPage(maxPage);
  }, [page, pageSize, totalScans]);

  if (loading && scans.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Failed Images" subtitle="Images that failed security policy evaluation" />

      {totalScans > 0 && (
        <div className="flex items-center gap-3 p-4 mb-4 rounded-xl border border-danger/30 bg-danger-bg">
          <AlertTriangle className="w-5 h-5 text-danger flex-shrink-0" />
          <div>
            <div className="text-sm font-medium text-danger">Policy Failures Detected</div>
            <div className="text-xs text-text-secondary">
              {totalScans} image{totalScans !== 1 ? 's' : ''} failed policy checks.
            </div>
          </div>
        </div>
      )}

      <div className="flex gap-3 mb-4">
        <input value={repositoryInput} onChange={e => setRepositoryInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setRepository(repositoryInput.trim()), setPage(1))}
          placeholder="Filter by repository…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <button onClick={() => { setRepository(repositoryInput.trim()); setPage(1); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Filter</button>
        <button onClick={() => { setRepositoryInput(''); setRepository(''); setPage(1); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {scans.length === 0 ? (
          <div className="p-12 text-center">
            <div className="text-3xl mb-2">✅</div>
            <h3 className="font-semibold text-accent">No Failed Images</h3>
            <p className="text-sm text-text-secondary">All images pass security policy</p>
          </div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="repository" label="Repository" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="tag" label="Tag" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Digest</th>
            <SortHeader column="scanned_at" label="Scanned" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Failure Reasons</th>
          </tr></thead><tbody>
            {scans.map(s => (
              <tr key={s.Digest} className="border-b border-border/50 hover:bg-bg-secondary cursor-pointer transition-colors" onClick={() => navigate(`/scans/${s.Digest}`)}>
                <td className="px-4 py-3 text-sm">
                  <span className="text-accent hover:underline cursor-pointer" onClick={e => { e.stopPropagation(); navigate(`/repositories/${encodeURIComponent(s.Repository)}`); }}>
                    {s.Repository || 'N/A'}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">{s.Tag || 'N/A'}</td>
                <td className="px-4 py-3 text-sm">
                  <div className="flex items-center gap-1"><code className="text-xs text-text-muted font-mono">{truncateDigest(s.Digest)}</code>
                    <button className="text-text-muted hover:text-text-primary p-0.5" onClick={e => { e.stopPropagation(); copyToClipboard(s.Digest).then(ok => toast(ok ? 'Copied!' : 'Fail', ok ? 'success' : 'error')); }}>
                      <Copy className="w-3 h-3" /></button></div>
                </td>
                <td className="px-4 py-3 text-sm text-text-secondary">{formatRelativeTime(s.ScannedAt)}</td>
                <td className="px-4 py-3"><VulnCounts critical={s.CriticalVulnCount} high={s.HighVulnCount} medium={s.MediumVulnCount} low={s.LowVulnCount} /></td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
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
