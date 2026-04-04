import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatRelativeTime, truncateDigest } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, SeverityBadge, Pagination } from '../components/ui';
import type { VulnerabilityGroup } from '../lib/api';
import { ChevronDown, ChevronRight, ExternalLink, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';

export default function VulnerabilitiesPage() {
  const { apiClient } = useAuth();
  const [searchParams] = useSearchParams();
  const [groups, setGroups] = useState<VulnerabilityGroup[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [cveId, setCveId] = useState(searchParams.get('cve_id') || '');
  const [severity, setSeverity] = useState(searchParams.get('severity') || 'all');
  const [sortBy, setSortBy] = useState('images');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [detailsByCVE, setDetailsByCVE] = useState<Record<string, VulnerabilityGroup>>({});
  const [loadingDetails, setLoadingDetails] = useState<Set<string>>(new Set());

  const handleSort = (col: string) => {
    if (col === sortBy) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(col);
      setSortDir(col === 'images' ? 'desc' : 'asc');
    }
    setPage(1);
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const filters: Record<string, unknown> = {
        limit: pageSize,
        offset: (page - 1) * pageSize,
        sort_by: sortBy,
        sort_dir: sortDir,
        include_digests: false,
      };
      if (cveId) filters.cve_id = cveId;
      if (severity !== 'all') filters.severity = severity.toUpperCase();
      const resp = await apiClient.queryVulnerabilities(filters);
      setGroups(resp.vulnerabilities);
      setTotal(resp.total);
      setDetailsByCVE({});
      setExpanded(new Set());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  }, [apiClient, cveId, severity, sortBy, sortDir, page]);

  useEffect(() => { load(); }, [load]);

  const loadDetails = useCallback(async (id: string) => {
    setLoadingDetails(prev => {
      const n = new Set(prev);
      n.add(id);
      return n;
    });

    try {
      const details = await apiClient.getVulnerabilityDetails(id, { max_digests: 500 });
      setDetailsByCVE(prev => ({ ...prev, [id]: details }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load vulnerability details');
    } finally {
      setLoadingDetails(prev => {
        const n = new Set(prev);
        n.delete(id);
        return n;
      });
    }
  }, [apiClient]);

  const toggle = (id: string) => {
    const isExpanded = expanded.has(id);
    setExpanded(prev => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });

    if (!isExpanded && !detailsByCVE[id] && !loadingDetails.has(id)) {
      loadDetails(id);
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  if (loading && groups.length === 0) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        subtitle="Search and browse vulnerabilities across all images"
        showImageUsage={false}
      />
      <div className="flex gap-3 mb-4 flex-wrap">
        <input value={cveId} onChange={e => setCveId(e.target.value)} onKeyDown={e => e.key === 'Enter' && (setPage(1), load())}
          placeholder="Search CVE ID…" className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors" />
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
          <option value="all" disabled>All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button onClick={() => { setPage(1); load(); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Search</button>
        <button onClick={() => { setCveId(''); setSeverity('all'); setPage(1); load(); }} className="px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors">Clear</button>
      </div>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {/* Sort bar */}
        <div className="flex items-center gap-1 px-4 py-2 border-b border-border bg-bg-secondary text-xs font-medium text-text-secondary uppercase">
          <span className="flex-1 pl-7">CVE</span>
          {(['images', 'severity', 'cve_id'] as const).map(col => {
            const labels: Record<string, string> = { images: 'Affected Images', severity: 'Severity', cve_id: 'CVE ID' };
            const active = sortBy === col;
            const Icon = active ? (sortDir === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
            return (
              <button key={col} onClick={() => handleSort(col)}
                className={`flex items-center gap-1 px-2 py-1 rounded hover:bg-bg-tertiary transition-colors select-none ${active ? 'text-accent' : ''}`}>
                {labels[col]} <Icon className="w-3 h-3" />
              </button>
            );
          })}
        </div>
        {groups.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No vulnerabilities found</div>
        ) : (
          <div className="divide-y divide-border">
            {groups.map(g => (
              <div key={g.CVEID}>
                <button onClick={() => toggle(g.CVEID)} className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-secondary transition-colors text-left">
                  {expanded.has(g.CVEID) ? <ChevronDown className="w-4 h-4 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 flex-shrink-0" />}
                  <SeverityBadge severity={g.Severity} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono font-medium">{g.CVEID}</span>
                      {g.PrimaryURL && (
                        <a href={g.PrimaryURL} target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-accent" onClick={e => e.stopPropagation()}>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                    {g.Title && <div className="text-xs text-text-secondary truncate">{g.Title}</div>}
                  </div>
                  <span className="text-xs text-text-muted">{g.affectedImageCount || 0} image{(g.affectedImageCount || 0) !== 1 ? 's' : ''}</span>
                </button>
                {expanded.has(g.CVEID) && (
                  <div className="border-t border-border bg-bg-secondary px-4 py-3">
                    {g.Description && <p className="text-xs text-text-muted mb-3 line-clamp-3">{g.Description}</p>}
                    {loadingDetails.has(g.CVEID) && (
                      <div className="text-xs text-text-muted mb-2">Loading affected digests...</div>
                    )}
                    {!loadingDetails.has(g.CVEID) && ((detailsByCVE[g.CVEID]?.affected || []).length === 0) && (
                      <div className="text-xs text-text-muted mb-2">No digest details available.</div>
                    )}
                    {(detailsByCVE[g.CVEID]?.affected || []).map((aff, ai) => (
                      <div key={ai} className="mb-3">
                        <div className="text-xs font-medium text-text-secondary mb-1">{aff.repository}</div>
                        <div className="space-y-1">
                          {aff.digests.map((d, di) => (
                            <Link key={di} to={`/scans/${d.digest}`} className="flex items-center gap-3 text-xs px-3 py-2 rounded bg-bg-tertiary hover:bg-border transition-colors">
                              <code className="text-text-muted font-mono">{truncateDigest(d.digest)}</code>
                              {d.tags && d.tags.length > 0 && <span className="text-text-secondary">{d.tags.join(', ')}</span>}
                              <span className="text-text-muted">{d.packageName} {d.installedVersion}</span>
                              {d.fixedVersion && <span className="text-accent">→ {d.fixedVersion}</span>}
                              <div className="ml-auto flex items-center gap-3 shrink-0">
                                {d.firstSeenAt && d.firstSeenAt !== d.scannedAt && (
                                  <span className="text-text-muted" title={`First seen: ${new Date(d.firstSeenAt * 1000).toLocaleString()}`}>
                                    first seen {formatRelativeTime(d.firstSeenAt)}
                                  </span>
                                )}
                                <span className="text-text-muted" title={`Last scanned: ${new Date(d.scannedAt * 1000).toLocaleString()}`}>
                                  {formatRelativeTime(d.scannedAt)}
                                </span>
                              </div>
                            </Link>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={p => { setPage(p); }} itemLabel="CVEs" />
      </div>
    </div>
  );
}
