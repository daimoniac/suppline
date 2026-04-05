import { useEffect, useState, useCallback, useMemo } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, daysUntilReleaseAge, formatRemainingDays } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, StatusBadge, VulnCounts, SortHeader, Pagination, ConfirmModal } from '../components/ui';
import type { RepositoryTag } from '../lib/api';
import { ArrowLeft, RefreshCw } from 'lucide-react';
import { useSortablePaginationState } from '../lib/useSortablePaginationState';
import { RuntimeUsageBadge } from '../components/RuntimeUsageBadge';
import { PageFiltersBar, FilterActionButton } from '../components/PageFiltersBar';

export default function RepositoryDetailPage() {
  const { name } = useParams<{ name: string }>();
  const decodedName = decodeURIComponent(name || '');
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const { inUseQuery } = useImageUsageFilter();
  const [searchParams] = useSearchParams();

  const [allTags, setAllTags] = useState<RepositoryTag[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const pageSize = 10;
  const [confirmRescan, setConfirmRescan] = useState<{ type: 'repo' | 'tag'; name: string } | null>(null);

  const { sortColumn: sortCol, sortDirection: sortDir, toggleSort, page, setPage, totalPages } = useSortablePaginationState({
    initialSortColumn: 'name',
    initialSortDirection: 'asc',
    resolveNewColumnDirection: () => 'asc',
    pageSize,
    totalItems: total,
  });

  const load = useCallback(async () => {
    if (!decodedName) return;
    setLoading(true);
    setError('');
    try {
      const fetchSize = 200;
      let offset = 0;
      let expectedTotal = 0;
      const collected: RepositoryTag[] = [];

      do {
        const resp = await apiClient.getRepository(decodedName, {
          limit: fetchSize,
          offset,
          ...(search && { search }),
          ...(inUseQuery !== undefined && { in_use: inUseQuery }),
        });
        const pageTags = resp?.Tags || [];
        expectedTotal = resp?.Total || 0;
        collected.push(...pageTags);
        offset += pageTags.length;

        if (pageTags.length === 0) break;
      } while (offset < expectedTotal);

      setAllTags(collected);
      setTotal(expectedTotal || collected.length);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [apiClient, decodedName, inUseQuery, search]);

  const sortedTags = useMemo(() => {
    const colMap: Record<string, keyof RepositoryTag> = {
      name: 'Name',
      lastScanTime: 'LastScanTime',
      status: 'PolicyPassed',
    };
    const apiCol = colMap[sortCol] || 'Name';
    return [...allTags].sort((a, b) => {
      const av = a[apiCol as keyof RepositoryTag] as unknown;
      const bv = b[apiCol as keyof RepositoryTag] as unknown;
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
  }, [allTags, sortCol, sortDir]);

  const tags = useMemo(() => {
    const start = (page - 1) * pageSize;
    return sortedTags.slice(start, start + pageSize);
  }, [sortedTags, page]);

  useEffect(() => { load(); }, [load]);

  const handleSort = (col: string) => {
    toggleSort(col);
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

  if (loading && tags.length === 0 && !search) return <LoadingState />;
  // A search-triggered error (e.g. no matches -> 404) should not hijack the whole page.
  if (error && !search) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <Link to="/repositories" className="p-2 rounded-lg border border-border hover:bg-bg-tertiary transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{decodedName}</h1>
          <p className="text-sm text-text-secondary">{total} tag{total !== 1 ? 's' : ''}</p>
        </div>
        <button onClick={() => setConfirmRescan({ type: 'repo', name: decodedName })} className="px-4 py-2 text-sm rounded-lg border border-warning/30 text-warning hover:bg-warning-bg flex items-center gap-2 transition-colors">
          <RefreshCw className="w-4 h-4" /> Rescan All
        </button>
      </div>

      <PageFiltersBar>
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setError(''); }}
          onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(); } }}
          placeholder="Filter tags..."
          className="flex-1 max-w-xs px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50 transition-colors"
        />
        <FilterActionButton onClick={() => { setPage(1); load(); }}>Filter</FilterActionButton>
      </PageFiltersBar>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        {tags.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">
            {search ? (
              <>
                <p className="mb-3">No tags matching &ldquo;{search}&rdquo;</p>
                <button onClick={() => { setSearch(''); setError(''); setPage(1); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Clear search</button>
              </>
            ) : error ? (
              <>
                <p className="mb-3">{error}</p>
                <button onClick={() => { setError(''); load(); }} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Retry</button>
              </>
            ) : 'No tags found'}
          </div>
        ) : (
          <div className="overflow-x-auto"><table className="w-full"><thead><tr className="border-b border-border">
            <SortHeader column="name" label="Tag" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <SortHeader column="lastScanTime" label="Last Scan" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
            <SortHeader column="status" label="Status" sortColumn={sortCol} sortDirection={sortDir} onSort={handleSort} />
            <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Action</th>
          </tr></thead><tbody>
            {tags.map(tag => {
              const isPending = tag.PolicyStatus === 'pending';
              return (
                <tr key={tag.Name} className="border-b border-border/50 hover:bg-bg-secondary transition-colors">
                  <td className="px-4 py-3 text-sm text-accent">
                    {tag.Digest ? (
                      <Link className="hover:underline" to={`/repositories/${encodeURIComponent(decodedName)}/tags/${encodeURIComponent(tag.Digest)}`}>{tag.Name}</Link>
                    ) : (
                      <span>{tag.Name}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">{tag.LastScanTime ? formatRelativeTime(tag.LastScanTime) : 'Never'}</td>
                  <td className="px-4 py-3"><VulnCounts critical={tag.VulnerabilityCount?.Critical} high={tag.VulnerabilityCount?.High} medium={tag.VulnerabilityCount?.Medium} low={tag.VulnerabilityCount?.Low} tolerated={tag.VulnerabilityCount?.Tolerated} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      {tag.ScanError ? <span className="text-xs text-danger" title={tag.ScanError}>Error</span> : <StatusBadge passed={tag.PolicyPassed} status={tag.PolicyStatus} />}
                      {isPending && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-warning-bg text-warning" title="Image is maturing and will be eligible based on release age">
                          {formatRemainingDays(daysUntilReleaseAge(tag.ReleaseAgeSeconds, tag.MinimumReleaseAgeSeconds))}
                        </span>
                      )}
                      <RuntimeUsageBadge inUse={!!tag.RuntimeUsed} clusters={tag.RuntimeClusters} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => setConfirmRescan({ type: 'tag', name: tag.Name })} className="px-3 py-1 text-xs rounded border border-warning/30 text-warning hover:bg-warning-bg flex items-center gap-1 transition-colors">
                      <RefreshCw className="w-3 h-3" /> Rescan
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody></table></div>
        )}
        <Pagination currentPage={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={setPage} itemLabel="tags" />
      </div>

      <ConfirmModal
        open={!!confirmRescan}
        title={`Rescan ${confirmRescan?.type === 'repo' ? 'Repository' : 'Tag'}`}
        message={confirmRescan?.type === 'repo' ? `Rescan all images in "${decodedName}"?` : `Rescan tag "${confirmRescan?.name}" in "${decodedName}"?`}
        onConfirm={() => confirmRescan && handleRescan(confirmRescan.type, confirmRescan.name)}
        onCancel={() => setConfirmRescan(null)}
      />
    </div>
  );
}
