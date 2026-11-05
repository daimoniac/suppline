import { useCallback, useEffect, useState } from 'react';
import { Navigate, useSearchParams } from 'react-router';
import { useAuth } from '../lib/auth';
import { formatRelativeTime } from '../lib/utils';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { usePageSizePreference } from '../lib/pageSizePreference';
import { EmptyState, ErrorState, LoadingState, PageHeader, Pagination } from '../components/ui';
import type { MirrorDeletion, MirrorImage, MirrorOverview, MirrorSync } from '../lib/api';
import { FolderSync, TriangleAlert } from 'lucide-react';

export default function MirrorPage() {
  const { apiClient } = useAuth();
  const { pageSize, setPageSize, options: pageSizeOptions } = usePageSizePreference();
  const [searchParams, setSearchParams] = useSearchParams();
  const [mirrorEnabled, setMirrorEnabled] = useState<boolean | null>(null);
  const [overview, setOverview] = useState<MirrorOverview | null>(null);
  const [images, setImages] = useState<MirrorImage[]>([]);
  const [imageTotal, setImageTotal] = useState(0);
  const [deletions, setDeletions] = useState<MirrorDeletion[]>([]);
  const [deletionTotal, setDeletionTotal] = useState(0);
  const [hubDeletions, setHubDeletions] = useState<MirrorDeletion[]>([]);
  const [hubTotal, setHubTotal] = useState(0);
  const [imagePage, setImagePage] = useState(1);
  const [deletionPage, setDeletionPage] = useState(1);
  const [hubPage, setHubPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const selectedKey = searchParams.get('sync') || '';

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const health = await apiClient.getHealth();
      if (!health.mirrorEnabled) {
        setMirrorEnabled(false);
        setLoading(false);
        return;
      }
      setMirrorEnabled(true);
      const [summary, hub] = await Promise.all([
        apiClient.getMirror(),
        apiClient.getMirrorHubDeletions(pageSize, (hubPage - 1) * pageSize),
      ]);
      const syncs = summary.Syncs ?? [];
      const key = syncs.some(sync => sync.Key === selectedKey) ? selectedKey : (syncs[0]?.Key ?? '');
      let nextImages: MirrorImage[] = [];
      let nextImageTotal = 0;
      let nextDeletions: MirrorDeletion[] = [];
      let nextDeletionTotal = 0;
      if (key) {
        const [imagePageResult, deletionPageResult] = await Promise.all([
          apiClient.getMirrorImages(key, pageSize, (imagePage - 1) * pageSize),
          apiClient.getMirrorTagDeletions(key, pageSize, (deletionPage - 1) * pageSize),
        ]);
        nextImages = imagePageResult.images;
        nextImageTotal = imagePageResult.total;
        nextDeletions = deletionPageResult.deletions;
        nextDeletionTotal = deletionPageResult.total;
      }
      setOverview(summary);
      setHubDeletions(hub.deletions);
      setHubTotal(hub.total);
      setImages(nextImages);
      setImageTotal(nextImageTotal);
      setDeletions(nextDeletions);
      setDeletionTotal(nextDeletionTotal);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load mirror');
    } finally {
      setLoading(false);
    }
  }, [apiClient, deletionPage, hubPage, imagePage, pageSize, selectedKey]);

  useEffect(() => { scheduleEffectLoad(load); }, [load]);

  if (mirrorEnabled === false) return <Navigate to="/" replace />;
  if (loading && !overview) return <LoadingState message="Loading mirror…" />;
  if (error && !overview) return <ErrorState message={error} onRetry={load} />;

  const syncs = overview?.Syncs ?? [];
  const selected = syncs.find(sync => sync.Key === selectedKey) ?? syncs[0];

  const selectSync = (key: string) => {
    setImagePage(1);
    setDeletionPage(1);
    const next = new URLSearchParams(searchParams);
    next.set('sync', key);
    setSearchParams(next);
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Mirror" subtitle="In-process registry sync health" showImageUsage={false} />

      {overview?.HubError && (
        <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger-bg px-3 py-2 text-sm text-danger">
          <TriangleAlert className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>Docker Hub repository cleanup failed: {overview.HubError}</span>
        </div>
      )}

      <section className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold">Syncs</h2>
          <p className="text-xs text-text-muted mt-1">One row per entry in suppline.yml</p>
        </div>
        {syncs.length === 0 ? (
          <EmptyState icon={<FolderSync className="w-8 h-8" />} title="No syncs" message="suppline.yml has no sync entries." />
        ) : (
          <div className="divide-y divide-border">
            {syncs.map(sync => (
              <button
                key={sync.Key}
                type="button"
                onClick={() => selectSync(sync.Key)}
                className={`w-full text-left px-5 py-3 transition-colors hover:bg-bg-secondary ${selected?.Key === sync.Key ? 'bg-bg-secondary' : ''}`}
              >
                <SyncRow sync={sync} />
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold">Docker Hub repository deletions</h2>
          <p className="text-xs text-text-muted mt-1">Kept for 7 days, or until the repository is mirrored again</p>
        </div>
        {hubDeletions.length === 0 ? (
          <EmptyState icon={<FolderSync className="w-8 h-8" />} title="No repository deletions" message="cleanupRepos has not removed a Docker Hub repository in the last 7 days." />
        ) : (
          <DeletionTable rows={hubDeletions} showTag={false} />
        )}
        <Pagination
          currentPage={hubPage}
          totalPages={Math.max(1, Math.ceil(hubTotal / pageSize))}
          total={hubTotal}
          pageSize={pageSize}
          onPageChange={setHubPage}
          onPageSizeChange={size => { setPageSize(size); setHubPage(1); setImagePage(1); setDeletionPage(1); }}
          pageSizeOptions={pageSizeOptions}
          itemLabel="repositories"
        />
      </section>

      {selected && (
        <>
          <section className="bg-bg-primary border border-border rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-border">
              <h2 className="text-sm font-semibold">Mirrored images</h2>
              <p className="text-xs text-text-muted mt-1">{selected.Source} → {selected.Target}</p>
            </div>
            {images.length === 0 ? (
              <EmptyState icon={<FolderSync className="w-8 h-8" />} title="No images yet" message="This sync has not recorded a wanted tag on the target." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-xs text-text-muted">
                    <tr className="border-b border-border">
                      <th className="px-5 py-2 font-medium">Repository</th>
                      <th className="px-5 py-2 font-medium">Tag</th>
                      <th className="px-5 py-2 font-medium">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {images.map(image => (
                      <tr key={`${image.Repository}:${image.Tag}`} className="border-b border-border last:border-0">
                        <td className="px-5 py-2 text-text-primary">{image.Repository}</td>
                        <td className="px-5 py-2 text-text-secondary">{image.Tag}</td>
                        <td className="px-5 py-2 text-text-muted">{formatRelativeTime(image.LastSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pagination
              currentPage={imagePage}
              totalPages={Math.max(1, Math.ceil(imageTotal / pageSize))}
              total={imageTotal}
              pageSize={pageSize}
              onPageChange={setImagePage}
              onPageSizeChange={size => { setPageSize(size); setImagePage(1); setDeletionPage(1); setHubPage(1); }}
              pageSizeOptions={pageSizeOptions}
              itemLabel="images"
            />
          </section>

          <section className="bg-bg-primary border border-border rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-border">
              <h2 className="text-sm font-semibold">Tag deletions</h2>
              <p className="text-xs text-text-muted mt-1">Tags cleanup removed from this sync’s target</p>
            </div>
            {deletions.length === 0 ? (
              <EmptyState icon={<FolderSync className="w-8 h-8" />} title="No tag deletions" message="No tags removed by cleanup are still listed for this sync." />
            ) : (
              <DeletionTable rows={deletions} showTag />
            )}
            <Pagination
              currentPage={deletionPage}
              totalPages={Math.max(1, Math.ceil(deletionTotal / pageSize))}
              total={deletionTotal}
              pageSize={pageSize}
              onPageChange={setDeletionPage}
              onPageSizeChange={size => { setPageSize(size); setDeletionPage(1); setImagePage(1); setHubPage(1); }}
              pageSizeOptions={pageSizeOptions}
              itemLabel="deletions"
            />
          </section>
        </>
      )}
    </div>
  );
}

function SyncRow({ sync }: { sync: MirrorSync }) {
  return (
    <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-text-primary truncate">{sync.Source}</span>
          <span className="text-xs text-text-muted">→</span>
          <span className="text-sm text-text-secondary truncate">{sync.Target}</span>
          <span className="px-2 py-0.5 rounded text-xs bg-bg-tertiary text-text-secondary">{sync.Type}</span>
        </div>
        <div className="mt-1 text-xs text-text-muted">
          {sync.Schedule || 'No schedule'}
          {sync.FinishedAt ? ` · finished ${formatRelativeTime(sync.FinishedAt)}` : ''}
          {sync.Status === 'failed' && sync.Error ? ` · ${sync.Error}` : ''}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill status={sync.Status} />
        <span className="text-xs text-text-secondary">{sync.ImageCount.toLocaleString()} images</span>
        <span className="text-xs text-text-secondary">{sync.TagDeletionCount.toLocaleString()} deletions</span>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    running: 'bg-info/15 text-info',
    ok: 'bg-success-bg text-success',
    failed: 'bg-danger-bg text-danger',
    never: 'bg-bg-tertiary text-text-secondary',
  };
  const label = status === 'ok' ? 'Ok' : status.charAt(0).toUpperCase() + status.slice(1);
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${styles[status] || styles.never}`}>{label}</span>;
}

function DeletionTable({ rows, showTag }: { rows: MirrorDeletion[]; showTag: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-text-muted">
          <tr className="border-b border-border">
            <th className="px-5 py-2 font-medium">Repository</th>
            {showTag && <th className="px-5 py-2 font-medium">Tag</th>}
            <th className="px-5 py-2 font-medium">Deleted</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(row => (
            <tr key={`${row.Repository}:${row.Tag}:${row.DeletedAt}`} className="border-b border-border last:border-0">
              <td className="px-5 py-2 text-text-primary">{row.Repository}</td>
              {showTag && <td className="px-5 py-2 text-text-secondary">{row.Tag}</td>}
              <td className="px-5 py-2 text-text-muted">{formatRelativeTime(row.DeletedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
