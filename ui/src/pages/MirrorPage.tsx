import { useCallback, useEffect, useState } from 'react';
import { Navigate, useSearchParams } from 'react-router';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatCooldown, formatDate, formatRelativeTime } from '../lib/utils';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { usePageSizePreference } from '../lib/pageSizePreference';
import { ConfirmModal, DigestLinkWithCopy, EmptyState, ErrorState, LoadingState, PageHeader, Pagination, StatusBadge, RepoName } from '../components/ui';
import type { HeldDigest, MirrorDeletion, MirrorImage, MirrorOverview, MirrorSync } from '../lib/api';
import { Clock, FolderSync, TriangleAlert } from 'lucide-react';

export default function MirrorPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
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
  const [held, setHeld] = useState<HeldDigest[]>([]);
  const [releaseTarget, setReleaseTarget] = useState<HeldDigest | null>(null);
  const [releaseReason, setReleaseReason] = useState('');
  const [releasing, setReleasing] = useState(false);
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
      const [summary, hub, heldDigests] = await Promise.all([
        apiClient.getMirror(),
        apiClient.getMirrorHubDeletions(pageSize, (hubPage - 1) * pageSize),
        apiClient.getHeldDigests(),
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
      setHeld(heldDigests);
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

  const confirmRelease = async () => {
    if (!releaseTarget || !releaseReason.trim()) return;
    setReleasing(true);
    try {
      const result = await apiClient.releaseCooldown(releaseTarget.Repository, releaseTarget.Digest, releaseReason.trim());
      toast(result.commit ? `Released; committed ${result.commit.slice(0, 7)}. The tag moves after a passing scan.` : 'Released. The tag moves after a passing scan.', 'success');
      setReleaseTarget(null);
      setReleaseReason('');
      await load();
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to release digest', 'error');
    } finally {
      setReleasing(false);
    }
  };

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
          <h2 className="text-sm font-semibold">Held</h2>
          <p className="text-xs text-text-muted mt-1">New images from upstream that are held back for the configured cooldown period.</p>
        </div>
        {held.length === 0 ? (
          <EmptyState icon={<Clock className="w-8 h-8" />} title="Nothing held" message="No images are being held back." />
        ) : (
          <HeldTable rows={held} onRelease={row => { setReleaseTarget(row); setReleaseReason(''); }} />
        )}
      </section>

      <ConfirmModal
        open={releaseTarget !== null}
        title="Release from cooldown"
        message={releaseTarget ? `Skip the rest of the cooldown of ${releaseTarget.Digest.slice(0, 19)}… in ${releaseTarget.Repository}. This is recorded in suppline.yml. The tag still moves only after a passing scan and attestation.` : ''}
        confirmLabel={releasing ? 'Releasing…' : 'Release now'}
        confirmDisabled={releasing || !releaseReason.trim()}
        onConfirm={confirmRelease}
        onCancel={() => { if (!releasing) setReleaseTarget(null); }}
      >
        <label className="block text-xs text-text-secondary mb-1" htmlFor="release-reason">Reason</label>
        <input
          id="release-reason"
          value={releaseReason}
          onChange={e => setReleaseReason(e.target.value)}
          placeholder="e.g. CVE-2026-1234 hotfix"
          className="w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50"
        />
      </ConfirmModal>

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
                        <td className="px-5 py-2 text-text-primary"><RepoName repo={image.Repository} /></td>
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
          <RepoName repo={sync.Source} truncate="end" className="text-sm font-semibold text-text-primary" />
          <span className="text-xs text-text-muted">→</span>
          <RepoName repo={sync.Target} truncate="end" className="text-sm text-text-secondary" />
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
              <td className="px-5 py-2 text-text-primary"><RepoName repo={row.Repository} /></td>
              {showTag && <td className="px-5 py-2 text-text-secondary">{row.Tag}</td>}
              <td className="px-5 py-2 text-text-muted">{formatRelativeTime(row.DeletedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HeldTable({ rows, onRelease }: { rows: HeldDigest[]; onRelease: (row: HeldDigest) => void }) {
  return (
    <>
      {/* Below xl the seven columns don't fit next to the sidebar: one card per held digest, no sideways scrolling. */}
      <ul className="xl:hidden divide-y divide-border">
        {rows.map(row => (
          <li key={`${row.Repository}@${row.Digest}`} className="px-4 py-3 space-y-2">
            <div className="min-w-0">
              <div className="text-sm text-text-primary"><RepoName repo={row.Repository} /></div>
              {row.Source && <div className="text-xs text-text-muted">from <RepoName repo={row.Source} /></div>}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span className="text-text-secondary wrap-anywhere">{(row.Tags ?? []).join(', ')}</span>
              <DigestLinkWithCopy digest={row.Digest} to={heldDigestLink(row)} />
            </div>
            <dl className="grid grid-cols-3 gap-2 text-xs">
              <div>
                <dt className="text-text-muted">First seen</dt>
                <dd className="text-text-secondary" title={formatDate(row.FirstSeen)}>{formatRelativeTime(row.FirstSeen)}</dd>
              </div>
              <div>
                <dt className="text-text-muted">Cooldown</dt>
                <dd><CooldownCell row={row} /></dd>
              </div>
              <div>
                <dt className="text-text-muted">Scan</dt>
                <dd><ScanCell row={row} /></dd>
              </div>
            </dl>
            {canRelease(row) && (
              <button
                type="button"
                onClick={() => onRelease(row)}
                className="w-full px-3 py-2 text-xs rounded border border-warning/30 text-warning hover:bg-warning-bg transition-colors"
              >
                Release now
              </button>
            )}
          </li>
        ))}
      </ul>

      <div className="hidden xl:block overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-text-muted">
            <tr className="border-b border-border">
              <th className="px-5 py-2 font-medium">Repository</th>
              <th className="px-5 py-2 font-medium min-w-32">Tags</th>
              <th className="px-5 py-2 font-medium">Digest</th>
              <th className="px-5 py-2 font-medium">First seen</th>
              <th className="px-5 py-2 font-medium">Cooldown</th>
              <th className="px-5 py-2 font-medium">Scan</th>
              <th className="px-5 py-2 font-medium" />
            </tr>
          </thead>
          <tbody>
            {rows.map(row => (
              <tr key={`${row.Repository}@${row.Digest}`} className="border-b border-border last:border-0 align-top">
                <td className="px-5 py-2 text-text-primary">
                  <div><RepoName repo={row.Repository} /></div>
                  {row.Source && <div className="text-xs text-text-muted">from <RepoName repo={row.Source} /></div>}
                </td>
                <td className="px-5 py-2 text-text-secondary wrap-anywhere">{(row.Tags ?? []).join(', ')}</td>
                <td className="px-5 py-2"><DigestLinkWithCopy digest={row.Digest} to={heldDigestLink(row)} /></td>
                <td className="px-5 py-2 text-text-muted whitespace-nowrap" title={formatDate(row.FirstSeen)}>{formatRelativeTime(row.FirstSeen)}</td>
                <td className="px-5 py-2"><CooldownCell row={row} /></td>
                <td className="px-5 py-2"><ScanCell row={row} /></td>
                <td className="px-5 py-2 text-right">
                  {canRelease(row) && (
                    <button
                      type="button"
                      onClick={() => onRelease(row)}
                      className="px-3 py-1 text-xs rounded border border-warning/30 text-warning hover:bg-warning-bg whitespace-nowrap transition-colors"
                    >
                      Release now
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function heldDigestLink(row: HeldDigest): string {
  return `/repositories/${encodeURIComponent(row.Repository)}/tags/${encodeURIComponent(row.Digest)}`;
}

function canRelease(row: HeldDigest): boolean {
  return row.CooldownSeconds > 0 && !row.Released && row.RemainingSeconds > 0;
}

function ScanCell({ row }: { row: HeldDigest }) {
  if (!row.PolicyStatus) return <span className="text-xs text-text-muted">Not scanned yet</span>;
  return (
    <div className="flex flex-col items-start gap-1">
      <StatusBadge passed={row.PolicyStatus === 'passed'} status={row.PolicyStatus} label={row.PolicyStatus === 'pending' ? 'Held' : undefined} />
      {row.ScannedAt ? <span className="text-xs text-text-muted">{formatRelativeTime(row.ScannedAt)}</span> : null}
    </div>
  );
}

function CooldownCell({ row }: { row: HeldDigest }) {
  if (row.Released) return <span className="text-xs font-medium text-info">Released</span>;
  if (row.CooldownSeconds <= 0) return <span className="text-xs text-text-muted">None</span>;
  if (row.RemainingSeconds <= 0) return <span className="text-xs text-text-secondary">Over</span>;
  return (
    <span className="text-xs font-medium text-warning" title={`Cooldown ${formatCooldown(row.CooldownSeconds)}`}>
      {formatCooldown(row.RemainingSeconds)} left
    </span>
  );
}
