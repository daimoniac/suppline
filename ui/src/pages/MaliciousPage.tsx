import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, Navigate, useSearchParams } from 'react-router';
import { ExternalLink, ShieldCheck, Skull, TriangleAlert } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { cn, formatRelativeTime } from '../lib/utils';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { runtimeWorkloadLocations } from '../lib/policyComplianceData';
import {
  activeFindings, feedCommitURL, formatSeconds, groupMaliciousByPackage, maliciousFeedWarning,
} from '../lib/malicious';
import type { MaliciousCoverage, MaliciousFeed, MaliciousImage, MaliciousOverview } from '../lib/api';
import {
  DigestLinkWithCopy, EmptyState, ErrorState, LoadingState, MaliciousCheckBadge, PageHeader,
  RuntimeUsageBadge, StatusBadge,
} from '../components/ui';

type View = 'packages' | 'images';

export default function MaliciousPage() {
  const { apiClient } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [overview, setOverview] = useState<MaliciousOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const view: View = searchParams.get('view') === 'images' ? 'images' : 'packages';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setOverview(await apiClient.getMalicious());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load malicious packages');
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { scheduleEffectLoad(load); }, [load]);

  const images = useMemo(() => overview?.Images ?? [], [overview]);
  const packages = useMemo(() => groupMaliciousByPackage(images), [images]);

  if (overview && !overview.Enabled) return <Navigate to="/" replace />;
  if (loading && !overview) return <LoadingState message="Loading malicious packages…" />;
  if (error && !overview) return <ErrorState message={error} onRetry={load} />;
  if (!overview) return null;

  const feed = overview.Feed;
  const warning = maliciousFeedWarning(feed);
  const affected = images.filter(image => activeFindings(image).length > 0);
  const inUseCount = affected.filter(image => image.RuntimeUsed).length;
  const activePackages = packages.filter(group => !group.exempted).length;
  const exemptedCount = images.length - affected.length;

  const setView = (next: View) => {
    const params = new URLSearchParams(searchParams);
    if (next === 'packages') params.delete('view'); else params.set('view', next);
    setSearchParams(params, { replace: true });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Malicious packages"
        subtitle="Known-malicious language packages (OSV MAL advisories from ossf/malicious-packages) in current images"
        showImageUsage={false}
      />

      {warning && (
        <div className={cn(
          'flex items-start gap-2 rounded-lg border px-3 py-2 text-sm',
          feed?.Status === 'ok' ? 'border-warning/30 bg-warning-bg text-warning' : 'border-danger/30 bg-danger-bg text-danger',
        )}>
          <TriangleAlert className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{warning}</span>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <AffectedSummary images={affected.length} packages={activePackages} inUse={inUseCount} exempted={exemptedCount} block={feed?.Block ?? true} />
        {feed && <FeedCard feed={feed} />}
        <CoverageCard coverage={overview.Coverage} />
      </div>

      <section className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Affected {view === 'packages' ? 'packages' : 'images'}</h2>
            <p className="text-xs text-text-muted mt-1">From each image’s latest scan; images running in a cluster first</p>
          </div>
          <div className="inline-flex rounded-lg border border-border p-0.5 text-xs">
            {(['packages', 'images'] as const).map(option => (
              <button
                key={option}
                type="button"
                onClick={() => setView(option)}
                className={cn(
                  'px-3 py-1 rounded-md transition-colors',
                  view === option ? 'bg-bg-tertiary text-text-primary font-medium' : 'text-text-secondary hover:text-text-primary',
                )}
              >
                By {option === 'packages' ? 'package' : 'image'}
              </button>
            ))}
          </div>
        </div>
        {images.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="w-8 h-8" />}
            title="No malicious packages"
            message="No current image’s latest scan contains a package with a known-malicious advisory."
          />
        ) : view === 'packages' ? (
          <div className="divide-y divide-border">
            {packages.map(group => (
              <div key={group.key} className={cn('px-5 py-4', group.exempted && 'opacity-60')}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-mono font-medium text-text-primary">{group.packageName}@{group.version}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-bg-tertiary text-text-secondary">{group.ecosystem}</span>
                  {group.ids.map(id => <AdvisoryLink key={id} id={id} />)}
                  {group.exempted
                    ? <FalsePositiveBadge />
                    : group.inUse && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-danger-bg text-danger">Running</span>}
                </div>
                {group.summary && <p className="text-xs text-text-muted mt-1">{group.summary}</p>}
                <ul className="mt-3 space-y-2">
                  {group.images.map(image => <li key={`${image.Repository}@${image.Digest}`}><ImageLine image={image} /></li>)}
                </ul>
              </div>
            ))}
          </div>
        ) : (
          <div className="divide-y divide-border">
            {images.map(image => (
              <div key={`${image.Repository}@${image.Digest}`} className={cn('px-5 py-4', activeFindings(image).length === 0 && 'opacity-60')}>
                <ImageLine image={image} />
                <ul className="mt-2 ml-1 space-y-1">
                  {image.Findings.map((finding, i) => (
                    <li key={`${finding.ID}-${finding.PURL}-${i}`} className="flex flex-wrap items-center gap-2 text-xs">
                      <AdvisoryLink id={finding.ID} />
                      <span className="font-mono text-text-primary">{finding.PackageName}@{finding.Version}</span>
                      <span className="text-text-muted">{finding.Ecosystem}</span>
                      {finding.Exempted && <FalsePositiveBadge />}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function AffectedSummary({ images, packages, inUse, exempted, block }: { images: number; packages: number; inUse: number; exempted: number; block: boolean }) {
  return (
    <section className="bg-bg-primary border border-border rounded-xl p-5">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Skull className={cn('w-4 h-4', images > 0 ? 'text-danger' : 'text-text-muted')} />
        Affected
      </div>
      <div className="mt-3 grid grid-cols-3 gap-3 text-center">
        <Stat value={images} label="images" danger={images > 0} />
        <Stat value={inUse} label="running" danger={inUse > 0} />
        <Stat value={packages} label="packages" danger={packages > 0} />
      </div>
      {exempted > 0 && (
        <p className="text-xs text-text-muted mt-3">
          {exempted} more image{exempted === 1 ? '' : 's'} only match advisories marked false_positive in x-vex.
        </p>
      )}
      <p className="text-xs text-text-muted mt-3">
        {block
          ? 'Blocking: any malicious package fails the policy, whatever the policy expression says.'
          : 'Not blocking: x-malicious-packages.block is off, so only the policy expression decides.'}
        {' '}A confirmed false positive is exempted with a hand-written x-vex statement in state false_positive.
      </p>
    </section>
  );
}

function FeedCard({ feed }: { feed: MaliciousFeed }) {
  const commitURL = feedCommitURL(feed.RepoURL, feed.Commit);
  const packages = Object.entries(feed.Packages ?? {}).sort((a, b) => b[1] - a[1]);
  return (
    <section className="bg-bg-primary border border-border rounded-xl p-5">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Feed</h2>
        <FeedStatusBadge status={feed.Status} />
      </div>
      <dl className="mt-3 space-y-1.5 text-xs">
        <Row label="Last sync" value={feed.SyncedAt ? formatRelativeTime(feed.SyncedAt) : 'Never'} />
        <Row
          label="Last attempt"
          value={feed.LastAttemptAt
            ? `${formatRelativeTime(feed.LastAttemptAt)}${feed.LastDurationMs ? ` · ${(feed.LastDurationMs / 1000).toFixed(1)}s` : ''}${feed.LastError ? ' · failed' : ''}`
            : 'Not yet'}
        />
        <Row label="Schedule" value={`every ${formatSeconds(feed.SyncIntervalSeconds)}, stale after ${formatSeconds(feed.StaleAfterSeconds)}`} />
        <Row
          label="Snapshot"
          value={feed.Commit
            ? commitURL
              ? <a href={commitURL} target="_blank" rel="noopener noreferrer" className="font-mono text-accent hover:underline inline-flex items-center gap-1">{feed.Commit.slice(0, 12)} <ExternalLink className="w-3 h-3" /></a>
              : <span className="font-mono">{feed.Commit.slice(0, 12)}</span>
            : '—'}
        />
        <Row label="Source" value={<span className="break-all">{feed.RepoURL}{feed.Ref ? ` (${feed.Ref})` : ''}</span>} />
        <Row label="Advisories" value={feed.Entries.toLocaleString()} />
      </dl>
      {packages.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {packages.map(([ecosystem, count]) => (
            <span key={ecosystem} className="px-1.5 py-0.5 rounded text-[10px] bg-bg-tertiary text-text-secondary">
              {ecosystem} {count.toLocaleString()}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

function CoverageCard({ coverage }: { coverage: MaliciousCoverage }) {
  const total = coverage.OK + coverage.Unavailable + coverage.Stale + coverage.Unchecked;
  const rows: { label: string; value: number; tone: string; hint: string }[] = [
    { label: 'Checked on current data', value: coverage.OK, tone: 'bg-success', hint: '' },
    { label: 'Checked on stale data', value: coverage.Stale, tone: 'bg-warning', hint: 'scanned while the feed was stale' },
    { label: 'Not checked', value: coverage.Unavailable, tone: 'bg-warning', hint: 'scanned before the feed loaded; re-matched once it does' },
    { label: 'Never checked', value: coverage.Unchecked, tone: 'bg-text-muted', hint: 'scanned before the check existed; covered at the next rescan' },
  ];
  return (
    <section className="bg-bg-primary border border-border rounded-xl p-5">
      <h2 className="text-sm font-semibold">Coverage</h2>
      <p className="text-xs text-text-muted mt-1">Latest scan of {total.toLocaleString()} current image{total === 1 ? '' : 's'}</p>
      {total > 0 && (
        <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-bg-tertiary">
          {rows.filter(row => row.value > 0).map(row => (
            <div key={row.label} className={row.tone} style={{ width: `${(row.value / total) * 100}%` }} />
          ))}
        </div>
      )}
      <dl className="mt-3 space-y-1.5 text-xs">
        {rows.map(row => (
          <div key={row.label} className="flex items-start justify-between gap-3" title={row.hint || undefined}>
            <dt className="flex items-center gap-2 text-text-secondary">
              <span className={cn('inline-block h-2 w-2 rounded-full', row.tone)} />
              {row.label}
            </dt>
            <dd className="text-text-primary tabular-nums">{row.value.toLocaleString()}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function ImageLine({ image }: { image: MaliciousImage }) {
  const tags = image.Tags ?? [];
  const locations = runtimeWorkloadLocations(image.Runtime ?? undefined);
  const to = `/repositories/${encodeURIComponent(image.Repository)}/tags/${encodeURIComponent(image.Digest)}`;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Link to={to} className="text-text-primary hover:text-accent">{image.Repository}</Link>
        {tags.length > 0 && <span className="text-xs text-text-secondary">{tags.join(', ')}</span>}
        <DigestLinkWithCopy digest={image.Digest} to={to} />
        <RuntimeUsageBadge inUse={image.RuntimeUsed} runtime={image.Runtime ?? undefined} />
        <StatusBadge passed={image.PolicyPassed} status={image.PolicyStatus} />
        <span className="text-xs text-text-muted">scanned {formatRelativeTime(image.ScannedAt)}</span>
      </div>
      {image.RuntimeUsed && locations.length > 0 && (
        <div className="mt-1 text-xs text-text-muted">
          Running in {locations.map(l => l.workloads.length ? `${l.location} (${l.workloads.join(', ')})` : l.location).join('; ')}
        </div>
      )}
    </div>
  );
}

function AdvisoryLink({ id }: { id: string }) {
  return (
    <a
      href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 font-mono text-xs text-accent hover:underline"
    >
      {id} <ExternalLink className="w-3 h-3" />
    </a>
  );
}

function FeedStatusBadge({ status }: { status: string }) {
  if (status === 'ok') return <MaliciousCheckBadge status="ok" />;
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-danger-bg text-danger">
      {status === 'stale' ? 'Stale' : 'Loading'}
    </span>
  );
}

function Stat({ value, label, danger }: { value: number; label: string; danger: boolean }) {
  return (
    <div className="rounded-lg bg-bg-secondary p-2">
      <div className={cn('text-xl font-bold tabular-nums', danger ? 'text-danger' : 'text-text-primary')}>{value}</div>
      <div className="text-[11px] text-text-muted">{label}</div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="text-text-muted flex-shrink-0">{label}</dt>
      <dd className="text-text-secondary text-right min-w-0">{value}</dd>
    </div>
  );
}

function FalsePositiveBadge() {
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-bg-tertiary text-text-secondary"
      title="Exempted by a false_positive x-vex statement"
    >
      False positive
    </span>
  );
}
