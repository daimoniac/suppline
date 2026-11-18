import { Link } from 'react-router';
import { PolicyAgentPromptCard } from './PolicyAgentPromptCard';
import { PolicyDescriptionText } from './ui';
import type { PolicyInfo, Scan } from '../lib/api';
import { runtimeWorkloadLocations, supersededRunningLabel } from '../lib/policyComplianceData';
import { truncateDigest } from '../lib/utils';

const TOP_POLICY_DISPLAY_COUNT = 5;

export function PolicyCompliancePanel({
  policyByRepo,
  failedScans,
  defaultPolicy,
  showCardHeading = true,
  embedded = false,
  onTriageQueued,
}: {
  policyByRepo: Record<string, { failed: number; pending: number }>;
  failedScans: Scan[];
  /** Default policy from config; rendered under the heading when configured. */
  defaultPolicy?: PolicyInfo | null;
  /** When false, the main heading is omitted (e.g. parent TaskSection already provides a title). */
  showCardHeading?: boolean;
  /** When true, skip the outer card shell (e.g. inside TaskSection which is already a card). */
  embedded?: boolean;
  onTriageQueued?: () => void;
}) {
  const topPolicyRepos = Object.entries(policyByRepo)
    .sort((a, b) => (b[1].failed + b[1].pending) - (a[1].failed + a[1].pending))
    .slice(0, TOP_POLICY_DISPLAY_COUNT);
  const totalPolicyRepos = Object.keys(policyByRepo).length;
  const hasMorePolicyRepos = totalPolicyRepos > TOP_POLICY_DISPLAY_COUNT;
  const hasVisibleFailures = failedScans.some(scan => scan.PolicyStatus !== 'pending');
  const supersededRunning = failedScans.filter(scan => scan.Superseded);
  // A superseded digest is fixed by rolling its pods, not by triaging its CVEs.
  const triageScans = failedScans.filter(scan => !scan.Superseded);
  const heading = showCardHeading || defaultPolicy ? (
    <div className={hasVisibleFailures ? '' : 'mb-4'}>
      {showCardHeading && <h2 className="text-sm font-semibold">Policy Compliance Status</h2>}
      <PolicyDescriptionText
        description={defaultPolicy?.Description}
        expression={defaultPolicy?.Expression}
        label="Default policy gate"
        className="mt-1"
      />
    </div>
  ) : null;

  const repoSection =
    Object.keys(policyByRepo).length === 0 ? (
      <div className={`text-center ${hasVisibleFailures ? 'py-6' : 'py-8'}`}>
        <div className="text-3xl mb-2">🎆</div>
        <h3 className="font-semibold text-accent">All Compliant</h3>
        <p className="text-sm text-text-secondary">All images pass policy evaluation</p>
      </div>
    ) : (
      <PolicyRepoBarsList
        policyByRepo={policyByRepo}
        topPolicyRepos={topPolicyRepos}
        hasMorePolicyRepos={hasMorePolicyRepos}
        totalPolicyRepos={totalPolicyRepos}
      />
    );

  const body = hasVisibleFailures ? (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
      <div className="lg:col-span-2 space-y-3 min-w-0">
        {heading}
        {repoSection}
        <SupersededRunningList scans={supersededRunning} />
      </div>
      <PolicyAgentPromptCard scans={triageScans} onTriageQueued={onTriageQueued} />
    </div>
  ) : (
    <>
      {heading}
      {repoSection}
    </>
  );

  if (embedded) {
    return <div className="min-w-0">{body}</div>;
  }

  return (
    <div className="bg-bg-primary border border-border rounded-xl p-5">
      {body}
    </div>
  );
}

function PolicyRepoBarsList({
  policyByRepo,
  topPolicyRepos,
  hasMorePolicyRepos,
  totalPolicyRepos,
}: {
  policyByRepo: Record<string, { failed: number; pending: number }>;
  topPolicyRepos: [string, { failed: number; pending: number }][];
  hasMorePolicyRepos: boolean;
  totalPolicyRepos: number;
}) {
  const max = Math.max(...Object.values(policyByRepo).map(v => v.failed + v.pending), 0);
  return (
    <div className="space-y-2">
      {topPolicyRepos.map(([repo, counts]) => {
        const total = counts.failed + counts.pending;
        const failedWidth = total > 0 ? (counts.failed / total) * 100 : 0;
        const pendingWidth = total > 0 ? (counts.pending / total) * 100 : 0;
        return (
          <Link key={repo} to={`/repositories/${encodeURIComponent(repo)}`} className="flex items-center gap-3 hover:bg-bg-secondary rounded px-2 py-1 transition-colors">
            <span className="text-sm text-text-primary truncate w-48 flex-shrink-0">{repo}</span>
            <div className="flex-1 h-2 bg-bg-tertiary rounded-full overflow-hidden">
              <div className="h-full flex transition-all" style={{ width: `${max > 0 ? (total / max) * 100 : 0}%` }}>
                {counts.failed > 0 && <div className="h-full bg-danger" style={{ width: `${failedWidth}%` }} />}
                {counts.pending > 0 && <div className="h-full bg-warning" style={{ width: `${pendingWidth}%` }} />}
              </div>
            </div>
            <span className="text-xs font-medium text-text-secondary w-20 text-right">
              F {counts.failed} / P {counts.pending}
            </span>
          </Link>
        );
      })}
      {hasMorePolicyRepos && (
        <p className="text-xs text-text-secondary pt-1">
          Showing top {TOP_POLICY_DISPLAY_COUNT} of {totalPolicyRepos} repositories with policy issues.{' '}
          <Link to="/failed" className="text-accent hover:text-accent-hover hover:underline">
            View all on Policy Exceptions
          </Link>
        </p>
      )}
    </div>
  );
}

export function SupersededRunningList({ scans }: { scans: Scan[] }) {
  if (scans.length === 0) return null;
  return (
    <div className="rounded-lg border border-danger/30 bg-danger-bg/10 p-3 space-y-2">
      <div>
        <h3 className="text-xs font-semibold text-text-primary">Pods running a superseded digest</h3>
        <p className="text-xs text-text-secondary">
          These tags now point at a newer digest, but clusters still run the old, failing one. Restart the workloads below so their pods pull the current digest.
        </p>
        <p className="text-xs text-text-secondary mt-1">
          A restart alone is not enough with <code>imagePullPolicy: IfNotPresent</code>: a node that cached the old digest starts the new pod from it again. Set <code>imagePullPolicy: Always</code> or pin the image by digest first.
        </p>
      </div>
      <ul className="space-y-1">
        {scans.map(scan => (
          <li key={`${scan.Repository}:${scan.Tag}:${scan.Digest}`} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
            <Link to={`/scans/${encodeURIComponent(scan.Digest)}`} className="text-accent hover:underline font-medium">
              {scan.Repository}
            </Link>
            <span className="text-text-secondary">{supersededRunningLabel(scan)}</span>
            <code className="text-text-muted" title={scan.Digest}>{truncateDigest(scan.Digest)}</code>
            {runtimeWorkloadLocations(scan.Runtime).map(({ location, workloads }) => (
              <span key={location} className="text-text-muted">
                on {location}
                {workloads.length > 0 && (
                  <>: {workloads.map(workload => <code key={workload} className="ml-1 text-text-primary">{workload}</code>)}</>
                )}
              </span>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
}
