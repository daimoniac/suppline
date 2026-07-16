import { Link } from 'react-router-dom';
import { PolicyAgentPromptCard } from './PolicyAgentPromptCard';
import type { Scan } from '../lib/api';

const TOP_POLICY_DISPLAY_COUNT = 5;

export function PolicyCompliancePanel({
  policyByRepo,
  failedScans,
  showCardHeading = true,
  embedded = false,
}: {
  policyByRepo: Record<string, { failed: number; pending: number }>;
  failedScans: Scan[];
  /** When false, the main heading is omitted (e.g. parent TaskSection already provides a title). */
  showCardHeading?: boolean;
  /** When true, skip the outer card shell (e.g. inside TaskSection which is already a card). */
  embedded?: boolean;
}) {
  const topPolicyRepos = Object.entries(policyByRepo)
    .sort((a, b) => (b[1].failed + b[1].pending) - (a[1].failed + a[1].pending))
    .slice(0, TOP_POLICY_DISPLAY_COUNT);
  const totalPolicyRepos = Object.keys(policyByRepo).length;
  const hasMorePolicyRepos = totalPolicyRepos > TOP_POLICY_DISPLAY_COUNT;
  const hasVisibleFailures = failedScans.some(scan => scan.PolicyStatus !== 'pending');
  const heading = showCardHeading ? (
    <h2 className={`text-sm font-semibold${hasVisibleFailures ? '' : ' mb-4'}`}>Policy Compliance Status</h2>
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
      </div>
      <PolicyAgentPromptCard scans={failedScans} />
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
