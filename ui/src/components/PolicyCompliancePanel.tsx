import { Link } from 'react-router-dom';
import { useToast } from '../lib/toast';
import { copyToClipboard } from '../lib/utils';
import { buildPolicyFixPrompt, buildPolicyFixPromptRows } from '../lib/policyComplianceData';
import type { Scan } from '../lib/api';
import { Copy, Sparkles } from 'lucide-react';

const PROMPT_HINT = 'Copy a prompt to triage visible CEL policy failures with your coding agent.';

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
  const { toast } = useToast();
  const topPolicyRepos = Object.entries(policyByRepo)
    .sort((a, b) => (b[1].failed + b[1].pending) - (a[1].failed + a[1].pending))
    .slice(0, 5);
  const visibleRepoSet = new Set(topPolicyRepos.map(([repo]) => repo));
  const visibleFailures = failedScans.filter(scan => visibleRepoSet.has(scan.Repository || 'unknown') && scan.PolicyStatus !== 'pending');
  const promptRows = buildPolicyFixPromptRows(visibleFailures);
  const policyFixPrompt = buildPolicyFixPrompt(promptRows);
  const hasVisibleFailures = visibleFailures.length > 0;

  const body = (
    <>
      {hasVisibleFailures ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
          <div className="lg:col-span-2 space-y-3 min-w-0">
            {showCardHeading && <h2 className="text-sm font-semibold">Policy Compliance Status</h2>}
            {Object.keys(policyByRepo).length === 0 ? (
              <div className="text-center py-6">
                <div className="text-3xl mb-2">🎆</div>
                <h3 className="font-semibold text-accent">All Compliant</h3>
                <p className="text-sm text-text-secondary">All images pass policy evaluation</p>
              </div>
            ) : (
              <PolicyRepoBarsList policyByRepo={policyByRepo} topPolicyRepos={topPolicyRepos} />
            )}
          </div>
          <PolicyFixPromptCard
            hint={PROMPT_HINT}
            onCopy={() => {
              if (!policyFixPrompt) {
                toast('No CEL policy failure findings available yet for these images. Re-scan to populate actionable findings.', 'warning');
                return;
              }
              copyToClipboard(policyFixPrompt).then(ok =>
                toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
              );
            }}
          />
        </div>
      ) : (
        <>
          {showCardHeading && <h2 className="text-sm font-semibold mb-4">Policy Compliance Status</h2>}
          {Object.keys(policyByRepo).length === 0 ? (
            <div className="text-center py-8">
              <div className="text-3xl mb-2">🎆</div>
              <h3 className="font-semibold text-accent">All Compliant</h3>
              <p className="text-sm text-text-secondary">All images pass policy evaluation</p>
            </div>
          ) : (
            <PolicyRepoBarsList policyByRepo={policyByRepo} topPolicyRepos={topPolicyRepos} />
          )}
        </>
      )}
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
}: {
  policyByRepo: Record<string, { failed: number; pending: number }>;
  topPolicyRepos: [string, { failed: number; pending: number }][];
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
    </div>
  );
}

function PolicyFixPromptCard({ hint, onCopy }: { hint: string; onCopy: () => void }) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-accent/35 bg-gradient-to-r from-accent/15 via-bg-secondary to-warning/10 p-4">
      <div className="absolute -top-10 -right-10 w-24 h-24 rounded-full bg-accent/20 blur-2xl pointer-events-none" />
      <div className="relative flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center justify-center w-7 h-7 rounded-lg bg-accent/20 text-accent">
            <Sparkles className="w-4 h-4" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-text-primary">AI Agent Prompt</h3>
            <p className="text-xs text-text-secondary">{hint}</p>
          </div>
        </div>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs rounded-lg border border-accent/30 text-text-primary bg-bg-primary/70 hover:bg-bg-primary transition-colors"
        >
          <Copy className="w-3 h-3" />
          Fix using coding agent
        </button>
      </div>
    </div>
  );
}
