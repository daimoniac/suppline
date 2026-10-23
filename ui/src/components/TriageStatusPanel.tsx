import { Link } from 'react-router';
import { formatDate } from '../lib/utils';
import type { TriageRun, TriageStatus } from '../lib/api';

const STATUS_LABELS: Record<string, string> = {
  dry_run: 'Dry run',
  committed: 'Committed',
  written: 'Written',
  push_failed: 'Push failed',
  rejected_by_guardrail: 'Rejected',
  error: 'Error',
};

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    dry_run: 'bg-info-bg text-info',
    committed: 'bg-success-bg text-success',
    written: 'bg-success-bg text-success',
    push_failed: 'bg-danger-bg text-danger',
    rejected_by_guardrail: 'bg-warning-bg text-warning',
    error: 'bg-danger-bg text-danger',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] || 'bg-bg-tertiary text-text-secondary'}`}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

export function TriageStatusPanel({
  status,
  runs,
}: {
  status: TriageStatus | null;
  runs: TriageRun[];
}) {
  if (!status) {
    return <p className="text-sm text-text-secondary">Triage status is unavailable.</p>;
  }
  if (!status.Enabled) {
    return (
      <p className="text-sm text-text-secondary">
        Triage is not enabled. Set <code className="bg-bg-tertiary px-1 rounded">x-triage</code> to decide policy failures from gitops context.
      </p>
    );
  }

  const counts = runs.reduce<Record<string, number>>((acc, run) => {
    acc[run.Status] = (acc[run.Status] || 0) + 1;
    return acc;
  }, {});
  const recent = runs.slice(0, 8);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="px-2 py-1 rounded-md bg-bg-tertiary text-text-secondary">Mode {status.Mode || 'dry-run'}</span>
        <span className="px-2 py-1 rounded-md bg-bg-tertiary text-text-secondary">
          {status.OnlyInUse ? 'Running images' : 'All images'}
        </span>
        <span className="px-2 py-1 rounded-md bg-bg-tertiary text-text-secondary">Pending {status.Pending}</span>
        {Object.entries(counts).map(([value, count]) => (
          <span key={value} className="px-2 py-1 rounded-md bg-bg-secondary border border-border text-text-secondary">
            {STATUS_LABELS[value] || value} {count}
          </span>
        ))}
        <Link to="/triage" className="ml-auto text-accent hover:text-accent-hover">
          Open triage
        </Link>
      </div>
      {recent.length === 0 ? (
        <p className="text-sm text-text-secondary">No triage runs yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Status</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">CVE</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Repository</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Verdict</th>
                <th className="px-3 py-2 text-right text-xs font-semibold text-text-muted uppercase tracking-wide">When</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(run => (
                <tr key={run.ID} className="border-b border-border/50 last:border-0">
                  <td className="px-3 py-3"><StatusPill status={run.Status} /></td>
                  <td className="px-3 py-3 font-mono text-xs text-text-primary">{run.CVEID}</td>
                  <td className="px-3 py-3 text-xs text-text-secondary max-w-[18rem] truncate">{run.Repository}</td>
                  <td className="px-3 py-3 text-xs text-text-secondary">{run.Verdict || '—'}</td>
                  <td className="px-3 py-3 text-xs text-text-muted text-right">{formatDate(run.CreatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
