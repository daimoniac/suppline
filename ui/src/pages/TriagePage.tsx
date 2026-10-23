import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../lib/auth';
import { formatDate } from '../lib/utils';
import { ErrorState, LoadingState, PageHeader } from '../components/ui';
import type { TriageRun } from '../lib/api';

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

export default function TriagePage() {
  const { apiClient } = useAuth();
  const [runs, setRuns] = useState<TriageRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [repository, setRepository] = useState('');
  const [cve, setCve] = useState('');
  const [status, setStatus] = useState('');
  const [openID, setOpenID] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await apiClient.getTriageRuns({
        repository: repository || undefined,
        cve: cve || undefined,
        status: status || undefined,
      });
      setRuns(result);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load triage runs');
    } finally {
      setLoading(false);
    }
  }, [apiClient, repository, cve, status]);

  useEffect(() => { load(); }, [load]);

  if (loading && runs.length === 0) return <LoadingState message="Loading triage runs..." />;
  if (error && runs.length === 0) return <ErrorState message={error} onRetry={load} />;

  return (
    <div>
      <PageHeader title="Triage" subtitle="Automated decisions on whether a policy exception affects this environment" />
      <div className="flex flex-wrap gap-2 mb-4">
        <input value={repository} onChange={e => setRepository(e.target.value)} placeholder="Repository"
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50" />
        <input value={cve} onChange={e => setCve(e.target.value)} placeholder="CVE"
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50" />
        <select value={status} onChange={e => setStatus(e.target.value)}
          className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
          <option value="">All statuses</option>
          {Object.entries(STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
      </div>
      {error && <p className="text-sm text-danger mb-3">{error}</p>}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
        {runs.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No triage runs</div>
        ) : runs.map(run => {
          const open = openID === run.ID;
          return (
            <div key={run.ID}>
              <button type="button" onClick={() => setOpenID(open ? null : run.ID)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-bg-secondary transition-colors">
                <StatusPill status={run.Status} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-mono font-medium">{run.CVEID}</div>
                  <div className="text-xs text-text-muted truncate">{run.Repository}</div>
                </div>
                <span className="text-xs text-text-secondary shrink-0">{run.Verdict || '—'}</span>
                <span className="text-xs text-text-muted shrink-0 w-28 text-right">{formatDate(run.CreatedAt)}</span>
              </button>
              {open && (
                <div className="px-4 pb-4 text-sm text-text-secondary space-y-2">
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                    {run.Justification && <span>Justification: {run.Justification}</span>}
                    <span>Confidence: {run.Confidence.toFixed(2)}</span>
                    {run.Model && <span>Model: {run.Model}</span>}
                    <span>Tokens: {run.Tokens}</span>
                    {run.CommitSHA && <span className="font-mono">Commit: {run.CommitSHA.slice(0, 12)}</span>}
                  </div>
                  {run.Reasoning && <p className="whitespace-pre-wrap text-text-primary">{run.Reasoning}</p>}
                  {run.Evidence && run.Evidence.length > 0 && (
                    <ul className="space-y-1">
                      {run.Evidence.map((item, index) => (
                        <li key={`${item.repo}-${item.path}-${item.line}-${index}`} className="font-mono text-xs">
                          {item.repo}:{item.path}:{item.line} {item.quote}
                        </li>
                      ))}
                    </ul>
                  )}
                  {run.RepoSHAs && run.RepoSHAs.length > 0 && (
                    <ul className="text-xs font-mono text-text-muted">
                      {run.RepoSHAs.map(repo => (
                        <li key={repo.name}>{repo.name}@{repo.sha.slice(0, 12)}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
