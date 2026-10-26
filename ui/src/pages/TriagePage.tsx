import { useCallback, useEffect, useState } from 'react';
import { Clock, Copy, Loader2 } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { buildOpenTriagePrompt } from '../lib/policyComplianceData';
import { copyToClipboard, formatDate } from '../lib/utils';
import { ErrorState, LoadingState, PageHeader } from '../components/ui';
import type { TriageAccept, TriageActive, TriageRun } from '../lib/api';

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

const VEX_STATES = [
  ['not_affected', 'Not affected'],
  ['affected', 'Affected'],
  ['in_triage', 'In triage'],
  ['false_positive', 'False positive'],
  ['resolved', 'Resolved'],
  ['resolved_with_pedigree', 'Resolved with pedigree'],
] as const;

const VEX_JUSTIFICATIONS = [
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment',
  'protected_by_compiler',
  'protected_at_runtime',
  'protected_at_perimeter',
  'protected_by_mitigations',
];

function fromLocalInput(value: string) {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000);
}

function AcceptModal({ run, onClose, onSave }: { run: TriageRun; onClose: () => void; onSave: (body: TriageAccept) => Promise<void> }) {
  const knownState = VEX_STATES.some(([value]) => value === run.Verdict);
  const [state, setState] = useState(knownState ? run.Verdict : 'not_affected');
  const [justification, setJustification] = useState(run.Justification || 'code_not_reachable');
  const [detail, setDetail] = useState(run.Reasoning || '');
  const [expires, setExpires] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await onSave({
        Repository: run.Repository,
        CVEID: run.CVEID,
        State: state,
        Justification: state === 'not_affected' ? justification : undefined,
        Detail: detail.trim() || undefined,
        ExpiresAt: fromLocalInput(expires),
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save');
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-bg-secondary border border-border rounded-xl p-6 max-w-lg w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold mb-1">Accept into x-vex</h3>
        <p className="text-sm text-text-secondary mb-4">
          Writes a hand-written x-vex statement for {run.CVEID}. It overrides the automated decision for {run.Repository}.
        </p>
        <div className="space-y-3">
          <label className="block text-xs text-text-secondary">
            Outcome
            <select value={state} onChange={e => setState(e.target.value)}
              className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
              {VEX_STATES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          {state === 'not_affected' && (
            <label className="block text-xs text-text-secondary">
              Justification
              <select value={justification} onChange={e => setJustification(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
                {VEX_JUSTIFICATIONS.map(value => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
          )}
          <label className="block text-xs text-text-secondary">
            Detail
            <textarea value={detail} onChange={e => setDetail(e.target.value)} rows={4}
              className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
          </label>
          <label className="block text-xs text-text-secondary">
            Expires
            <input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)}
              className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
          </label>
          {expires && <p className="text-xs text-text-muted">Expires {formatDate(fromLocalInput(expires) || 0)}</p>}
          {error && <p className="text-sm text-danger">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary transition-colors">Cancel</button>
          <button type="button" onClick={save} disabled={saving} className="px-4 py-2 text-sm rounded-lg bg-accent text-bg-primary font-medium hover:bg-accent-hover transition-colors disabled:opacity-50">
            {saving ? 'Saving…' : 'Save to x-vex'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function TriagePage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [copying, setCopying] = useState(false);
  const [runs, setRuns] = useState<TriageRun[]>([]);
  const [active, setActive] = useState<TriageActive[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [repository, setRepository] = useState('');
  const [cve, setCve] = useState('');
  const [status, setStatus] = useState('');
  const [openID, setOpenID] = useState<number | null>(null);
  const [editing, setEditing] = useState<TriageRun | null>(null);
  const [retryingID, setRetryingID] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async (quiet: boolean) => {
    if (!quiet) setLoading(true);
    try {
      const [result, triageStatus] = await Promise.all([
        apiClient.getTriageRuns({
          repository: repository || undefined,
          cve: cve || undefined,
          status: status || undefined,
        }),
        apiClient.getTriageStatus().catch(() => null),
      ]);
      setRuns(result);
      setActive(triageStatus?.Active ?? []);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load triage runs');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [apiClient, repository, cve, status]);

  useEffect(() => { refresh(false); }, [refresh]);

  useEffect(() => {
    if (active.length === 0) return;
    const id = window.setInterval(() => { refresh(true); }, 3000);
    return () => window.clearInterval(id);
  }, [active.length, refresh]);

  const running = active.filter(job => job.Running);
  const queued = active.filter(job => !job.Running);
  const busyKey = new Set(active.map(job => `${job.Repository}\n${job.CVEID}`));

  const copyOpenPrompt = async () => {
    setCopying(true);
    try {
      const latest = await apiClient.getTriageRuns({ limit: 200 });
      const prompt = buildOpenTriagePrompt(latest);
      if (!prompt) {
        toast('No open or uncertain triage runs to copy', 'warning');
        return;
      }
      const ok = await copyToClipboard(prompt);
      toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error');
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to build the coding-agent prompt', 'error');
    } finally {
      setCopying(false);
    }
  };

  const retry = async (run: TriageRun) => {
    setRetryingID(run.ID);
    setNotice(null);
    try {
      const result = await apiClient.retryTriage({ Repository: run.Repository, CVEID: run.CVEID });
      if (result.Queued > 0) {
        await refresh(true);
      } else {
        setNotice('Triage was not queued. It may already be waiting, or the image is not running in a cluster.');
      }
    } catch (e: unknown) {
      setNotice(e instanceof Error ? e.message : 'Failed to queue triage');
    } finally {
      setRetryingID(null);
    }
  };

  if (loading && runs.length === 0 && active.length === 0) return <LoadingState message="Loading triage runs..." />;
  if (error && runs.length === 0) return <ErrorState message={error} onRetry={() => refresh(false)} />;

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
        <button type="button" onClick={copyOpenPrompt} disabled={copying}
          className="inline-flex items-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-accent/30 text-text-primary bg-bg-secondary hover:bg-bg-tertiary disabled:opacity-50 transition-colors">
          <Copy className="w-3.5 h-3.5" />
          {copying ? 'Copying…' : 'Coding agent for open runs'}
        </button>
      </div>
      {error && <p className="text-sm text-danger mb-3">{error}</p>}
      {notice && <p className="text-sm text-text-secondary mb-3">{notice}</p>}
      {running.length > 0 && (
        <div className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">Currently running</div>
          {running.map(job => (
            <div key={`${job.Repository}\n${job.CVEID}`} className="flex items-center gap-3 px-4 py-3">
              <Loader2 className="w-4 h-4 animate-spin text-accent shrink-0" />
              <div className="min-w-0">
                <div className="text-sm font-mono font-medium">{job.CVEID}</div>
                <div className="text-xs text-text-muted truncate">{job.Image || job.Repository}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {queued.length > 0 && (
        <div className="mb-4 bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
          <div className="px-4 py-2 text-xs font-medium text-text-secondary">Queued</div>
          {queued.map(job => (
            <div key={`${job.Repository}\n${job.CVEID}`} className="flex items-center gap-3 px-4 py-3">
              <Clock className="w-4 h-4 text-text-muted shrink-0" />
              <div className="min-w-0">
                <div className="text-sm font-mono font-medium">{job.CVEID}</div>
                <div className="text-xs text-text-muted truncate">{job.Image || job.Repository}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden divide-y divide-border">
        {runs.length === 0 ? (
          <div className="p-12 text-center text-text-secondary text-sm">No triage runs</div>
        ) : runs.map(run => {
          const open = openID === run.ID;
          return (
            <div key={run.ID} className={run.Superseded ? 'opacity-50' : undefined}>
              <div className="flex items-center gap-3 px-4 py-3 hover:bg-bg-secondary transition-colors">
                <button type="button" onClick={() => setOpenID(open ? null : run.ID)}
                  className="flex-1 min-w-0 flex items-center gap-3 text-left">
                  <StatusPill status={run.Status} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-mono font-medium">{run.CVEID}</div>
                    <div className="text-xs text-text-muted truncate">{run.Repository}</div>
                  </div>
                  {run.Superseded && <span className="text-xs text-text-muted shrink-0">Superseded</span>}
                  <span className="text-xs text-text-secondary shrink-0">{run.Verdict || '—'}</span>
                  <span className="text-xs text-text-muted shrink-0 w-28 text-right">{formatDate(run.CreatedAt)}</span>
                </button>
                <button type="button" onClick={() => retry(run)}
                  disabled={retryingID === run.ID || busyKey.has(`${run.Repository}\n${run.CVEID}`)}
                  className="px-2 py-1 text-xs rounded-md border border-border text-text-secondary hover:bg-bg-tertiary shrink-0 disabled:opacity-50">
                  {busyKey.has(`${run.Repository}\n${run.CVEID}`) ? 'Queued' : retryingID === run.ID ? 'Queuing…' : 'Queue again'}
                </button>
                <button type="button" onClick={() => setEditing(run)}
                  className="px-2 py-1 text-xs rounded-md border border-border text-text-secondary hover:bg-bg-tertiary shrink-0">
                  Edit
                </button>
              </div>
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
      {editing && (
        <AcceptModal
          key={editing.ID}
          run={editing}
          onClose={() => setEditing(null)}
          onSave={async body => {
            await apiClient.acceptTriage(body);
            setEditing(null);
            await refresh(true);
          }}
        />
      )}
    </div>
  );
}
