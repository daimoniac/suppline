import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { loadAllRuntimeUnusedRepositories, summarizeRuntimeUnusedRepositories } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { fetchPolicyComplianceData, type PolicyComplianceSnapshot } from '../lib/policyComplianceData';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { LoadingState, ErrorState, PageHeader, EmptyState, ConfirmModal } from '../components/ui';
import { PolicyCompliancePanel } from '../components/PolicyCompliancePanel';
import { TriageBoard } from '../components/TriageBoard';
import type {
  ConfigEditResult,
  ConfigEditStatus,
  RepositoriesResponse,
  SemverUpdateEntry,
  SemverUpdateTasksResponse,
  VEXSummary,
  VEXExpiryTaskEntry,
  VEXExpiryTasksResponse,
} from '../lib/api';
import { CheckCircle2, Clock3, RefreshCw, Scale, Server, ShieldAlert, Tag, TriangleAlert, Trash2 } from 'lucide-react';

// ─── status badge ─────────────────────────────────────────────────────────────

function SemverStatusBadge({ status }: { status: string }) {
  if (status === 'current') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">
        <CheckCircle2 className="w-3 h-3" />
        Up to date
      </span>
    );
  }
  if (status === 'out_of_bounds') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">
        <TriangleAlert className="w-3 h-3" />
        Out of bounds
      </span>
    );
  }
  if (status === 'tighten') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-accent/15 text-accent">
        <CheckCircle2 className="w-3 h-3" />
        Tighten
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-bg-tertiary text-text-muted">
      No data
    </span>
  );
}

// ─── runtime versions cell ────────────────────────────────────────────────────

function RuntimeVersionsCell({ entry }: { entry: SemverUpdateEntry }) {
  if (entry.runtime_versions.length === 0) {
    return <span className="text-text-muted text-xs italic">none</span>;
  }
  const oor = new Set(entry.out_of_range_versions);
  return (
    <div className="flex flex-wrap gap-1">
      {entry.runtime_versions.map(v => (
        <span
          key={v}
          className={`inline-block px-1.5 py-0.5 rounded text-xs font-mono font-medium ${
            oor.has(v)
              ? 'bg-warning-bg text-warning'
              : 'bg-bg-tertiary text-text-secondary'
          }`}
          title={oor.has(v) ? 'Out of configured range' : 'Within range'}
        >
          {v}
        </span>
      ))}
    </div>
  );
}

function configEditMessage(result: ConfigEditResult, noun: string) {
  if (result.updated === 0) return 'No config changes were needed';
  const commit = result.commit ? ` (${result.commit.slice(0, 7)})` : '';
  if (result.mode === 'git') return `Updated ${result.updated} ${noun} and committed${commit}`;
  return `Updated ${result.updated} ${noun} in the local config`;
}

function ConfigEditNote({ status }: { status: ConfigEditStatus | null }) {
  if (!status) return <p className="text-xs text-text-muted">Checking whether the config can be edited…</p>;
  return <p className={`text-xs ${status.available ? 'text-text-muted' : 'text-warning'}`}>{status.detail}</p>;
}

function TaskSection({
  anchor,
  active,
  icon,
  title,
  subtitle,
  loading,
  loadingMessage,
  error,
  onRetry,
  children,
}: {
  anchor: string;
  active: boolean;
  icon: ReactNode;
  title: string;
  subtitle: ReactNode;
  loading: boolean;
  loadingMessage: string;
  error: string;
  onRetry: () => void;
  children: ReactNode;
}) {
  return (
    <section
      id={anchor}
      className={`bg-bg-primary border rounded-xl overflow-hidden scroll-mt-24 ${active ? 'border-accent shadow-[0_0_0_1px_rgba(62,207,142,0.35)]' : 'border-border'}`}
    >
      <div className="flex items-center justify-between px-5 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          {icon}
          <h2 className="text-sm font-semibold">{title}</h2>
        </div>
        <p className="text-xs text-text-muted">{subtitle}</p>
      </div>
      <div className="p-4">
        {loading ? <LoadingState message={loadingMessage} /> : error ? <ErrorState message={error} onRetry={onRetry} /> : children}
      </div>
    </section>
  );
}

function TaskListControls({
  summary,
  toggleLabel,
  onToggle,
}: {
  summary: ReactNode;
  toggleLabel: string;
  onToggle: () => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <p className="text-xs text-text-muted">{summary}</p>
      <button
        onClick={onToggle}
        className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary flex items-center gap-1.5 transition-colors"
      >
        {toggleLabel}
      </button>
    </div>
  );
}

// ─── semver update task card ──────────────────────────────────────────────────

function SemverUpdateTask({
  data,
  edits,
  onChanged,
}: {
  data: SemverUpdateTasksResponse;
  edits: ConfigEditStatus | null;
  onChanged: () => void;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);
  const [applying, setApplying] = useState(false);
  const [pending, setPending] = useState<Array<{ target: string; ranges: string[] }> | null>(null);

  if (data.no_runtime_data) {
    return (
      <EmptyState
        icon={<Server className="w-12 h-12 mb-4 opacity-30" />}
        title="No runtime data"
        message="Deploy the clusterstate-agent to your clusters so suppline can compare running versions against your configured semverRanges."
      />
    );
  }

  if (data.entries.length === 0) {
    return (
      <EmptyState
        icon={<Tag className="w-12 h-12 mb-4 opacity-30" />}
        title="No semverRange entries"
        message="Add tags.semverRange to sync entries in suppline.yml to enable version tracking."
      />
    );
  }

  const outOfBoundsCount = data.entries.filter(e => e.status === 'out_of_bounds').length;
  const tightenCount = data.entries.filter(e => e.status === 'tighten').length;
  const defaultEntries = data.entries.filter(e => e.status === 'out_of_bounds' || e.status === 'tighten');
  const displayedEntries = showAll ? data.entries : defaultEntries;
  const actionable = data.entries.flatMap(entry => (
    (entry.status === 'out_of_bounds' || entry.status === 'tighten') && entry.suggested_ranges && entry.suggested_ranges.length > 0
      ? [{ target: entry.target, ranges: entry.suggested_ranges }]
      : []
  ));

  const applyRanges = async (updates: Array<{ target: string; ranges: string[] }>) => {
    setPending(null);
    setApplying(true);
    try {
      const result = await apiClient.applySemverUpdates(updates);
      toast(configEditMessage(result, result.updated === 1 ? 'range' : 'ranges'), result.updated > 0 ? 'success' : 'warning');
      if (result.updated > 0) onChanged();
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to update semver ranges', 'error');
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="space-y-4">
      {(outOfBoundsCount > 0 || tightenCount > 0) && (
        <div className="space-y-2">
          {outOfBoundsCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-warning-bg border border-warning/20 text-sm text-warning">
              <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              <span>
                {outOfBoundsCount} sync {outOfBoundsCount === 1 ? 'entry has' : 'entries have'} runtime versions outside the configured range.
              </span>
            </div>
          )}

          {tightenCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-bg-secondary border border-border text-sm text-text-secondary">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-accent" />
              <span>
                {tightenCount} sync {tightenCount === 1 ? 'entry has' : 'entries have'} optional range tightening suggestions based on currently running versions.
              </span>
            </div>
          )}
          {actionable.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <ConfigEditNote status={edits} />
              <button
                type="button"
                disabled={!edits?.available || applying}
                onClick={() => setPending(actionable)}
                className="px-3 py-1.5 text-xs rounded-lg border border-accent/30 text-text-primary hover:bg-bg-tertiary disabled:opacity-40 transition-colors"
              >
                {applying ? 'Applying…' : `Apply ${actionable.length} suggested ${actionable.length === 1 ? 'range' : 'ranges'}`}
              </button>
            </div>
          )}
        </div>
      )}

      <TaskListControls
        summary={<>Showing {displayedEntries.length} of {data.entries.length} entries{!showAll ? ' (out of bounds + tighten only)' : ''}</>}
        toggleLabel={showAll ? 'Show actionable' : 'Show all'}
        onToggle={() => setShowAll(v => !v)}
      />

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Target</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Semver Range</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Runtime Versions</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Status</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Suggested Range</th>
              <th className="px-3 py-2 text-right text-xs font-semibold text-text-muted uppercase tracking-wide">Action</th>
            </tr>
          </thead>
          <tbody>
            {displayedEntries.map((entry, idx) => (
              <tr key={idx} className="border-b border-border/50 last:border-0">
                <td className="px-3 py-3">
                  <span className="text-xs font-mono text-text-primary max-w-[22rem] inline-block truncate" title={entry.target}>{entry.target}</span>
                </td>
                <td className="px-3 py-3">
                  <div className="flex flex-col gap-0.5">
                    {entry.current_ranges.map((r, i) => (
                      <code key={i} className="text-xs font-mono text-text-secondary bg-bg-tertiary px-1.5 py-0.5 rounded whitespace-nowrap">{r}</code>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-3">
                  <RuntimeVersionsCell entry={entry} />
                </td>
                <td className="px-3 py-3">
                  <SemverStatusBadge status={entry.status} />
                </td>
                <td className="px-3 py-3">
                  {entry.suggested_ranges && entry.suggested_ranges.length > 0 ? (
                    <div className="flex flex-col gap-0.5">
                      {entry.suggested_ranges.map((r, i) => (
                        <code key={i} className="text-xs font-mono text-success bg-success-bg px-1.5 py-0.5 rounded whitespace-nowrap">{r}</code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-text-muted text-xs">—</span>
                  )}
                </td>
                <td className="px-3 py-3 text-right">
                  {entry.suggested_ranges && entry.suggested_ranges.length > 0 && (entry.status === 'out_of_bounds' || entry.status === 'tighten') ? (
                    <button
                      type="button"
                      disabled={!edits?.available || applying}
                      onClick={() => setPending([{ target: entry.target, ranges: entry.suggested_ranges || [] }])}
                      className="px-2.5 py-1 text-xs rounded-lg border border-accent/30 text-text-secondary hover:bg-bg-tertiary disabled:opacity-40 transition-colors"
                    >
                      Apply
                    </button>
                  ) : (
                    <span className="text-text-muted text-xs">—</span>
                  )}
                </td>
              </tr>
            ))}
            {displayedEntries.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-8 text-center text-xs text-text-muted">
                  No out-of-bounds or tighten entries right now. Use Show all to view current entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <ConfirmModal
        open={!!pending}
        title="Update semver ranges"
        message={pending ? `Write ${pending.length} suggested ${pending.length === 1 ? 'range' : 'ranges'} to the suppline config${edits?.mode === 'git' ? ' and commit it' : ''}?` : ''}
        onConfirm={() => { if (pending) void applyRanges(pending); }}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}

function RuntimeUnusedRepoStatusBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">
      <TriangleAlert className="w-3 h-3" />
      Unused
    </span>
  );
}

function RuntimeUnusedRepositoryTask({
  data,
  edits,
  onChanged,
}: {
  data: RepositoriesResponse;
  edits: ConfigEditStatus | null;
  onChanged: () => void;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [confirmRescan, setConfirmRescan] = useState('');
  const [removing, setRemoving] = useState(false);
  const [pendingRemoval, setPendingRemoval] = useState<string[] | null>(null);

  const loadWhitelist = useCallback(async () => {
    const result = await apiClient.getRuntimeUnusedWhitelist();
    setWhitelist((result.repositories || []).slice().sort((a, b) => a.localeCompare(b)));
  }, [apiClient]);

  useEffect(() => {
    scheduleEffectLoad(() =>
      loadWhitelist().catch(() => {
        toast('Failed to load whitelist', 'error');
      }),
    );
  }, [loadWhitelist, toast]);

  const onWhitelist = useCallback(async (repository: string) => {
    const trimmed = repository.trim();
    if (!trimmed) {
      return;
    }

    setBusyKey(`add:${trimmed}`);
    try {
      await apiClient.addRuntimeUnusedWhitelist(trimmed);
      setWhitelist(prev => {
        if (prev.includes(trimmed)) {
          return prev;
        }
        return [...prev, trimmed].sort((a, b) => a.localeCompare(b));
      });
    } finally {
      setBusyKey(null);
    }
  }, [apiClient]);

  const onRemoveWhitelist = useCallback(async (repository: string) => {
    const trimmed = repository.trim();
    if (!trimmed) {
      return;
    }

    setBusyKey(`remove:${trimmed}`);
    try {
      await apiClient.removeRuntimeUnusedWhitelist(trimmed);
      setWhitelist(prev => prev.filter(r => r !== trimmed));
    } finally {
      setBusyKey(null);
    }
  }, [apiClient]);

  const handleRescan = async (name: string) => {
    setConfirmRescan('');
    try {
      const resp = await apiClient.triggerRepositoryRescan(name);
      toast(resp.message || 'Rescan triggered', 'success');
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed', 'error');
    }
  };

  const { whitelistSet, actionableRepositories, hiddenByWhitelistCount } = summarizeRuntimeUnusedRepositories(data.Repositories, whitelist);
  const displayedRepositories = showAll ? data.Repositories : actionableRepositories;

  if (data.Repositories.length === 0) {
    return (
      <EmptyState
        icon={<Tag className="w-12 h-12 mb-4 opacity-30" />}
        title="No unused repositories"
        message="All tracked repositories are currently observed in runtime inventory."
      />
    );
  }

  const unusedCount = actionableRepositories.length;
  const removable = Array.from(new Set(actionableRepositories.map(entry => entry.Name).filter(Boolean)));

  const removeTargets = async (targets: string[]) => {
    setPendingRemoval(null);
    setRemoving(true);
    try {
      const result = await apiClient.removeSyncTargets(targets);
      toast(configEditMessage(result, result.updated === 1 ? 'sync entry' : 'sync entries'), result.updated > 0 ? 'success' : 'warning');
      if (result.updated > 0) onChanged();
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to remove sync entries', 'error');
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className="space-y-4">
      {(unusedCount > 0 || hiddenByWhitelistCount > 0) && (
        <div className="space-y-2">
          {unusedCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-warning-bg border border-warning/20 text-sm text-warning">
              <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              <span>
                {unusedCount} {unusedCount === 1 ? 'repository is' : 'repositories are'} not observed in runtime inventory.
              </span>
            </div>
          )}

          {hiddenByWhitelistCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-bg-secondary border border-border text-sm text-text-secondary">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-accent" />
              <span>
                {hiddenByWhitelistCount} {hiddenByWhitelistCount === 1 ? 'repository is' : 'repositories are'} hidden by whitelist.
              </span>
            </div>
          )}
          {removable.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <ConfigEditNote status={edits} />
              <button
                type="button"
                disabled={!edits?.available || removing}
                onClick={() => setPendingRemoval(removable)}
                className="px-3 py-1.5 text-xs rounded-lg border border-danger/30 text-danger hover:bg-danger-bg disabled:opacity-40 transition-colors"
              >
                {removing ? 'Removing…' : `Remove ${removable.length} unused ${removable.length === 1 ? 'repository' : 'repositories'}`}
              </button>
            </div>
          )}
        </div>
      )}

      <TaskListControls
        summary={<>Showing {displayedRepositories.length} of {data.Repositories.length} unused repositories{!showAll ? ' (excluding whitelist)' : ''}</>}
        toggleLabel={showAll ? 'Show actionable' : 'Show all'}
        onToggle={() => setShowAll(v => !v)}
      />

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Repository</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Artifacts</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Status</th>
              <th className="px-3 py-2 text-right text-xs font-semibold text-text-muted uppercase tracking-wide">Action</th>
            </tr>
          </thead>
          <tbody>
            {displayedRepositories.map((entry: RepositoriesResponse['Repositories'][number], idx: number) => {
              const isWhitelisted = whitelistSet.has(entry.Name);
              return (
              <tr key={idx} className={`border-b border-border/50 last:border-0 ${isWhitelisted ? 'bg-bg-secondary/45' : ''}`}>
                <td className="px-3 py-3">
                  <Link
                    to={`/repositories/${encodeURIComponent(entry.Name)}`}
                    className="text-xs font-mono text-accent hover:underline max-w-[24rem] inline-block truncate"
                    title={entry.Name}
                  >
                    {entry.Name}
                  </Link>
                </td>
                <td className="px-3 py-3">
                  <span className="text-xs text-text-secondary">{entry.ArtifactCount}</span>
                </td>
                <td className="px-3 py-3">
                  <RuntimeUnusedRepoStatusBadge />
                </td>
                <td className="px-3 py-3 text-right">
                  <div className="inline-flex items-center gap-2">
                    {!isWhitelisted && (
                      <button
                        type="button"
                        disabled={!edits?.available || removing}
                        onClick={() => setPendingRemoval([entry.Name])}
                        className="px-2.5 py-1 text-xs rounded-lg border border-danger/30 text-danger hover:bg-danger-bg disabled:opacity-40 transition-colors"
                      >
                        Remove
                      </button>
                    )}
                    <button
                      onClick={() => setConfirmRescan(entry.Name)}
                      className="px-2.5 py-1 text-xs rounded-lg border border-warning/30 text-warning hover:bg-warning-bg transition-colors flex items-center gap-1"
                    >
                      <RefreshCw className="w-3 h-3" /> Rescan
                    </button>
                    <button
                      onClick={() => {
                        const action = isWhitelisted ? onRemoveWhitelist : onWhitelist;
                        const successMessage = isWhitelisted
                          ? `Removed ${entry.Name} from whitelist`
                          : `Whitelisted ${entry.Name}`;

                        action(entry.Name)
                          .then(() => toast(successMessage, 'success'))
                          .catch(() => undefined);
                      }}
                      disabled={busyKey === `add:${entry.Name}` || busyKey === `remove:${entry.Name}`}
                      className="px-2.5 py-1 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-40 transition-colors"
                    >
                      {isWhitelisted ? 'Remove from whitelist' : 'Whitelist'}
                    </button>
                  </div>
                </td>
              </tr>
              );
            })}
            {displayedRepositories.length === 0 && (
              <tr>
                <td colSpan={4} className="px-3 py-8 text-center text-xs text-text-muted">
                  No housekeeping repositories remain after whitelist filtering.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <ConfirmModal
        open={!!confirmRescan}
        title="Rescan Repository"
        message={`Trigger rescan for all images in "${confirmRescan}"?`}
        onConfirm={() => handleRescan(confirmRescan)}
        onCancel={() => setConfirmRescan('')}
      />
      <ConfirmModal
        open={!!pendingRemoval}
        title="Remove unused sync repositories"
        message={pendingRemoval ? `Remove ${pendingRemoval.length} sync ${pendingRemoval.length === 1 ? 'entry' : 'entries'} from the suppline config${edits?.mode === 'git' ? ' and commit it' : ''}?` : ''}
        onConfirm={() => { if (pendingRemoval) void removeTargets(pendingRemoval); }}
        onCancel={() => setPendingRemoval(null)}
      />
    </div>
  );
}

function VEXExpiryStatusBadge({ status }: { status: string }) {
  if (status === 'expired') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-danger-bg text-danger">
        <TriangleAlert className="w-3 h-3" />
        Expired
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">
      <Clock3 className="w-3 h-3" />
      Expiring soon
    </span>
  );
}

function VEXExpiryTask({
  data,
  inactiveEntries,
  edits,
  onChanged,
}: {
  data: VEXExpiryTasksResponse;
  inactiveEntries: VEXSummary[];
  edits: ConfigEditStatus | null;
  onChanged: () => void;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [pendingRemoval, setPendingRemoval] = useState<string[] | null>(null);

  const inactiveCount = inactiveEntries.length;
  const hasExpiryEntries = data.entries.length > 0;

  if (!hasExpiryEntries && inactiveCount === 0) {
    return (
      <EmptyState
        icon={<CheckCircle2 className="w-12 h-12 mb-4 opacity-30" />}
        title="No VEX review issues"
        message="No VEX statements currently need review for inactivity, expiry, or near-term expiry."
      />
    );
  }

  const expiredCount = data.entries.filter(e => e.status === 'expired').length;
  const expiringSoonCount = data.entries.filter(e => e.status === 'expiring_soon').length;
  const displayedEntries = showAll ? data.entries : data.entries.slice(0, 12);
  const removable = inactiveEntries.map(entry => entry.CVEID).filter(Boolean);

  const removeStatements = async (ids: string[]) => {
    setPendingRemoval(null);
    setRemoving(true);
    try {
      const result = await apiClient.removeVEXStatements(ids);
      toast(configEditMessage(result, result.updated === 1 ? 'statement' : 'statements'), result.updated > 0 ? 'success' : 'warning');
      if (result.updated > 0) onChanged();
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed to remove VEX statements', 'error');
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {inactiveCount > 0 && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-warning-bg border border-warning/20 text-sm text-warning">
            <TriangleAlert className="w-4 h-4 flex-shrink-0" />
            <span>
              {inactiveCount} VEX {inactiveCount === 1 ? 'statement is' : 'statements are'} unused and can be removed.
            </span>
          </div>
        )}
        {expiredCount > 0 && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-danger-bg border border-danger/20 text-sm text-danger">
            <TriangleAlert className="w-4 h-4 flex-shrink-0" />
            <span>
              {expiredCount} VEX {expiredCount === 1 ? 'statement is' : 'statements are'} expired and should be updated or removed.
            </span>
          </div>
        )}
        {expiringSoonCount > 0 && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-warning-bg border border-warning/20 text-sm text-warning">
            <Clock3 className="w-4 h-4 flex-shrink-0" />
            <span>
              {expiringSoonCount} VEX {expiringSoonCount === 1 ? 'statement is' : 'statements are'} expiring within 7 days.
            </span>
          </div>
        )}
        {removable.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <ConfigEditNote status={edits} />
            <button
              type="button"
              disabled={!edits?.available || removing}
              onClick={() => setPendingRemoval(removable)}
              className="px-3 py-1.5 text-xs rounded-lg border border-danger/30 text-danger hover:bg-danger-bg disabled:opacity-40 transition-colors"
            >
              {removing ? 'Removing…' : `Remove ${removable.length} unused ${removable.length === 1 ? 'statement' : 'statements'}`}
            </button>
          </div>
        )}
      </div>

      {hasExpiryEntries && (
        <TaskListControls
          summary={<>Showing {displayedEntries.length} of {data.entries.length} expiring or expired entries</>}
          toggleLabel={showAll ? 'Show less' : 'Show more'}
          onToggle={() => setShowAll(v => !v)}
        />
      )}

      {hasExpiryEntries && (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">CVE</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Repositories</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Expires</th>
                <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Status</th>
              </tr>
            </thead>
            <tbody>
              {displayedEntries.map((entry: VEXExpiryTaskEntry) => (
                <tr key={entry.cve_id} className="border-b border-border/50 last:border-0">
                  <td className="px-3 py-3 text-xs font-mono text-text-primary">{entry.cve_id}</td>
                  <td className="px-3 py-3 text-xs text-text-secondary">
                    <span className="max-w-[28rem] inline-block truncate" title={entry.repositories.join(', ')}>{entry.repositories.join(', ')}</span>
                  </td>
                  <td className="px-3 py-3 text-xs text-text-secondary">{new Date(entry.expires_at * 1000).toISOString().slice(0, 10)}</td>
                  <td className="px-3 py-3">
                    <VEXExpiryStatusBadge status={entry.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {inactiveCount > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-text-secondary uppercase tracking-wide">Inactive statements</p>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">CVE</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Repositories</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">State</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Expires</th>
                  <th className="px-3 py-2 text-right text-xs font-semibold text-text-muted uppercase tracking-wide">Action</th>
                </tr>
              </thead>
              <tbody>
                {inactiveEntries
                  .slice()
                  .sort((a, b) => a.CVEID.localeCompare(b.CVEID))
                  .map(entry => {
                    const repos = (entry.Repositories || []).map(r => r.Repository).filter(Boolean);
                    return (
                      <tr key={`inactive-${entry.CVEID}`} className="border-b border-border/50 last:border-0">
                        <td className="px-3 py-3 text-xs font-mono text-text-primary">{entry.CVEID}</td>
                        <td className="px-3 py-3 text-xs text-text-secondary">
                          <span className="max-w-[28rem] inline-block truncate" title={repos.join(', ') || '(all repositories)'}>
                            {repos.join(', ') || '(all repositories)'}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-xs text-text-secondary">{entry.State || 'unknown'}</td>
                        <td className="px-3 py-3 text-xs text-text-secondary">
                          {entry.ExpiresAt ? new Date(entry.ExpiresAt * 1000).toISOString().slice(0, 10) : 'No expiry'}
                        </td>
                        <td className="px-3 py-3 text-right">
                          <button
                            type="button"
                            disabled={!edits?.available || removing}
                            onClick={() => setPendingRemoval([entry.CVEID])}
                            className="px-2.5 py-1 text-xs rounded-lg border border-danger/30 text-danger hover:bg-danger-bg disabled:opacity-40 transition-colors"
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <ConfirmModal
        open={!!pendingRemoval}
        title="Remove unused VEX statements"
        message={pendingRemoval ? `Remove ${pendingRemoval.length} unused VEX ${pendingRemoval.length === 1 ? 'statement' : 'statements'} from the suppline config${edits?.mode === 'git' ? ' and commit it' : ''}?` : ''}
        onConfirm={() => { if (pendingRemoval) void removeStatements(pendingRemoval); }}
        onCancel={() => setPendingRemoval(null)}
      />
    </div>
  );
}

// ─── page ─────────────────────────────────────────────────────────────────────

export default function TasksPage() {
  const { apiClient } = useAuth();
  const { inUseRequestParams } = useImageUsageFilter();
  const location = useLocation();
  const [semverData, setSemverData] = useState<SemverUpdateTasksResponse | null>(null);
  const [runtimeUnusedData, setRuntimeUnusedData] = useState<RepositoriesResponse | null>(null);
  const [vexExpiryData, setVexExpiryData] = useState<VEXExpiryTasksResponse | null>(null);
  const [inactiveVEXData, setInactiveVEXData] = useState<VEXSummary[]>([]);
  const [policyCompliance, setPolicyCompliance] = useState<PolicyComplianceSnapshot | null>(null);
  const [configEdits, setConfigEdits] = useState<ConfigEditStatus | null>(null);
  const [triageRefresh, setTriageRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [semverResult, runtimeUnusedResult, vexExpiryResult, inactiveVEXResult, policySnap, editStatus] = await Promise.all([
        apiClient.getSemverUpdateTasks(),
        loadAllRuntimeUnusedRepositories(apiClient),
        apiClient.getVEXExpiryTasks(),
        apiClient.getInactiveVEXStatements(),
        fetchPolicyComplianceData(apiClient, inUseRequestParams),
        apiClient.getConfigEdits().catch(() => ({ available: false, mode: 'unavailable', detail: 'Config editing status is unavailable.' })),
      ]);
      setSemverData(semverResult);
      setRuntimeUnusedData(runtimeUnusedResult);
      setVexExpiryData(vexExpiryResult);
      setInactiveVEXData(inactiveVEXResult);
      setPolicyCompliance(policySnap);
      setConfigEdits(editStatus);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load tasks');
    } finally {
      setLoading(false);
    }
  }, [apiClient, inUseRequestParams]);

  useEffect(() => { scheduleEffectLoad(load); }, [load]);

  useEffect(() => {
    if (!location.hash || loading) {
      return;
    }

    const id = location.hash.slice(1);
    const target = document.getElementById(id);
    if (!target) {
      return;
    }

    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [location.hash, loading]);

  const activeAnchor = location.hash.slice(1);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <PageHeader
          title="Tasks"
          subtitle="Action items requiring human review"
          showImageUsage
        />
        <button
          onClick={load}
          disabled={loading}
          className="mt-1 px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-40 flex items-center gap-1.5 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Policy compliance (same as dashboard) */}
      <TaskSection
        anchor="policy-compliance"
        active={activeAnchor === 'policy-compliance'}
        icon={<ShieldAlert className="w-4 h-4 text-danger" />}
        title="Policy Compliance Status"
        subtitle="Repositories with the most non-passing policy evaluations (top 5). Respects the image usage filter."
        loading={loading}
        loadingMessage="Loading policy compliance…"
        error={error}
        onRetry={load}
      >
        {policyCompliance ? (
          <PolicyCompliancePanel
            embedded
            showCardHeading={false}
            policyByRepo={policyCompliance.policyByRepo}
            failedScans={policyCompliance.failedScans}
            onTriageQueued={() => setTriageRefresh(value => value + 1)}
          />
        ) : null}
      </TaskSection>

      <TaskSection
        anchor="triage-status"
        active={activeAnchor === 'triage-status'}
        icon={<Scale className="w-4 h-4 text-accent" />}
        title="Triage Status"
        subtitle="Current rejected and unresolved automated triages. Accepted and manual statements stay on the Triage page."
        loading={false}
        loadingMessage="Loading triage status…"
        error=""
        onRetry={load}
      >
        <TriageBoard mode="attention" refreshToken={triageRefresh} />
      </TaskSection>

      {/* SemVer Range Updates */}
      <TaskSection
        anchor="semver-range-updates"
        active={activeAnchor === 'semver-range-updates'}
        icon={<Tag className="w-4 h-4 text-accent" />}
        title="SemVer Range Updates"
        subtitle={<>Sync entries with <code className="bg-bg-tertiary px-1 rounded">tags.semverRange</code> compared against runtime versions</>}
        loading={loading}
        loadingMessage="Checking runtime versions..."
        error={error}
        onRetry={load}
      >
        {semverData ? <SemverUpdateTask data={semverData} edits={configEdits} onChanged={load} /> : null}
      </TaskSection>

      {/* Runtime Unused Repositories */}
      <TaskSection
        anchor="unused-sync-repositories"
        active={activeAnchor === 'unused-sync-repositories'}
        icon={<Trash2 className="w-4 h-4 text-warning" />}
        title="Unused Sync Repositories"
        subtitle={<>Derived from <code className="bg-bg-tertiary px-1 rounded">/api/v1/repositories?in_use=false</code></>}
        loading={loading}
        loadingMessage="Checking runtime repository usage..."
        error={error}
        onRetry={load}
      >
        {runtimeUnusedData ? <RuntimeUnusedRepositoryTask data={runtimeUnusedData} edits={configEdits} onChanged={load} /> : null}
      </TaskSection>

      {/* VEX Review Tasks */}
      <TaskSection
        anchor="vex-review"
        active={activeAnchor === 'vex-review'}
        icon={<Clock3 className="w-4 h-4 text-danger" />}
        title="VEX Review"
        subtitle={<>VEX statements from <code className="bg-bg-tertiary px-1 rounded">x-vex</code> that are inactive, expired, or expiring within 7 days</>}
        loading={loading}
        loadingMessage="Checking VEX review tasks..."
        error={error}
        onRetry={load}
      >
        {vexExpiryData ? <VEXExpiryTask data={vexExpiryData} inactiveEntries={inactiveVEXData} edits={configEdits} onChanged={load} /> : null}
      </TaskSection>
    </div>
  );
}
