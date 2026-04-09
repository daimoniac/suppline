import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { copyToClipboard, loadAllRuntimeUnusedRepositories, summarizeRuntimeUnusedRepositories } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, EmptyState } from '../components/ui';
import type {
  RepositoriesResponse,
  SemverUpdateEntry,
  SemverUpdateTasksResponse,
  VEXSummary,
  VEXExpiryTaskEntry,
  VEXExpiryTasksResponse,
} from '../lib/api';
import { CheckCircle2, Clock3, Copy, RefreshCw, Server, Sparkles, Tag, TriangleAlert, Trash2 } from 'lucide-react';

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

function TaskPromptCard({ hint, onCopy }: { hint: string; onCopy: () => void }) {
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
          onClick={onCopy}
          className="inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs rounded-lg border border-accent/30 text-text-primary bg-bg-primary/70 hover:bg-bg-primary transition-colors"
        >
          <Copy className="w-3 h-3" />
          Copy prompt to clipboard
        </button>
      </div>
    </div>
  );
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

// ─── semver update task card ──────────────────────────────────────────────────

function SemverUpdateTask({ data }: { data: SemverUpdateTasksResponse }) {
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);

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
  const hasUpdates = data.ai_agent_prompt.trim().length > 0;

  return (
    <div className="space-y-4">
      {(outOfBoundsCount > 0 || tightenCount > 0 || hasUpdates) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 items-start">
          <div className="lg:col-span-2 space-y-2">
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
          </div>

          {hasUpdates && (
            <TaskPromptCard
              hint="Ready to apply semverRange updates."
              onCopy={() => {
                copyToClipboard(data.ai_agent_prompt).then(ok =>
                  toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
                );
              }}
            />
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-text-muted">
          Showing {displayedEntries.length} of {data.entries.length} entries
          {!showAll ? ' (out of bounds + tighten only)' : ''}
        </p>
        <button
          onClick={() => setShowAll(v => !v)}
          className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary flex items-center gap-1.5 transition-colors"
        >
          {showAll ? 'Show actionable' : 'Show all'}
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Target</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Semver Range</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Runtime Versions</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Status</th>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Suggested Range</th>
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
              </tr>
            ))}
            {displayedEntries.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-xs text-text-muted">
                  No out-of-bounds or tighten entries right now. Use Show all to view current entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

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

function buildRuntimeUnusedPrompt(entries: RepositoriesResponse['Repositories']): string {
  if (!entries || entries.length === 0) {
    return '';
  }

  const uniqueTargets = Array.from(new Set(entries.map(entry => entry.Name).filter(Boolean))).sort();
  if (uniqueTargets.length === 0) {
    return '';
  }

  const targetsList = uniqueTargets.map(target => `  - ${target}`).join('\n');
  return [
    'Remove the following sync entries completely:',
    targetsList,
  ].join('\n');
}

function RuntimeUnusedRepositoryTask({
  data,
}: {
  data: RepositoriesResponse;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const loadWhitelist = useCallback(async () => {
    const result = await apiClient.getRuntimeUnusedWhitelist();
    setWhitelist((result.repositories || []).slice().sort((a, b) => a.localeCompare(b)));
  }, [apiClient]);

  useEffect(() => {
    loadWhitelist().catch(() => {
      toast('Failed to load whitelist', 'error');
    });
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
  const aiAgentPrompt = buildRuntimeUnusedPrompt(actionableRepositories);
  const hasUpdates = aiAgentPrompt.trim().length > 0;

  return (
    <div className="space-y-4">
      {(unusedCount > 0 || hasUpdates) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 items-start">
          <div className="lg:col-span-2">
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
          </div>

          {hasUpdates && (
            <TaskPromptCard
              hint="Ready to remove or disable unused sync targets."
              onCopy={() => {
                copyToClipboard(aiAgentPrompt).then(ok =>
                  toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
                );
              }}
            />
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-text-muted">
          Showing {displayedRepositories.length} of {data.Repositories.length} unused repositories
          {!showAll ? ' (excluding whitelist)' : ''}
        </p>
        <button
          onClick={() => setShowAll(v => !v)}
          className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary flex items-center gap-1.5 transition-colors"
        >
          {showAll ? 'Show actionable' : 'Show all'}
        </button>
      </div>

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
                  <span className="text-xs font-mono text-text-primary max-w-[24rem] inline-block truncate" title={entry.Name}>{entry.Name}</span>
                </td>
                <td className="px-3 py-3">
                  <span className="text-xs text-text-secondary">{entry.ArtifactCount}</span>
                </td>
                <td className="px-3 py-3">
                  <RuntimeUnusedRepoStatusBadge />
                </td>
                <td className="px-3 py-3 text-right">
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

function buildInactiveVEXPrompt(entries: VEXSummary[]): string {
  if (!entries || entries.length === 0) {
    return '';
  }

  const lines = entries
    .slice()
    .sort((a, b) => a.CVEID.localeCompare(b.CVEID))
    .map(entry => `- ${entry.CVEID} | state=${entry.State}`);

  return [
    'Update suppline.yml x-vex entries based on this inactive VEX review. Remove the following VEX Entries from all sync entries:',
    ...lines,
  ].join('\n');
}

function VEXExpiryTask({ data, inactiveEntries }: { data: VEXExpiryTasksResponse; inactiveEntries: VEXSummary[] }) {
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);

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
  const expiryPrompt = data.ai_agent_prompt.trim();
  const inactivePrompt = buildInactiveVEXPrompt(inactiveEntries).trim();
  const combinedPrompt = [
    expiryPrompt && `Expiry-related VEX review tasks:\n${expiryPrompt}`,
    inactivePrompt && `Inactive VEX review tasks:\n${inactivePrompt}`,
  ].filter(Boolean).join('\n\n---\n\n');
  const hasUpdates = combinedPrompt.length > 0;
  const showPromptHint = inactiveCount > 0
    ? 'Ready to review inactive, expired, and expiring VEX statements.'
    : 'Ready to review and fix expiring VEX statements.';

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 items-start">
        <div className="lg:col-span-2 space-y-2">
          {inactiveCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-warning-bg border border-warning/20 text-sm text-warning">
              <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              <span>
                {inactiveCount} VEX {inactiveCount === 1 ? 'statement is' : 'statements are'} inactive and should be removed or narrowed.
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
        </div>

        {hasUpdates && (
          <TaskPromptCard
            hint={showPromptHint}
            onCopy={() => {
              copyToClipboard(combinedPrompt).then(ok =>
                toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
              );
            }}
          />
        )}
      </div>

      {hasExpiryEntries && (
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-text-muted">Showing {displayedEntries.length} of {data.entries.length} expiring or expired entries</p>
          <button
            onClick={() => setShowAll(v => !v)}
            className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary flex items-center gap-1.5 transition-colors"
          >
            {showAll ? 'Show less' : 'Show more'}
          </button>
        </div>
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
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── page ─────────────────────────────────────────────────────────────────────

export default function TasksPage() {
  const { apiClient } = useAuth();
  const location = useLocation();
  const [semverData, setSemverData] = useState<SemverUpdateTasksResponse | null>(null);
  const [runtimeUnusedData, setRuntimeUnusedData] = useState<RepositoriesResponse | null>(null);
  const [vexExpiryData, setVexExpiryData] = useState<VEXExpiryTasksResponse | null>(null);
  const [inactiveVEXData, setInactiveVEXData] = useState<VEXSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [semverResult, runtimeUnusedResult, vexExpiryResult, inactiveVEXResult] = await Promise.all([
        apiClient.getSemverUpdateTasks(),
        loadAllRuntimeUnusedRepositories(apiClient),
        apiClient.getVEXExpiryTasks(),
        apiClient.getInactiveVEXStatements(),
      ]);
      setSemverData(semverResult);
      setRuntimeUnusedData(runtimeUnusedResult);
      setVexExpiryData(vexExpiryResult);
      setInactiveVEXData(inactiveVEXResult);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load tasks');
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { load(); }, [load]);

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
          showImageUsage={false}
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
        {semverData ? <SemverUpdateTask data={semverData} /> : null}
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
        {runtimeUnusedData ? <RuntimeUnusedRepositoryTask data={runtimeUnusedData} /> : null}
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
        {vexExpiryData ? <VEXExpiryTask data={vexExpiryData} inactiveEntries={inactiveVEXData} /> : null}
      </TaskSection>
    </div>
  );
}
