import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { copyToClipboard } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader, EmptyState } from '../components/ui';
import type { SemverUpdateEntry, SemverUpdateTasksResponse } from '../lib/api';
import { ArrowRight, CheckCircle2, ClipboardList, Copy, RefreshCw, Server, Tag, TriangleAlert } from 'lucide-react';

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

// ─── semver update task card ──────────────────────────────────────────────────

function SemverUpdateTask({ data }: { data: SemverUpdateTasksResponse }) {
  const { toast } = useToast();
  const [configExpanded, setConfigExpanded] = useState(false);
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
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Source → Target</th>
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
                  <div className="flex items-center gap-1.5 text-xs font-mono">
                    <span className="text-text-secondary max-w-[14rem] truncate" title={entry.source}>{entry.source}</span>
                    <ArrowRight className="w-3 h-3 flex-shrink-0 text-text-muted" />
                    <span className="text-text-primary max-w-[14rem] truncate" title={entry.target}>{entry.target}</span>
                  </div>
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

      {hasUpdates && (
        <div className="border border-border rounded-lg overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-text-primary hover:bg-bg-tertiary transition-colors"
            onClick={() => setConfigExpanded(v => !v)}
            aria-expanded={configExpanded}
          >
            <span className="flex items-center gap-2">
              <ClipboardList className="w-4 h-4 text-accent" />
              AI Agent Prompt
            </span>
            <span className="text-xs text-text-muted">{configExpanded ? 'Hide' : 'Show'}</span>
          </button>
          {configExpanded && (
            <div className="border-t border-border">
              <div className="flex items-center justify-between px-4 py-2 bg-bg-secondary border-b border-border">
                <p className="text-xs text-text-muted">Use this prompt with your AI coding agent to apply the semverRange updates to suppline.yml.</p>
                <button
                  onClick={() => {
                    copyToClipboard(data.ai_agent_prompt).then(ok =>
                      toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
                    );
                  }}
                  className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary flex items-center gap-1.5 transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  Copy prompt
                </button>
              </div>
              <pre className="text-xs font-mono text-text-secondary bg-bg-secondary p-4 overflow-x-auto whitespace-pre max-h-[28rem]">
                {data.ai_agent_prompt}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── page ─────────────────────────────────────────────────────────────────────

export default function TasksPage() {
  const { apiClient } = useAuth();
  const [data, setData] = useState<SemverUpdateTasksResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await apiClient.getSemverUpdateTasks();
      setData(result);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load tasks');
    } finally {
      setLoading(false);
    }
  }, [apiClient]);

  useEffect(() => { load(); }, [load]);

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
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Tag className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold">SemVer Range Updates</h2>
          </div>
          <p className="text-xs text-text-muted">
            Sync entries with <code className="bg-bg-tertiary px-1 rounded">tags.semverRange</code> compared against runtime versions
          </p>
        </div>
        <div className="p-4">
          {loading ? (
            <LoadingState message="Checking runtime versions..." />
          ) : error ? (
            <ErrorState message={error} onRetry={load} />
          ) : data ? (
            <SemverUpdateTask data={data} />
          ) : null}
        </div>
      </div>
    </div>
  );
}
