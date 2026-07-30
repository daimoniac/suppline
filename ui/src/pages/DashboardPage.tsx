import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useAuth } from '../lib/auth';
import { formatRelativeTime, countActionableRuntimeUnusedRepositories } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { fetchPolicyComplianceData, type PolicyComplianceSnapshot } from '../lib/policyComplianceData';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { LoadingState, ErrorState, StatusBadge, VulnCounts, DigestLinkWithCopy } from '../components/ui';
import { PolicyCompliancePanel } from '../components/PolicyCompliancePanel';
import type { CoverageResponse, PoliciesResponse, Scan, SemverUpdateTasksResponse, VEXExpiryTasksResponse } from '../lib/api';
import { ShieldAlert, ShieldCheck, Clock, Clock3, ArrowRight, ClipboardList, Sparkles, Trash2, TriangleAlert, Radar, Server } from 'lucide-react';

interface DashboardData {
  recentScans: Scan[];
  policy: PolicyComplianceSnapshot;
  failedCount: number;
  failedInUseCount: number;
  pendingCount: number;
  activeVEXStatements: number;
  inactiveVEXStatements: number;
  coverage: CoverageResponse;
  outOfBoundsTaskCount: number;
  tightenTaskCount: number;
  runtimeUnusedTaskCount: number;
  vexExpiredTaskCount: number;
  vexExpiringSoonTaskCount: number;
  defaultPolicy: PoliciesResponse['Default'];
}

function emptyCoverage(): CoverageResponse {
  return {
    Clusters: [],
    DueForRescanCount: 0,
    StaleAfterSeconds: 24 * 60 * 60,
    StaleClusterCount: 0,
  };
}

function isClusterStale(lastReported: number | undefined, staleAfterSeconds: number, nowSeconds: number): boolean {
  if (lastReported == null) return true;
  return lastReported < nowSeconds - staleAfterSeconds;
}

export default function DashboardPage() {
  const { apiClient } = useAuth();
  const { inUseRequestParams } = useImageUsageFilter();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [recentScans, policySnap, allVEXStatements, inactiveVEXStatements, coverage, semverTasksResult, runtimeUnusedReposResult, runtimeUnusedWhitelistResult, vexExpiryTasksResult, policies] = await Promise.all([
        apiClient.getScans({ limit: 20, ...(inUseRequestParams && inUseRequestParams) }),
        fetchPolicyComplianceData(apiClient, inUseRequestParams),
        apiClient.getVEXStatements({}),
        apiClient.getInactiveVEXStatements(),
        apiClient.getCoverage().catch(() => emptyCoverage()),
        apiClient.getSemverUpdateTasks().catch(() => null as SemverUpdateTasksResponse | null),
        // limit=1: only need Total for the unused-task badge (full list lives on /tasks).
        apiClient.getRepositories({ in_use_mode: 'not_in_use', limit: 1 }).catch(() => null),
        apiClient.getRuntimeUnusedWhitelist().catch(() => ({ repositories: [] })),
        apiClient.getVEXExpiryTasks().catch(() => null as VEXExpiryTasksResponse | null),
        apiClient.getPolicies().catch(() => ({}) as PoliciesResponse),
      ]);

      const runtimeUnusedTaskCount = runtimeUnusedReposResult
        ? countActionableRuntimeUnusedRepositories(
          runtimeUnusedReposResult.Total,
          runtimeUnusedWhitelistResult.repositories,
        )
        : 0;
      const outOfBoundsTaskCount = semverTasksResult?.entries?.filter(entry => entry.status === 'out_of_bounds').length ?? 0;
      const tightenTaskCount = semverTasksResult?.entries?.filter(entry => entry.status === 'tighten').length ?? 0;
      const vexExpiredTaskCount = vexExpiryTasksResult?.entries?.filter(entry => entry.status === 'expired').length ?? 0;
      const vexExpiringSoonTaskCount = vexExpiryTasksResult?.entries?.filter(entry => entry.status === 'expiring_soon').length ?? 0;

      setData({
        recentScans,
        policy: policySnap,
        failedCount: policySnap.failedCount,
        failedInUseCount: policySnap.failedInUseCount,
        pendingCount: policySnap.pendingCount,
        activeVEXStatements: allVEXStatements.length,
        inactiveVEXStatements: inactiveVEXStatements.length,
        coverage,
        outOfBoundsTaskCount,
        tightenTaskCount,
        runtimeUnusedTaskCount,
        vexExpiredTaskCount,
        vexExpiringSoonTaskCount,
        defaultPolicy: policies.Default ?? null,
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { scheduleEffectLoad(load); }, [inUseRequestParams]); // eslint-disable-line react-hooks/exhaustive-deps -- reload when usage filter changes

  if (loading) return <LoadingState message="Loading dashboard…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!data) return null;

  const nowSeconds = Math.floor(Date.now() / 1000);
  const clusters = data.coverage.Clusters ?? [];
  const staleAfter = data.coverage.StaleAfterSeconds || 24 * 60 * 60;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Security Dashboard</h1>
        <p className="text-sm text-text-secondary mt-1">Container image security overview</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <SummaryCard
          icon={<ShieldAlert className="w-5 h-5" />}
          value={data.failedCount}
          label="Policy Failures"
          detail={`${data.failedInUseCount} in use`}
          variant="danger"
          to="/failed"
        />
        <SummaryCard icon={<Clock className="w-5 h-5" />} value={data.pendingCount} label="Pending Release" variant="warning" detail="Waiting to mature" />
        <SummaryCard icon={<ShieldCheck className="w-5 h-5" />} value={data.activeVEXStatements} label="Active VEX Statements" variant="info" to="/vex" />
      </div>

      {(data.outOfBoundsTaskCount > 0 || data.tightenTaskCount > 0 || data.runtimeUnusedTaskCount > 0 || data.vexExpiredTaskCount > 0 || data.vexExpiringSoonTaskCount > 0 || data.inactiveVEXStatements > 0) && (
        <div className="bg-bg-primary border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <ClipboardList className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold">Task Notifications</h2>
          </div>
          <div className="space-y-2">
            {data.inactiveVEXStatements > 0 && (
              <Link
                to="/tasks#vex-review"
                className="flex items-center justify-between gap-3 rounded-lg border border-warning/30 bg-warning-bg px-3 py-2 text-sm text-warning hover:brightness-95 transition"
              >
                <span>
                  {data.inactiveVEXStatements} VEX {data.inactiveVEXStatements === 1 ? 'statement is' : 'statements are'} inactive and should be reviewed.
                </span>
                <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              </Link>
            )}
            {data.vexExpiredTaskCount > 0 && (
              <Link
                to="/tasks#vex-review"
                className="flex items-center justify-between gap-3 rounded-lg border border-danger/30 bg-danger-bg px-3 py-2 text-sm text-danger hover:brightness-95 transition"
              >
                <span>
                  {data.vexExpiredTaskCount} VEX {data.vexExpiredTaskCount === 1 ? 'statement is' : 'statements are'} expired and needs review.
                </span>
                <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              </Link>
            )}
            {data.vexExpiringSoonTaskCount > 0 && (
              <Link
                to="/tasks#vex-review"
                className="flex items-center justify-between gap-3 rounded-lg border border-warning/30 bg-warning-bg px-3 py-2 text-sm text-warning hover:brightness-95 transition"
              >
                <span>
                  {data.vexExpiringSoonTaskCount} VEX {data.vexExpiringSoonTaskCount === 1 ? 'statement is' : 'statements are'} expiring within 7 days.
                </span>
                <Clock3 className="w-4 h-4 flex-shrink-0" />
              </Link>
            )}
            {data.runtimeUnusedTaskCount > 0 && (
              <Link
                to="/tasks#unused-sync-repositories"
                className="flex items-center justify-between gap-3 rounded-lg border border-warning/30 bg-warning-bg px-3 py-2 text-sm text-warning hover:brightness-95 transition"
              >
                <span>
                  {data.runtimeUnusedTaskCount} sync {data.runtimeUnusedTaskCount === 1 ? 'entry is' : 'entries are'} configured but not observed in runtime inventory.
                </span>
                <Trash2 className="w-4 h-4 flex-shrink-0" />
              </Link>
            )}
            {data.outOfBoundsTaskCount > 0 && (
              <Link
                to="/tasks#semver-range-updates"
                className="flex items-center justify-between gap-3 rounded-lg border border-warning/30 bg-warning-bg px-3 py-2 text-sm text-warning hover:brightness-95 transition"
              >
                <span>
                  {data.outOfBoundsTaskCount} sync {data.outOfBoundsTaskCount === 1 ? 'entry has' : 'entries have'} runtime versions outside the configured range.
                </span>
                <TriangleAlert className="w-4 h-4 flex-shrink-0" />
              </Link>
            )}
            {data.tightenTaskCount > 0 && (
              <Link
                to="/tasks#semver-range-updates"
                className="flex items-center justify-between gap-3 rounded-lg border border-accent/20 bg-bg-secondary px-3 py-2 text-sm text-text-secondary hover:bg-bg-tertiary transition"
              >
                <span>
                  {data.tightenTaskCount} sync {data.tightenTaskCount === 1 ? 'entry has' : 'entries have'} optional range tightening suggestions based on currently running versions.
                </span>
                <Sparkles className="w-4 h-4 flex-shrink-0 text-accent" />
              </Link>
            )}
          </div>
        </div>
      )}

      <PolicyCompliancePanel
        policyByRepo={data.policy.policyByRepo}
        failedScans={data.policy.failedScans}
        defaultPolicy={data.defaultPolicy}
      />

      <div className="bg-bg-primary border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Coverage & Freshness</h2>
            <p className="text-xs text-text-muted mt-1">Runtime inventory sync and scan schedule health</p>
          </div>
          <Link to="/integrations" className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:text-accent-hover transition-colors">
            Integrations
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="rounded-lg border border-border bg-bg-secondary/40 px-3 py-3">
            <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
              <Server className="w-3.5 h-3.5" />
              Clusters
            </div>
            <div className="text-xl font-bold">{clusters.length}</div>
          </div>
          <div className={`rounded-lg border px-3 py-3 ${data.coverage.StaleClusterCount > 0 ? 'border-warning/30 bg-warning-bg' : 'border-border bg-bg-secondary/40'}`}>
            <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
              <Radar className="w-3.5 h-3.5" />
              Stale inventory
            </div>
            <div className={`text-xl font-bold ${data.coverage.StaleClusterCount > 0 ? 'text-warning' : ''}`}>
              {data.coverage.StaleClusterCount}
            </div>
            <div className="text-xs text-text-muted mt-1">No sync in {Math.round(staleAfter / 3600)}h</div>
          </div>
          <div className={`rounded-lg border px-3 py-3 ${data.coverage.DueForRescanCount > 0 ? 'border-warning/30 bg-warning-bg' : 'border-border bg-bg-secondary/40'}`}>
            <div className="flex items-center gap-2 text-text-secondary text-xs mb-1">
              <Clock className="w-3.5 h-3.5" />
              Due for rescan
            </div>
            <div className={`text-xl font-bold ${data.coverage.DueForRescanCount > 0 ? 'text-warning' : ''}`}>
              {data.coverage.DueForRescanCount.toLocaleString()}
            </div>
            <div className="text-xs text-text-muted mt-1">Digests past next_scan_at</div>
          </div>
        </div>

        {clusters.length === 0 ? (
          <div className="rounded-lg border border-border bg-bg-secondary/30 px-4 py-6 text-center text-sm text-text-secondary">
            No cluster inventory reported yet. Connect a clusterstate agent under Integrations.
          </div>
        ) : (
          <div className="space-y-2">
            {clusters
              .slice()
              .sort((a, b) => (b.LastReported ?? 0) - (a.LastReported ?? 0))
              .map(cluster => {
                const stale = isClusterStale(cluster.LastReported, staleAfter, nowSeconds);
                return (
                  <div
                    key={cluster.Name}
                    className={`flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm ${stale ? 'border-warning/30 bg-warning-bg/40' : 'border-border bg-bg-secondary/30'}`}
                  >
                    <div className="min-w-0">
                      <div className="font-medium truncate">{cluster.Name}</div>
                      <div className="text-xs text-text-muted">
                        {cluster.ImageCount.toLocaleString()} image{cluster.ImageCount === 1 ? '' : 's'}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-xs ${stale ? 'text-warning' : 'text-text-secondary'}`}>
                        {cluster.LastReported != null ? formatRelativeTime(cluster.LastReported) : 'Never synced'}
                      </div>
                      {stale && <div className="text-[11px] text-warning">Stale</div>}
                    </div>
                  </div>
                );
              })}
          </div>
        )}
      </div>

      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Recent Scans</h2>
            <p className="text-xs text-text-muted mt-1">Latest image analysis events across repositories</p>
          </div>
          <Link to="/scans" className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:text-accent-hover transition-colors">
            View all
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
        {data.recentScans.length === 0 ? (
          <div className="p-8 text-center text-text-secondary text-sm">No scans found</div>
        ) : (
          <div className="p-4 space-y-3">
            {data.recentScans.map(scan => (
              <div key={scan.Digest} className="rounded-lg border border-border bg-bg-secondary/40 hover:bg-bg-secondary hover:border-border-hover transition-colors p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link className="text-sm font-semibold text-accent hover:underline" to={`/repositories/${encodeURIComponent(scan.Repository)}`}>
                        {scan.Repository || 'N/A'}
                      </Link>
                      <span className="px-2 py-0.5 rounded text-xs bg-bg-tertiary text-text-secondary">{scan.Tag || 'untagged'}</span>
                    </div>
                    <div className="mt-2">
                      <DigestLinkWithCopy digest={scan.Digest} to={`/scans/${scan.Digest}`} />
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 lg:justify-end lg:text-right">
                    <span className="text-xs text-text-muted">{formatRelativeTime(scan.CreatedAt)}</span>
                    <StatusBadge passed={scan.PolicyPassed} status={scan.PolicyStatus} />
                    <div className="w-full lg:w-auto lg:pt-0 pt-1">
                      <VulnCounts critical={scan.CriticalVulnCount} high={scan.HighVulnCount} medium={scan.MediumVulnCount} low={scan.LowVulnCount} />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}

function SummaryCard({ icon, value, label, detail, variant, to }: {
  icon: React.ReactNode; value: number; label: string;
  detail?: string;
  variant: 'danger' | 'warning' | 'info' | 'muted';
  to?: string;
}) {
  const colors = { danger: 'border-danger/20 hover:border-danger/40', warning: 'border-warning/20 hover:border-warning/40', info: 'border-info/20 hover:border-info/40', muted: 'border-border hover:border-border-hover' };
  const iconColors = { danger: 'text-danger', warning: 'text-warning', info: 'text-info', muted: 'text-text-secondary' };
  const className = `bg-bg-primary border ${colors[variant]} rounded-xl p-4 transition-colors ${to ? 'cursor-pointer' : ''}`;
  const content = <><div className={`${iconColors[variant]} mb-3`}>{icon}</div><div className="text-2xl font-bold">{value.toLocaleString()}</div><div className="text-xs text-text-secondary mt-0.5">{label}</div>{detail && <div className="text-xs text-text-muted mt-1">{detail}</div>}</>;
  return to ? <Link to={to} className={className}>{content}</Link> : <div className={className}>{content}</div>;
}
