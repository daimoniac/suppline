import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { formatRelativeTime } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, StatusBadge, SeverityBadge, VulnCounts, DigestLinkWithCopy } from '../components/ui';
import type { Scan, VEXSummary } from '../lib/api';
import { ShieldAlert, ShieldCheck, Clock, CheckSquare, ExternalLink, ArrowRight } from 'lucide-react';

interface DashboardData {
  recentScans: Scan[];
  failedCount: number;
  failedInUseCount: number;
  pendingCount: number;
  activeVEXStatements: number;
  expiringVEXStatements: VEXSummary[];
  expiredVEXStatements: VEXSummary[];
  inactiveVEXStatements: VEXSummary[];
  vulnBreakdown: { critical: number; high: number; medium: number; low: number };
  policyByRepo: Record<string, { failed: number; pending: number }>;
}

export default function DashboardPage() {
  const { apiClient } = useAuth();
  const { inUseQuery } = useImageUsageFilter();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [recentScans, nonPassedScans, allVEXStatements, inactiveVEXStatements, vulnStats] = await Promise.all([
        apiClient.getScans({ limit: 20, ...(inUseQuery !== undefined && { in_use: inUseQuery }) }),
        apiClient.getScans({ policy_passed: false, ...(inUseQuery !== undefined && { in_use: inUseQuery }) }),
        apiClient.getVEXStatements({}),
        apiClient.getInactiveVEXStatements(),
        apiClient.getVulnerabilityStats(),
      ]);

      const now = Date.now();
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      const expired = allVEXStatements.filter(t => t.ExpiresAt && t.ExpiresAt * 1000 <= now);
      const expiring = allVEXStatements.filter(t => {
        if (!t.ExpiresAt) return false;
        const ms = t.ExpiresAt * 1000;
        return ms > now && ms <= now + sevenDays;
      });

      const failedScans = nonPassedScans.filter(s => s.PolicyStatus !== 'pending');
      const pendingScans = nonPassedScans.filter(s => s.PolicyStatus === 'pending');
      const policyByRepo = nonPassedScans.reduce<Record<string, { failed: number; pending: number }>>((acc, scan) => {
        const repo = scan.Repository || 'unknown';
        acc[repo] ||= { failed: 0, pending: 0 };
        if (scan.PolicyStatus === 'pending') acc[repo].pending += 1;
        else acc[repo].failed += 1;
        return acc;
      }, {});

      setData({
        recentScans,
        failedCount: failedScans.length,
        failedInUseCount: failedScans.filter(s => !!s.RuntimeUsed).length,
        pendingCount: pendingScans.length,
        activeVEXStatements: allVEXStatements.length,
        expiringVEXStatements: expiring,
        expiredVEXStatements: expired,
        inactiveVEXStatements: inactiveVEXStatements,
        vulnBreakdown: {
          critical: vulnStats?.CRITICAL || 0,
          high: vulnStats?.HIGH || 0,
          medium: vulnStats?.MEDIUM || 0,
          low: vulnStats?.LOW || 0,
        },
        policyByRepo,
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [inUseQuery]); // eslint-disable-line

  if (loading) return <LoadingState message="Loading dashboard…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!data) return null;

  const totalVulns = data.vulnBreakdown.critical + data.vulnBreakdown.high + data.vulnBreakdown.medium + data.vulnBreakdown.low;
  const attentionCount = data.expiredVEXStatements.length + data.expiringVEXStatements.length + data.inactiveVEXStatements.length;
  const topPolicyRepos = Object.entries(data.policyByRepo)
    .sort((a, b) => (b[1].failed + b[1].pending) - (a[1].failed + a[1].pending))
    .slice(0, 5);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Security Dashboard</h1>
        <p className="text-sm text-text-secondary mt-1">Container image security overview</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
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
        <SummaryCard icon={<CheckSquare className="w-5 h-5" />} value={data.inactiveVEXStatements.length} label="Inactive VEX Statements" variant="muted" />
      </div>

      {attentionCount > 0 && (
        <div className="bg-bg-primary border border-border rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-3">VEX Statements Requiring Attention</h2>
          <div className="flex gap-2 mb-4 flex-wrap">
            {data.expiredVEXStatements.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-danger-bg text-danger">{data.expiredVEXStatements.length} Expired</span>}
            {data.expiringVEXStatements.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-warning-bg text-warning">{data.expiringVEXStatements.length} Expiring Soon</span>}
            {data.inactiveVEXStatements.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-bg-tertiary text-text-secondary">{data.inactiveVEXStatements.length} Inactive</span>}
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {data.expiredVEXStatements.slice(0, 5).map(t => (
              <VEXAttentionItem key={`exp-${t.CVEID}`} statement={t} status="expired" to={`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`} />
            ))}
            {data.expiringVEXStatements.slice(0, 5).map(t => (
              <VEXAttentionItem key={`expiring-${t.CVEID}`} statement={t} status="expiring" to={`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`} />
            ))}
            {data.inactiveVEXStatements.slice(0, 3).map(t => (
              <VEXAttentionItem key={`inactive-${t.CVEID}`} statement={t} status="inactive" to={`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`} />
            ))}
          </div>
        </div>
      )}

      {totalVulns > 0 && (
        <div className="bg-bg-primary border border-border rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-4">Vulnerability Breakdown</h2>
          <div className="h-3 rounded-full overflow-hidden flex bg-bg-tertiary mb-4">
            {data.vulnBreakdown.critical > 0 && <div className="bg-severity-critical transition-all" style={{ width: `${(data.vulnBreakdown.critical / totalVulns) * 100}%` }} />}
            {data.vulnBreakdown.high > 0 && <div className="bg-severity-high transition-all" style={{ width: `${(data.vulnBreakdown.high / totalVulns) * 100}%` }} />}
            {data.vulnBreakdown.medium > 0 && <div className="bg-severity-medium transition-all" style={{ width: `${(data.vulnBreakdown.medium / totalVulns) * 100}%` }} />}
            {data.vulnBreakdown.low > 0 && <div className="bg-severity-low transition-all" style={{ width: `${(data.vulnBreakdown.low / totalVulns) * 100}%` }} />}
          </div>
          <div className="grid grid-cols-4 gap-4">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
              <Link key={sev} to={`/vulnerabilities?severity=${sev}`} className="text-center rounded-lg p-2 -m-2 hover:bg-bg-secondary transition-colors">
                <SeverityBadge severity={sev} />
                <div className="text-lg font-bold mt-1">{data.vulnBreakdown[sev]}</div>
                <div className="text-xs text-text-muted">{totalVulns > 0 ? ((data.vulnBreakdown[sev] / totalVulns) * 100).toFixed(0) : 0}%</div>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div className="bg-bg-primary border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4">Policy Compliance Status</h2>
        {Object.keys(data.policyByRepo).length === 0 ? (
          <div className="text-center py-8">
            <div className="text-3xl mb-2">🎆</div>
            <h3 className="font-semibold text-accent">All Compliant</h3>
            <p className="text-sm text-text-secondary">All images pass policy evaluation</p>
          </div>
        ) : (
          <div className="space-y-2">
            {topPolicyRepos.map(([repo, counts]) => {
              const max = Math.max(...Object.values(data.policyByRepo).map(v => v.failed + v.pending));
              const total = counts.failed + counts.pending;
              const failedWidth = total > 0 ? (counts.failed / total) * 100 : 0;
              const pendingWidth = total > 0 ? (counts.pending / total) * 100 : 0;
              return (
                <Link key={repo} to={`/repositories/${encodeURIComponent(repo)}`} className="flex items-center gap-3 hover:bg-bg-secondary rounded px-2 py-1 transition-colors">
                  <span className="text-sm text-text-primary truncate w-48 flex-shrink-0">{repo}</span>
                  <div className="flex-1 h-2 bg-bg-tertiary rounded-full overflow-hidden">
                    <div className="h-full flex transition-all" style={{ width: `${(total / max) * 100}%` }}>
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

function VEXAttentionItem({ statement, status, to }: {
  statement: VEXSummary; status: 'expired' | 'expiring' | 'inactive'; to: string;
}) {
  const repos = statement.Repositories || [];
  const repoDisplay = repos.length === 0 ? 'No repositories' : repos.length <= 3 ? repos.map(r => r.Repository).join(', ') : 'multiple repos';
  const statusConfig = { expired: { badge: 'bg-danger-bg text-danger', label: '⚠️ EXPIRED' }, expiring: { badge: 'bg-warning-bg text-warning', label: '⏰ Expiring' }, inactive: { badge: 'bg-bg-tertiary text-text-secondary', label: '📋 Inactive' } };

  return (
    <Link to={to} className="flex items-start gap-3 p-3 rounded-lg bg-bg-secondary hover:bg-bg-tertiary transition-colors">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-mono font-medium">{statement.CVEID}</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${statusConfig[status].badge}`}>{statusConfig[status].label}</span>
        </div>
        <div className="text-xs text-text-muted truncate">{repoDisplay}</div>
        {statement.Detail && <div className="text-xs text-text-secondary mt-1 truncate">{statement.Detail}</div>}
      </div>
      <ExternalLink className="w-3.5 h-3.5 text-text-muted flex-shrink-0 mt-1" />
    </Link>
  );
}
