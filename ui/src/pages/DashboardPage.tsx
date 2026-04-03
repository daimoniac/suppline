import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, truncateDigest, copyToClipboard } from '../lib/utils';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { LoadingState, ErrorState, StatusBadge, SeverityBadge, VulnCounts } from '../components/ui';
import type { Scan, Toleration } from '../lib/api';
import {
  ShieldAlert, FileWarning, Clock, CheckSquare,
  Copy, ExternalLink,
} from 'lucide-react';

interface DashboardData {
  recentScans: Scan[];
  failedCount: number;
  activeTolerations: number;
  expiringTolerations: Toleration[];
  expiredTolerations: Toleration[];
  inactiveTolerations: Toleration[];
  vulnBreakdown: { critical: number; high: number; medium: number; low: number };
  failedByRepo: Record<string, number>;
}

export default function DashboardPage() {
  const { apiClient } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { inUseQuery } = useImageUsageFilter();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [recentScans, failedScans, allTolerations, inactiveTolerations, vulnStats] = await Promise.all([
        apiClient.getScans({ limit: 20, ...(inUseQuery !== undefined && { in_use: inUseQuery }) }),
        apiClient.getScans({ policy_passed: false, ...(inUseQuery !== undefined && { in_use: inUseQuery }) }),
        apiClient.getTolerations({}),
        apiClient.getInactiveTolerations(),
        apiClient.getVulnerabilityStats(),
      ]);

      const now = Date.now();
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      const expired = allTolerations.filter(t => t.ExpiresAt && t.ExpiresAt * 1000 <= now);
      const expiring = allTolerations.filter(t => {
        if (!t.ExpiresAt) return false;
        const ms = t.ExpiresAt * 1000;
        return ms > now && ms <= now + sevenDays;
      });

      const failedByRepo: Record<string, number> = {};
      failedScans.forEach(s => { failedByRepo[s.Repository || 'unknown'] = (failedByRepo[s.Repository || 'unknown'] || 0) + 1; });

      setData({
        recentScans,
        failedCount: failedScans.length,
        activeTolerations: allTolerations.length,
        expiringTolerations: expiring,
        expiredTolerations: expired,
        inactiveTolerations,
        vulnBreakdown: {
          critical: vulnStats?.CRITICAL || 0,
          high: vulnStats?.HIGH || 0,
          medium: vulnStats?.MEDIUM || 0,
          low: vulnStats?.LOW || 0,
        },
        failedByRepo,
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
  const attentionCount = data.expiredTolerations.length + data.expiringTolerations.length + data.inactiveTolerations.length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Security Dashboard</h1>
        <p className="text-sm text-text-secondary mt-1">Container image security overview</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard icon={<ShieldAlert className="w-5 h-5" />} value={data.failedCount} label="Policy Failures" variant="danger" onClick={() => navigate('/failed')} />
        <SummaryCard icon={<FileWarning className="w-5 h-5" />} value={data.activeTolerations} label="Active Tolerations" variant="info" onClick={() => navigate('/tolerations')} />
        <SummaryCard icon={<Clock className="w-5 h-5" />} value={data.expiringTolerations.length} label="Expiring Soon" variant="warning" onClick={() => navigate('/tolerations?expiration_status=expiring')} />
        <SummaryCard icon={<CheckSquare className="w-5 h-5" />} value={data.inactiveTolerations.length} label="Inactive Tolerations" variant="muted" />
      </div>

      {/* Tolerations Attention */}
      {attentionCount > 0 && (
        <div className="bg-bg-primary border border-border rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-3">Tolerations Requiring Attention</h2>
          <div className="flex gap-2 mb-4 flex-wrap">
            {data.expiredTolerations.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-danger-bg text-danger">{data.expiredTolerations.length} Expired</span>}
            {data.expiringTolerations.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-warning-bg text-warning">{data.expiringTolerations.length} Expiring Soon</span>}
            {data.inactiveTolerations.length > 0 && <span className="px-2 py-1 rounded text-xs font-medium bg-bg-tertiary text-text-secondary">{data.inactiveTolerations.length} Inactive</span>}
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {data.expiredTolerations.slice(0, 5).map(t => (
              <TolerationAttentionItem key={`exp-${t.CVEID}`} toleration={t} status="expired" onClick={() => navigate(`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`)} />
            ))}
            {data.expiringTolerations.slice(0, 5).map(t => (
              <TolerationAttentionItem key={`expiring-${t.CVEID}`} toleration={t} status="expiring" onClick={() => navigate(`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`)} />
            ))}
            {data.inactiveTolerations.slice(0, 3).map(t => (
              <TolerationAttentionItem key={`inactive-${t.CVEID}`} toleration={t} status="inactive" onClick={() => navigate(`/vulnerabilities?cve_id=${encodeURIComponent(t.CVEID)}`)} />
            ))}
          </div>
        </div>
      )}

      {/* Vulnerability Breakdown */}
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
              <div key={sev} className="text-center cursor-pointer rounded-lg p-2 -m-2 hover:bg-bg-secondary transition-colors"
                onClick={() => navigate(`/vulnerabilities?severity=${sev}`)}>
                <SeverityBadge severity={sev} />
                <div className="text-lg font-bold mt-1">{data.vulnBreakdown[sev]}</div>
                <div className="text-xs text-text-muted">{totalVulns > 0 ? ((data.vulnBreakdown[sev] / totalVulns) * 100).toFixed(0) : 0}%</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Failed by Repository */}
      <div className="bg-bg-primary border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4">Policy Compliance Status</h2>
        {Object.keys(data.failedByRepo).length === 0 ? (
          <div className="text-center py-8">
            <div className="text-3xl mb-2">🎆</div>
            <h3 className="font-semibold text-accent">All Compliant</h3>
            <p className="text-sm text-text-secondary">All images pass policy evaluation</p>
          </div>
        ) : (
          <div className="space-y-2">
            {Object.entries(data.failedByRepo).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([repo, count]) => {
              const max = Math.max(...Object.values(data.failedByRepo));
              return (
                <div key={repo} className="flex items-center gap-3 cursor-pointer hover:bg-bg-secondary rounded px-2 py-1 transition-colors" onClick={() => navigate(`/repositories/${encodeURIComponent(repo)}`)}>
                  <span className="text-sm text-text-primary truncate w-48 flex-shrink-0">{repo}</span>
                  <div className="flex-1 h-2 bg-bg-tertiary rounded-full overflow-hidden">
                    <div className="h-full bg-danger rounded-full transition-all" style={{ width: `${(count / max) * 100}%` }} />
                  </div>
                  <span className="text-sm font-medium text-text-secondary w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Recent Scans */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold">Recent Scans</h2>
        </div>
        {data.recentScans.length === 0 ? (
          <div className="p-8 text-center text-text-secondary text-sm">No scans found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Repository</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Tag</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Digest</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Scanned</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Vulns</th>
                </tr>
              </thead>
              <tbody>
                {data.recentScans.map(scan => (
                  <tr key={scan.Digest} className="border-b border-border/50 hover:bg-bg-secondary cursor-pointer transition-colors" onClick={() => navigate(`/scans/${scan.Digest}`)}>
                    <td className="px-4 py-3 text-sm">
                      <span className="text-accent hover:underline cursor-pointer" onClick={e => { e.stopPropagation(); navigate(`/repositories/${encodeURIComponent(scan.Repository)}`); }}>
                        {scan.Repository || 'N/A'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">{scan.Tag || 'N/A'}</td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center gap-1">
                        <code className="text-xs text-text-muted font-mono">{truncateDigest(scan.Digest)}</code>
                        <button className="text-text-muted hover:text-text-primary p-0.5" onClick={e => { e.stopPropagation(); copyToClipboard(scan.Digest).then(ok => toast(ok ? 'Copied!' : 'Failed to copy', ok ? 'success' : 'error')); }}>
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">{formatRelativeTime(scan.CreatedAt)}</td>
                    <td className="px-4 py-3"><StatusBadge passed={scan.PolicyPassed} /></td>
                    <td className="px-4 py-3">
                      <VulnCounts critical={scan.CriticalVulnCount} high={scan.HighVulnCount} medium={scan.MediumVulnCount} low={scan.LowVulnCount} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function SummaryCard({ icon, value, label, variant, onClick }: {
  icon: React.ReactNode; value: number; label: string;
  variant: 'danger' | 'warning' | 'info' | 'muted';
  onClick?: () => void;
}) {
  const colors = {
    danger: 'border-danger/20 hover:border-danger/40',
    warning: 'border-warning/20 hover:border-warning/40',
    info: 'border-info/20 hover:border-info/40',
    muted: 'border-border hover:border-border-hover',
  };
  const iconColors = { danger: 'text-danger', warning: 'text-warning', info: 'text-info', muted: 'text-text-secondary' };

  return (
    <div
      onClick={onClick}
      className={`bg-bg-primary border ${colors[variant]} rounded-xl p-4 ${onClick ? 'cursor-pointer' : ''} transition-colors`}
    >
      <div className={`${iconColors[variant]} mb-3`}>{icon}</div>
      <div className="text-2xl font-bold">{value.toLocaleString()}</div>
      <div className="text-xs text-text-secondary mt-0.5">{label}</div>
    </div>
  );
}

function TolerationAttentionItem({ toleration, status, onClick }: {
  toleration: Toleration; status: 'expired' | 'expiring' | 'inactive'; onClick: () => void;
}) {
  const repos = toleration.Repositories || [];
  const repoDisplay = repos.length === 0 ? 'No repositories' : repos.length <= 3 ? repos.map(r => r.Repository).join(', ') : 'multiple repos';
  const statusConfig = {
    expired: { badge: 'bg-danger-bg text-danger', label: '⚠️ EXPIRED' },
    expiring: { badge: 'bg-warning-bg text-warning', label: '⏰ Expiring' },
    inactive: { badge: 'bg-bg-tertiary text-text-secondary', label: '📋 Inactive' },
  };

  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-bg-secondary hover:bg-bg-tertiary cursor-pointer transition-colors" onClick={onClick}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-mono font-medium">{toleration.CVEID}</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${statusConfig[status].badge}`}>{statusConfig[status].label}</span>
        </div>
        <div className="text-xs text-text-muted truncate">{repoDisplay}</div>
        {toleration.Statement && <div className="text-xs text-text-secondary mt-1 truncate">{toleration.Statement}</div>}
      </div>
      <ExternalLink className="w-3.5 h-3.5 text-text-muted flex-shrink-0 mt-1" />
    </div>
  );
}
