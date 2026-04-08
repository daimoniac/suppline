import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { formatRelativeTime, formatDate, truncateDigest, copyToClipboard, daysUntilReleaseAge, formatRemainingDays, getRuntimeClusterCount, getRuntimeNamespaceEntries } from '../lib/utils';
import { LoadingState, ErrorState, StatusBadge, SeverityBadge } from '../components/ui';
import type { ScanDetail, Vulnerability } from '../lib/api';
import { ArrowLeft, RefreshCw, Copy, CheckCircle, XCircle, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';

export default function ScanDetailPage() {
  const { digest, name } = useParams<{ digest: string; name?: string }>();
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedSeverities, setExpandedSeverities] = useState<Set<string>>(new Set());
  const [expandedVEXStatements, setExpandedVEXStatements] = useState<Set<number>>(new Set());
  const [rescanning, setRescanning] = useState(false);

  const isArtifactView = !!name;

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await apiClient.getScanByDigest(digest || '');
      setScan(result);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load scan');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [digest]); // eslint-disable-line

  const handleRescan = async () => {
    if (!digest) return;
    setRescanning(true);
    try {
      const resp = await apiClient.triggerScan({ digest });
      toast(resp.message || 'Rescan triggered', 'success');
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : 'Failed', 'error');
    } finally {
      setRescanning(false);
    }
  };

  const toggleSeverity = (sev: string) => {
    setExpandedSeverities(prev => {
      const n = new Set(prev);
      if (n.has(sev)) n.delete(sev);
      else n.add(sev);
      return n;
    });
  };

  const toggleVEXStatement = (idx: number) => {
    setExpandedVEXStatements(prev => {
      const n = new Set(prev);
      if (n.has(idx)) n.delete(idx);
      else n.add(idx);
      return n;
    });
  };

  if (loading) return <LoadingState message="Loading scan details…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!scan) return null;

  const vexStatements = scan.AppliedVEXStatements || [];
  const exemptedIds = new Set(vexStatements.map(t => t.CVEID));
  const activeVulns = (scan.Vulnerabilities || []).filter(v => !exemptedIds.has(v.CVEID));
  const grouped = groupBySeverity(activeVulns);
  const runtimeEntries = getRuntimeNamespaceEntries(scan.Runtime);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to={isArtifactView ? `/repositories/${encodeURIComponent(name || '')}` : '/scans'} className="p-2 rounded-lg border border-border hover:bg-bg-tertiary transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">Scan Detail</h1>
          <p className="text-sm text-text-secondary">{scan.Repository}:{scan.Tag}</p>
        </div>
        <button onClick={handleRescan} disabled={rescanning} className="px-4 py-2 text-sm rounded-lg border border-warning/30 text-warning hover:bg-warning-bg flex items-center gap-2 disabled:opacity-50 transition-colors">
          <RefreshCw className={`w-4 h-4 ${rescanning ? 'animate-spin' : ''}`} /> {rescanning ? 'Rescanning…' : 'Trigger Rescan'}
        </button>
      </div>

      {/* Image Info */}
      <div className="bg-bg-primary border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4">Image Information</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <InfoItem label="Repository" value={
            <Link className="text-accent hover:underline" to={`/repositories/${encodeURIComponent(scan.Repository)}`}>{scan.Repository}</Link>
          } />
          <InfoItem label={scan.Tags && scan.Tags.length > 1 ? 'Tags' : 'Tag'} value={
            scan.Tags && scan.Tags.length > 0
              ? <div className="flex flex-wrap gap-1">{scan.Tags.map((t, i) => <code key={i} className="px-1.5 py-0.5 rounded bg-bg-tertiary text-xs">{t.Tag}</code>)}</div>
              : <span>{scan.Tag || 'N/A'}</span>
          } />
          <InfoItem label="Digest" value={
            <div className="flex items-center gap-1">
              <code className="text-xs text-text-muted font-mono">{truncateDigest(scan.Digest)}</code>
              <button className="text-text-muted hover:text-text-primary" onClick={() => copyToClipboard(scan.Digest).then(ok => toast(ok ? 'Copied!' : 'Failed', ok ? 'success' : 'error'))}>
                <Copy className="w-3 h-3" />
              </button>
            </div>
          } />
          <InfoItem label="Runtime" value={
            <div className="space-y-1">
              <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold ${scan.RuntimeUsed ? 'bg-success-bg text-success' : 'bg-bg-tertiary text-text-muted'}`}>
                {scan.RuntimeUsed ? `In use on ${getRuntimeClusterCount(scan.Runtime)} cluster(s)` : 'Not in use'}
              </span>
              {scan.RuntimeUsed && runtimeEntries.length > 0 && (
                <div className="space-y-2 text-xs text-text-secondary">
                  {runtimeEntries.map(({ cluster, namespace, images }) => (
                    <div key={`${cluster}-${namespace}`}>
                      <div className="font-medium text-text-primary">{cluster}/{namespace}</div>
                      <div className="mt-1 space-y-1">
                        {images.map((image, idx) => (
                          <div key={`${cluster}-${namespace}-${image.ImageRef}-${image.Tag}-${image.Digest}-${idx}`} className="font-mono text-[11px] text-text-secondary break-all">
                            {image.ImageRef}{image.Tag ? `:${image.Tag}` : ''}{image.Digest ? ` @ ${truncateDigest(image.Digest)}` : ''}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          } />
          <InfoItem label="Scanned" value={<span title={formatDate(scan.CreatedAt)}>{formatRelativeTime(scan.CreatedAt)}</span>} />
          <InfoItem label="Policy" value={
            <div className="flex flex-col gap-1">
              <StatusBadge
                passed={scan.PolicyPassed}
                status={scan.PolicyStatus}
                label={scan.PolicyStatus === 'pending' ? 'Pending Maturity' : undefined}
              />
              {scan.PolicyStatus === 'pending' && (
                <div className="text-xs text-warning font-medium">
                  {formatRemainingDays(daysUntilReleaseAge(scan.ReleaseAgeSeconds, scan.MinimumReleaseAgeSeconds))}
                </div>
              )}
            </div>
          } />
          <InfoItem label="Attestation" value={
            <div className="flex items-center gap-2">
              <AttestBadge label="SBOM" attested={scan.SBOMAttested} />
              <AttestBadge label="Vuln" attested={scan.VulnAttested} />
            </div>
          } />
        </div>
      </div>

      {/* Vulnerability Summary */}
      <div className="bg-bg-primary border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4">Vulnerability Summary</h2>
        <div className="grid grid-cols-4 gap-4">
          {[
            { sev: 'critical', count: scan.CriticalVulnCount },
            { sev: 'high', count: scan.HighVulnCount },
            { sev: 'medium', count: scan.MediumVulnCount },
            { sev: 'low', count: scan.LowVulnCount },
          ].map(i => (
            <div key={i.sev} className="text-center p-3 rounded-lg bg-bg-secondary">
              <SeverityBadge severity={i.sev} />
              <div className="text-xl font-bold mt-2">{i.count || 0}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerability Details */}
      {activeVulns.length > 0 && (
        <div className="bg-bg-primary border border-border rounded-xl p-5">
          <h2 className="text-sm font-semibold mb-4">Vulnerability Details</h2>
          <div className="space-y-2">
            {Object.entries(grouped).filter(([, vulns]) => vulns.length > 0).map(([sev, vulns]) => (
              <div key={sev} className="border border-border rounded-lg overflow-hidden">
                <button onClick={() => toggleSeverity(sev)} className="w-full flex items-center justify-between px-4 py-3 hover:bg-bg-secondary transition-colors">
                  <div className="flex items-center gap-2">
                    {expandedSeverities.has(sev) ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    <SeverityBadge severity={sev} />
                    <span className="text-sm text-text-secondary">{vulns.length} vulnerabilit{vulns.length !== 1 ? 'ies' : 'y'}</span>
                  </div>
                </button>
                {expandedSeverities.has(sev) && (
                  <div className="border-t border-border divide-y divide-border/50">
                    {vulns.map((v, i) => <VulnItem key={i} vuln={v} />)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VEX Statements */}
      <div className="bg-bg-primary border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold mb-4">Applied VEX Statements ({vexStatements.length})</h2>
        {vexStatements.length === 0 ? (
          <p className="text-sm text-text-secondary">No VEX statements applied</p>
        ) : (
          <div className="space-y-2">
            {vexStatements.map((stmt, idx) => {
              const mitigated = (scan.Vulnerabilities || []).filter(v => v.CVEID === stmt.CVEID);
              const isExpired = stmt.ExpiresAt && (stmt.ExpiresAt < 1e12 ? stmt.ExpiresAt * 1000 : stmt.ExpiresAt) <= Date.now();
              return (
                <div key={idx} className="border border-border rounded-lg overflow-hidden">
                  <button onClick={() => toggleVEXStatement(idx)} className="w-full flex items-center justify-between px-4 py-3 hover:bg-bg-secondary transition-colors">
                    <div className="flex items-center gap-3 min-w-0">
                      {expandedVEXStatements.has(idx) ? <ChevronDown className="w-4 h-4 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 flex-shrink-0" />}
                      <span className="text-sm font-mono font-medium">{stmt.CVEID}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${isExpired ? 'bg-danger-bg text-danger' : 'bg-success-bg text-success'}`}>
                        {isExpired ? 'EXPIRED' : 'ACTIVE'}
                      </span>
                      {stmt.State && <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-info-bg text-info">{stmt.State}</span>}
                    </div>
                    <span className="text-xs text-text-muted truncate max-w-sm">{stmt.Detail}</span>
                  </button>
                  {expandedVEXStatements.has(idx) && (
                    <div className="border-t border-border p-4 bg-bg-secondary">
                      <div className="text-xs text-text-secondary space-y-1 mb-3">
                        {stmt.State && <div><span className="text-text-muted">State:</span> {stmt.State}</div>}
                        {stmt.Justification && <div><span className="text-text-muted">Justification:</span> {stmt.Justification}</div>}
                        {stmt.Detail && <div><span className="text-text-muted">Detail:</span> {stmt.Detail}</div>}
                        <div><span className="text-text-muted">Applied:</span> {formatDate(stmt.AppliedAt)}</div>
                        <div><span className="text-text-muted">Expires:</span> {stmt.ExpiresAt ? formatDate(stmt.ExpiresAt) : 'Never'}</div>
                      </div>
                      {mitigated.length > 0 && (
                        <div>
                          <div className="text-xs font-medium text-text-secondary mb-2">Exempted Vulnerabilities ({mitigated.length})</div>
                          <div className="space-y-1">{mitigated.map((v, vi) => <VulnItem key={vi} vuln={v} compact />)}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function InfoItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs text-text-muted mb-1">{label}</div>
      <div className="text-sm">{value}</div>
    </div>
  );
}

function AttestBadge({ label, attested }: { label: string; attested: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${attested ? 'bg-success-bg text-success' : 'bg-danger-bg text-danger'}`}>
      {attested ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
      {label}
    </span>
  );
}

function VulnItem({ vuln, compact }: { vuln: Vulnerability; compact?: boolean }) {
  return (
    <div className={compact ? 'p-2 rounded bg-bg-tertiary' : 'px-4 py-3'}>
      <div className="flex items-start gap-2 mb-1">
        {compact && <SeverityBadge severity={vuln.Severity} />}
        <span className="text-sm font-medium">
          {vuln.PrimaryURL ? (
            <a href={vuln.PrimaryURL} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline flex items-center gap-1">
              {vuln.CVEID} <ExternalLink className="w-3 h-3" />
            </a>
          ) : vuln.CVEID}
        </span>
        {vuln.Title && <span className="text-xs text-text-secondary truncate">{vuln.Title}</span>}
      </div>
      <div className="flex gap-4 text-xs text-text-muted">
        <span><span className="text-text-secondary">Pkg:</span> {vuln.PackageName}</span>
        <span><span className="text-text-secondary">Ver:</span> {vuln.InstalledVersion}</span>
        {vuln.FixedVersion && <span className="text-accent"><span className="text-text-secondary">Fix:</span> {vuln.FixedVersion}</span>}
      </div>
      {!compact && vuln.Description && <p className="text-xs text-text-muted mt-1 line-clamp-2">{vuln.Description}</p>}
    </div>
  );
}

function groupBySeverity(vulns: Vulnerability[]): Record<string, Vulnerability[]> {
  const r: Record<string, Vulnerability[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  vulns.forEach(v => { const s = (v.Severity || 'LOW').toUpperCase(); (r[s] || (r[s] = [])).push(v); });
  return r;
}
