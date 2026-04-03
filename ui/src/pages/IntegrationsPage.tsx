import { useEffect, useState } from 'react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { copyToClipboard, formatDate, formatRelativeTime } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader } from '../components/ui';
import type { KubernetesClusterSummary } from '../lib/api';
import { Boxes, Copy, Download, Key, Shield } from 'lucide-react';

export default function IntegrationsPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [publicKey, setPublicKey] = useState('');
  const [kyvernoPolicy, setKyvernoPolicy] = useState('');
  const [clusters, setClusters] = useState<KubernetesClusterSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [clusterData, key, policy] = await Promise.all([
        apiClient.getKubernetesClusters().catch(() => []),
        apiClient.getPublicKey().catch(() => ''),
        apiClient.getKyvernoPolicy().catch(() => ''),
      ]);
      setClusters(clusterData);
      setPublicKey(key);
      setKyvernoPolicy(policy);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []); // eslint-disable-line

  const handleCopy = async (text: string, label: string) => {
    const ok = await copyToClipboard(text);
    toast(ok ? `${label} copied!` : 'Copy failed', ok ? 'success' : 'error');
  };

  const handleDownload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Downloaded ${filename}`, 'success');
  };

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-6">
      <PageHeader title="Integrations" subtitle="Export keys and policies for Kubernetes integration" />

      {/* Kubernetes */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Boxes className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold">Kubernetes Clusters</h2>
          </div>
          {clusters.length > 0 && (
            <span className="text-xs text-text-muted">{clusters.length} cluster{clusters.length === 1 ? '' : 's'}</span>
          )}
        </div>
        <div className="p-4">
          {clusters.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Cluster</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Latest Sync</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Images</th>
                  </tr>
                </thead>
                <tbody>
                  {clusters.map(cluster => (
                    <tr key={cluster.Name} className="border-b border-border/50 last:border-0">
                      <td className="px-3 py-3 text-text-primary font-medium">{cluster.Name}</td>
                      <td className="px-3 py-3 text-text-secondary" title={cluster.LastReported ? formatDate(cluster.LastReported) : 'N/A'}>
                        {cluster.LastReported ? formatRelativeTime(cluster.LastReported) : 'Never'}
                      </td>
                      <td className="px-3 py-3 text-text-secondary">{cluster.ImageCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-text-muted">not integrated</p>
          )}
        </div>
      </div>

      {/* Public Key */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold">Cosign Public Key</h2>
          </div>
          <div className="flex gap-2">
            <button onClick={() => handleCopy(publicKey, 'Public key')} disabled={!publicKey}
              className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 flex items-center gap-1 transition-colors">
              <Copy className="w-3 h-3" /> Copy
            </button>
            <button onClick={() => handleDownload(publicKey, 'cosign.pub')} disabled={!publicKey}
              className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 flex items-center gap-1 transition-colors">
              <Download className="w-3 h-3" /> Download
            </button>
          </div>
        </div>
        <div className="p-4">
          {publicKey ? (
            <pre className="text-xs font-mono text-text-secondary bg-bg-secondary p-4 rounded-lg overflow-x-auto whitespace-pre">{publicKey}</pre>
          ) : (
            <p className="text-sm text-text-muted p-4">No public key available. Configure the attestation key to enable signing.</p>
          )}
        </div>
      </div>

      {/* Kyverno Policy */}
      <div className="bg-bg-primary border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-accent" />
            <h2 className="text-sm font-semibold">Kyverno ClusterPolicy</h2>
          </div>
          <div className="flex gap-2">
            <button onClick={() => handleCopy(kyvernoPolicy, 'Policy')} disabled={!kyvernoPolicy}
              className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 flex items-center gap-1 transition-colors">
              <Copy className="w-3 h-3" /> Copy
            </button>
            <button onClick={() => handleDownload(kyvernoPolicy, 'kyverno-policy.yaml')} disabled={!kyvernoPolicy}
              className="px-3 py-1.5 text-xs rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 flex items-center gap-1 transition-colors">
              <Download className="w-3 h-3" /> Download
            </button>
          </div>
        </div>
        <div className="p-4">
          {kyvernoPolicy ? (
            <pre className="text-xs font-mono text-text-secondary bg-bg-secondary p-4 rounded-lg overflow-x-auto whitespace-pre max-h-96">{kyvernoPolicy}</pre>
          ) : (
            <p className="text-sm text-text-muted p-4">No Kyverno policy available. Configure attestation to generate policy.</p>
          )}
        </div>
      </div>
    </div>
  );
}
