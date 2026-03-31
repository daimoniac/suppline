import { useEffect, useState } from 'react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { copyToClipboard } from '../lib/utils';
import { LoadingState, ErrorState, PageHeader } from '../components/ui';
import { Copy, Download, Key, Shield } from 'lucide-react';

export default function IntegrationsPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [publicKey, setPublicKey] = useState('');
  const [kyvernoPolicy, setKyvernoPolicy] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [key, policy] = await Promise.all([
        apiClient.getPublicKey().catch(() => ''),
        apiClient.getKyvernoPolicy().catch(() => ''),
      ]);
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
