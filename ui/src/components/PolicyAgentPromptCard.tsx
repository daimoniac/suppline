import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../lib/auth';
import { useToast } from '../lib/toast';
import { buildPolicyFixPromptFromScans, POLICY_AGENT_PROMPT_HINT_DEFAULT } from '../lib/policyComplianceData';
import { copyToClipboard } from '../lib/utils';
import type { Scan, TriageStatus } from '../lib/api';
import { Copy, Scale, Sparkles } from 'lucide-react';

export function PolicyAgentPromptCard({
  scans,
  hint = POLICY_AGENT_PROMPT_HINT_DEFAULT,
  onTriageQueued,
}: {
  scans: Pick<Scan, 'Repository' | 'Tag' | 'Digest' | 'PolicyStatus' | 'PolicyFailureFindings'>[];
  hint?: string;
  onTriageQueued?: () => void;
}) {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [triageStatus, setTriageStatus] = useState<TriageStatus | null>(null);
  const [triageKnown, setTriageKnown] = useState(false);
  const [queuing, setQueuing] = useState(false);
  const policyFixPrompt = useMemo(() => buildPolicyFixPromptFromScans(scans), [scans]);
  const celFailures = useMemo(
    () => scans.filter(scan => scan.PolicyStatus !== 'pending' && scan.Digest),
    [scans]
  );

  useEffect(() => {
    let cancelled = false;
    apiClient.getTriageStatus()
      .then(status => {
        if (!cancelled) setTriageStatus(status);
      })
      .catch(() => {
        if (!cancelled) setTriageStatus({ Enabled: false, OnlyInUse: true, Pending: 0 });
      })
      .finally(() => {
        if (!cancelled) setTriageKnown(true);
      });
    return () => { cancelled = true; };
  }, [apiClient]);

  if (celFailures.length === 0) {
    return null;
  }

  if (triageStatus?.Enabled) {
    return (
      <div className="relative overflow-hidden rounded-xl border border-accent/35 bg-gradient-to-r from-accent/15 via-bg-secondary to-warning/10 p-4">
        <div className="absolute -top-10 -right-10 w-24 h-24 rounded-full bg-accent/20 blur-2xl pointer-events-none" />
        <div className="relative flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center w-7 h-7 rounded-lg bg-accent/20 text-accent">
              <Scale className="w-4 h-4" />
            </span>
            <div>
              <h3 className="text-sm font-semibold text-text-primary">Triage</h3>
              <p className="text-xs text-text-secondary">
                {triageStatus.OnlyInUse
                  ? 'Queue triage for CEL failures in this view that are running in a cluster.'
                  : 'Queue triage for the CEL policy failures in this view.'}
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={queuing}
            onClick={() => {
              setQueuing(true);
              apiClient.queueTriage(celFailures.map(scan => ({
                Repository: scan.Repository,
                Digest: scan.Digest,
                Tag: scan.Tag,
              })))
                .then(result => {
                  const queued = result.Queued;
                  toast(
                    queued > 0
                      ? `Triage queued for ${queued} finding${queued === 1 ? '' : 's'}`
                      : 'No findings queued',
                    queued > 0 ? 'success' : 'warning'
                  );
                  if (queued > 0) onTriageQueued?.();
                })
                .catch((e: unknown) => {
                  toast(e instanceof Error ? e.message : 'Failed to queue triage', 'error');
                })
                .finally(() => setQueuing(false));
            }}
            className="inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs rounded-lg border border-accent/30 text-text-primary bg-bg-primary/70 hover:bg-bg-primary disabled:opacity-50 transition-colors"
          >
            <Scale className="w-3 h-3" />
            {queuing ? 'Queuing…' : 'Triage now'}
          </button>
        </div>
      </div>
    );
  }

  if (!triageKnown) {
    return (
      <div className="rounded-xl border border-border bg-bg-secondary p-4">
        <p className="text-xs text-text-muted">Checking triage…</p>
      </div>
    );
  }

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
          type="button"
          onClick={() => {
            if (!policyFixPrompt) {
              toast(
                'No CEL policy failure findings available yet for these images. Re-scan to populate actionable findings.',
                'warning'
              );
              return;
            }
            copyToClipboard(policyFixPrompt).then(ok =>
              toast(ok ? 'Prompt copied to clipboard!' : 'Failed to copy', ok ? 'success' : 'error')
            );
          }}
          className="inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs rounded-lg border border-accent/30 text-text-primary bg-bg-primary/70 hover:bg-bg-primary transition-colors"
        >
          <Copy className="w-3 h-3" />
          Fix using coding agent
        </button>
      </div>
    </div>
  );
}
