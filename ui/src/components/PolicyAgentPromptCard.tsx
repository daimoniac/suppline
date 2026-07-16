import { useMemo } from 'react';
import { useToast } from '../lib/toast';
import { buildPolicyFixPromptFromScans, POLICY_AGENT_PROMPT_HINT_DEFAULT } from '../lib/policyComplianceData';
import { copyToClipboard } from '../lib/utils';
import type { Scan } from '../lib/api';
import { Copy, Sparkles } from 'lucide-react';

export function PolicyAgentPromptCard({
  scans,
  hint = POLICY_AGENT_PROMPT_HINT_DEFAULT,
}: {
  scans: Pick<Scan, 'Repository' | 'Tag' | 'PolicyStatus' | 'PolicyFailureFindings'>[];
  hint?: string;
}) {
  const { toast } = useToast();
  const policyFixPrompt = useMemo(() => buildPolicyFixPromptFromScans(scans), [scans]);
  const hasCelFailures = useMemo(
    () => scans.some(scan => scan.PolicyStatus !== 'pending'),
    [scans]
  );

  if (!hasCelFailures) {
    return null;
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
