import type { TriageRun, TriageStatement } from './api';

export const STATUS_LABELS: Record<string, string> = {
  dry_run: 'Dry run',
  committed: 'Committed',
  written: 'Written',
  push_failed: 'Push failed',
  rejected_by_guardrail: 'Rejected',
  error: 'Error',
};

export const VEX_STATES = [
  ['not_affected', 'Not affected'],
  ['affected', 'Affected'],
  ['in_triage', 'In triage'],
  ['false_positive', 'False positive'],
  ['resolved', 'Resolved'],
  ['resolved_with_pedigree', 'Resolved with pedigree'],
] as const;

// States whose statements take a finding out of policy counts. Must match
// VEXAnalysisState.ExemptsVulnerability in internal/types/vex.go.
export const EXEMPTING_VEX_STATES: readonly string[] = ['not_affected', 'false_positive'];

export function vexStateExempts(state: string): boolean {
  return EXEMPTING_VEX_STATES.includes(state);
}

export const VEX_STATE_LABELS: Record<string, string> = {
  not_affected: 'Not affected',
  affected: 'Affected',
  in_triage: 'In triage',
  fixed: 'Fixed',
  false_positive: 'False positive',
  resolved: 'Resolved',
  resolved_with_pedigree: 'Resolved with pedigree',
};

const VERDICT_LABELS: Record<string, string> = {
  ...VEX_STATE_LABELS,
  uncertain: 'Uncertain',
};

/**
 * One line for a triage run: how it ended, what it wrote, and what the model
 * said when that differs. The confidence is the model's, in its own verdict.
 */
export function runSummary(run: Pick<TriageRun, 'Status' | 'Verdict' | 'WrittenState' | 'Confidence'>): string {
  const parts = [STATUS_LABELS[run.Status] || run.Status];
  const verdict = run.Verdict ? VERDICT_LABELS[run.Verdict] || run.Verdict : '';
  if (run.WrittenState) {
    const written = VEX_STATE_LABELS[run.WrittenState] || run.WrittenState;
    const verb = run.Status === 'dry_run' ? 'would write' : 'wrote';
    parts.push(run.WrittenState === run.Verdict || !verdict ? `${verb} ${written}` : `${verb} ${written}, model said ${verdict}`);
  } else if (verdict) {
    parts.push(`model said ${verdict}`);
  }
  if (run.Confidence > 0) parts.push(`model confidence ${run.Confidence.toFixed(2)}`);
  return parts.join(' · ');
}

export const VEX_JUSTIFICATIONS = [
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment',
  'protected_by_compiler',
  'protected_at_runtime',
  'protected_at_perimeter',
  'protected_by_mitigations',
];

export type StatementRow = {
  key: string;
  cve: string;
  repository: string;
  /** Packages the finding names, when the caller knows them. */
  packages?: string[];
  state: string;
  justification: string;
  detail: string;
  expiresAt: number;
  triagedAt: number;
  affectedImages: number;
  source: 'auto' | 'manual' | 'open';
  needsFix: boolean;
  run?: TriageStatement['Run'];
};

export function fromLocalInput(value: string) {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000);
}

export function toLocalInput(unix?: number) {
  if (!unix) return '';
  const date = new Date(unix * 1000);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** A malicious-package advisory id (OSV MAL-*). */
export function isMaliciousID(id: string): boolean {
  return id.startsWith('MAL-');
}
