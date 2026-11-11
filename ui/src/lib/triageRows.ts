import type { TriageStatement } from './api';

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

export const VEX_STATE_LABELS: Record<string, string> = {
  not_affected: 'Not affected',
  affected: 'Affected',
  in_triage: 'In triage',
  fixed: 'Fixed',
  false_positive: 'False positive',
  resolved: 'Resolved',
  resolved_with_pedigree: 'Resolved with pedigree',
};

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
