import { daysUntil, isPast, isWithinDays } from '../lib/utils';
import { STATUS_LABELS, VEX_STATE_LABELS } from '../lib/triageRows';

export function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    dry_run: 'bg-info-bg text-info',
    committed: 'bg-success-bg text-success',
    written: 'bg-success-bg text-success',
    push_failed: 'bg-danger-bg text-danger',
    rejected_by_guardrail: 'bg-warning-bg text-warning',
    error: 'bg-danger-bg text-danger',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] || 'bg-bg-tertiary text-text-secondary'}`}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

export function StatePill({ state }: { state: string }) {
  const styles: Record<string, string> = {
    not_affected: 'bg-success-bg text-success',
    affected: 'bg-danger-bg text-danger',
    in_triage: 'bg-warning-bg text-warning',
    fixed: 'bg-info-bg text-info',
    false_positive: 'bg-bg-tertiary text-text-secondary',
    resolved: 'bg-success-bg text-success',
    resolved_with_pedigree: 'bg-success-bg text-success',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[state] || 'bg-bg-tertiary text-text-secondary'}`}>
      {VEX_STATE_LABELS[state] || state || 'Open'}
    </span>
  );
}

export function ExpirationBadge({ expiresAt }: { expiresAt?: number }) {
  if (!expiresAt) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">Active</span>;
  const expired = isPast(expiresAt);
  const expiringSoon = !expired && isWithinDays(expiresAt, 7);
  const days = daysUntil(expiresAt);
  if (expired) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-danger-bg text-danger">Expired</span>;
  if (expiringSoon) return <span className="px-2 py-0.5 rounded text-xs font-medium bg-warning-bg text-warning">{days}d left</span>;
  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-success-bg text-success">Active</span>;
}
