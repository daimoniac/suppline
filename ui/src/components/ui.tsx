import { cn, severityColor } from '../lib/utils';
import { Loader2, AlertCircle, Search, ChevronUp, ChevronDown } from 'lucide-react';
import type { ReactNode } from 'react';
import { useImageUsageFilter } from '../lib/imageUsageFilter';

// Status Badge
export function StatusBadge({ passed, label, status }: { passed: boolean; label?: string; status?: string }) {
  const isPending = status === 'pending';
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
      isPending
        ? 'bg-warning-bg text-warning'
        : passed
          ? 'bg-success-bg text-success'
          : 'bg-danger-bg text-danger'
    )}>
      {label || (isPending ? 'Pending' : passed ? 'Passed' : 'Failed')}
    </span>
  );
}

// Severity Badge
export function SeverityBadge({ severity, count }: { severity: string; count?: number }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold text-white',
      severityColor(severity),
    )}>
      {count !== undefined ? count : severity.toUpperCase()}
    </span>
  );
}

// Vuln Count Row
export function VulnCounts({ critical, high, medium, low, tolerated }: {
  critical?: number; high?: number; medium?: number; low?: number; tolerated?: number;
}) {
  const items = [
    { severity: 'critical', count: critical },
    { severity: 'high', count: high },
    { severity: 'medium', count: medium },
    { severity: 'low', count: low },
    { severity: 'tolerated', count: tolerated },
  ].filter(i => i.count !== undefined);

  return (
    <div className="flex items-center gap-1 flex-wrap">
      {items.map(i => (
        <SeverityBadge key={i.severity} severity={i.severity} count={i.count} />
      ))}
    </div>
  );
}

// Loading state
export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-text-secondary">
      <Loader2 className="w-8 h-8 animate-spin mb-3 text-accent" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

// Empty state
export function EmptyState({ icon, title, message }: { icon?: ReactNode; title: string; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-secondary">
      {icon || <Search className="w-12 h-12 mb-4 opacity-30" />}
      <h3 className="text-lg font-semibold text-text-primary mb-1">{title}</h3>
      <p className="text-sm">{message}</p>
    </div>
  );
}

// Error state
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-secondary">
      <AlertCircle className="w-12 h-12 mb-4 text-danger opacity-60" />
      <h3 className="text-lg font-semibold text-text-primary mb-1">Error</h3>
      <p className="text-sm mb-4">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">
          Retry
        </button>
      )}
    </div>
  );
}

// Sortable table header
export function SortHeader({ column, label, sortColumn, sortDirection, onSort }: {
  column: string; label: string; sortColumn: string; sortDirection: 'asc' | 'desc';
  onSort: (column: string) => void;
}) {
  const active = sortColumn === column;
  return (
    <th
      className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider cursor-pointer hover:text-text-primary select-none transition-colors"
      onClick={() => onSort(column)}
    >
      <div className="flex items-center gap-1">
        {label}
        {active && (sortDirection === 'asc' ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}
      </div>
    </th>
  );
}

// Pagination
export function Pagination({ currentPage, totalPages, total, pageSize, onPageChange, itemLabel = 'items' }: {
  currentPage: number; totalPages: number; total: number; pageSize: number;
  onPageChange: (page: number) => void; itemLabel?: string;
}) {
  if (totalPages <= 1) return null;
  const start = (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, total);

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border">
      <span className="text-sm text-text-secondary">
        {start}–{end} of {total} {itemLabel}
      </span>
      <div className="flex items-center gap-1">
        {[
          { label: '«', page: 1, disabled: currentPage === 1 },
          { label: '‹', page: currentPage - 1, disabled: currentPage === 1 },
          { label: '›', page: currentPage + 1, disabled: currentPage === totalPages },
          { label: '»', page: totalPages, disabled: currentPage === totalPages },
        ].map((btn, i) => (
          <button
            key={i}
            disabled={btn.disabled}
            onClick={() => onPageChange(btn.page)}
            className="px-2.5 py-1 text-sm rounded border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            {btn.label}
          </button>
        ))}
        <span className="text-xs text-text-muted ml-2">Page {currentPage}/{totalPages}</span>
      </div>
    </div>
  );
}

// Confirmation modal
export function ConfirmModal({ open, title, message, onConfirm, onCancel }: {
  open: boolean; title: string; message: string;
  onConfirm: () => void; onCancel: () => void;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onCancel}>
      <div className="bg-bg-secondary border border-border rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold mb-2">{title}</h3>
        <p className="text-sm text-text-secondary mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <button onClick={onCancel} className="px-4 py-2 text-sm rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary transition-colors">
            Cancel
          </button>
          <button onClick={onConfirm} className="px-4 py-2 text-sm rounded-lg bg-accent text-bg-primary font-medium hover:bg-accent-hover transition-colors">
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// Page header
export function PageHeader({ title, subtitle }: { title: string; subtitle: string }) {
  const { filter } = useImageUsageFilter();
  const filterLabel = filter === 'all' ? 'All images' : filter === 'in-use' ? 'In use' : 'Not in use';

  return (
    <div className="mb-6">
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="text-sm text-text-secondary mt-1">{subtitle}</p>
      <div className="mt-2">
        <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-bg-secondary border border-border text-text-secondary">
          Image usage filter: <span className="ml-1 text-text-primary">{filterLabel}</span>
        </span>
      </div>
    </div>
  );
}
