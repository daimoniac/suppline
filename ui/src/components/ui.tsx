import { cn, severityColor, copyToClipboard, truncateDigest, getRuntimeClusterCount, getRuntimeClusterNames } from '../lib/utils';
import { Loader2, AlertCircle, Search, ChevronUp, ChevronDown, Copy } from 'lucide-react';
import type { ReactNode } from 'react';
import type { RuntimeInventory } from '../lib/api';
import { Link } from 'react-router-dom';
import { useImageUsageFilter } from '../lib/imageUsageFilter';
import { useToast } from '../lib/toast';

export function StatusBadge({ passed, label, status }: { passed: boolean; label?: string; status?: string }) {
  const isPending = status === 'pending';
  return <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', isPending ? 'bg-warning-bg text-warning' : passed ? 'bg-success-bg text-success' : 'bg-danger-bg text-danger')}>{label || (isPending ? 'Pending' : passed ? 'Passed' : 'Failed')}</span>;
}

export function SeverityBadge({ severity, count }: { severity: string; count?: number }) {
  return <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold text-white', severityColor(severity))}>{count !== undefined ? count : severity.toUpperCase()}</span>;
}

export function VulnCounts({ critical, high, medium, low, exempted }: { critical?: number; high?: number; medium?: number; low?: number; exempted?: number }) {
  const items = [{ severity: 'critical', count: critical }, { severity: 'high', count: high }, { severity: 'medium', count: medium }, { severity: 'low', count: low }, { severity: 'exempted', count: exempted }].filter(i => i.count !== undefined);
  return <div className="flex items-center gap-1 flex-wrap">{items.map(i => <SeverityBadge key={i.severity} severity={i.severity} count={i.count} />)}</div>;
}

export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return <div className="flex flex-col items-center justify-center py-20 text-text-secondary"><Loader2 className="w-8 h-8 animate-spin mb-3 text-accent" /><p className="text-sm">{message}</p></div>;
}

export function EmptyState({ icon, title, message }: { icon?: ReactNode; title: string; message: string }) {
  return <div className="flex flex-col items-center justify-center py-16 text-text-secondary">{icon || <Search className="w-12 h-12 mb-4 opacity-30" />}<h3 className="text-lg font-semibold text-text-primary mb-1">{title}</h3><p className="text-sm">{message}</p></div>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-secondary">
      <AlertCircle className="w-12 h-12 mb-4 text-danger opacity-60" />
      <h3 className="text-lg font-semibold text-text-primary mb-1">Error</h3>
      <p className="text-sm mb-4">{message}</p>
      {onRetry && <button onClick={onRetry} className="px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors">Retry</button>}
    </div>
  );
}

export function SortHeader({ column, label, sortColumn, sortDirection, onSort }: { column: string; label: string; sortColumn: string; sortDirection: 'asc' | 'desc'; onSort: (column: string) => void }) {
  const active = sortColumn === column;
  return (
    <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider cursor-pointer hover:text-text-primary select-none transition-colors" onClick={() => onSort(column)}>
      <div className="flex items-center gap-1">{label}{active && (sortDirection === 'asc' ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />)}</div>
    </th>
  );
}

export function Pagination({ currentPage, totalPages, total, pageSize, onPageChange, itemLabel = 'items' }: { currentPage: number; totalPages: number; total: number; pageSize: number; onPageChange: (page: number) => void; itemLabel?: string }) {
  if (totalPages <= 1) return null;
  const start = (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, total);
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border">
      <span className="text-sm text-text-secondary">{start}–{end} of {total} {itemLabel}</span>
      <div className="flex items-center gap-1">
        {[{ label: '«', page: 1, disabled: currentPage === 1 }, { label: '‹', page: currentPage - 1, disabled: currentPage === 1 }, { label: '›', page: currentPage + 1, disabled: currentPage === totalPages }, { label: '»', page: totalPages, disabled: currentPage === totalPages }].map((btn, i) => (
          <button key={i} disabled={btn.disabled} onClick={() => onPageChange(btn.page)} className="px-2.5 py-1 text-sm rounded border border-border text-text-secondary hover:bg-bg-tertiary disabled:opacity-30 disabled:cursor-not-allowed transition-colors">{btn.label}</button>
        ))}
        <span className="text-xs text-text-muted ml-2">Page {currentPage}/{totalPages}</span>
      </div>
    </div>
  );
}

export function ConfirmModal({ open, title, message, onConfirm, onCancel }: { open: boolean; title: string; message: string; onConfirm: () => void; onCancel: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onCancel}>
      <div className="bg-bg-secondary border border-border rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold mb-2">{title}</h3>
        <p className="text-sm text-text-secondary mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <button onClick={onCancel} className="px-4 py-2 text-sm rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary transition-colors">Cancel</button>
          <button onClick={onConfirm} className="px-4 py-2 text-sm rounded-lg bg-accent text-bg-primary font-medium hover:bg-accent-hover transition-colors">Confirm</button>
        </div>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, showImageUsage = true }: { title: string; subtitle: string; showImageUsage?: boolean }) {
  const { filter } = useImageUsageFilter();
  const filterLabel = filter === 'all'
    ? 'All images'
    : filter === 'in-use'
      ? 'In use'
      : filter === 'in-use-newer'
        ? 'In use + newer'
        : 'Not in use';
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="text-sm text-text-secondary mt-1">{subtitle}</p>
      {showImageUsage && <div className="mt-2"><span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-bg-secondary border border-border text-text-secondary">Image usage filter: <span className="ml-1 text-text-primary">{filterLabel}</span></span></div>}
    </div>
  );
}

export function DigestLinkWithCopy({ digest, to, showAsCode = false, wrap = false }: { digest: string; to?: string; showAsCode?: boolean; wrap?: boolean }) {
  const { toast } = useToast();
  const display = truncateDigest(digest);
  const digestNode = showAsCode ? <code className="text-xs text-text-muted font-mono">{display}</code> : to ? <Link to={to} className="text-xs text-accent font-mono hover:underline">{display}</Link> : <span className="text-xs text-text-muted font-mono">{display}</span>;
  return <div className={`flex items-center gap-1 ${wrap ? 'flex-wrap' : ''}`}>{digestNode}<button className="text-text-muted hover:text-text-primary p-0.5" onClick={() => { copyToClipboard(digest).then(ok => toast(ok ? 'Copied!' : 'Failed to copy', ok ? 'success' : 'error')); }}><Copy className="w-3 h-3" /></button></div>;
}

export function RuntimeUsageBadge({ inUse, runtime, showWhenNotInUse = false, showClusterCount = false, whitelisted = false }: { inUse: boolean; runtime?: RuntimeInventory; showWhenNotInUse?: boolean; showClusterCount?: boolean; whitelisted?: boolean }) {
  if (whitelisted) {
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-bg-tertiary text-white" title="Included due to housekeeping whitelist">Whitelisted</span>;
  }

  if (!inUse && !showWhenNotInUse) return null;

  const clusterNames = getRuntimeClusterNames(runtime);
  const label = inUse ? (showClusterCount ? `In use on ${getRuntimeClusterCount(runtime)} cluster(s)` : 'In use') : 'Not in use';
  const title = inUse && clusterNames.length ? `Running on: ${clusterNames.join(', ')}` : label;
  return <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${inUse ? 'bg-success-bg text-success' : 'bg-bg-tertiary text-text-muted'}`} title={title}>{label}</span>;
}

export function PageFiltersBar({ children }: { children: ReactNode }) {
  return <div className="flex gap-3 mb-4 flex-wrap">{children}</div>;
}

export function FilterActionButton({ children, onClick, variant = 'primary' }: { children: ReactNode; onClick: () => void; variant?: 'primary' | 'secondary' }) {
  return <button onClick={onClick} className={variant === 'primary' ? 'px-4 py-2 bg-accent text-bg-primary rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors' : 'px-4 py-2 border border-border rounded-lg text-sm text-text-secondary hover:bg-bg-tertiary transition-colors'}>{children}</button>;
}

export function FilterSelect({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="px-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors">
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

const POLICY_STATUS_OPTIONS = [
  { value: 'all', label: 'All Statuses' },
  { value: 'passed', label: 'Passed' },
  { value: 'failed', label: 'Failed' },
  { value: 'pending', label: 'Pending' },
];

export function PolicyStatusSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return <FilterSelect value={value} onChange={onChange} options={POLICY_STATUS_OPTIONS} />;
}
