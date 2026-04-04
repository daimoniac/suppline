export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

export function formatRelativeTime(timestamp: number): string {
  if (!timestamp) return 'N/A';
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  const diff = Date.now() - ms;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

export function formatDate(timestamp: number): string {
  if (!timestamp) return 'N/A';
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  return new Date(ms).toLocaleString();
}

export function formatShortDate(timestamp: number): string {
  if (!timestamp) return 'N/A';
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  return new Date(ms).toLocaleDateString();
}

export function truncateDigest(digest: string): string {
  if (!digest) return 'N/A';
  return digest.length > 19 ? digest.substring(0, 19) + '…' : digest;
}

export function truncateText(text: string, maxLen: number): string {
  if (!text) return '';
  return text.length > maxLen ? text.substring(0, maxLen) + '…' : text;
}

export function isPast(timestamp: number): boolean {
  if (!timestamp) return false;
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  return ms <= Date.now();
}

export function daysUntil(timestamp: number): number | null {
  if (!timestamp) return null;
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  return Math.ceil((ms - Date.now()) / (1000 * 60 * 60 * 24));
}

export function isWithinDays(timestamp: number, days: number): boolean {
  if (!timestamp) return false;
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  const diff = ms - Date.now();
  return diff > 0 && diff <= days * 24 * 60 * 60 * 1000;
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'tolerated' | 'unknown';

export function severityColor(severity: string): string {
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical': return 'bg-severity-critical';
    case 'high': return 'bg-severity-high';
    case 'medium': return 'bg-severity-medium';
    case 'low': return 'bg-severity-low';
    case 'tolerated': return 'bg-severity-tolerated';
    default: return 'bg-gray-500';
  }
}

export function severityTextColor(severity: string): string {
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical': return 'text-severity-critical';
    case 'high': return 'text-severity-high';
    case 'medium': return 'text-severity-medium';
    case 'low': return 'text-severity-low';
    case 'tolerated': return 'text-severity-tolerated';
    default: return 'text-gray-400';
  }
}

export function daysUntilReleaseAge(releaseAgeSeconds?: number, minimumReleaseAgeSeconds?: number): number | null {
  if (!releaseAgeSeconds || !minimumReleaseAgeSeconds) return null;
  if (releaseAgeSeconds >= minimumReleaseAgeSeconds) return null;
  const remainingSeconds = minimumReleaseAgeSeconds - releaseAgeSeconds;
  return Math.ceil(remainingSeconds / (24 * 60 * 60));
}

export function formatRemainingDays(days: number | null): string {
  if (days === null) return '';
  if (days <= 0) return 'Ready';
  if (days === 1) return '1 day remaining';
  return `${days} days remaining`;
}
