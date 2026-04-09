import type { APIClient, RepositoriesResponse, RuntimeImage, RuntimeInventory } from './api';

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

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'exempted' | 'unknown';

export function severityColor(severity: string): string {
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical': return 'bg-severity-critical';
    case 'high': return 'bg-severity-high';
    case 'medium': return 'bg-severity-medium';
    case 'low': return 'bg-severity-low';
    case 'exempted': return 'bg-severity-exempted';
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
    case 'exempted': return 'text-severity-exempted';
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

export function getRuntimeClusterNames(runtime?: RuntimeInventory): string[] {
  if (!runtime) return [];
  return Object.keys(runtime).sort((left, right) => left.localeCompare(right));
}

export function getRuntimeClusterCount(runtime?: RuntimeInventory): number {
  return getRuntimeClusterNames(runtime).length;
}

export function getRuntimeNamespaceEntries(runtime?: RuntimeInventory): Array<{ cluster: string; namespace: string; images: RuntimeImage[] }> {
  if (!runtime) return [];

  const entries: Array<{ cluster: string; namespace: string; images: RuntimeImage[] }> = [];
  for (const cluster of getRuntimeClusterNames(runtime)) {
    const namespaces = runtime[cluster] || {};
    for (const namespace of Object.keys(namespaces).sort((left, right) => left.localeCompare(right))) {
      entries.push({ cluster, namespace, images: namespaces[namespace] || [] });
    }
  }

  return entries;
}

type ParsedSemver = {
  major: number;
  minor: number;
  patch: number;
  preRelease: string[];
};

function parseSemver(value: string): ParsedSemver | null {
  const trimmed = value.trim();
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(trimmed);
  if (!match) return null;

  const major = Number(match[1]);
  const minor = Number(match[2] ?? 0);
  const patch = Number(match[3] ?? 0);
  const preRelease = match[4] ? match[4].split('.') : [];

  return { major, minor, patch, preRelease };
}

function comparePreRelease(left: string[], right: string[]): number {
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;

  const max = Math.max(left.length, right.length);
  for (let i = 0; i < max; i++) {
    const l = left[i];
    const r = right[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;

    const ln = /^\d+$/.test(l);
    const rn = /^\d+$/.test(r);
    if (ln && rn) {
      const diff = Number(l) - Number(r);
      if (diff !== 0) return diff;
      continue;
    }
    if (ln && !rn) return -1;
    if (!ln && rn) return 1;
    const cmp = l.localeCompare(r);
    if (cmp !== 0) return cmp;
  }

  return 0;
}

export function compareTagNames(left: string, right: string): number {
  const l = parseSemver(left);
  const r = parseSemver(right);

  if (l && r) {
    if (l.major !== r.major) return l.major - r.major;
    if (l.minor !== r.minor) return l.minor - r.minor;
    if (l.patch !== r.patch) return l.patch - r.patch;
    const preCmp = comparePreRelease(l.preRelease, r.preRelease);
    if (preCmp !== 0) return preCmp;
  }

  return left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' });
}

export async function loadAllRuntimeUnusedRepositories(apiClient: APIClient, pageSize = 100): Promise<RepositoriesResponse> {
  const firstPage = await apiClient.getRepositories({
    in_use: false,
    sort_by: 'age_desc',
    limit: pageSize,
    offset: 0,
  });

  let repositories = firstPage.Repositories;
  for (let offset = repositories.length; offset < firstPage.Total; offset += pageSize) {
    const page = await apiClient.getRepositories({
      in_use: false,
      sort_by: 'age_desc',
      limit: pageSize,
      offset,
    });
    repositories = repositories.concat(page.Repositories);
  }

  return {
    Repositories: repositories,
    Total: firstPage.Total,
  };
}

export function summarizeRuntimeUnusedRepositories(
  repositories: RepositoriesResponse['Repositories'],
  whitelist: string[],
) {
  const whitelistSet = new Set(whitelist.map(entry => entry.trim()).filter(Boolean));
  const actionableRepositories = repositories.filter(entry => !whitelistSet.has(entry.Name));

  return {
    whitelistSet,
    actionableRepositories,
    hiddenByWhitelistCount: repositories.length - actionableRepositories.length,
  };
}
