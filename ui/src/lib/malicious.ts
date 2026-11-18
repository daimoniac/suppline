import type { MaliciousFeed, MaliciousImage } from './api';

/** One malicious package version and every current image that contains it. */
export interface MaliciousPackageGroup {
  key: string;
  ids: string[];
  ecosystem: string;
  packageName: string;
  version: string;
  summary: string;
  url: string;
  images: MaliciousImage[];
  inUse: boolean;
  /** Every occurrence is covered by a false_positive VEX statement. */
  exempted: boolean;
}

/** An image's findings that are not exempted by a false_positive statement. */
export function activeFindings(image: Pick<MaliciousImage, 'Findings'>) {
  return image.Findings.filter(finding => !finding.Exempted);
}

/** Groups affected images by package version; in-use packages first, then by name. */
export function groupMaliciousByPackage(images: MaliciousImage[]): MaliciousPackageGroup[] {
  const groups = new Map<string, MaliciousPackageGroup>();
  for (const image of images) {
    const seenInImage = new Set<string>();
    for (const finding of image.Findings) {
      const key = `${finding.Ecosystem}\n${finding.PackageName}\n${finding.Version}`;
      let group = groups.get(key);
      if (!group) {
        group = {
          key,
          ids: [],
          ecosystem: finding.Ecosystem,
          packageName: finding.PackageName,
          version: finding.Version,
          summary: finding.Summary,
          url: finding.URL,
          images: [],
          inUse: false,
          exempted: true,
        };
        groups.set(key, group);
      }
      if (!group.ids.includes(finding.ID)) group.ids.push(finding.ID);
      group.exempted &&= finding.Exempted === true;
      if (!seenInImage.has(key)) {
        seenInImage.add(key);
        group.images.push(image);
        group.inUse ||= image.RuntimeUsed;
      }
    }
  }
  return Array.from(groups.values())
    .map(group => ({ ...group, ids: [...group.ids].sort() }))
    .sort((a, b) =>
      Number(a.exempted) - Number(b.exempted)
      || Number(b.inUse) - Number(a.inUse)
      || a.packageName.localeCompare(b.packageName)
      || a.version.localeCompare(b.version));
}

/** A warning about the feed, or null when it is current. */
export function maliciousFeedWarning(feed: MaliciousFeed | null): string | null {
  if (!feed) return null;
  if (feed.Status === 'unavailable') {
    return feed.LastError
      ? `The malicious-package feed has not loaded yet: ${feed.LastError}. Scans pass the check as "not checked" until it does.`
      : 'The malicious-package feed is still loading. Scans pass the check as "not checked" until it does.';
  }
  if (feed.Status === 'stale') {
    return `The feed has not synced successfully for longer than ${formatSeconds(feed.StaleAfterSeconds)}${feed.LastError ? `: ${feed.LastError}` : ''}. Scans still match against the old data and are marked stale.`;
  }
  if (feed.LastError) {
    return `The last sync failed: ${feed.LastError}. The data is still within its ${formatSeconds(feed.StaleAfterSeconds)} limit.`;
  }
  return null;
}

/** "1h", "6h", "30m", "1d 2h" from seconds. */
export function formatSeconds(seconds: number): string {
  if (!seconds || seconds < 60) return `${Math.max(0, Math.round(seconds || 0))}s`;
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes && !days) parts.push(`${minutes}m`);
  return parts.join(' ') || '0m';
}

/** Web link to a commit when the feed repository is on GitHub, otherwise null. */
export function feedCommitURL(repoURL: string, commit: string): string | null {
  if (!commit) return null;
  const match = /^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/.exec(repoURL.trim());
  if (!match) return null;
  return `https://github.com/${match[1]}/${match[2]}/commit/${encodeURIComponent(commit)}`;
}
