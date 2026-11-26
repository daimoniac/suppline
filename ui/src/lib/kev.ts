import type { KEVInfo, KEVStatus } from './api';

/** Warning for a KEV view whose catalog cannot be fully trusted, or null. */
export function kevFeedWarning(status: KEVStatus | undefined | null): string | null {
  switch (status) {
    case 'unavailable':
      return 'The CISA KEV catalog has not loaded yet, so no finding is marked as known exploited. An empty list does not mean nothing is exploited.';
    case 'stale':
      return 'The CISA KEV catalog has not synced for a while. Findings are marked from the last catalog, so recently listed CVEs may be missing.';
    default:
      return null;
  }
}

/** Tooltip for a KEV badge. */
export function kevBadgeTitle(info: KEVInfo): string {
  const parts = [`In the CISA Known Exploited Vulnerabilities catalog since ${info.DateAdded || 'an unknown date'}`];
  if (info.DueDate) parts.push(`US federal remediation due ${info.DueDate}`);
  if (info.Ransomware) parts.push('known to be used in ransomware campaigns');
  return parts.join('; ') + '.';
}
