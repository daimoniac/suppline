import { describe, expect, it } from 'vitest';
import { kevBadgeTitle, kevFeedWarning } from './kev';

describe('kevFeedWarning', () => {
  it('warns only when the catalog cannot be trusted', () => {
    expect(kevFeedWarning('ok')).toBeNull();
    expect(kevFeedWarning('disabled')).toBeNull();
    expect(kevFeedWarning(undefined)).toBeNull();
    expect(kevFeedWarning('unavailable')).toContain('has not loaded yet');
    expect(kevFeedWarning('stale')).toContain('last catalog');
  });
});

describe('kevBadgeTitle', () => {
  it('lists date, due date and ransomware use', () => {
    expect(kevBadgeTitle({ DateAdded: '2024-03-01', DueDate: '2024-03-22', Ransomware: true })).toBe(
      'In the CISA Known Exploited Vulnerabilities catalog since 2024-03-01; US federal remediation due 2024-03-22; known to be used in ransomware campaigns.',
    );
    expect(kevBadgeTitle({ DateAdded: '2023-11-21', DueDate: '', Ransomware: false })).toBe(
      'In the CISA Known Exploited Vulnerabilities catalog since 2023-11-21.',
    );
  });
});
