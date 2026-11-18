import { describe, expect, it } from 'vitest';
import type { MaliciousFeed, MaliciousImage } from './api';
import { activeFindings, feedCommitURL, formatSeconds, groupMaliciousByPackage, maliciousFeedWarning } from './malicious';
import { buildPolicyFixPromptRows } from './policyComplianceData';
import { sidebarItems } from './navigation';

function image(overrides: Partial<MaliciousImage>): MaliciousImage {
  return {
    Repository: 'library/app',
    Digest: 'sha256:a',
    Tags: ['1.0'],
    ScannedAt: 1,
    PolicyPassed: false,
    PolicyStatus: 'failed',
    RuntimeUsed: false,
    CheckStatus: 'ok',
    Findings: [],
    ...overrides,
  };
}

const evil = { ID: 'MAL-2', Ecosystem: 'npm', PackageName: 'evil', Version: '1.0.0', PURL: 'pkg:npm/evil@1.0.0', Summary: 'Malicious code in evil (npm)', URL: '' };

function feed(overrides: Partial<MaliciousFeed>): MaliciousFeed {
  return {
    Status: 'ok', Commit: 'abc', SyncedAt: 1, LastAttemptAt: 1, LastDurationMs: 0, LastError: '',
    SyncIntervalSeconds: 3600, StaleAfterSeconds: 21600, RepoURL: '', Ref: 'main', Block: true,
    Ecosystems: null, Entries: 0, Packages: null,
    ...overrides,
  };
}

describe('groupMaliciousByPackage', () => {
  it('groups images per package version with running packages first', () => {
    const groups = groupMaliciousByPackage([
      image({ Digest: 'sha256:a', Findings: [evil, { ...evil, ID: 'MAL-1' }] }),
      image({ Digest: 'sha256:b', Findings: [evil] }),
      image({ Digest: 'sha256:c', RuntimeUsed: true, Findings: [{ ...evil, PackageName: 'zz-other', ID: 'MAL-9' }] }),
    ]);
    expect(groups.map(g => g.packageName)).toEqual(['zz-other', 'evil']);
    expect(groups[0].inUse).toBe(true);
    expect(groups[1].ids).toEqual(['MAL-1', 'MAL-2']);
    expect(groups[1].images.map(i => i.Digest)).toEqual(['sha256:a', 'sha256:b']);
  });
});

describe('false positives', () => {
  it('sorts fully exempted packages last and leaves them out of active findings', () => {
    const exempted = { ...evil, PackageName: 'aaa-workspace', ID: 'MAL-3', Exempted: true };
    const images = [image({ Digest: 'sha256:x', RuntimeUsed: true, Findings: [exempted] }), image({ Digest: 'sha256:y', Findings: [evil] })];
    const groups = groupMaliciousByPackage(images);
    expect(groups.map(g => [g.packageName, g.exempted])).toEqual([['evil', false], ['aaa-workspace', true]]);
    expect(activeFindings(images[0])).toEqual([]);
    expect(activeFindings(images[1])).toHaveLength(1);
  });
});

describe('maliciousFeedWarning', () => {
  it('is quiet while the feed is current', () => {
    expect(maliciousFeedWarning(feed({}))).toBeNull();
  });
  it('explains loading, stale and failed syncs', () => {
    expect(maliciousFeedWarning(feed({ Status: 'unavailable' }))).toContain('still loading');
    expect(maliciousFeedWarning(feed({ Status: 'stale', LastError: 'network down' }))).toContain('6h: network down');
    expect(maliciousFeedWarning(feed({ LastError: 'timeout' }))).toContain('last sync failed: timeout');
  });
});

describe('formatSeconds', () => {
  it('formats durations compactly', () => {
    expect(formatSeconds(3600)).toBe('1h');
    expect(formatSeconds(1800)).toBe('30m');
    expect(formatSeconds(93600)).toBe('1d 2h');
  });
});

describe('feedCommitURL', () => {
  it('links GitHub repositories only', () => {
    expect(feedCommitURL('https://github.com/ossf/malicious-packages.git', 'abc')).toBe('https://github.com/ossf/malicious-packages/commit/abc');
    expect(feedCommitURL('https://git.example/mirror/mal.git', 'abc')).toBeNull();
    expect(feedCommitURL('https://github.com/ossf/malicious-packages', '')).toBeNull();
  });
});

describe('policy fix prompt', () => {
  it('leaves malicious findings out of the VEX triage prompt', () => {
    const rows = buildPolicyFixPromptRows([{
      Repository: 'library/app', Tag: '1.0',
      PolicyFailureFindings: [
        { CVEID: 'CVE-1', PackageName: 'openssl' },
        { CVEID: 'MAL-1', PackageName: 'evil', Kind: 'malicious' },
      ],
    }]);
    expect(rows.map(r => r.cve)).toEqual(['CVE-1']);
  });
});

describe('sidebarItems', () => {
  it('adds the malicious view after vulnerabilities only when enabled', () => {
    expect(sidebarItems(false, false).some(i => i.to === '/malicious')).toBe(false);
    const labels = sidebarItems(true, true).map(i => i.label);
    expect(labels.indexOf('Malicious Packages')).toBe(labels.indexOf('Vulnerabilities') + 1);
    expect(labels.indexOf('Mirror')).toBe(labels.indexOf('Integrations') - 1);
  });
});
