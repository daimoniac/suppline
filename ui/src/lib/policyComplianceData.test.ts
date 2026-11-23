import { describe, expect, it, vi } from 'vitest';
import type { Scan } from './api';
import { fetchPolicyComplianceData, runtimeWorkloadLocations, supersededRunningLabel } from './policyComplianceData';

const repo = 'hostingmaloonde/memcached';
const tag = '1.6.45';

function scan(overrides: Partial<Scan>): Scan {
  return {
    Digest: '',
    Repository: repo,
    Tag: tag,
    CreatedAt: 0,
    PolicyPassed: false,
    PolicyStatus: 'failed',
    CriticalVulnCount: 3,
    HighVulnCount: 0,
    MediumVulnCount: 0,
    LowVulnCount: 0,
    SBOMAttested: true,
    VulnAttested: true,
    SCAIAttested: true,
    VEXAttested: false,
    ...overrides,
  };
}

// internal-1, 2026-11-16: memcached:1.6.45 moved to a passing digest while
// hetzner-1/monitoring still runs two older, failing digests.
const runningSuperseded = [
  scan({
    Digest: 'sha256:57f76c81',
    Superseded: true,
    CurrentDigest: 'sha256:b09d8056',
    RuntimeUsed: true,
    Runtime: { 'hetzner-1': { monitoring: [{ ImageRef: `docker.io/${repo}`, Tag: tag, Digest: 'sha256:57f76c81' }] } },
  }),
  scan({
    Digest: 'sha256:af555492',
    Superseded: true,
    CurrentDigest: 'sha256:b09d8056',
    RuntimeUsed: true,
    Runtime: { 'hetzner-1': { monitoring: [{ ImageRef: `docker.io/${repo}`, Tag: tag, Digest: 'sha256:af555492' }] } },
  }),
];

function fakeClient(current: Scan[], running: Scan[]) {
  return {
    getScansPage: vi.fn(async () => ({ scans: current, total: current.length })),
    getRunningPolicyFailures: vi.fn(async () => running),
  };
}

describe('fetchPolicyComplianceData', () => {
  it('counts running superseded failing digests that the current-binding list misses', async () => {
    const client = fakeClient([], runningSuperseded);

    const snapshot = await fetchPolicyComplianceData(client, { in_use_mode: 'in_use_newer' });

    expect(snapshot.failedInUseCount).toBe(2);
    expect(snapshot.failedCount).toBe(2);
    expect(snapshot.policyByRepo).toEqual({ [repo]: { failed: 2, pending: 0 } });
    expect(snapshot.failedScans.every(s => s.Superseded)).toBe(true);
  });

  it('does not list a running failure twice when it is also the current binding', async () => {
    const current = scan({ Digest: 'sha256:current', RuntimeUsed: true });
    const client = fakeClient([current], [current, ...runningSuperseded]);

    const snapshot = await fetchPolicyComplianceData(client, { in_use_mode: 'in_use' });

    expect(snapshot.failedScans.map(s => s.Digest)).toEqual(['sha256:current', 'sha256:57f76c81', 'sha256:af555492']);
    expect(snapshot.failedInUseCount).toBe(3);
  });

  it('leaves running failures out of the not-in-use view', async () => {
    const client = fakeClient([], runningSuperseded);

    const snapshot = await fetchPolicyComplianceData(client, { in_use_mode: 'not_in_use' });

    expect(client.getRunningPolicyFailures).not.toHaveBeenCalled();
    expect(snapshot.failedCount).toBe(0);
    expect(snapshot.failedInUseCount).toBe(0);
  });
});

describe('supersededRunningLabel', () => {
  it('names the tag the digest used to be', () => {
    expect(supersededRunningLabel({ Tag: tag })).toBe('running an older digest of 1.6.45');
  });
});

describe('runtimeWorkloadLocations', () => {
  it('lists the workloads running the image per cluster/namespace', () => {
    const locations = runtimeWorkloadLocations({
      'hetzner-1': {
        monitoring: [
          { ImageRef: 'memcached', Tag: '1.6.45', Digest: 'sha256:a', Workloads: ['StatefulSet/b', 'StatefulSet/a'] },
          { ImageRef: 'docker.io/memcached', Tag: '1.6.45', Digest: 'sha256:a', Workloads: ['StatefulSet/a'] },
        ],
      },
      'internal-1': { cache: [{ ImageRef: 'memcached', Tag: '1.6.45', Digest: 'sha256:a' }] },
    });

    expect(locations).toEqual([
      { location: 'hetzner-1/monitoring', workloads: ['StatefulSet/a', 'StatefulSet/b'] },
      { location: 'internal-1/cache', workloads: [] },
    ]);
  });
});
