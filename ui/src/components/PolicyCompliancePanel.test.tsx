import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import type { Scan } from '../lib/api';
import { PolicyCompliancePanel } from './PolicyCompliancePanel';

vi.mock('./PolicyAgentPromptCard', () => ({
  PolicyAgentPromptCard: ({ scans }: { scans: Scan[] }) => <div data-prompt-scans={scans.length} />,
}));

const repo = 'hostingmaloonde/memcached';

const superseded: Scan = {
  Digest: 'sha256:57f76c81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  Repository: repo,
  Tag: '1.6.45',
  CreatedAt: 0,
  PolicyPassed: false,
  PolicyStatus: 'failed',
  CriticalVulnCount: 3,
  HighVulnCount: 0,
  MediumVulnCount: 0,
  LowVulnCount: 0,
  SBOMAttested: true,
  VulnAttested: true,
  RuntimeUsed: true,
  Superseded: true,
  CurrentDigest: 'sha256:b09d8056',
  Runtime: {
    'hetzner-1': {
      monitoring: [{
        ImageRef: `docker.io/${repo}`,
        Tag: '1.6.45',
        Digest: 'sha256:57f76c81',
        Workloads: ['StatefulSet/cortex-memcached-blocks-index', 'StatefulSet/cortex-memcached-frontend'],
      }],
    },
  },
};

function render(failedScans: Scan[], policyByRepo: Record<string, { failed: number; pending: number }>) {
  return renderToStaticMarkup(
    <MemoryRouter>
      <PolicyCompliancePanel failedScans={failedScans} policyByRepo={policyByRepo} />
    </MemoryRouter>,
  );
}

describe('PolicyCompliancePanel', () => {
  it('shows a running superseded failing digest instead of All Compliant', () => {
    const html = render([superseded], { [repo]: { failed: 1, pending: 0 } });

    expect(html).not.toContain('All Compliant');
    expect(html).toContain('running an older digest of 1.6.45');
    expect(html).toContain('StatefulSet/cortex-memcached-blocks-index');
    expect(html).toContain('StatefulSet/cortex-memcached-frontend');
    // Restarting alone keeps the cached digest under IfNotPresent.
    expect(html).toContain('imagePullPolicy: Always');
    expect(html).toContain('hetzner-1/monitoring');
    // Rolling pods fixes it; the VEX triage prompt should not ask about it.
    expect(html).toContain('data-prompt-scans="0"');
  });

  it('stays All Compliant when nothing fails', () => {
    const html = render([], {});

    expect(html).toContain('All Compliant');
    expect(html).not.toContain('running an older digest');
  });
});
