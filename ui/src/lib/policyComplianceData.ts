import type { APIClient, PolicyFailureFinding, Scan } from './api';

export type PolicyComplianceSnapshot = {
  failedScans: Scan[];
  policyByRepo: Record<string, { failed: number; pending: number }>;
  failedCount: number;
  pendingCount: number;
  failedInUseCount: number;
};

export async function fetchPolicyComplianceData(
  apiClient: APIClient,
  inUseQuery: boolean | undefined
): Promise<PolicyComplianceSnapshot> {
  const nonPassedScans = await apiClient.getScans({
    policy_passed: false,
    ...(inUseQuery !== undefined && { in_use: inUseQuery }),
  });

  const failedScans = nonPassedScans.filter(s => s.PolicyStatus !== 'pending');
  const pendingScans = nonPassedScans.filter(s => s.PolicyStatus === 'pending');
  const policyByRepo = nonPassedScans.reduce<Record<string, { failed: number; pending: number }>>((acc, scan) => {
    const repo = scan.Repository || 'unknown';
    acc[repo] ||= { failed: 0, pending: 0 };
    if (scan.PolicyStatus === 'pending') acc[repo].pending += 1;
    else acc[repo].failed += 1;
    return acc;
  }, {});

  return {
    failedScans,
    policyByRepo,
    failedCount: failedScans.length,
    pendingCount: pendingScans.length,
    failedInUseCount: failedScans.filter(s => !!s.RuntimeUsed).length,
  };
}

export function buildPolicyFixPromptRows(
  scans: Pick<Scan, 'Repository' | 'Tag' | 'PolicyFailureFindings'>[]
) {
  const grouped = new Map<string, { image: string; cve: string; component: string; tags: Set<string> }>();
  for (const scan of scans) {
    const image = scan.Repository || 'unknown';
    const tag = scan.Tag || 'untagged';
    const findings: PolicyFailureFinding[] = scan.PolicyFailureFindings || [];
    for (const finding of findings) {
      const cve = finding.CVEID || '';
      const component = finding.PackageName || '';
      if (!cve || !component) continue;
      const key = `${image}|${cve}|${component}`;
      const existing = grouped.get(key);
      if (existing) {
        existing.tags.add(tag);
        continue;
      }
      grouped.set(key, {
        image,
        cve,
        component,
        tags: new Set([tag]),
      });
    }
  }

  return Array.from(grouped.values())
    .sort((a, b) => a.image.localeCompare(b.image) || a.cve.localeCompare(b.cve) || a.component.localeCompare(b.component))
    .map(entry => ({
      image: entry.image,
      cve: entry.cve,
      component: entry.component,
      affectedTags: Array.from(entry.tags).sort().join(', '),
    }));
}

export function buildPolicyFixPrompt(
  rows: Array<{ image: string; cve: string; component: string; affectedTags: string }>
): string {
  if (rows.length === 0) {
    return '';
  }

  const lines = rows.map(row => `| ${row.image} | ${row.cve} | ${row.component} | ${row.affectedTags} |`).join('\n');
  return [
    'Please use the "cve-vex-triage" skill to triage and fix policy violations for the following vulnerabilities. Use the "Batch Triage Template" from the skill for processing these multiple findings:',
    '',
    '| Image | CVE | Affected component | Affected tags |',
    '|---|---|---|---|',
    lines,
  ].join('\n');
}
