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
  inUseRequestParams: Record<string, string> | undefined
): Promise<PolicyComplianceSnapshot> {
  const nonPassedScans = await apiClient.getScans({
    policy_passed: false,
    ...(inUseRequestParams && inUseRequestParams),
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
    .sort((a, b) => a.cve.localeCompare(b.cve) || a.image.localeCompare(b.image) || a.component.localeCompare(b.component))
    .map(entry => ({
      image: entry.image,
      cve: entry.cve,
      component: entry.component,
      affectedTags: Array.from(entry.tags).sort().join(', '),
    }));
}

const CVE_VEX_TRIAGE_WORKFLOW_PROMPT = `## CVE VEX Triage workflow description
Use this skill to triage vulnerabilities against deployed reality in this repo and write image-level VEX statements in \`values/common/suppline.yaml\`.

0. locate suppline.yaml and get to know the infrastructure context.
this repository is a gitops repo and should contain an AGENTS.md.
it should also contain a suppline.yml or suppline.yaml to which all changes will apply.
this should give you enough context on infrastructure topology to make educated decisions for vulnerability triage.

1. Build and enrich the working set.
Start from the incoming table:

| CVE | Image | Affected tags |
|---|---|---|

Then enrich each row with package, fixed version, and authoritative advisory source.

2. Group before deep triage.
Group by vulnerable package, then by image family/base-image lineage.
Analyze advisory details once per group, but keep final decisions per image.

3. Map each finding to this repo.
Identify which release is enabled, which mirrored image is used, and which routes/features are exposed. Check if network policies or ingress routes make the vulnerable code inaccessible from outside.

4. Decide exploitability by reachability.
Do not mark not affected based only on transitive presence.
Assess whether the vulnerable code path is reachable in this deployment.
Assign a state: \`not_affected\`, \`affected\`
Assign a justification: one of
  - \`code_not_present\`
  - \`code_not_reachable\`
  - \`requires_configuration\`
  - \`requires_dependency\`
  - \`requires_environment\`
  - \`protected_by_compiler\`
  - \`protected_at_runtime\`
  - \`protected_at_perimeter\`
  - \`protected_by_mitigations\`
For x-vex.detail: Prefer concrete wording tied to exploit preconditions and repo configuration.
Good style examples:
- \`Not practically vulnerable: ... requires attacker-controlled ...\`
- \`... does not expose any feature that ...\`
- \`... is only present through fixed internal dependency stacks ...\`
Avoid vague phrasing such as \`not used by us\` or \`safe in our setup\`.

5. clearance

If you are not sure about a CVE's details or how to assess reachability, flag it for human review rather than guessing. It's better to have an open question than an inaccurate VEX statement.

6. Record per-image decisions using this matrix:

| CVE | Suppline image key | Deployment path | Reachable code path | VEX status | Justification summary |
|---|---|---|---|---|---|

7. Apply VEX edits safely and validate.
Append statements to the nearest \`x-vex\` block under the exact affected image entry in \`values/common/suppline.yaml\`.
If missing, create \`x-vex\` only for that image entry.
Do not overwrite sibling entries and do not merge statements across images.
After edits, validate YAML and ensure every CVE-image pair has one clear disposition.

## Done Criteria
- Advisory details verified from authoritative source(s)
- Affected Suppline image entries identified
- Reachability assessed from actual repo config
- VEX statements added/updated per image
- YAML formatting validated

Please use the described workflow to triage and fix policy violations for the following vulnerabilities:`;

export function buildPolicyFixPrompt(
  rows: Array<{ image: string; cve: string; component: string; affectedTags: string }>
): string {
  if (rows.length === 0) {
    return '';
  }

  const lines = rows.map(row => `| ${row.cve} | ${row.image} | ${row.affectedTags} |`).join('\n');
  return [
    CVE_VEX_TRIAGE_WORKFLOW_PROMPT,
    '',
    '| CVE | Image | Affected tags |',
    '|---|---|---|',
    lines,
  ].join('\n');
}
