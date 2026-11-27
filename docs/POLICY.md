# Policy Configuration Guide

suppline uses CEL (Common Expression Language) for flexible, powerful security policies.

## Quick Reference

### Common Policies

| Policy | Expression |
|--------|-----------|
| Block critical only (default) | `criticalCount == 0` |
| Block critical + high | `criticalCount == 0 && highCount == 0` |
| Block medium+ | `criticalCount == 0 && highCount == 0 && mediumCount == 0` |
| Allow up to 2 high | `criticalCount == 0 && highCount <= 2` |
| Block only fixable vulns | `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.exempted).size() == 0` |
| Block known-exploited (CISA KEV) | `criticalCount == 0 && kevCount == 0` |

## Configuration

### Default Policy

Set a default policy for all repositories:

```yaml
defaults:
  policy:
    expression: "criticalCount == 0"
    failureMessage: "critical vulnerabilities found"
```

### Per-Repository Policy

Override the default for specific repositories:

```yaml
sync:
  - source: nginx
    target: myregistry/nginx
    type: repository
    policy:
      expression: "criticalCount == 0 && highCount == 0"
      failureMessage: "critical or high vulnerabilities found"
```

## Available Variables

### Vulnerability Counts

- `criticalCount` - Number of critical vulnerabilities (excluding VEX-exempted)
- `highCount` - Number of high vulnerabilities (excluding VEX-exempted)
- `mediumCount` - Number of medium vulnerabilities (excluding VEX-exempted)
- `lowCount` - Number of low vulnerabilities (excluding VEX-exempted)
- `exemptedCount` - Number of VEX-exempted vulnerabilities
- `kevCount` - Number of vulnerabilities in the CISA KEV catalog (excluding VEX-exempted)

### Other Variables

- `vulnerabilities` - List of all vulnerabilities with details
- `imageRef` - Image reference being evaluated (string)
- `osEndOfLife` - Whether the scanner reports the image operating system as end of life (bool). Images with no OS metadata, and scans recorded before this field existed, are `false`.
- `malicious` - List of known-malicious packages found in the image (see below)
- `maliciousCount` - Number of known-malicious packages found (int)
- `kevStatus` - State of the CISA KEV catalog: `ok`, `stale`, `unavailable` or `disabled` (see below)

### Known Exploited Vulnerabilities (CISA KEV)

Each vulnerability carries whether it is in the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): CVEs with evidence of exploitation in the wild. That is a stronger signal than severity alone, and the catalog includes many HIGH and some MEDIUM CVEs. The catalog comes from the `kev` feed ([CONFIGURATION.md](CONFIGURATION.md#known-exploited-vulnerabilities-kev)).

Nothing changes until an expression uses these fields. When CISA adds a CVE that a stored image has, images in repositories whose policy reads KEV are rescanned within one `kev.sync_interval`, so the gate closes the same day rather than at the next rescan. To block every non-exempted known-exploited finding, add `kevCount == 0`:

```yaml
expression: "criticalCount == 0 && kevCount == 0"
```

`kevStatus` says how far to trust the KEV fields:

| `kevStatus` | Meaning | KEV fields |
|---|---|---|
| `ok` | The catalog is loaded and recent | Current |
| `stale` | No sync has succeeded for `kev.stale_after` | Still answered from the last catalog |
| `unavailable` | No catalog has loaded yet (just after startup) | All `false`, `kevCount == 0` |
| `disabled` | `kev.enabled: false` | All `false`, `kevCount == 0` |

`kevCount == 0` alone fails open while the catalog is unavailable. To fail closed instead, so an image is never passed without a KEV check, require a usable catalog:

```yaml
expression: 'criticalCount == 0 && kevCount == 0 && kevStatus in ["ok", "stale"]'
```

A scan rejected only because the catalog was not loaded yet passes on its next rescan.

Kernel CVEs are reported against kernel header packages such as `linux-libc-dev`, which ship no kernel code. A container runs the node's kernel, so these findings are a host patching concern, not an image one, and several are in the KEV catalog. `kernelHeaderPackage` lets a policy leave them out:

```yaml
expression: '!vulnerabilities.exists(v, v.kev && !v.exempted && !v.kernelHeaderPackage)'
```

A VEX statement exempts a KEV finding like any other. Automated triage never writes `not_affected` for a CVE in the catalog while `triage.block_kev` is on (the default).

### Malicious Packages

Each scan matches the image's language packages (npm, PyPI, RubyGems, NuGet, crates.io, Go, Maven, Packagist) against [ossf/malicious-packages](https://github.com/ossf/malicious-packages). A match is not a vulnerability: it has no severity, is not counted in `criticalCount` and friends, is not in `vulnerabilities`, and is never sent to triage.

A false positive — the image contains a *different* package with the same name and version, typically an internal workspace package that someone squatted on the public registry — is exempted with a hand-written `vex` statement in state `false_positive`:

```yaml
vex:
  - id: MAL-2025-9145
    state: false_positive
    detail: "@opensearch/datemath 5.0.3 is OpenSearch Dashboards' own workspace package, not the squatted npm publish"
    expires_at: 2027-05-01T00:00:00Z
```

You can write it by hand, or from the **Triage** view (malicious findings show there as *Malicious*; automated triage never runs on them) and the **Malicious Packages** view, which open the usual statement dialog locked to `false_positive` with a required detail. No other state exempts a MAL id (`not_affected` with a MAL id is rejected when the config loads), and `vex-auto` may never name one. An exempted finding stays in the `malicious` list with `exempted: true`, is not counted in `maliciousCount`, does not trigger the gate, and is recorded in the VEX and SCAI attestations.

With `malicious-packages.block: true` (the default), any malicious finding fails the image regardless of the expression. The reason starts with `malicious packages found:` and each finding is recorded as a policy-failure finding with `Kind: "malicious"`. You don't need to add `maliciousCount == 0` to your expression. With `block: false` only the expression decides, and you can write rules such as:

```yaml
expression: 'criticalCount == 0 && malicious.filter(m, m.ecosystem == "npm").size() == 0'
```

Each item in the `malicious` list has `id` (MAL id), `ecosystem`, `packageName`, `version`, `purl`, `summary`, `url`, and `exempted` (covered by a `false_positive` statement). See [CONFIGURATION.md](CONFIGURATION.md#malicious-packages-x-malicious-packages).

## Vulnerability Object Fields

Each item in the `vulnerabilities` list has:

- `id` - CVE identifier (string)
- `severity` - Severity level (string: CRITICAL, HIGH, MEDIUM, LOW)
- `packageName` - Affected package name (string)
- `version` - Installed version (string)
- `fixedVersion` - Version with fix (string, empty if no fix)
- `description` - Vulnerability description (string)
- `exempted` - Whether this CVE is exempted by a VEX statement (bool)
- `vexState` - VEX analysis state for this CVE (string, if exempted)
- `vexJustification` - VEX justification (string, if exempted)
- `vexDetail` - VEX detail/reason (string, if exempted)
- `kev` - Whether the CVE is in the CISA KEV catalog (bool)
- `kevDateAdded` - When CISA added it, `YYYY-MM-DD` (string, empty if not listed)
- `kevRansomware` - Whether CISA lists it as known to be used in ransomware campaigns (bool)
- `kernelHeaderPackage` - Whether the package is a kernel header package such as `linux-libc-dev` (bool)
- `vendorStatus` - Distro status as the scanner reports it (string): `affected`, `fixed`, `will_not_fix`, `fix_deferred`, `end_of_life`, `not_affected`, or empty
- `vendorSeverity` - Distro severity for the image OS (string: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`, or empty). Empty when the distro published no rating. The NVD rating is not copied here; it restates the scanner severity already in `severity`
- `attackVector` - CVSS attack vector (string: `NETWORK`, `ADJACENT`, `LOCAL`, `PHYSICAL`, or empty). Taken from the distro CVSS vector when that source published one, otherwise from NVD

## Distro status, vendor severity, attack vector, and OS end of life

These fields are facts. The default expression does not read them, so a repository keeps failing on `criticalCount` until its own expression opts in. An empty string means the scanner had no value. Expressions that should stay closed when the value is missing treat empty as still failing.

A repository that still fails criticals, but accepts a critical the distro rated below CRITICAL:

```yaml
expression: |
  !vulnerabilities.exists(v, !v.exempted && v.severity == "CRITICAL" &&
    (v.vendorSeverity == "" || v.vendorSeverity == "CRITICAL" || v.vendorSeverity == "UNKNOWN"))
```

A repository that fails criticals the scanner could not place, or that are reachable over the network, and lets a local or physical vector pass:

```yaml
expression: |
  !vulnerabilities.exists(v, !v.exempted && v.severity == "CRITICAL" &&
    (v.attackVector == "" || v.attackVector == "NETWORK"))
```

A repository that also fails an image whose operating system is end of life:

```yaml
expression: |
  criticalCount == 0 && !osEndOfLife
```

`vendorStatus` is the distro's own word for the finding (`will_not_fix`, `not_affected`, `end_of_life`). `fixed` overlaps `fixedVersion`: a fix exists, and the installed package does not have it yet.

## CEL Operators

### Comparison

- `==` - Equal
- `!=` - Not equal
- `<` - Less than
- `<=` - Less than or equal
- `>` - Greater than
- `>=` - Greater than or equal

### Logic

- `&&` - Logical AND
- `||` - Logical OR
- `!` - Logical NOT

### String Operations

- `.startsWith(prefix)` - Check if string starts with prefix
- `.endsWith(suffix)` - Check if string ends with suffix
- `.contains(substring)` - Check if string contains substring

### List Operations

- `.filter(var, condition)` - Filter list by condition
- `.size()` - Get list size
- `in` - Check if item is in list

## Policy Examples

### Strict Production Policy

Block all critical, high, and medium vulnerabilities:

```yaml
policy:
  expression: "criticalCount == 0 && highCount == 0 && mediumCount == 0"
  failureMessage: "critical, high, or medium vulnerabilities found"
```

### Lenient Development Policy

Allow up to 5 critical vulnerabilities:

```yaml
policy:
  expression: "criticalCount <= 5"
  failureMessage: "too many critical vulnerabilities"
```

### Only Block Fixable Vulnerabilities

Block only critical vulnerabilities that have a fix available:

```yaml
policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      v.fixedVersion != "" &&
      !v.exempted
    ).size() == 0
  failureMessage: "fixable critical vulnerabilities found"
```

### Package-Specific Policy

Block critical vulnerabilities in specific packages:

```yaml
policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      v.packageName.startsWith("openssl")
    ).size() == 0
  failureMessage: "critical vulnerabilities in openssl found"
```

### Complex Policy

Combine multiple conditions:

```yaml
policy:
  expression: |
    criticalCount == 0 &&
    highCount <= 3 &&
    vulnerabilities.filter(v,
      v.severity == "HIGH" &&
      v.fixedVersion == ""
    ).size() == 0
  failureMessage: "policy failed: too many vulnerabilities or unfixable high severity issues"
```

### Allow Specific CVEs

Allow specific CVEs without using VEX statements:

```yaml
policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      !(v.id in ["CVE-2024-12345", "CVE-2024-67890"])
    ).size() == 0
  failureMessage: "critical vulnerabilities found (excluding known exceptions)"
```

## Policy Evaluation Flow

1. **Scan completes** - Trivy returns vulnerability list
2. **Apply VEX statements** - VEX-exempted CVEs are marked and excluded from counts
3. **Evaluate policy** - CEL expression is evaluated with current data
4. **Make decision** - If expression returns `true`, policy passes
5. **Attest results** - All images receive attestations (SBOM, vulnerabilities, VEX, SCAI)

## Interaction with VEX Statements

VEX statements are applied **before** policy evaluation:

```yaml
sync:
  - source: nginx
    target: myregistry/nginx
    type: repository
    vex:
      - id: CVE-2024-56171
        state: not_affected
        justification: vulnerable_code_not_present
        detail: "Accepted risk"
        expires_at: 2025-12-31T23:59:59Z
    policy:
      expression: "criticalCount == 0"  # CVE-2024-56171 won't count
```

**Behavior:**
- VEX-exempted CVEs (state `not_affected` or `false_positive`, not expired) are excluded from `criticalCount`, `highCount`, etc.
- Exempted CVEs have `exempted: true` in the `vulnerabilities` list
- Expired VEX statements are ignored (CVE counts as normal)
- Only `not_affected` and `false_positive` exempt CVEs from policy counts; other states (`affected`, `in_triage`, `resolved`, `resolved_with_pedigree`) are informational. A resolved build no longer reports the CVE, so a repository-wide `resolved` statement would only ever exempt the unfixed tags

### `vex-auto`

Triage writes exemptions into `vex-auto` on the sync entry. Effective statements are `defaults.vex`, then the sync entry's `vex`, then `vex-auto`. The first statement for an id wins, so a hand-written `vex` id is never replaced by an auto statement. A sync-entry statement whose id is also in `defaults.vex` never applies, whatever its expiry; Tasks lists it under VEX statements without effect as overridden by `defaults.vex`. An auto statement with `state: affected` stays in the file as the decision record and does not exempt the CVE, so the gate fails.

## Testing Policies

### Using the API

Test policy changes without modifying configuration:

```bash
# Re-evaluate policy for all images
curl -X POST http://localhost:8080/api/v1/policy/reevaluate \
  -H "Authorization: Bearer your-api-key"

# Check results
curl http://localhost:8080/api/v1/images/failed
```

### Dry Run

To test a policy without affecting production:

1. Add the policy to a test repository
2. Monitor logs for policy evaluation results
3. Check metrics for policy pass/fail counts
4. Adjust policy as needed

## Best Practices

### Start Strict, Relax as Needed

Begin with a strict policy and add VEX statements for specific CVEs:

```yaml
policy:
  expression: "criticalCount == 0 && highCount == 0"
vex:
  - id: CVE-2024-12345
    state: not_affected
    justification: vulnerable_code_not_in_execute_path
    detail: "No fix available, mitigated by network policy"
    expires_at: 2025-06-30T23:59:59Z
```

### Use Descriptive Failure Messages

Help developers understand why an image failed:

```yaml
policy:
  expression: "criticalCount == 0 && highCount <= 3"
  failureMessage: "Image has critical vulnerabilities or more than 3 high severity issues. Please update base image or add VEX statement with justification."
```

### Document Policy Decisions

Keep a record of why policies are configured a certain way:

```yaml
# Production: Zero tolerance for critical/high
# Rationale: Customer-facing service with PII
- source: myapp-prod
  target: myregistry/myapp-prod
  policy:
    expression: "criticalCount == 0 && highCount == 0"
```

### Monitor Policy Effectiveness

Track metrics to understand policy impact:

```bash
# Check policy pass rate
curl http://localhost:9090/metrics | grep suppline_policy

# Review failed images
curl http://localhost:8080/api/v1/images/failed
```

### Use Environment-Specific Policies

Different policies for different environments:

```yaml
sync:
  # Strict for production
  - source: myapp
    target: myregistry/myapp-prod
    policy:
      expression: "criticalCount == 0 && highCount == 0"
  
  # Lenient for development
  - source: myapp
    target: myregistry/myapp-dev
    policy:
      expression: "criticalCount <= 10"
```

## Troubleshooting

### Policy Always Fails

**Check:**
1. Are there unexempted critical vulnerabilities?
2. Is the expression syntax correct?
3. Are variable names spelled correctly?

```bash
# View vulnerability details
curl http://localhost:8080/api/v1/scans/sha256:abc123... | jq '.vulnerabilities'

# Check logs for policy evaluation
docker compose logs suppline | grep "policy evaluation"
```

### Policy Always Passes

**Check:**
1. Is the expression too lenient?
2. Are all CVEs being exempted by VEX statements?
3. Is the policy being applied to the correct repository?

```bash
# Check VEX statement status
curl http://localhost:8080/api/v1/vex

# Verify policy configuration
cat suppline.yml | grep -A5 policy
```

### Expression Syntax Errors

**Common mistakes:**
- Using `=` instead of `==`
- Forgetting quotes around strings
- Incorrect variable names
- Missing parentheses in complex expressions

**Check logs:**
```bash
docker compose logs suppline | grep -i "policy\|cel\|expression"
```

## Advanced Examples

### Time-Based Policy

Allow more vulnerabilities during business hours (requires custom implementation):

```yaml
# This is a conceptual example - not currently supported
policy:
  expression: |
    (hour(now()) >= 9 && hour(now()) <= 17) ?
      criticalCount <= 2 :
      criticalCount == 0
```

### Severity-Weighted Policy

Assign weights to different severity levels:

```yaml
policy:
  expression: |
    (criticalCount * 10 + highCount * 5 + mediumCount * 2 + lowCount) <= 20
  failureMessage: "vulnerability score exceeds threshold"
```

### Package Allowlist

Only allow vulnerabilities in specific packages:

```yaml
policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      !(v.packageName in ["pkg1", "pkg2", "pkg3"])
    ).size() == 0
  failureMessage: "critical vulnerabilities in non-approved packages"
```

## Migration from Other Systems

### From Kyverno

Kyverno policy:
```yaml
spec:
  rules:
    - name: check-vulnerabilities
      validate:
        message: "Critical vulnerabilities found"
        pattern:
          critical: 0
```

Equivalent suppline policy:
```yaml
policy:
  expression: "criticalCount == 0"
  failureMessage: "Critical vulnerabilities found"
```

### From OPA/Rego

OPA policy:
```rego
deny[msg] {
  input.critical > 0
  msg := "Critical vulnerabilities found"
}
```

Equivalent suppline policy:
```yaml
policy:
  expression: "criticalCount == 0"
  failureMessage: "Critical vulnerabilities found"
```

## Further Reading

- [CEL Language Specification](https://github.com/google/cel-spec)
- [CEL Go Implementation](https://github.com/google/cel-go)
- [Configuration Reference](CONFIGURATION.md)
- [API Documentation](API.md)
