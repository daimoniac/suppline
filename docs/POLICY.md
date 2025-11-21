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
| Block only fixable vulns | `vulnerabilities.filter(v, v.severity == "CRITICAL" && v.fixedVersion != "" && !v.tolerated).size() == 0` |

## Configuration

### Default Policy

Set a default policy for all repositories:

```yaml
defaults:
  x-policy:
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
    x-policy:
      expression: "criticalCount == 0 && highCount == 0"
      failureMessage: "critical or high vulnerabilities found"
```

## Available Variables

### Vulnerability Counts

- `criticalCount` - Number of critical vulnerabilities (excluding tolerated)
- `highCount` - Number of high vulnerabilities (excluding tolerated)
- `mediumCount` - Number of medium vulnerabilities (excluding tolerated)
- `lowCount` - Number of low vulnerabilities (excluding tolerated)
- `toleratedCount` - Number of tolerated vulnerabilities

### Other Variables

- `vulnerabilities` - List of all vulnerabilities with details
- `imageRef` - Image reference being evaluated (string)

## Vulnerability Object Fields

Each item in the `vulnerabilities` list has:

- `id` - CVE identifier (string)
- `severity` - Severity level (string: CRITICAL, HIGH, MEDIUM, LOW)
- `packageName` - Affected package name (string)
- `version` - Installed version (string)
- `fixedVersion` - Version with fix (string, empty if no fix)
- `description` - Vulnerability description (string)
- `tolerated` - Whether this CVE is tolerated (bool)
- `tolerationStatement` - Reason for toleration (string, if tolerated)
- `tolerationExpiry` - Expiry timestamp (string, RFC3339, if tolerated)

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
x-policy:
  expression: "criticalCount == 0 && highCount == 0 && mediumCount == 0"
  failureMessage: "critical, high, or medium vulnerabilities found"
```

### Lenient Development Policy

Allow up to 5 critical vulnerabilities:

```yaml
x-policy:
  expression: "criticalCount <= 5"
  failureMessage: "too many critical vulnerabilities"
```

### Only Block Fixable Vulnerabilities

Block only critical vulnerabilities that have a fix available:

```yaml
x-policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      v.fixedVersion != "" &&
      !v.tolerated
    ).size() == 0
  failureMessage: "fixable critical vulnerabilities found"
```

### Package-Specific Policy

Block critical vulnerabilities in specific packages:

```yaml
x-policy:
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
x-policy:
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

Allow specific CVEs without using tolerations:

```yaml
x-policy:
  expression: |
    vulnerabilities.filter(v,
      v.severity == "CRITICAL" &&
      !(v.id in ["CVE-2024-12345", "CVE-2024-67890"])
    ).size() == 0
  failureMessage: "critical vulnerabilities found (excluding known exceptions)"
```

## Policy Evaluation Flow

1. **Scan completes** - Trivy returns vulnerability list
2. **Apply tolerations** - Tolerated CVEs are marked and excluded from counts
3. **Evaluate policy** - CEL expression is evaluated with current data
4. **Make decision** - If expression returns `true`, policy passes
5. **Attest results** - All images receive attestations (SBOM, vulnerabilities, SCAI)

## Interaction with Tolerations

Tolerations are applied **before** policy evaluation:

```yaml
sync:
  - source: nginx
    target: myregistry/nginx
    type: repository
    x-tolerate:
      - id: CVE-2024-56171
        statement: "Accepted risk"
        expires_at: 2025-12-31T23:59:59Z
    x-policy:
      expression: "criticalCount == 0"  # CVE-2024-56171 won't count
```

**Behavior:**
- Tolerated CVEs are excluded from `criticalCount`, `highCount`, etc.
- Tolerated CVEs have `tolerated: true` in the `vulnerabilities` list
- Expired tolerations are ignored (CVE counts as normal)

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

Begin with a strict policy and add tolerations for specific CVEs:

```yaml
x-policy:
  expression: "criticalCount == 0 && highCount == 0"
x-tolerate:
  - id: CVE-2024-12345
    statement: "No fix available, mitigated by network policy"
    expires_at: 2025-06-30T23:59:59Z
```

### Use Descriptive Failure Messages

Help developers understand why an image failed:

```yaml
x-policy:
  expression: "criticalCount == 0 && highCount <= 3"
  failureMessage: "Image has critical vulnerabilities or more than 3 high severity issues. Please update base image or add toleration with justification."
```

### Document Policy Decisions

Keep a record of why policies are configured a certain way:

```yaml
# Production: Zero tolerance for critical/high
# Rationale: Customer-facing service with PII
- source: myapp-prod
  target: myregistry/myapp-prod
  x-policy:
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
    x-policy:
      expression: "criticalCount == 0 && highCount == 0"
  
  # Lenient for development
  - source: myapp
    target: myregistry/myapp-dev
    x-policy:
      expression: "criticalCount <= 10"
```

## Troubleshooting

### Policy Always Fails

**Check:**
1. Are there untolerated critical vulnerabilities?
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
2. Are all CVEs being tolerated?
3. Is the policy being applied to the correct repository?

```bash
# Check toleration status
curl http://localhost:8080/api/v1/tolerations

# Verify policy configuration
cat suppline.yml | grep -A5 x-policy
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
x-policy:
  expression: |
    (hour(now()) >= 9 && hour(now()) <= 17) ?
      criticalCount <= 2 :
      criticalCount == 0
```

### Severity-Weighted Policy

Assign weights to different severity levels:

```yaml
x-policy:
  expression: |
    (criticalCount * 10 + highCount * 5 + mediumCount * 2 + lowCount) <= 20
  failureMessage: "vulnerability score exceeds threshold"
```

### Package Allowlist

Only allow vulnerabilities in specific packages:

```yaml
x-policy:
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
x-policy:
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
x-policy:
  expression: "criticalCount == 0"
  failureMessage: "Critical vulnerabilities found"
```

## Further Reading

- [CEL Language Specification](https://github.com/google/cel-spec)
- [CEL Go Implementation](https://github.com/google/cel-go)
- [Configuration Reference](CONFIGURATION.md)
- [API Documentation](API.md)
