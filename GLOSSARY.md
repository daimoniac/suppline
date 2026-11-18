# suppline

suppline mirrors container images, scans them, decides by policy whether they may be used, and signs attestations of the outcome.

## Language

### Malicious packages

**Malicious finding**:
A package in an image that matches a known-malicious package advisory (`MAL-*`). It has no severity and is not a vulnerability.
_Avoid_: malware vulnerability, MAL CVE

**MAL check status**:
Whether a scan's malicious-package check actually ran: `ok`, `unavailable` (no index) or `stale` (data older than allowed).
_Avoid_: MAL health

**Package inventory**:
The language-ecosystem packages (by purl) recorded for an image digest, kept so new advisories can be matched without rescanning.
_Avoid_: SBOM cache

**Malicious-package gate**:
The built-in rule that fails policy for any malicious finding, independent of the policy expression.
_Avoid_: MAL policy
