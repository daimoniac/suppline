package policy

// DefaultExpression is the policy a repository gets when neither
// defaults.policy nor its sync entry sets one. It fails an image on any
// critical vulnerability, and on a high one that is in the CISA Known
// Exploited Vulnerabilities catalog. Exempted findings never count. Kernel
// CVEs reported against header-only packages (linux-libc-dev and friends)
// never fail: they ship no kernel code and a container runs the node's
// kernel, so they are a host patching concern, not an image one.
//
// A known-malicious package fails an image whatever the expression says; that
// gate is separate (see WithMaliciousGate).
const DefaultExpression = `!vulnerabilities.exists(v, !v.exempted && !v.kernelHeaderPackage && (
  v.severity == "CRITICAL" ||
  (v.severity == "HIGH" && v.kev)
))`

// DefaultFailureMessage accompanies DefaultExpression.
const DefaultFailureMessage = "critical, or known-exploited high, vulnerabilities found"

// defaultDescription is what DescribeExpression says for DefaultExpression.
const defaultDescription = "No critical or known-exploited high vulnerabilities (kernel header packages ignored)"

// DefaultConfig returns the implicit policy.
func DefaultConfig() PolicyConfig {
	return PolicyConfig{
		Expression:     DefaultExpression,
		FailureMessage: DefaultFailureMessage,
	}
}

// IsDefaultExpression reports whether expr is DefaultExpression, ignoring
// whitespace. That is safe here because DefaultExpression has no whitespace
// inside a string literal.
func IsDefaultExpression(expr string) bool {
	return stripSpace(expr) == stripSpace(DefaultExpression)
}

func stripSpace(s string) string {
	return whitespaceRE.ReplaceAllString(s, "")
}
