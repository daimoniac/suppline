package worker

import "strings"

// isTransientError determines if an error is transient and should be retried
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network-related errors (transient)
	transientPatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"too many requests",
		"rate limit",
		"service unavailable",
		"gateway timeout",
		"bad gateway",
		"dial tcp",
		"i/o timeout",
		"EOF",
		"broken pipe",
	}

	for _, pattern := range transientPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	// Permanent errors (not transient)
	permanentPatterns := []string{
		"not found",
		"unauthorized",
		"forbidden",
		"authentication",
		"invalid",
		"malformed",
		"permission denied",
		"not configured",
		"is nil",
	}

	for _, pattern := range permanentPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return false
		}
	}

	// Default to transient for unknown errors (safer to retry)
	return true
}
