package errors

import (
	"errors"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// TestManifestNotFoundDetectionProperty tests the property that MANIFEST_UNKNOWN errors
// are correctly classified as ManifestNotFoundError
// **Feature: scan-cleanup-management, Property 1: MANIFEST_UNKNOWN cleanup completeness**
// **Validates: Requirements 1.1, 1.2**
func TestManifestNotFoundDetectionProperty(t *testing.T) {
	properties := gopter.NewProperties(nil)

	// Property: MANIFEST_UNKNOWN patterns are always classified as ManifestNotFoundError
	properties.Property("MANIFEST_UNKNOWN patterns are classified correctly", prop.ForAll(
		func(manifestPattern string, prefix string, suffix string) bool {
			// Create an error with the manifest pattern
			fullMessage := prefix + manifestPattern + suffix
			originalErr := errors.New(fullMessage)
			
			// Classify the error
			classifiedErr := ClassifyRegistryError(originalErr)
			
			// Should be classified as ManifestNotFound
			return IsManifestNotFound(classifiedErr) && !IsTransient(classifiedErr)
		},
		genManifestPattern(),
		gen.AlphaString().Map(func(s string) string { return s[:min(len(s), 5)] }),
		gen.AlphaString().Map(func(s string) string { return s[:min(len(s), 5)] }),
	))

	// Property: Non-manifest errors are classified as transient
	properties.Property("Non-manifest errors are transient", prop.ForAll(
		func(errorMessage string) bool {
			originalErr := errors.New(errorMessage)
			classifiedErr := ClassifyRegistryError(originalErr)
			
			// Should be transient and not manifest error
			return IsTransient(classifiedErr) && !IsManifestNotFound(classifiedErr)
		},
		genNonManifestError(),
	))

	// Property: Nil errors remain nil after classification
	properties.Property("Nil errors remain nil", prop.ForAll(
		func() bool {
			return ClassifyRegistryError(nil) == nil
		},
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// genManifestPattern generates known MANIFEST_UNKNOWN patterns
func genManifestPattern() gopter.Gen {
	manifestPatterns := []interface{}{
		"MANIFEST_UNKNOWN",
		"manifest unknown", 
		"manifest not found",
	}
	
	return gen.OneConstOf(manifestPatterns...)
}

// genNonManifestError generates error messages that should not be classified as manifest errors
func genNonManifestError() gopter.Gen {
	nonManifestMessages := []interface{}{
		"connection timeout",
		"network unreachable", 
		"authentication failed",
		"rate limit exceeded",
		"internal server error",
		"bad gateway",
		"service unavailable",
		"unknown error occurred",
		"repository access denied",
		"invalid credentials",
		"ssl certificate error",
	}
	
	return gen.OneConstOf(nonManifestMessages...)
}

// containsManifestPattern checks if a string contains patterns that should be classified as MANIFEST_UNKNOWN
func containsManifestPattern(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "manifest_unknown") ||
		strings.Contains(s, "manifest unknown") ||
		(strings.Contains(s, "not found") && strings.Contains(s, "manifest"))
}