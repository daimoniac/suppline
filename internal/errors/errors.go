package errors

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for common cases
var (
	// ErrTransient indicates a temporary error that should be retried
	ErrTransient = errors.New("transient error")

	// ErrPermanent indicates a permanent error that should not be retried
	ErrPermanent = errors.New("permanent error")

	// ErrNotFound indicates a resource was not found
	ErrNotFound = errors.New("not found")

	// ErrUnauthorized indicates authentication failure
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates authorization failure
	ErrForbidden = errors.New("forbidden")

	// ErrInvalidInput indicates invalid input data
	ErrInvalidInput = errors.New("invalid input")

	// ErrTimeout indicates an operation timed out
	ErrTimeout = errors.New("timeout")

	// ErrRateLimit indicates rate limiting
	ErrRateLimit = errors.New("rate limit exceeded")

	// ErrManifestNotFound indicates a manifest was not found (MANIFEST_UNKNOWN)
	ErrManifestNotFound = errors.New("manifest not found")
)

// TransientError wraps an error to mark it as transient (retryable)
type TransientError struct {
	Cause error
}

func (e *TransientError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transient error: %v", e.Cause)
	}
	return "transient error"
}

func (e *TransientError) Unwrap() error {
	return e.Cause
}

// NewTransient creates a new transient error
func NewTransient(err error) error {
	if err == nil {
		return nil
	}
	return &TransientError{Cause: err}
}

// NewTransientf creates a new transient error with formatting
func NewTransientf(format string, args ...interface{}) error {
	return &TransientError{Cause: fmt.Errorf(format, args...)}
}

// PermanentError wraps an error to mark it as permanent (not retryable)
type PermanentError struct {
	Cause error
}

func (e *PermanentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("permanent error: %v", e.Cause)
	}
	return "permanent error"
}

func (e *PermanentError) Unwrap() error {
	return e.Cause
}

// NewPermanent creates a new permanent error
func NewPermanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Cause: err}
}

// NewPermanentf creates a new permanent error with formatting
func NewPermanentf(format string, args ...interface{}) error {
	return &PermanentError{Cause: fmt.Errorf(format, args...)}
}

// ManifestNotFoundError represents a MANIFEST_UNKNOWN error from registry
type ManifestNotFoundError struct {
	Cause error
}

func (e *ManifestNotFoundError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("manifest not found: %v", e.Cause)
	}
	return "manifest not found"
}

func (e *ManifestNotFoundError) Unwrap() error {
	return e.Cause
}

// NewManifestNotFound creates a new manifest not found error
func NewManifestNotFound(err error) error {
	if err == nil {
		return nil
	}
	return &ManifestNotFoundError{Cause: err}
}

// NewManifestNotFoundf creates a new manifest not found error with formatting
func NewManifestNotFoundf(format string, args ...interface{}) error {
	return &ManifestNotFoundError{Cause: fmt.Errorf(format, args...)}
}

// IsTransient checks if an error is transient using errors.As
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	var transientErr *TransientError
	if errors.As(err, &transientErr) {
		return true
	}

	var permanentErr *PermanentError
	if errors.As(err, &permanentErr) {
		return false
	}

	var manifestErr *ManifestNotFoundError
	if errors.As(err, &manifestErr) {
		return false
	}

	if errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrInvalidInput) ||
		errors.Is(err, ErrManifestNotFound) {
		return false
	}

	if errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrRateLimit) {
		return true
	}

	return false
}

// IsPermanent checks if an error is permanent (not retryable)
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}

	var permanentErr *PermanentError
	return errors.As(err, &permanentErr)
}

// IsManifestNotFound checks if an error is a manifest not found error
func IsManifestNotFound(err error) bool {
	if err == nil {
		return false
	}

	var manifestErr *ManifestNotFoundError
	if errors.As(err, &manifestErr) {
		return true
	}

	return errors.Is(err, ErrManifestNotFound)
}

// ClassifyRegistryError classifies registry errors, specifically detecting MANIFEST_UNKNOWN
func ClassifyRegistryError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	
	// Check for MANIFEST_UNKNOWN error patterns
	if strings.Contains(errStr, "MANIFEST_UNKNOWN") ||
		strings.Contains(errStr, "manifest unknown") ||
		strings.Contains(errStr, "not found") && strings.Contains(errStr, "manifest") {
		return NewManifestNotFound(err)
	}

	// Default to transient for other registry errors
	return NewTransientf("registry error: %w", err)
}
