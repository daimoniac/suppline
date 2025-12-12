package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestTransientError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "with cause",
			err:     NewTransient(errors.New("network timeout")),
			wantMsg: "transient error: network timeout",
		},
		{
			name:    "with nil cause",
			err:     NewTransient(nil),
			wantMsg: "",
		},
		{
			name:    "with formatted error",
			err:     NewTransientf("connection failed: %s", "timeout"),
			wantMsg: "transient error: connection failed: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				return
			}
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestPermanentError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "with cause",
			err:     NewPermanent(errors.New("not found")),
			wantMsg: "permanent error: not found",
		},
		{
			name:    "with nil cause",
			err:     NewPermanent(nil),
			wantMsg: "",
		},
		{
			name:    "with formatted error",
			err:     NewPermanentf("invalid input: %s", "malformed"),
			wantMsg: "permanent error: invalid input: malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				return
			}
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "explicit transient error",
			err:  NewTransient(errors.New("timeout")),
			want: true,
		},
		{
			name: "explicit permanent error",
			err:  NewPermanent(errors.New("not found")),
			want: false,
		},
		{
			name: "wrapped transient error",
			err:  fmt.Errorf("failed: %w", NewTransient(errors.New("timeout"))),
			want: true,
		},
		{
			name: "wrapped permanent error",
			err:  fmt.Errorf("failed: %w", NewPermanent(errors.New("invalid"))),
			want: false,
		},
		{
			name: "timeout sentinel",
			err:  ErrTimeout,
			want: true,
		},
		{
			name: "rate limit sentinel",
			err:  ErrRateLimit,
			want: true,
		},
		{
			name: "not found sentinel",
			err:  ErrNotFound,
			want: false,
		},
		{
			name: "unauthorized sentinel",
			err:  ErrUnauthorized,
			want: false,
		},
		{
			name: "forbidden sentinel",
			err:  ErrForbidden,
			want: false,
		},
		{
			name: "invalid input sentinel",
			err:  ErrInvalidInput,
			want: false,
		},
		{
			name: "wrapped timeout sentinel",
			err:  fmt.Errorf("operation failed: %w", ErrTimeout),
			want: true,
		},
		{
			name: "wrapped not found sentinel",
			err:  fmt.Errorf("resource missing: %w", ErrNotFound),
			want: false,
		},
		{
			name: "unknown error defaults to non-transient",
			err:  errors.New("unknown error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTransient(tt.err); got != tt.want {
				t.Errorf("IsTransient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPermanent(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "explicit permanent error",
			err:  NewPermanent(errors.New("not found")),
			want: true,
		},
		{
			name: "explicit transient error",
			err:  NewTransient(errors.New("timeout")),
			want: false,
		},
		{
			name: "wrapped permanent error",
			err:  fmt.Errorf("failed: %w", NewPermanent(errors.New("invalid"))),
			want: true,
		},
		{
			name: "unknown error",
			err:  errors.New("unknown error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermanent(tt.err); got != tt.want {
				t.Errorf("IsPermanent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	t.Run("transient error unwrap", func(t *testing.T) {
		cause := errors.New("original error")
		err := NewTransient(cause)

		unwrapped := errors.Unwrap(err)
		if unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})

	t.Run("permanent error unwrap", func(t *testing.T) {
		cause := errors.New("original error")
		err := NewPermanent(cause)

		unwrapped := errors.Unwrap(err)
		if unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})

	t.Run("manifest not found error unwrap", func(t *testing.T) {
		cause := errors.New("original error")
		err := NewManifestNotFound(cause)

		unwrapped := errors.Unwrap(err)
		if unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})
}

func TestManifestNotFoundError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "with cause",
			err:     NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
			wantMsg: "manifest not found: MANIFEST_UNKNOWN",
		},
		{
			name:    "with nil cause",
			err:     NewManifestNotFound(nil),
			wantMsg: "",
		},
		{
			name:    "with formatted error",
			err:     NewManifestNotFoundf("manifest error: %s", "not found"),
			wantMsg: "manifest not found: manifest error: not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				return
			}
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestIsManifestNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "explicit manifest not found error",
			err:  NewManifestNotFound(errors.New("MANIFEST_UNKNOWN")),
			want: true,
		},
		{
			name: "wrapped manifest not found error",
			err:  fmt.Errorf("failed: %w", NewManifestNotFound(errors.New("MANIFEST_UNKNOWN"))),
			want: true,
		},
		{
			name: "manifest not found sentinel",
			err:  ErrManifestNotFound,
			want: true,
		},
		{
			name: "wrapped manifest not found sentinel",
			err:  fmt.Errorf("registry error: %w", ErrManifestNotFound),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("other error"),
			want: false,
		},
		{
			name: "transient error",
			err:  NewTransient(errors.New("timeout")),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsManifestNotFound(tt.err); got != tt.want {
				t.Errorf("IsManifestNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyRegistryError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantType       string
		wantManifest   bool
		wantTransient  bool
	}{
		{
			name:          "nil error",
			err:           nil,
			wantType:      "nil",
			wantManifest:  false,
			wantTransient: false,
		},
		{
			name:          "MANIFEST_UNKNOWN error",
			err:           errors.New("MANIFEST_UNKNOWN: manifest not found"),
			wantType:      "manifest",
			wantManifest:  true,
			wantTransient: false,
		},
		{
			name:          "manifest unknown lowercase",
			err:           errors.New("manifest unknown"),
			wantType:      "manifest",
			wantManifest:  true,
			wantTransient: false,
		},
		{
			name:          "manifest not found",
			err:           errors.New("manifest not found"),
			wantType:      "manifest",
			wantManifest:  true,
			wantTransient: false,
		},
		{
			name:          "other registry error",
			err:           errors.New("connection timeout"),
			wantType:      "transient",
			wantManifest:  false,
			wantTransient: true,
		},
		{
			name:          "network error",
			err:           errors.New("network unreachable"),
			wantType:      "transient",
			wantManifest:  false,
			wantTransient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyRegistryError(tt.err)
			
			if tt.wantType == "nil" {
				if result != nil {
					t.Errorf("ClassifyRegistryError() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Errorf("ClassifyRegistryError() = nil, want non-nil")
				return
			}

			gotManifest := IsManifestNotFound(result)
			if gotManifest != tt.wantManifest {
				t.Errorf("IsManifestNotFound() = %v, want %v", gotManifest, tt.wantManifest)
			}

			gotTransient := IsTransient(result)
			if gotTransient != tt.wantTransient {
				t.Errorf("IsTransient() = %v, want %v", gotTransient, tt.wantTransient)
			}
		})
	}
}
