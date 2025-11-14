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
}
