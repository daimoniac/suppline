package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// caller is who made a scan request: the API key holder, or a CI identity.
type caller struct {
	admin   bool
	subject string
}

type callerKey struct{}

func callerFrom(ctx context.Context) caller {
	c, _ := ctx.Value(callerKey{}).(caller)
	if c.admin && c.subject == "" {
		c.subject = "api-key"
	}
	return c
}

// bearerToken returns the Authorization header without an optional "Bearer " prefix.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	return strings.TrimPrefix(header, "Bearer ")
}

// validAPIKey compares a token with the API key in constant time.
func (s *APIServer) validAPIKey(token string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.config.APIKey)) == 1
}

// scanRequestAuth guards the scan-request endpoints. The API key may request
// scans of every in-place repository; handlers check other callers against
// the repository's scan-requesters.
func (s *APIServer) scanRequestAuth(next http.HandlerFunc, requireWrite bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireWrite && s.config.ReadOnly {
			s.respondError(w, http.StatusForbidden, "API is in read-only mode")
			return
		}
		if s.config.APIKey == "" {
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller{admin: true})))
			return
		}
		token := bearerToken(r)
		if token == "" {
			s.respondError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}
		if s.validAPIKey(token) {
			next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller{admin: true})))
			return
		}
		s.respondError(w, http.StatusUnauthorized, "Invalid API key")
	}
}
