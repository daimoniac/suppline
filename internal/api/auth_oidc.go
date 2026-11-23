package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/daimoniac/suppline/internal/config"
)

// oidcVerifier checks OIDC ID tokens, such as GitLab CI id_tokens, and returns
// the claim that names the caller. It discovers the issuer on first use, so
// suppline starts even when the issuer is unreachable.
type oidcVerifier struct {
	settings config.OIDCSettings
	client   *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

func newOIDCVerifier(settings config.OIDCSettings, client *http.Client) *oidcVerifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if settings.Claim == "" {
		settings.Claim = config.DefaultOIDCClaim
	}
	return &oidcVerifier{settings: settings, client: client}
}

// load discovers the issuer once. A failure is not cached, so the next
// request tries again.
func (v *oidcVerifier) load() (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	// The provider keeps this context to fetch signing keys later, so it must
	// not be a request context.
	ctx := oidc.ClientContext(context.Background(), v.client)
	provider, err := oidc.NewProvider(ctx, v.settings.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %s: %w", v.settings.Issuer, err)
	}
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.settings.Audience})
	return v.verifier, nil
}

// errIssuerUnavailable means the token could not be checked because the
// issuer could not be discovered.
type errIssuerUnavailable struct{ err error }

func (e errIssuerUnavailable) Error() string { return e.err.Error() }

// subject verifies raw and returns the configured claim of the token.
func (v *oidcVerifier) subject(ctx context.Context, raw string) (string, error) {
	verifier, err := v.load()
	if err != nil {
		return "", errIssuerUnavailable{err}
	}
	token, err := verifier.Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil {
		return "", fmt.Errorf("verify ID token: %w", err)
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return "", fmt.Errorf("read ID token claims: %w", err)
	}
	value, _ := claims[v.settings.Claim].(string)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("ID token has no %s claim", v.settings.Claim)
	}
	return value, nil
}

// looksLikeJWT reports a compact JWS: three dot-separated parts.
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}
