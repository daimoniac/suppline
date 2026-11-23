package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/daimoniac/suppline/internal/config"
)

// testIssuer is an OIDC issuer like gitlab.com: discovery plus a JWKS.
type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.server.URL,
			"jwks_uri":                              issuer.server.URL + "/jwks",
			"authorization_endpoint":                issuer.server.URL + "/authorize",
			"token_endpoint":                        issuer.server.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}})
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testIssuer) token(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	now := time.Now()
	payload := map[string]any{
		"iss": i.server.URL,
		"aud": "https://suppline.example",
		"sub": "project_path:group/app:ref_type:branch:ref:main",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range claims {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestScanRequest_OIDCTokens(t *testing.T) {
	issuer := newTestIssuer(t)
	f := newScanRequestFixture(t, "secret")
	f.server.oidc = newOIDCVerifier(config.OIDCSettings{Issuer: issuer.server.URL, Audience: "https://suppline.example"}, issuer.server.Client())

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"image":"` + ciRepo + `:` + ciTag + `"}`
	cases := []struct {
		name   string
		token  string
		status int
	}{
		{"listed requester", issuer.token(t, issuer.key, map[string]any{"project_path": "group/app"}), http.StatusAccepted},
		{"other project", issuer.token(t, issuer.key, map[string]any{"project_path": "group/other"}), http.StatusForbidden},
		{"no project claim", issuer.token(t, issuer.key, nil), http.StatusUnauthorized},
		{"wrong audience", issuer.token(t, issuer.key, map[string]any{"project_path": "group/app", "aud": "someone-else"}), http.StatusUnauthorized},
		{"expired", issuer.token(t, issuer.key, map[string]any{"project_path": "group/app", "exp": time.Now().Add(-time.Minute).Unix()}), http.StatusUnauthorized},
		{"foreign key", issuer.token(t, otherKey, map[string]any{"project_path": "group/app"}), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do(http.MethodPost, "/api/v1/scan-requests?wait=10ms", body, tc.token)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.status, w.Body.String())
			}
		})
	}

	good := issuer.token(t, issuer.key, map[string]any{"project_path": "group/app"})
	w := f.do(http.MethodGet, "/api/v1/scan-requests/"+ciDigest+"?repository="+ciRepo, "", good)
	if w.Code != http.StatusAccepted {
		t.Fatalf("poll with ID token: status = %d; body %s", w.Code, w.Body.String())
	}
	// ID tokens open the scan-request endpoints only.
	w = f.do(http.MethodGet, "/api/v1/scans", "", good)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ID token on /api/v1/scans: status = %d", w.Code)
	}
}

func TestScanRequest_OIDCIssuerUnavailable(t *testing.T) {
	issuer := newTestIssuer(t)
	f := newScanRequestFixture(t, "secret")
	token := issuer.token(t, issuer.key, map[string]any{"project_path": "group/app"})
	f.server.oidc = newOIDCVerifier(config.OIDCSettings{Issuer: "https://127.0.0.1:1", Audience: "https://suppline.example"}, issuer.server.Client())
	w := f.do(http.MethodPost, "/api/v1/scan-requests", `{"image":"`+ciRepo+`:`+ciTag+`"}`, token)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; body %s", w.Code, w.Body.String())
	}
}
