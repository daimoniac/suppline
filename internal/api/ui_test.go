package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
)

var testUIFiles = fstest.MapFS{
	"index.html":         {Data: []byte("<!doctype html><html><head><title>t</title></head><body>app</body></html>")},
	"favicon.svg":        {Data: []byte("<svg/>")},
	"assets/app-abc.js":  {Data: []byte("console.log(1)")},
	"assets/app-abc.css": {Data: []byte("body{}")},
}

func newUITestServer(t *testing.T, basePath string) http.Handler {
	t.Helper()
	cfg := &config.APIConfig{Port: 8080, BasePath: basePath}
	server := NewAPIServer(cfg, mockAttestationConfig(), &mockStateStore{}, queue.NewInMemoryQueue(10), mockRegsyncConfig(), observability.NewLogger("error"))
	h, err := server.rootHandler(testUIFiles)
	if err != nil {
		t.Fatalf("rootHandler: %v", err)
	}
	return h
}

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
	return w
}

func TestUI_RootPath(t *testing.T) {
	h := newUITestServer(t, "")

	t.Run("index has base href and no-cache", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/")
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), `<head>`+"\n"+`<base href="/" />`) {
			t.Errorf("missing base href: %s", w.Body.String())
		}
		if got := w.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("Cache-Control = %q", got)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
			t.Errorf("missing security headers: %v", w.Header())
		}
	})

	t.Run("client route falls back to index", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/repositories/library/nginx")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "app") {
			t.Fatalf("status %d body %q", w.Code, w.Body.String())
		}
	})

	t.Run("hashed asset is immutable", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/assets/app-abc.js")
		if w.Code != http.StatusOK || w.Body.String() != "console.log(1)" {
			t.Fatalf("status %d body %q", w.Code, w.Body.String())
		}
		if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
			t.Errorf("Cache-Control = %q", got)
		}
	})

	t.Run("missing file with extension is 404", func(t *testing.T) {
		if w := serve(h, http.MethodGet, "/assets/gone.js"); w.Code != http.StatusNotFound {
			t.Errorf("status %d", w.Code)
		}
	})

	t.Run("non-GET is rejected", func(t *testing.T) {
		if w := serve(h, http.MethodPost, "/repositories"); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", w.Code)
		}
	})

	t.Run("unknown API path is JSON 404", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/api/v1/nope")
		if w.Code != http.StatusNotFound {
			t.Fatalf("status %d", w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("body is not JSON: %q", w.Body.String())
		}
	})

	t.Run("metrics no longer on API port", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/metrics")
		if strings.Contains(w.Body.String(), "Metrics endpoint") {
			t.Errorf("/metrics still served by the API: %q", w.Body.String())
		}
	})

	t.Run("no CORS headers", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/health")
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("unexpected CORS header")
		}
	})
}

func TestUI_BasePath(t *testing.T) {
	h := newUITestServer(t, "/suppline")

	t.Run("bare base path redirects with slash", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/suppline?x=1")
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/suppline/?x=1" {
			t.Errorf("status %d Location %q", w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("index has prefixed base href", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/suppline/scans/abc")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<base href="/suppline/" />`) {
			t.Errorf("status %d body %q", w.Code, w.Body.String())
		}
	})

	t.Run("API is served under the prefix", func(t *testing.T) {
		if w := serve(h, http.MethodGet, "/suppline/health"); w.Code != http.StatusOK {
			t.Errorf("health status %d", w.Code)
		}
		if w := serve(h, http.MethodGet, "/suppline/api/v1/policies"); w.Code != http.StatusOK {
			t.Errorf("policies status %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("paths outside the prefix are 404", func(t *testing.T) {
		for _, p := range []string{"/", "/api/v1/policies", "/supplinex/"} {
			if w := serve(h, http.MethodGet, p); w.Code != http.StatusNotFound {
				t.Errorf("%s: status %d", p, w.Code)
			}
		}
	})

	t.Run("swagger redirects keep the prefix", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/suppline/swagger")
		if loc := w.Header().Get("Location"); loc != "/suppline/swagger/" {
			t.Errorf("Location %q", loc)
		}
		w = serve(h, http.MethodGet, "/suppline/swagger/")
		if loc := w.Header().Get("Location"); loc != "/suppline/swagger/index.html" {
			t.Errorf("Location %q", loc)
		}
	})

	t.Run("swagger static files load under the prefix", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/suppline/swagger/swagger-ui.css")
		if w.Code != http.StatusOK {
			t.Errorf("status %d", w.Code)
		}
	})

	t.Run("swagger doc is public", func(t *testing.T) {
		w := serve(h, http.MethodGet, "/suppline/swagger/doc.json")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"basePath": "/suppline/api/v1"`) {
			t.Errorf("status %d body prefix %.200q", w.Code, w.Body.String())
		}
	})
}

func TestInjectBaseHrefWithoutHead(t *testing.T) {
	got := string(injectBaseHref([]byte("<p>x</p>"), "/a/"))
	if got != `<base href="/a/" /><p>x</p>` {
		t.Errorf("got %q", got)
	}
}
