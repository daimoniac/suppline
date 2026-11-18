package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/runway"
)

type fakeHeld []runway.HeldDigest

func (f fakeHeld) Held() []runway.HeldDigest { return f }

func TestHeldDigestsAndCooldownRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
defaults:
  x-cooldown: 7d
sync:
  - source: docker.io/nginx
    target: registry.example.com/nginx
    type: repository
`), 0o644); err != nil {
		t.Fatal(err)
	}
	regsync := &config.RegsyncConfig{
		Version:  1,
		Defaults: config.Defaults{Cooldown: "7d"},
		Sync:     []config.SyncEntry{{Source: "docker.io/nginx", Target: "registry.example.com/nginx", Type: "repository"}},
	}
	server := tasksTestServer(t, &mockStateStore{}, regsync)
	server.SetConfigEditor(configedit.New(
		configedit.Target{LocalPath: path, Retention: 10},
		server.policyCatalog.(*catalog.ConfigCatalog), nil, observability.NewLogger("error"),
	))
	firstSeen := time.Now().Add(-48 * time.Hour)
	server.SetHeldDigests(fakeHeld{{
		Repository: "registry.example.com/nginx", Digest: "sha256:held", Source: "docker.io/nginx",
		Tags: []string{"1.27.4"}, FirstSeen: firstSeen, Cooldown: 7 * 24 * time.Hour,
	}})

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/mirror/held", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var held []HeldDigestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &held); err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].Digest != "sha256:held" || held[0].CooldownSeconds != int64((7*24*time.Hour).Seconds()) {
		t.Fatalf("held = %+v", held)
	}
	if remaining := time.Duration(held[0].RemainingSeconds) * time.Second; remaining < 119*time.Hour || remaining > 120*time.Hour {
		t.Errorf("remaining = %s, want about 5d", remaining)
	}

	release := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mirror/held/release", bytes.NewBufferString(body)))
		return rec
	}
	if rec := release(`{"repository":"registry.example.com/nginx","digest":"sha256:held"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("release without reason: %d %s", rec.Code, rec.Body.String())
	}
	if rec := release(`{"repository":"registry.example.com/nginx","digest":"sha256:held","reason":"CVE hotfix"}`); rec.Code != http.StatusOK {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	if !server.runningConfig().CooldownReleased("registry.example.com/nginx", "sha256:held") {
		t.Error("running configuration has no release")
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "x-cooldown-release:") || !strings.Contains(string(written), "reason: CVE hotfix") {
		t.Errorf("file not updated:\n%s", written)
	}
}
