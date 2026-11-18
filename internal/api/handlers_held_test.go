package api

import (
	"bytes"
	"context"
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

type fakeHeld struct {
	held     []runway.HeldDigest
	released []string
}

func (f *fakeHeld) Held() []runway.HeldDigest { return f.held }

func (f *fakeHeld) Release(_ context.Context, repository, digest string) (bool, error) {
	f.released = append(f.released, repository+"@"+digest)
	return true, nil
}

func TestHeldDigestsAndCooldownRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(`version: 1
defaults:
  cooldown: 7d
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
	held := &fakeHeld{held: []runway.HeldDigest{{
		Repository: "registry.example.com/nginx", Digest: "sha256:held", Source: "docker.io/nginx",
		Tags: []string{"1.27.4"}, FirstSeen: firstSeen, Cooldown: 7 * 24 * time.Hour,
	}}}
	server.SetHeldDigests(held)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/mirror/held", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var listed []HeldDigestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Digest != "sha256:held" || listed[0].CooldownSeconds != int64((7*24*time.Hour).Seconds()) {
		t.Fatalf("held = %+v", listed)
	}
	if remaining := time.Duration(listed[0].RemainingSeconds) * time.Second; remaining < 119*time.Hour || remaining > 120*time.Hour {
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
	// The held digest is not among the repository's current images, so the
	// config edit's requeue misses it; the runway rescans it.
	if len(held.released) != 1 || held.released[0] != "registry.example.com/nginx@sha256:held" {
		t.Errorf("runway releases = %v", held.released)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "cooldown-release:") || !strings.Contains(string(written), "reason: CVE hotfix") {
		t.Errorf("file not updated:\n%s", written)
	}
}
