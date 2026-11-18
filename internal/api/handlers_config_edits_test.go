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

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/configedit"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/types"
	"gopkg.in/yaml.v3"
)

func TestApplyTaskEditsWriteTheLocalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	original := []byte(`version: 1
defaults:
  vex:
    - id: CVE-OLD
      state: not_affected
      justification: code_not_present
sync:
  - source: docker.io/nginx
    target: registry.example.com/nginx
    type: repository
    tags:
      semverRange:
        - ">=1.20.0"
      deny:
        - latest
  - source: docker.io/legacy
    target: registry.example.com/legacy
    type: repository
    vex:
      - id: CVE-OLD
        state: not_affected
        justification: code_not_present
`)
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	regsync := &config.RegsyncConfig{
		Version: 1,
		Defaults: config.Defaults{VEX: []types.VEXStatement{{
			ID: "CVE-OLD", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent,
		}}},
		Sync: []config.SyncEntry{
			{
				Source: "docker.io/nginx",
				Target: "registry.example.com/nginx",
				Type:   "repository",
				Tags:   &config.TagFilter{SemverRange: []string{">=1.20.0"}, Deny: []string{"latest"}},
			},
			{
				Source: "docker.io/legacy",
				Target: "registry.example.com/legacy",
				Type:   "repository",
				VEX: []types.VEXStatement{{
					ID: "CVE-OLD", State: types.VEXStateNotAffected, Justification: types.VEXJustCodeNotPresent,
				}},
			},
		},
	}
	server := tasksTestServer(t, &mockStateStore{}, regsync)
	server.SetConfigEditor(configedit.New(
		configedit.Target{LocalPath: path, Retention: 10},
		server.policyCatalog.(*catalog.ConfigCatalog), nil, observability.NewLogger("error"),
	))

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/config-edits", nil)
	statusRec := httptest.NewRecorder()
	server.router.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status %d %s", statusRec.Code, statusRec.Body.String())
	}
	var status ConfigEditStatus
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Available || status.Mode != "local" {
		t.Fatalf("status = %+v", status)
	}

	apply := func(path, body string) ConfigEditResult {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var result ConfigEditResult
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	semver := apply("/api/v1/tasks/semver-updates", `{"updates":[{"target":"registry.example.com/nginx","ranges":[">=1.27.0"]}]}`)
	if semver.Updated != 1 || semver.Mode != "local" {
		t.Fatalf("semver = %+v", semver)
	}
	if running := server.runningConfig(); len(running.Sync[0].Tags.SemverRange) != 1 || running.Sync[0].Tags.SemverRange[0] != ">=1.27.0" {
		t.Fatalf("memory ranges = %+v", running.Sync[0].Tags.SemverRange)
	}

	removed := apply("/api/v1/tasks/sync-removals", `{"targets":["registry.example.com/legacy"]}`)
	if running := server.runningConfig(); removed.Updated != 1 || len(running.Sync) != 1 || running.Sync[0].Target != "registry.example.com/nginx" {
		t.Fatalf("removed %+v sync %+v", removed, running.Sync)
	}

	vex := apply("/api/v1/tasks/vex-removals", `{"ids":["CVE-OLD"]}`)
	if running := server.runningConfig(); vex.Updated != 1 || len(running.Defaults.VEX) != 0 {
		t.Fatalf("vex %+v defaults %+v", vex, running.Defaults.VEX)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed config.RegsyncConfig
	if err := yaml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if len(parsed.Sync) != 1 || parsed.Sync[0].Tags == nil || parsed.Sync[0].Tags.SemverRange[0] != ">=1.27.0" {
		t.Fatalf("file sync = %+v\n%s", parsed.Sync, body)
	}
	if len(parsed.Sync[0].Tags.Deny) != 1 {
		t.Fatalf("deny lost:\n%s", body)
	}
	if strings.Contains(string(body), "legacy") || strings.Contains(string(body), "CVE-OLD") || strings.Contains(string(body), "vex:") {
		t.Fatalf("removed content remains:\n%s", body)
	}
}
