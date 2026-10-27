package triage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdvisoryAndPublicCode(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/vulns/CVE-2024-0001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "CVE-2024-0001",
				"summary": "demo bug",
				"aliases": []string{"GHSA-abcd-efgh-ijkl"},
				"affected": []any{map[string]any{
					"package": map[string]string{"ecosystem": "Go", "name": "example.com/mod"},
					"ranges": []any{map[string]any{
						"type":   "ECOSYSTEM",
						"events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": "1.2.3"}},
					}},
				}},
				"references": []any{map[string]string{"type": "FIX", "url": "https://github.com/acme/mod/commit/abc"}},
				"details":    "reachable from the handler",
			})
		case r.URL.Path == "/v1/vulns/CVE-2024-9999":
			http.NotFound(w, r)
		case r.URL.Path == "/advisories" && r.URL.Query().Get("cve_id") == "CVE-2024-9999":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{
				"ghsa_id": "GHSA-zzzz-yyyy-xxxx",
				"cve_id":  "CVE-2024-9999",
				"summary": "github only",
				"vulnerabilities": []any{map[string]any{
					"package":                  map[string]string{"ecosystem": "npm", "name": "leftpad"},
					"vulnerable_version_range": "< 1.0.0",
					"patched_versions":         "1.0.0",
				}},
			}})
		case strings.HasSuffix(r.URL.Path, "/contents/main.go"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":     "file",
				"encoding": "base64",
				"size":     40,
				"content":  base64.StdEncoding.EncodeToString([]byte("package main\n" + pem + "\n")),
			})
		case strings.HasSuffix(r.URL.Path, "/contents/"):
			entries := make([]map[string]string, 0, maxToolMatches+1)
			for i := 0; i < maxToolMatches+1; i++ {
				entries = append(entries, map[string]string{"name": "f", "type": "file"})
			}
			_ = json.NewEncoder(w).Encode(entries)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	src := &publicSource{
		client:   srv.Client(),
		hosts:    map[string]struct{}{parsed.Hostname(): {}},
		insecure: true,
		osv:      srv.URL,
		github:   srv.URL,
	}

	out, err := src.Advisory(context.Background(), "cve-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE-2024-0001", "example.com/mod", "fixed 1.2.3", "github.com/acme/mod/commit/abc", "reachable from the handler"} {
		if !strings.Contains(out, want) {
			t.Fatalf("advisory missing %q\n%s", want, out)
		}
	}
	fallback, err := src.Advisory(context.Background(), "CVE-2024-9999")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fallback, "GHSA-zzzz-yyyy-xxxx") || !strings.Contains(fallback, "leftpad") {
		t.Fatalf("github fallback: %s", fallback)
	}
	if _, err := src.Advisory(context.Background(), "https://evil.example/v1"); err == nil {
		t.Fatal("accepted a non advisory id")
	}

	file, err := src.GitHubFile(context.Background(), "acme", "mod", "main", "main.go", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(file, "1|package main") || !strings.Contains(file, "[REDACTED]") || strings.Contains(file, "BEGIN RSA") {
		t.Fatalf("file output: %s", file)
	}
	if text, ok := src.line("acme/mod", "main.go", 1); !ok || text != "package main" {
		t.Fatalf("remembered line: %q %v", text, ok)
	}
	if _, err := src.GitHubFile(context.Background(), "acme", "mod", "main", "../secrets", 1, 5); err == nil {
		t.Fatal("accepted a path escape")
	}
	dir, err := src.GitHubFile(context.Background(), "acme", "mod.git", "", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dir, "truncated") {
		t.Fatalf("directory listing: %s", dir)
	}

	blocked := &publicSource{client: srv.Client(), hosts: map[string]struct{}{"api.osv.dev": {}}, osv: "https://api.osv.dev", github: "https://api.github.com"}
	if _, _, err := blocked.get(context.Background(), "https://evil.example/secret"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("off-allowlist host: %v", err)
	}
}

func TestPublicRedirectStaysOnAllowlist(t *testing.T) {
	src := newPublicSource()
	blocked, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/latest/meta-data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.client.CheckRedirect(blocked, nil); err == nil {
		t.Fatal("allowed a redirect off the host allowlist")
	}
	allowed, err := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/acme/mod/main/main.go", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.client.CheckRedirect(allowed, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPublicIPAndToolAdvertisement(t *testing.T) {
	if isPublicIP(net.ParseIP("8.8.8.8")) != true {
		t.Fatal("8.8.8.8")
	}
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"} {
		if isPublicIP(net.ParseIP(raw)) {
			t.Fatalf("%s was treated as public", raw)
		}
	}
	names := map[string]bool{}
	for _, tool := range toolDefinitions(false) {
		names[tool.Function.Name] = true
	}
	if !names["cve_advisory"] || !names["public_code"] || !names["public_search"] || names["cluster_runtime"] {
		t.Fatalf("tools: %v", names)
	}
	prompt := systemPrompt(nil, false, "", 0)
	if !names["image_source"] || !names["public_checkout"] {
		t.Fatalf("tools: %v", names)
	}
	if !strings.Contains(prompt, "cve_advisory") || !strings.Contains(prompt, "public_checkout") || !strings.Contains(prompt, "empty grep") || strings.Contains(prompt, "cluster_runtime") {
		t.Fatal("prompt does not describe the public tools")
	}
}

func TestPublicSearch(t *testing.T) {
	t.Setenv("SUPPLINE_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	blocked := &publicSource{github: "https://api.github.com", hosts: map[string]struct{}{"api.github.com": {}}}
	if _, err := blocked.GitHubSearch(context.Background(), "acme", "mod", "", "SAFE_FOR_TEMPLATES"); err == nil || !strings.Contains(err.Error(), "SUPPLINE_GITHUB_TOKEN") {
		t.Fatalf("missing token: %v", err)
	}

	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		if r.Header.Get("Accept") != "application/vnd.github.text-match+json" {
			http.Error(w, "accept", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count":        2,
			"incomplete_results": true,
			"items": []any{map[string]any{
				"path": "apps/studio/lib/sanitize.ts",
				"text_matches": []any{map[string]string{
					"fragment": "DOMPurify.sanitize(value)",
				}},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUPPLINE_GITHUB_TOKEN", "test-token")
	src := &publicSource{
		client:   srv.Client(),
		hosts:    map[string]struct{}{parsed.Hostname(): {}},
		insecure: true,
		github:   srv.URL,
	}
	out, err := src.GitHubSearch(context.Background(), "acme", "mod.git", "apps/studio", "DOMPurify.sanitize")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "apps/studio/lib/sanitize.ts") || !strings.Contains(out, "DOMPurify.sanitize(value)") || !strings.Contains(out, "truncated") {
		t.Fatalf("search output: %s", out)
	}
	if query != "DOMPurify.sanitize repo:acme/mod path:apps/studio" {
		t.Fatalf("query: %s", query)
	}
	if _, ok := src.line("acme/mod", "apps/studio/lib/sanitize.ts", 1); ok {
		t.Fatal("search hit was stored as evidence")
	}
	if _, err := src.GitHubSearch(context.Background(), "acme", "mod", "", "SAFE_FOR_TEMPLATES repo:evil/other"); err == nil {
		t.Fatal("accepted a qualifier in the query")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	}))
	t.Cleanup(empty.Close)
	emptyURL, err := url.Parse(empty.URL)
	if err != nil {
		t.Fatal(err)
	}
	src.client = empty.Client()
	src.hosts = map[string]struct{}{emptyURL.Hostname(): {}}
	src.github = empty.URL
	none, err := src.GitHubSearch(context.Background(), "acme", "mod", "", "SAFE_FOR_TEMPLATES")
	if err != nil || none != "no matches\n" {
		t.Fatalf("empty search: %q %v", none, err)
	}
}

func TestDecisionPromptIsConfigurable(t *testing.T) {
	builtIn := systemPrompt([]string{"requires_configuration"}, false, "", 0.8)
	for _, phrase := range []string{
		"requires_configuration",
		"requires_environment",
		"critical -> high, high -> medium, medium -> low",
		"confidence of at least 0.80",
		"A missing npm or pnpm lockfile is not a failure",
		"Cite that grep_id",
		"citable: absence",
		evidenceContract(),
	} {
		if !strings.Contains(builtIn, phrase) {
			t.Fatalf("built-in prompt missing %q", phrase)
		}
	}
	custom := systemPrompt([]string{"requires_environment"}, false, "Operator policy: accept only weekend windows.", 0.9)
	if !strings.Contains(custom, "Operator policy: accept only weekend windows.") {
		t.Fatal("custom prompt was dropped")
	}
	if strings.Contains(custom, "critical -> high") {
		t.Fatal("custom prompt kept the built-in decision policy")
	}
	if !strings.Contains(custom, "confidence of at least 0.90") || !strings.Contains(custom, "empty grep") {
		t.Fatal("custom prompt lost the output contract")
	}
}
