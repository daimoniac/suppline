package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPnpmDependents(t *testing.T) {
	lock := []byte(`
lockfileVersion: '9.0'
importers:
  apps/studio:
    dependencies:
      mermaid:
        version: 11.15.0
packages:
  dompurify@3.4.13: {}
  mermaid@11.15.0:
    dependencies:
      dompurify: 3.4.13
  posthog-js@1.391.2:
    dependencies:
      dompurify: 3.4.13
`)
	deps, err := pnpmDependents(lock, "dompurify")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 || deps[0].Name != "mermaid" || deps[0].Version != "11.15.0" || deps[1].Name != "posthog-js" {
		t.Fatalf("dependents %+v", deps)
	}
	var extra strings.Builder
	extra.WriteString("packages:\n  dompurify@3.4.13: {}\n")
	for i := 0; i < 6; i++ {
		extra.WriteString("  pkg" + string(rune('a'+i)) + "@1.0.0:\n    dependencies:\n      dompurify: 3.4.13\n")
	}
	many, err := pnpmDependents([]byte(extra.String()), "dompurify")
	if err != nil || len(many) != 6 {
		t.Fatalf("many %+v %v", many, err)
	}
	none, err := pnpmDependents(lock, "next")
	if err != nil || len(none) != 0 {
		t.Fatalf("next %+v %v", none, err)
	}
}

func TestNpmDependents(t *testing.T) {
	lock := []byte(`{"packages":{
		"node_modules/dompurify":{"version":"3.4.13"},
		"node_modules/mermaid":{"version":"11.15.0","dependencies":{"dompurify":"3.4.13"}},
		"node_modules/posthog-js":{"version":"1.391.2","dependencies":{"dompurify":"3.4.13"}}
	}}`)
	deps, err := npmDependents(lock, "dompurify")
	if err != nil || len(deps) != 2 || deps[0].Name != "mermaid" || deps[1].Version != "1.391.2" {
		t.Fatalf("%+v %v", deps, err)
	}
}

func TestDependencySourcesChecksOutDependents(t *testing.T) {
	sha := studioSHA
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "pnpm-lock.yaml"):
			_, _ = w.Write([]byte("packages:\n  mermaid@11.15.0:\n    dependencies:\n      dompurify: 3.4.13\n"))
		case strings.Contains(r.URL.Path, "mermaid"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"gitHead": sha,
				"repository": map[string]string{
					"url":       "git+https://github.com/mermaid-js/mermaid.git",
					"directory": "packages/mermaid",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := &publicSource{
		client: srv.Client(), hosts: map[string]struct{}{parsed.Hostname(): {}}, insecure: true,
		raw: srv.URL, npm: srv.URL, github: srv.URL,
	}
	var gotRel string
	upstream := &publicCheckouts{pub: pub, clone: func(_ context.Context, _, _, gotSHA, rel string) error {
		if gotSHA != sha {
			t.Fatalf("sha %s", gotSHA)
		}
		gotRel = rel
		return nil
	}}
	roots := &Roots{}
	out, err := dependencySources(context.Background(), roots, upstream, pub, Job{PackageName: "dompurify"}, "supabase", "supabase", sha)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "checked out mermaid-js/mermaid@"+sha) || gotRel != "packages/mermaid" {
		t.Fatalf("out %s rel %s", out, gotRel)
	}
	if !roots.public("mermaid-js/mermaid") {
		t.Fatal("dependent checkout was not registered")
	}
	kernel, err := dependencySources(context.Background(), roots, upstream, pub, Job{PackageName: "linux-libc-dev"}, "supabase", "postgres", sha)
	if err != nil || !strings.Contains(kernel, "kernel package") {
		t.Fatalf("kernel %q %v", kernel, err)
	}
}

func TestDependencySourcesRefusesASixthDependent(t *testing.T) {
	var lock strings.Builder
	lock.WriteString("packages:\n")
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&lock, "  pkg%d@1.0.0:\n    dependencies:\n      dompurify: 1.0.0\n", i)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "pnpm-lock.yaml") {
			_, _ = w.Write([]byte(lock.String()))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := &publicSource{
		client: srv.Client(), hosts: map[string]struct{}{parsed.Hostname(): {}}, insecure: true,
		raw: srv.URL, npm: srv.URL, github: srv.URL,
	}
	upstream := &publicCheckouts{pub: pub, clone: func(context.Context, string, string, string, string) error {
		t.Fatal("checkout ran past the cap")
		return nil
	}}
	out, err := dependencySources(context.Background(), &Roots{}, upstream, pub, Job{PackageName: "dompurify"}, "supabase", "supabase", studioSHA)
	if err != nil || !strings.Contains(out, "too many direct dependents (6)") {
		t.Fatalf("cap: %q %v", out, err)
	}
}
