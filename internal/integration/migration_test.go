package integration

import (
	"strings"
	"testing"
)

func TestSplitImage(t *testing.T) {
	tests := []struct {
		ref, tag, digest string
		want             imageName
	}{
		{"nginx", "1.27", "", imageName{"docker.io", "nginx", "1.27", ""}},
		{"nginx:1.27", "", "", imageName{"docker.io", "nginx", "1.27", ""}},
		{"library/nginx", "1.27", "", imageName{"docker.io", "nginx", "1.27", ""}},
		{"docker.io/library/nginx", "1", "", imageName{"docker.io", "nginx", "1", ""}},
		{"index.docker.io/supabase/gotrue", "v2", "", imageName{"docker.io", "supabase/gotrue", "v2", ""}},
		{"supabase/gotrue", "v2", "", imageName{"docker.io", "supabase/gotrue", "v2", ""}},
		{"ghcr.io/org/app", "1.0", "sha256:abc", imageName{"ghcr.io", "org/app", "1.0", "sha256:abc"}},
		{"ghcr.io/org/app@sha256:abc", "", "", imageName{"ghcr.io", "org/app", "", "sha256:abc"}},
		{"localhost:5000/app:dev", "", "", imageName{"localhost:5000", "app", "dev", ""}},
		{"registry.example.com:8443/team/app:2", "", "", imageName{"registry.example.com:8443", "team/app", "2", ""}},
	}
	for _, tt := range tests {
		if got := splitImage(tt.ref, tt.tag, tt.digest); got != tt.want {
			t.Errorf("splitImage(%q, %q, %q) = %+v, want %+v", tt.ref, tt.tag, tt.digest, got, tt.want)
		}
	}
}

func TestFlatNameMatchesHandWrittenEntries(t *testing.T) {
	// These are the names an existing install's sync entries use.
	for path, want := range map[string]string{
		"nginx":                                 "nginx",
		"supabase/gotrue":                       "supabase_gotrue",
		"crunchydata/crunchy-postgres":          "crunchydata_crunchy-postgres",
		"docker/library/alpine":                 "docker_library_alpine",
		"curlimages/curl":                       "curlimages_curl",
		"darthsim/imgproxy":                     "darthsim_imgproxy",
		"crunchydata/crunchy-postgres-exporter": "crunchydata_crunchy-postgres-exporter",
	} {
		if got := FlatName(path); got != want {
			t.Errorf("FlatName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestPlanMigration(t *testing.T) {
	images := []RunningImage{
		{ImageRef: "nginx", Tag: "1.27"},
		{ImageRef: "nginx", Tag: "1.27", Digest: "sha256:aaa"}, // same tag, reported twice
		{ImageRef: "docker.io/supabase/gotrue", Tag: "v2.1"},
		{ImageRef: "ghcr.io/org/app", Tag: "3"},
		{ImageRef: "redis", Tag: "7"},                                // repository entry exists
		{ImageRef: "busybox", Tag: "1.37"},                           // image entry for this tag exists
		{ImageRef: "busybox", Tag: "1.36"},                           // image entry is for another tag
		{ImageRef: "harbor.example.com/suppline/nginx", Tag: "1.26"}, // already on the mirror
		{ImageRef: "quay.io/org/pinned", Digest: "sha256:bbb"},       // no tag known
	}
	configured := []ConfiguredSource{
		{Source: "redis", Type: "repository"},
		{Source: "busybox:1.37", Type: "image"},
	}

	plan := PlanMigration(images, "harbor.example.com/suppline", "", configured)

	var sources []string
	for _, suggestion := range plan.Sync {
		sources = append(sources, suggestion.Source+" -> "+suggestion.Target)
	}
	want := []string{
		`docker.io/library/busybox:1.36 -> {{ env "SUPPLINE_REGISTRY_URL" }}/busybox:1.36`,
		`docker.io/library/nginx:1.27 -> {{ env "SUPPLINE_REGISTRY_URL" }}/nginx:1.27`,
		`docker.io/supabase/gotrue:v2.1 -> {{ env "SUPPLINE_REGISTRY_URL" }}/supabase_gotrue:v2.1`,
		`ghcr.io/org/app:3 -> {{ env "SUPPLINE_REGISTRY_URL" }}/org_app:3`,
	}
	if strings.Join(sources, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sync suggestions:\n%s\nwant:\n%s", strings.Join(sources, "\n"), strings.Join(want, "\n"))
	}
	if strings.Join(plan.Covered, ",") != "docker.io/busybox:1.37,docker.io/redis:7" {
		t.Errorf("Covered = %v", plan.Covered)
	}
	if strings.Join(plan.Mirrored, ",") != "harbor.example.com/suppline/nginx" {
		t.Errorf("Mirrored = %v", plan.Mirrored)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "quay.io/org/pinned@sha256:bbb is pinned by digest") {
		t.Errorf("Warnings = %v, want the digest-only image", plan.Warnings)
	}
}

func TestPlanMigrationWarnsAboutNameCollisions(t *testing.T) {
	plan := PlanMigration([]RunningImage{
		{ImageRef: "docker.io/team/app", Tag: "1"},
		{ImageRef: "ghcr.io/team/app", Tag: "1"},
	}, "mirror.example.com", "mirror.example.com", nil)
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "overwrite each other") {
		t.Fatalf("Warnings = %v, want a collision warning", plan.Warnings)
	}
}

func TestPlanMigrationYAML(t *testing.T) {
	plan := PlanMigration([]RunningImage{{ImageRef: "nginx", Tag: "1.27"}}, "", "", nil)
	got := plan.YAML("prod")
	for _, want := range []string{
		`# suppline migration plan for cluster "prod"`,
		"sync:\n  - source: docker.io/library/nginx:1.27\n    target: '{{ env \"SUPPLINE_REGISTRY_URL\" }}/nginx:1.27'\n    type: image\n",
		"# 1 to add, 0 already synced, 0 already pulled from the mirror.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("YAML missing %q in:\n%s", want, got)
		}
	}
	if empty := PlanMigration(nil, "", "", nil).YAML("prod"); !strings.Contains(empty, "sync: []") {
		t.Errorf("empty plan YAML = %q", empty)
	}
}

func TestExcludeRegistries(t *testing.T) {
	images := []RunningImage{
		{ImageRef: "nginx", Tag: "1"},
		{ImageRef: "index.docker.io/grafana/grafana", Tag: "11"},
		{ImageRef: "registry.example.com/team/app", Tag: "2"},
		{ImageRef: "localhost:5000/x/y"},
		{ImageRef: "ghcr.io/foo/bar", Tag: "3"},
	}
	got := ExcludeRegistries(images, []string{" Registry.Example.com ", "localhost:5000", "", "docker.io"})
	if len(got) != 1 || got[0].ImageRef != "ghcr.io/foo/bar" {
		t.Errorf("kept %+v", got)
	}
	if got := ExcludeRegistries(images, nil); len(got) != len(images) {
		t.Errorf("no registries must keep everything, kept %d", len(got))
	}
}
