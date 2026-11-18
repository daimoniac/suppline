package yamledit

import (
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"gopkg.in/yaml.v3"
)

func TestAddCooldownRelease(t *testing.T) {
	document := []byte(`# mirror setup
defaults:
  cooldown: 7d
sync:
  - source: docker.io/library/nginx
    target: registry.example/nginx
    type: repository
    # keep this comment
    cooldown: 3d
  - source: docker.io/library/redis
    target: registry.example/redis
    type: repository
`)
	release := config.CooldownRelease{Digest: "sha256:abc", Reason: "CVE-2026-1234: hotfix", Author: "steve", At: "2026-11-18T10:00:00Z"}

	out, err := AddCooldownRelease(document, "registry.example/nginx", release)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# keep this comment") || !strings.Contains(string(out), "# mirror setup") {
		t.Errorf("comments lost:\n%s", out)
	}
	var cfg config.RegsyncConfig
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("output does not parse: %v\n%s", err, out)
	}
	if got := cfg.Sync[0].CooldownReleases; len(got) != 1 || got[0] != release {
		t.Fatalf("nginx releases = %+v\n%s", got, out)
	}
	if len(cfg.Sync[1].CooldownReleases) != 0 {
		t.Errorf("redis got a release:\n%s", out)
	}

	// Releasing the same digest again replaces the entry.
	release.Reason = "second thoughts"
	out, err = AddCooldownRelease(out, "registry.example/nginx", release)
	if err != nil {
		t.Fatal(err)
	}
	cfg = config.RegsyncConfig{}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sync[0].CooldownReleases; len(got) != 1 || got[0].Reason != "second thoughts" {
		t.Fatalf("releases after replace = %+v\n%s", got, out)
	}

	if _, err := AddCooldownRelease(document, "registry.example/unknown", release); err == nil {
		t.Error("release for an unknown repository succeeded")
	}
	if _, err := AddCooldownRelease(document, "registry.example/nginx", config.CooldownRelease{Digest: "latest"}); err == nil {
		t.Error("release of a non-digest succeeded")
	}
}
