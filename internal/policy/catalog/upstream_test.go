package catalog

import (
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

func TestUpstream(t *testing.T) {
	cat := NewConfigCatalog(&config.RegsyncConfig{
		Sync: []config.SyncEntry{{
			Source:   "docker.io/supabase/studio",
			Target:   "hostingmaloonde/supabase_studio",
			Type:     "repository",
			Platform: "linux/amd64",
		}},
	})
	source, platform, ok := cat.Upstream("hostingmaloonde/supabase_studio")
	if !ok || source != "docker.io/supabase/studio" || platform != "linux/amd64" {
		t.Fatalf("upstream %s %s %v", source, platform, ok)
	}
	if _, _, ok := cat.Upstream("missing"); ok {
		t.Fatal("missing repository")
	}
}
