package mirror

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

func TestTagsToDelete_SharedTargetAndOrphans(t *testing.T) {
	present := []string{"1.2.3", "latest", "sha256-abc.sig", "keep.sig"}
	wanted := []string{"1.2.3", "sha256-abc.sig"}
	deleted, err := tagsToDelete(present, wanted, []string{`.*\.sig$`}, func(tag string) (bool, error) {
		return tag == "sha256-abc.sig", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(deleted)
	if !slices.Equal(deleted, []string{"latest", "sha256-abc.sig"}) {
		t.Fatalf("deleted = %#v", deleted)
	}
}

func TestWantedTags_TwoEntries(t *testing.T) {
	entries := []config.SyncEntry{
		{Tags: &config.TagFilter{Allow: []string{"keep-a"}}},
		{Tags: &config.TagFilter{Allow: []string{"keep-b"}}, CleanupTagsExclude: []string{`.*\.att$`}},
	}
	wanted, excludes, err := wantedTags(entries, []string{"keep-a", "keep-b", "drop", "note.att"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(wanted)
	if !slices.Equal(wanted, []string{"keep-a", "keep-b"}) {
		t.Fatalf("wanted = %#v", wanted)
	}
	if !slices.Equal(excludes, []string{`.*\.att$`}) {
		t.Fatalf("excludes = %#v", excludes)
	}
}

func TestSelectOrphanRepos(t *testing.T) {
	got, err := selectOrphanRepos([]string{"kept", "old", "skip"}, map[string]struct{}{"kept": {}}, "org", []string{"skip"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"old"}) {
		t.Fatalf("orphans = %#v", got)
	}
}

type fakeHub struct {
	repos   []string
	deleted []string
}

func (f *fakeHub) listRepositories(context.Context, string) ([]string, error) {
	return f.repos, nil
}

func (f *fakeHub) deleteRepository(_ context.Context, _, name string) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func TestCleanupReposNamespace(t *testing.T) {
	m := &runner{
		cfg: &config.RegsyncConfig{Defaults: config.Defaults{CleanupReposExclude: []string{"skip"}}},
		log: slog.Default(),
	}
	hub := &fakeHub{repos: []string{"kept", "old", "skip"}}
	err := m.cleanupReposNamespace(context.Background(), hub, &targetNamespace{
		registry:  "docker.io",
		namespace: "org",
		wanted:    map[string]struct{}{"kept": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hub.deleted, []string{"old"}) {
		t.Fatalf("deleted = %#v", hub.deleted)
	}
}
