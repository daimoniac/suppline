package registry

import (
	"context"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// holdFixture serves an in-memory registry with one image stored by digest
// only, the way the mirror leaves a Held digest.
func holdFixture(t *testing.T) (*clientImpl, string, string) {
	t.Helper()
	server := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	repo := u.Host + "/team/app"

	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewDigest(repo+"@"+digest.String(), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(&config.RegsyncConfig{Creds: []config.RegistryCredential{{Registry: u.Host, TLS: "disabled"}}})
	if err != nil {
		t.Fatal(err)
	}
	return client.(*clientImpl), repo, digest.String()
}

func TestHoldRoundTrip(t *testing.T) {
	ctx := context.Background()
	client, repo, digest := holdFixture(t)
	firstSeen := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

	if err := client.PutHold(ctx, repo, Hold{Digest: digest, FirstSeen: firstSeen, Source: "docker.io/team/app", Tags: []string{"latest", "1.2.4"}}); err != nil {
		t.Fatalf("PutHold() error = %v", err)
	}

	holds, err := client.ListHolds(ctx, repo)
	if err != nil {
		t.Fatalf("ListHolds() error = %v", err)
	}
	if len(holds) != 1 {
		t.Fatalf("holds = %+v, want one", holds)
	}
	got := holds[0]
	if got.Digest != digest || !got.FirstSeen.Equal(firstSeen) || got.Source != "docker.io/team/app" || !slices.Equal(got.Tags, []string{"1.2.4", "latest"}) {
		t.Errorf("hold = %+v", got)
	}

	// The watcher never sees a hold tag as an image tag.
	tags, err := client.ListTags(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 0 {
		t.Errorf("ListTags() = %v, want hold tag filtered", tags)
	}

	if err := client.DeleteHold(ctx, repo, digest); err != nil {
		t.Fatalf("DeleteHold() error = %v", err)
	}
	holds, err = client.ListHolds(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 0 {
		t.Errorf("holds after delete = %+v", holds)
	}
	// Deleting the hold keeps the held image itself.
	if _, err := client.GetManifest(ctx, repo, digest); err != nil {
		t.Errorf("held digest gone after DeleteHold: %v", err)
	}
	// A second delete is a no-op.
	if err := client.DeleteHold(ctx, repo, digest); err != nil {
		t.Errorf("second DeleteHold() error = %v", err)
	}
}

func TestHoldTagDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab12", 16)
	tag := HoldTag(digest)
	got, ok := HoldTagDigest(tag)
	if !ok || got != digest {
		t.Errorf("HoldTagDigest(%q) = %q, %t; want %q", tag, got, ok, digest)
	}
	for _, tag := range []string{"latest", "sha256-abc.hold", "sha256-" + digest[7:] + ".att"} {
		if _, ok := HoldTagDigest(tag); ok {
			t.Errorf("HoldTagDigest(%q) matched", tag)
		}
	}
}

// A target repository the mirror has not created yet has no hold tags; the
// registry answers NAME_UNKNOWN, which is not an error.
func TestListHoldsOfMissingRepository(t *testing.T) {
	client, repo, _ := holdFixture(t)
	missing := strings.TrimSuffix(repo, "/app") + "/not-yet-mirrored"

	holds, err := client.ListHolds(context.Background(), missing)
	if err != nil {
		t.Fatalf("ListHolds() error = %v, want none for a missing repository", err)
	}
	if len(holds) != 0 {
		t.Fatalf("ListHolds() = %v, want none", holds)
	}
}
