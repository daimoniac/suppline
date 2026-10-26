package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const studioSHA = "79964102d369991a3b3adda27dc1f528c3a77457"

func TestProvenanceRevision(t *testing.T) {
	amd := "sha256:0f797270d236090c79fd26a97a1e5d1cf7ec5f36e93b9b4c3c453e1cb1aeadab"
	attest := "sha256:ae43871e61336190fb98ae09a832703109a89e76b84184a126c29f6424ecbc4d"
	layer := "sha256:f46ecf6ae497aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	index := []byte(`{"manifests":[
		{"digest":"` + amd + `","platform":{"os":"linux","architecture":"amd64"}},
		{"digest":"` + attest + `","annotations":{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"` + amd + `"},"platform":{"os":"unknown","architecture":"unknown"}}
	]}`)
	manifest := []byte(`{"layers":[{"mediaType":"application/vnd.in-toto+json","digest":"` + layer + `","annotations":{"in-toto.io/predicate-type":"https://slsa.dev/provenance/v1"}}]}`)
	statement := []byte(`{"predicate":{"buildDefinition":{"externalParameters":{"configSource":{"uri":"https://github.com/supabase/supabase.git#` + studioSHA + `"}}}}}`)
	store := map[string][]byte{
		"docker.io/supabase/studio:2026.09.07-sha-7996410": index,
		"docker.io/supabase/studio@" + attest:              manifest,
		layer:                                              statement,
	}
	manifests := manifestMap(store)
	owner, repo, sha, err := readProvenance(context.Background(), manifests, Job{
		Upstream: "docker.io/supabase/studio",
		Tag:      "2026.09.07-sha-7996410",
		Digest:   amd,
		Platform: "linux/amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if owner != "supabase" || repo != "supabase" || sha != studioSHA {
		t.Fatalf("revision %s/%s@%s", owner, repo, sha)
	}
	out, err := explainImageSource(context.Background(), labelStub{labels: map[string]string{}}, nil, manifests, Job{
		Repository: "hostingmaloonde/supabase_studio",
		Digest:     amd,
		Upstream:   "docker.io/supabase/studio",
		Tag:        "2026.09.07-sha-7996410",
		Platform:   "linux/amd64",
	})
	if err != nil || !strings.Contains(out, "owner: supabase") || !strings.Contains(out, "revision: "+studioSHA) {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	labeled, err := explainImageSource(context.Background(), labelStub{labels: map[string]string{
		ociImageSource:   "https://github.com/acme/app.git",
		ociImageRevision: studioSHA,
	}}, nil, manifests, Job{Repository: "app", Digest: amd, Upstream: "docker.io/acme/app", Tag: "1"})
	if err != nil || !strings.Contains(labeled, "repo: app") || strings.Contains(labeled, "provenance:") {
		t.Fatalf("labels should win: %v\n%s", err, labeled)
	}
}

func TestCommitSearchFallback(t *testing.T) {
	t.Setenv("SUPPLINE_GITHUB_TOKEN", "test-token")
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []any{
				map[string]any{"sha": studioSHA, "repository": map[string]string{"full_name": "supabase/supabase"}},
				map[string]any{"sha": "7996410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "repository": map[string]string{"full_name": "other/mirror"}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := &publicSource{client: srv.Client(), hosts: map[string]struct{}{parsed.Hostname(): {}}, insecure: true, github: srv.URL}
	hit, ambiguous, err := pub.SearchCommits(context.Background(), "7996410", "docker.io/supabase/studio")
	if err != nil {
		t.Fatal(err)
	}
	if hit.Repo != "" || len(ambiguous) != 2 {
		t.Fatalf("hit %+v ambiguous %v", hit, ambiguous)
	}
	if query != "hash:7996410" {
		t.Fatalf("query %s", query)
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []any{map[string]any{"sha": studioSHA, "repository": map[string]string{"full_name": "supabase/supabase"}}},
		})
	})
	hit, ambiguous, err = pub.SearchCommits(context.Background(), "7996410", "docker.io/supabase/studio")
	if err != nil || hit.Owner != "supabase" || hit.Repo != "supabase" || hit.SHA != studioSHA || ambiguous != nil {
		t.Fatalf("unique %+v %v %v", hit, ambiguous, err)
	}
	out, err := explainImageSource(context.Background(), labelStub{}, pub, failingManifests{}, Job{
		Upstream: "docker.io/supabase/studio",
		Tag:      "2026.09.07-sha-7996410",
	})
	if err != nil || !strings.Contains(out, "commit_search: supabase/supabase@"+studioSHA) {
		t.Fatalf("fallback: %v\n%s", err, out)
	}
}

type labelStub struct {
	labels map[string]string
}

func (s labelStub) ImageLabels(context.Context, string, string) (map[string]string, error) {
	if s.labels == nil {
		return map[string]string{}, nil
	}
	return s.labels, nil
}

type manifestMap map[string][]byte

func (m manifestMap) Manifest(_ context.Context, ref string) ([]byte, error) {
	body, ok := m[ref]
	if !ok {
		return nil, errNotFound(ref)
	}
	return body, nil
}

func (m manifestMap) Blob(_ context.Context, _, digest string) ([]byte, error) {
	body, ok := m[digest]
	if !ok {
		return nil, errNotFound(digest)
	}
	return body, nil
}

type failingManifests struct{}

func (failingManifests) Manifest(context.Context, string) ([]byte, error) {
	return nil, errNotFound("index")
}
func (failingManifests) Blob(context.Context, string, string) ([]byte, error) {
	return nil, errNotFound("blob")
}

type errNotFound string

func (e errNotFound) Error() string { return "not found: " + string(e) }
