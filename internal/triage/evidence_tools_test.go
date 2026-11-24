package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/registry"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// operatorImage is an Alpine image whose Go operator binary was too large to
// unpack, the case that left an earlier triage with no citable evidence.
func operatorImage(t *testing.T, digest string) *Roots {
	t.Helper()
	cache := filepath.Join(os.TempDir(), "suppline-image", sanitizeDigest(digest))
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cache) })
	src := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/ssl/certs/ca-certificates.crt", "-----BEGIN CERTIFICATE-----\n")
	write("lib/apk/db/installed", strings.Join([]string{
		"P:musl", "V:1.2.5-r10", "F:lib", "R:ld-musl-x86_64.so.1", "",
		"P:ca-certificates-bundle", "V:20260413-r0", "o:ca-certificates", "F:etc/ssl/certs", "R:ca-certificates.crt", "",
	}, "\n"))
	write(registry.SkippedFilesManifest, "elastic-operator\t90000000\t1\n")
	return &Roots{Image: newImageFS(&copyUnpacker{src: src}, "hostingmaloonde/eck_eck-operator", digest)}
}

func TestImageFilesSeesFilesTheUnpackSkipped(t *testing.T) {
	roots := operatorImage(t, "sha256:files1")
	pub := newPublicSource()
	job := Job{CVEID: "CVE-2026-91403", PackageName: "ca-certificates-bundle", Digest: "sha256:files1"}
	pub.setPhase(job.CVEID)

	absent, err := imageFiles(context.Background(), roots, pub, job, `libjvm\.so|\.jar$|/bin/java$`, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(absent, "citable: absence") || !strings.Contains(absent, "matches: 0") {
		t.Fatalf("no JVM in the image:\n%s", absent)
	}
	present, err := imageFiles(context.Background(), roots, pub, job, `operator`, ".")
	if err != nil || !strings.Contains(present, "elastic-operator:1:file not unpacked, 90000000 bytes") || !strings.Contains(present, "citable: rows") {
		t.Fatalf("skipped file by name: %v\n%s", err, present)
	}
	if strings.Contains(present, registry.SkippedFilesManifest) {
		t.Fatalf("listed the bookkeeping manifest:\n%s", present)
	}

	verdict := modelVerdict{Verdict: "not_affected", Justification: "code_not_present", Evidence: []modelEvidence{{GrepID: "g1"}}}
	if err := verifyEvidence(*roots, pub, job, &verdict); err != nil {
		t.Fatalf("a path absence backs code_not_present: %v", err)
	}
	if got := verdict.Evidence[0].Pattern; got != imageNamePattern(`libjvm\.so|\.jar$|/bin/java$`) {
		t.Fatalf("recorded pattern %q", got)
	}
}

// A native file the unpack left out was never searched, so a content grep
// cannot claim absence while it is missing.
func TestImageGrepCountsSkippedNativeFiles(t *testing.T) {
	roots := operatorImage(t, "sha256:grep1")
	pub := newPublicSource()
	job := Job{PackageName: "ca-certificates-bundle", Digest: "sha256:grep1"}
	out, err := imageGrep(context.Background(), roots, pub, job, "SSLEngine", ".")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "citable: no") || !strings.Contains(out, "too large") {
		t.Fatalf("grep with a skipped native file:\n%s", out)
	}
}

func TestPackageFilesReadsApkRecord(t *testing.T) {
	roots := operatorImage(t, "sha256:pkg1")
	pub := newPublicSource()
	job := Job{CVEID: "CVE-2026-91403", PackageName: "ca-certificates-bundle", Digest: "sha256:pkg1"}
	pub.setPhase(job.CVEID)
	out, err := packageFiles(context.Background(), roots, pub, job, job.PackageName)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lib/apk/db/installed:6:P:ca-certificates-bundle", "lib/apk/db/installed:10:R:ca-certificates.crt", "citable: rows", "complete: true"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "musl") {
		t.Errorf("output includes another package:\n%s", out)
	}
	verdict := modelVerdict{Verdict: "not_affected", Justification: "code_not_reachable", Evidence: []modelEvidence{{GrepID: "g1"}}}
	if err := verifyEvidence(*roots, pub, job, &verdict); err != nil || len(verdict.Evidence) != 5 {
		t.Fatalf("package rows as evidence: %v %+v", err, verdict.Evidence)
	}

	missing, err := packageFiles(context.Background(), roots, pub, job, "openjdk21")
	if err != nil || !strings.Contains(missing, "citable: no") || !strings.Contains(missing, "is not in lib/apk/db/installed") {
		t.Fatalf("absent package: %v\n%s", err, missing)
	}
	if _, err := packageFiles(context.Background(), roots, pub, job, "../etc/passwd"); err == nil {
		t.Fatal("accepted a path as a package name")
	}
}

func TestPackageFilesReadsDpkgList(t *testing.T) {
	dir := t.TempDir()
	info := filepath.Join(dir, "var", "lib", "dpkg", "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "ca-certificates:all.list"), []byte("/.\n/usr/share/ca-certificates\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db, rows, err := readPackageFiles(dir, "ca-certificates")
	if err != nil || db != "var/lib/dpkg/info/ca-certificates:all.list" || len(rows) != 2 || rows[1] != db+":2:/usr/share/ca-certificates" {
		t.Fatalf("db %q rows %v err %v", db, rows, err)
	}
}

type runStub struct {
	statestore.TriageStore
	runs []statestore.TriageRun
}

func (s runStub) ListTriageRuns(context.Context, statestore.TriageFilter) ([]statestore.TriageRun, error) {
	return s.runs, nil
}

func TestRecheckEvidenceReplaysEarlierCitations(t *testing.T) {
	roots := operatorImage(t, "sha256:recheck1")
	gitops := t.TempDir()
	if err := os.WriteFile(filepath.Join(gitops, "app.yaml"), []byte("kind: Deployment\nimage: eck-operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots.Checkouts = append(roots.Checkouts, CheckoutRoot{Name: "infra", Dir: gitops})
	evidence, _ := json.Marshal([]modelEvidence{
		{Repo: imageCheckoutName, Path: ".", Pattern: imageNamePattern(`libjvm\.so`)},
		{Repo: imageCheckoutName, Path: "lib/apk/db/installed", Pattern: packagePrefix + "ca-certificates-bundle"},
		{Repo: "infra", Path: "app.yaml", Line: 2, Quote: "image: eck-operator"},
		{Repo: "acme/app", Path: "src/a.go", Line: 3, Quote: "x"},
	})
	statement := &types.VEXStatement{ID: "CVE-1", State: types.VEXStateNotAffected, Detail: "auto-generated by suppline triage\ntriage_id: ts-1\nmodel: m"}
	store := runStub{runs: []statestore.TriageRun{
		{SessionID: "ts-2", Status: StatusRejected},
		{SessionID: "ts-1", Status: StatusCommitted, EvidenceJSON: string(evidence)},
	}}
	prior := loadPriorEvidence(context.Background(), store, "app", map[string]*types.VEXStatement{"CVE-1": statement})
	if prior["CVE-1"].Missing != "" || len(prior["CVE-1"].Items) != 4 {
		t.Fatalf("prior = %+v", prior)
	}

	pub := newPublicSource()
	tools := &toolbox{roots: roots, pub: pub, prior: prior}
	job := Job{CVEID: "CVE-1", PackageName: "ca-certificates-bundle", Digest: "sha256:recheck1"}
	pub.setPhase(phaseContext)
	if _, err := recheckEvidence(context.Background(), tools, job); err == nil {
		t.Fatal("recheck ran in the context phase")
	}
	pub.setPhase(job.CVEID)
	out, err := recheckEvidence(context.Background(), tools, job)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"existing statement: not_affected from triage_id ts-1",
		"evidence[0]: file search", "grep_id: g1", "citable: absence",
		"evidence[1]: package files of ca-certificates-bundle", "grep_id: g2",
		"evidence[2]: line infra:app.yaml:2", "unchanged: image: eck-operator",
		"evidence[3]: line acme/app:src/a.go:3", "not replayable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("recheck lacks %q:\n%s", want, out)
		}
	}
	hit, ok := pub.grep("g1")
	if !ok || hit.Phase != job.CVEID {
		t.Fatalf("replayed search is not recorded for this CVE: %+v", hit)
	}

	none, err := recheckEvidence(context.Background(), tools, Job{CVEID: "CVE-2"})
	if err == nil || !strings.Contains(err.Error(), "no existing auto statement") {
		t.Fatalf("no statement: %v %s", err, none)
	}
	lost := loadPriorEvidence(context.Background(), runStub{}, "app", map[string]*types.VEXStatement{"CVE-1": statement})
	if !strings.Contains(lost["CVE-1"].Missing, "no written run ts-1") {
		t.Fatalf("missing run = %+v", lost)
	}
}

func TestImageSourceResolvesVersionTagFromSourceLabel(t *testing.T) {
	const annotated = "1111111111111111111111111111111111111111"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/repos/elastic/cloud-on-k8s/git/ref/tags/v3.5.0":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": annotated, "type": "tag"}})
		case "/repos/elastic/cloud-on-k8s/git/tags/" + annotated:
			_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": studioSHA, "type": "commit"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := &publicSource{client: srv.Client(), hosts: map[string]struct{}{parsed.Hostname(): {}}, insecure: true, github: srv.URL}
	single := manifestMap{"docker.elastic.co/eck/eck-operator:3.5.0": []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"digest":"sha256:aa"}]}`)}
	out, err := explainImageSource(context.Background(), labelStub{labels: map[string]string{ociImageSource: "https://github.com/elastic/cloud-on-k8s"}}, pub, single, Job{
		Repository: "hostingmaloonde/eck_eck-operator", Digest: "sha256:abc", Upstream: "docker.elastic.co/eck/eck-operator", Tag: "3.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"provenance: upstream tag is a single-platform image",
		"tag_lookup: elastic/cloud-on-k8s@v3.5.0 is " + studioSHA,
		"revision: " + studioSHA,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("image_source lacks %q:\n%s\npaths: %v", want, out, paths)
		}
	}

	if !versionTag.MatchString("v3.5.0") || !versionTag.MatchString("3.5.0-rc.1") || versionTag.MatchString("latest") {
		t.Fatal("versionTag")
	}
}

func TestStatementTriageID(t *testing.T) {
	if got := statementTriageID("auto-generated by suppline triage\ntriage_id: ts-17\nmodel: m"); got != "ts-17" {
		t.Fatalf("got %q", got)
	}
	if got := statementTriageID("hand-written"); got != "" {
		t.Fatalf("got %q", got)
	}
}
