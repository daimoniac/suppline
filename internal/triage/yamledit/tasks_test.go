package yamledit

import (
	"os"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"gopkg.in/yaml.v3"
)

const sampleConfig = `# keep
version: 1
defaults:
  x-vex:
    - id: CVE-DEFAULT
      state: not_affected
      justification: code_not_present
sync:
  - source: example.com/keep
    target: registry.local/keep
    type: repository
    tags:
      semverRange:
        - ">=1.0.0"
      deny:
        - latest
    x-vex:
      - id: CVE-KEEP
        state: not_affected
        justification: code_not_present
      - id: CVE-DROP
        state: not_affected
        justification: code_not_present
        detail: remove me
  - source: example.com/drop
    target: registry.local/drop:1.2.3
    type: image
    tags:
      semverRange:
        - ">=1.0.0"
    x-vex-auto:
      - id: CVE-DROP
        state: not_affected
        justification: code_not_reachable
`

func TestSetSemverRangesPreservesSiblingKeys(t *testing.T) {
	updated, n, err := SetSemverRanges([]byte(sampleConfig), []SemverRangeUpdate{{
		Target: "registry.local/keep",
		Ranges: []string{">=2.0.0"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("updated %d", n)
	}
	text := string(updated)
	if !strings.Contains(text, ">=2.0.0") || !strings.Contains(text, "deny:") || !strings.Contains(text, "CVE-KEEP") {
		t.Fatalf("semver edit lost siblings:\n%s", text)
	}
	if strings.Contains(text, ">=1.0.0") && strings.Count(text, ">=1.0.0") != 1 {
		t.Fatalf("keep range should be replaced and the other entry left alone:\n%s", text)
	}
	parsed := parseConfig(t, updated)
	if len(parsed.Sync) != 2 || parsed.Sync[0].Tags == nil || len(parsed.Sync[0].Tags.SemverRange) != 1 || parsed.Sync[0].Tags.SemverRange[0] != ">=2.0.0" {
		t.Fatalf("ranges = %+v", parsed.Sync[0].Tags)
	}
	if len(parsed.Sync[0].Tags.Deny) != 1 || parsed.Sync[0].Tags.Deny[0] != "latest" {
		t.Fatalf("deny = %+v", parsed.Sync[0].Tags.Deny)
	}
}

func TestRemoveSyncTargetsKeepsTheOtherEntry(t *testing.T) {
	updated, n, err := RemoveSyncTargets([]byte(sampleConfig), []string{"registry.local/drop"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed %d", n)
	}
	text := string(updated)
	if strings.Contains(text, "registry.local/drop") || strings.Contains(text, "example.com/drop") {
		t.Fatalf("dropped entry still present:\n%s", text)
	}
	if !strings.Contains(text, "registry.local/keep") || !strings.Contains(text, "# keep") || !strings.Contains(text, "CVE-DEFAULT") {
		t.Fatalf("kept content missing:\n%s", text)
	}
	parsed := parseConfig(t, updated)
	if len(parsed.Sync) != 1 || parsed.Sync[0].Target != "registry.local/keep" {
		t.Fatalf("sync = %+v", parsed.Sync)
	}
}

func TestRemoveVEXStatementsFromDefaultsAndSync(t *testing.T) {
	updated, n, err := RemoveVEXStatements([]byte(sampleConfig), []string{"CVE-DROP", "CVE-DEFAULT"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("removed %d statements", n)
	}
	text := string(updated)
	if strings.Contains(text, "CVE-DROP") || strings.Contains(text, "CVE-DEFAULT") || strings.Contains(text, "remove me") {
		t.Fatalf("removed statements still present:\n%s", text)
	}
	if !strings.Contains(text, "CVE-KEEP") || !strings.Contains(text, "registry.local/drop") {
		t.Fatalf("unrelated content missing:\n%s", text)
	}
	parsed := parseConfig(t, updated)
	if len(parsed.Defaults.VEX) != 0 {
		t.Fatalf("defaults = %+v", parsed.Defaults.VEX)
	}
	if len(parsed.Sync[0].VEX) != 1 || parsed.Sync[0].VEX[0].ID != "CVE-KEEP" {
		t.Fatalf("keep vex = %+v", parsed.Sync[0].VEX)
	}
	if len(parsed.Sync[1].VEXAuto) != 0 {
		t.Fatalf("auto = %+v", parsed.Sync[1].VEXAuto)
	}
}

func TestEditsReportNoMatch(t *testing.T) {
	_, _, err := RemoveSyncTargets([]byte(sampleConfig), []string{"registry.local/missing"})
	if err != ErrNoMatch {
		t.Fatalf("got %v", err)
	}
}

func TestSetSemverRangesExpandsTemplates(t *testing.T) {
	t.Setenv("REG", "registry.local")
	doc := []byte("version: 1\nsync:\n  - source: app\n    target: '{{ env \"REG\" }}/app'\n    type: repository\n    tags:\n      semverRange:\n        - \">=1.0.0\"\n")
	updated, n, err := SetSemverRanges(doc, []SemverRangeUpdate{{Target: "registry.local/app", Ranges: []string{">=3.0.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(string(updated), ">=3.0.0") || !strings.Contains(string(updated), `{{ env "REG" }}`) {
		t.Fatalf("template edit:\n%s", updated)
	}
}

func parseConfig(t *testing.T, document []byte) config.RegsyncConfig {
	t.Helper()
	path := t.TempDir() + "/suppline.yml"
	if err := os.WriteFile(path, document, 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := config.ParseRegsync(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, document)
	}
	raw := config.RegsyncConfig{}
	if err := yaml.Unmarshal(document, &raw); err != nil {
		t.Fatal(err)
	}
	if parsed.Sync == nil {
		t.Fatal("parsed sync is nil")
	}
	return raw
}
