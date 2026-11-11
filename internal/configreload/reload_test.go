package configreload

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

const baseConfig = `version: 1
sync:
  - source: nginx
    target: registry.local/nginx
    type: repository
`

const withStatement = `version: 1
sync:
  - source: nginx
    target: registry.local/nginx
    type: repository
    x-vex:
      - id: CVE-1
        state: not_affected
        justification: code_not_reachable
`

func TestReadChangeAppliesANewFileAndKeepsTheLastGoodParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppline.yml")
	if err := os.WriteFile(path, []byte(baseConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(baseConfig))

	parsed, next, err := readChange(path, sum)
	if err != nil || parsed != nil || next != sum {
		t.Fatalf("unchanged file applied: cfg=%v next-changed=%t err=%v", parsed, next != sum, err)
	}

	if err := os.WriteFile(path, []byte(withStatement), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, next, err = readChange(path, sum)
	if err != nil {
		t.Fatal(err)
	}
	if parsed == nil || len(parsed.Sync) != 1 || len(parsed.Sync[0].VEX) != 1 || parsed.Sync[0].VEX[0].ID != "CVE-1" {
		t.Fatalf("applied config = %+v", parsed)
	}
	sum = next

	if err := os.WriteFile(path, []byte("version: 1\nsync: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, next, err = readChange(path, sum)
	if err == nil || parsed != nil || next != sum {
		t.Fatalf("broken file applied: cfg=%v sum-changed=%t err=%v", parsed, next != sum, err)
	}

	if err := os.WriteFile(path, []byte(withStatement+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, next, err = readChange(path, sum)
	if err != nil || parsed == nil || len(parsed.Sync) != 1 || len(parsed.Sync[0].VEX) != 1 {
		t.Fatalf("fixed file was not applied: cfg=%v err=%v", parsed, err)
	}
	if next == sum {
		t.Fatal("fixed file kept the rejected hash")
	}
}
