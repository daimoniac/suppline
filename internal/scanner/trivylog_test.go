package scanner

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestParseTrivyLogLine_TabSeparated(t *testing.T) {
	parsed, ok := parseTrivyLogLine("2026-09-08T14:30:21Z\tINFO\tDetected OS\tfamily=\"alpine\" version=\"3.23.3\"")
	if !ok {
		t.Fatal("expected parse success")
	}
	if parsed.level != slog.LevelInfo {
		t.Fatalf("level: got %v", parsed.level)
	}
	if parsed.msg != "Detected OS" {
		t.Fatalf("msg: got %q", parsed.msg)
	}
	if got := attrMap(parsed.attrs); got["family"] != "alpine" || got["version"] != "3.23.3" {
		t.Fatalf("attrs: %#v", parsed.attrs)
	}
}

func TestParseTrivyLogLine_PrefixAndNumericAttr(t *testing.T) {
	line := "2026-09-08T14:30:22Z\tINFO\t[alpine] Detecting vulnerabilities...\tos_version=\"3.23.3\" repository=\"3.23\" pkg_num=47"
	parsed, ok := parseTrivyLogLine(line)
	if !ok {
		t.Fatal("expected parse success")
	}
	if parsed.prefix != "alpine" {
		t.Fatalf("prefix: got %q", parsed.prefix)
	}
	if parsed.msg != "Detecting vulnerabilities..." {
		t.Fatalf("msg: got %q", parsed.msg)
	}
	got := attrMap(parsed.attrs)
	if got["os_version"] != "3.23.3" || got["repository"] != "3.23" || got["pkg_num"] != "47" {
		t.Fatalf("attrs: %#v", parsed.attrs)
	}
}

func TestParseTrivyLogLine_WarnWithoutAttrs(t *testing.T) {
	line := "2026-09-08T14:30:22Z\tWARN\tUsing severities from other vendors for some vulnerabilities. Read https://trivy.dev/docs/v0.73/guide/scanner/vulnerability#severity-selection"
	parsed, ok := parseTrivyLogLine(line)
	if !ok {
		t.Fatal("expected parse success")
	}
	if parsed.level != slog.LevelWarn {
		t.Fatalf("level: got %v", parsed.level)
	}
	if !bytes.Contains([]byte(parsed.msg), []byte("Using severities from other vendors")) {
		t.Fatalf("msg: got %q", parsed.msg)
	}
}

func TestParseTrivyLogLine_SpaceSeparatedFallback(t *testing.T) {
	line := `2026-09-08T14:30:21Z  INFO  Detected OS  family="alpine" version="3.23.3"`
	parsed, ok := parseTrivyLogLine(line)
	if !ok {
		t.Fatal("expected parse success")
	}
	if parsed.msg != "Detected OS" {
		t.Fatalf("msg: got %q", parsed.msg)
	}
	if got := attrMap(parsed.attrs); got["family"] != "alpine" {
		t.Fatalf("attrs: %#v", parsed.attrs)
	}
}

func TestTrivyLogRelay_JSONWithImageRef(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	relay := newTrivyLogRelay(logger, "hostingmaloonde/supabase_storage_api@sha256:abc")
	if _, err := relay.Write([]byte("2026-09-08T14:30:21Z\tINFO\tDetected OS\tfamily=\"alpine\" version=\"3.23.3\"\n")); err != nil {
		t.Fatal(err)
	}
	relay.Flush()

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json: %v (raw %s)", err, buf.String())
	}
	if rec["msg"] != "Detected OS" {
		t.Fatalf("msg: %v", rec["msg"])
	}
	if rec["level"] != "INFO" {
		t.Fatalf("level: %v", rec["level"])
	}
	if rec["image_ref"] != "hostingmaloonde/supabase_storage_api@sha256:abc" {
		t.Fatalf("image_ref: %v", rec["image_ref"])
	}
	if rec["family"] != "alpine" || rec["version"] != "3.23.3" {
		t.Fatalf("trivy attrs: %s", buf.String())
	}
}

func attrMap(attrs []trivyLogAttr) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		out[a.key] = a.value
	}
	return out
}
