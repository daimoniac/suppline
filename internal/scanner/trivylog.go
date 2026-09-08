package scanner

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

var (
	ansiEscapeRe    = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	attrTokenRe     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(?:"((?:[^"\\]|\\.)*)"|(\S+))(?:\s+|$)`)
	rfc3339PrefixRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`)
	progressBarRe   = regexp.MustCompile(`\[=*>?\s*\]`)
)

// trivyLogRelay copies Trivy stderr into slog JSON, attaching the image currently being scanned.
type trivyLogRelay struct {
	logger   *slog.Logger
	imageRef string
	mu       sync.Mutex
	buf      []byte
}

func newTrivyLogRelay(logger *slog.Logger, imageRef string) *trivyLogRelay {
	if logger == nil {
		logger = slog.Default()
	}
	return &trivyLogRelay{logger: logger, imageRef: imageRef}
}

func (r *trivyLogRelay) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(r.buf[:i]), "\r")
		r.buf = r.buf[i+1:]
		r.emit(line)
	}
	return len(p), nil
}

func (r *trivyLogRelay) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return
	}
	line := strings.TrimRight(string(r.buf), "\r")
	r.buf = nil
	r.emit(line)
}

func (r *trivyLogRelay) emit(line string) {
	line = strings.TrimSpace(ansiEscapeRe.ReplaceAllString(line, ""))
	if line == "" || progressBarRe.MatchString(line) {
		return
	}
	parsed, ok := parseTrivyLogLine(line)
	if !ok {
		r.logger.Info(line, "image_ref", r.imageRef)
		return
	}
	args := make([]any, 0, 4+len(parsed.attrs)*2)
	if r.imageRef != "" {
		args = append(args, "image_ref", r.imageRef)
	}
	if parsed.prefix != "" {
		args = append(args, "trivy_prefix", parsed.prefix)
	}
	for _, attr := range parsed.attrs {
		args = append(args, attr.key, attr.value)
	}
	r.logger.Log(context.Background(), parsed.level, parsed.msg, args...)
}

type trivyLogAttr struct {
	key   string
	value string
}

type parsedTrivyLog struct {
	level  slog.Level
	msg    string
	prefix string
	attrs  []trivyLogAttr
}

func parseTrivyLogLine(line string) (parsedTrivyLog, bool) {
	fields := splitTrivyFields(line)
	if len(fields) < 3 || !rfc3339PrefixRe.MatchString(fields[0]) {
		return parsedTrivyLog{}, false
	}
	level, ok := parseTrivyLevel(fields[1])
	if !ok {
		return parsedTrivyLog{}, false
	}
	msg, prefix := splitTrivyPrefix(fields[2])
	var attrs []trivyLogAttr
	if len(fields) > 3 {
		attrs = parseTrivyAttrs(strings.Join(fields[3:], " "))
	}
	return parsedTrivyLog{level: level, msg: msg, prefix: prefix, attrs: attrs}, true
}

func splitTrivyFields(line string) []string {
	if strings.Contains(line, "\t") {
		parts := strings.Split(line, "\t")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	// Fallback for viewers that expand tabs to spaces: time  LEVEL  message  attrs
	rest := strings.TrimSpace(line)
	timeEnd := strings.IndexFunc(rest, unicode.IsSpace)
	if timeEnd < 0 {
		return nil
	}
	ts := rest[:timeEnd]
	rest = strings.TrimSpace(rest[timeEnd:])
	levelEnd := strings.IndexFunc(rest, unicode.IsSpace)
	if levelEnd < 0 {
		return []string{ts, rest}
	}
	level := rest[:levelEnd]
	rest = strings.TrimSpace(rest[levelEnd:])
	msg, attrs := splitMessageAndAttrs(rest)
	if attrs == "" {
		return []string{ts, level, msg}
	}
	return []string{ts, level, msg, attrs}
}

func splitMessageAndAttrs(rest string) (string, string) {
	idx := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] != ' ' {
			continue
		}
		j := i
		for j < len(rest) && rest[j] == ' ' {
			j++
		}
		if j-i >= 2 && attrTokenRe.MatchString(rest[j:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return rest, ""
	}
	return strings.TrimSpace(rest[:idx]), strings.TrimSpace(rest[idx:])
}

func splitTrivyPrefix(msg string) (string, string) {
	if !strings.HasPrefix(msg, "[") {
		return msg, ""
	}
	end := strings.IndexByte(msg, ']')
	if end < 2 {
		return msg, ""
	}
	prefix := msg[1:end]
	rest := strings.TrimSpace(msg[end+1:])
	if rest == "" {
		return msg, ""
	}
	return rest, prefix
}

func parseTrivyLevel(level string) (slog.Level, bool) {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug, true
	case "INFO":
		return slog.LevelInfo, true
	case "WARN", "WARNING":
		return slog.LevelWarn, true
	case "ERROR", "FATAL":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func parseTrivyAttrs(s string) []trivyLogAttr {
	s = strings.TrimSpace(s)
	var attrs []trivyLogAttr
	for s != "" {
		m := attrTokenRe.FindStringSubmatch(s)
		if m == nil {
			break
		}
		val := m[2]
		if val == "" {
			val = m[3]
		}
		if unquoted, err := strconv.Unquote(`"` + val + `"`); err == nil {
			val = unquoted
		}
		attrs = append(attrs, trivyLogAttr{key: m[1], value: val})
		s = strings.TrimSpace(s[len(m[0]):])
	}
	return attrs
}
