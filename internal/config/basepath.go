package config

import (
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

// NormalizeBasePath validates the URL prefix suppline is served under and
// returns it without a trailing slash. "" and "/" both mean the root and
// normalize to "".
func NormalizeBasePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" || p == "/" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", errors.NewPermanentf("SUPPLINE_BASE_PATH must start with '/', got %q", raw)
	}
	if strings.ContainsAny(p, "?#\\ \t\"'<>") {
		return "", errors.NewPermanentf("SUPPLINE_BASE_PATH must be a plain URL path, got %q", raw)
	}
	p = strings.TrimRight(p, "/")
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errors.NewPermanentf("SUPPLINE_BASE_PATH has an empty or relative segment: %q", raw)
		}
	}
	return p, nil
}
