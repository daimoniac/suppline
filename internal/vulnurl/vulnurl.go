package vulnurl

import (
	"net/url"
	"regexp"
	"strings"
)

var avdWithYearPrefix = regexp.MustCompile(`^https://avd\.aquasec\.com/nvd/\d{4}/cve-\d{4}-\d+`)

// avdLegacyPath matches Trivy's PrimaryURL shape before Aqua added the year segment to paths.
var avdLegacyPath = regexp.MustCompile(`(?i)^/nvd/(cve-\d{4}-\d+)/?$`)

// NormalizeRefURL fixes known-broken reference URLs from scanners (notably legacy Aqua AVD paths).
func NormalizeRefURL(raw string) string {
	if raw == "" {
		return raw
	}
	if avdWithYearPrefix.MatchString(raw) {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	if !strings.EqualFold(u.Host, "avd.aquasec.com") {
		return raw
	}
	m := avdLegacyPath.FindStringSubmatch(u.Path)
	if m == nil {
		return raw
	}
	cvePart := strings.ToLower(m[1])
	if len(cvePart) < 9 { // "cve-" + 4-digit year
		return raw
	}
	year := cvePart[4:8]
	u.Path = "/nvd/" + year + "/" + cvePart + "/"
	u.RawPath = ""
	return u.String()
}
