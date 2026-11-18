package yamledit

import (
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/config"
)

// AddCooldownRelease writes release into cooldown-release of every sync
// entry for repository, replacing an earlier release of the same digest.
func AddCooldownRelease(document []byte, repository string, release config.CooldownRelease) ([]byte, error) {
	if strings.TrimSpace(repository) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	if !strings.HasPrefix(release.Digest, "sha256:") {
		return nil, fmt.Errorf("cooldown release needs a sha256 digest, got %q", release.Digest)
	}
	const key = "cooldown-release"
	return spliceMatching(document, repository, key, func(text string, entry matchedEntry, delta int) (string, error) {
		return spliceItem(text, entry, key, "digest", release.Digest, func(dashPrefix string) string {
			return formatCooldownRelease(dashPrefix, release)
		}, delta)
	})
}

func formatCooldownRelease(dashPrefix string, release config.CooldownRelease) string {
	nested := dashPrefix + "  "
	var b strings.Builder
	fmt.Fprintf(&b, "%s- digest: %s\n", dashPrefix, yamlScalar(release.Digest, ""))
	if release.Reason != "" {
		fmt.Fprintf(&b, "%sreason: %s\n", nested, yamlScalar(release.Reason, nested+"  "))
	}
	if release.Author != "" {
		fmt.Fprintf(&b, "%sauthor: %s\n", nested, yamlScalar(release.Author, ""))
	}
	if release.At != "" {
		fmt.Fprintf(&b, "%sat: %s\n", nested, yamlScalar(release.At, ""))
	}
	return b.String()
}
