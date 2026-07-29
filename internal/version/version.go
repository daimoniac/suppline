// Package version holds the suppline build version.
// Overridden at link time via:
//
//	-ldflags "-X github.com/daimoniac/suppline/internal/version.Version=0.1.3"
package version

// Version is the semver of this binary (no leading "v"). Defaults to "dev" for local builds.
var Version = "dev"
