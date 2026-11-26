package policy

import (
	"regexp"

	"github.com/daimoniac/suppline/internal/kev"
	"github.com/daimoniac/suppline/internal/types"
)

// KEVSource gives the policy engine the CISA Known Exploited Vulnerabilities
// catalog.
type KEVSource interface {
	Snapshot() kev.Snapshot
}

// WithKEV lets policy expressions see which findings are in the CISA KEV
// catalog. Without it, or with a nil source, every finding has kev false and
// kevStatus is "disabled".
func WithKEV(source KEVSource) Option {
	return func(e *Engine) { e.kev = source }
}

func (e *Engine) kevSnapshot() kev.Snapshot {
	if e.kev == nil {
		return kev.Snapshot{Status: kev.StatusDisabled}
	}
	return e.kev.Snapshot()
}

// addKEVFields sets the KEV and kernel-header fields on one enriched finding
// and reports whether the finding is listed. A stale catalog still answers;
// kevStatus tells the expression how far to trust it.
func addKEVFields(enriched map[string]interface{}, vuln types.Vulnerability, catalog *kev.Catalog) bool {
	entry, listed := catalog.Lookup(vuln.ID)
	enriched["kev"] = listed
	enriched["kevDateAdded"] = entry.DateAdded
	enriched["kevRansomware"] = entry.Ransomware
	enriched["kernelHeaderPackage"] = types.IsKernelHeaderPackage(vuln.PackageName)
	return listed
}

// kevIdentRE matches any KEV variable or field in an expression.
var kevIdentRE = regexp.MustCompile(`\bkev(Count|Status|DateAdded|Ransomware)?\b`)

// UsesKEV reports whether a policy expression reads any KEV variable or
// field, so a change to the catalog can change its result. An empty
// expression is the default policy, which does not.
func UsesKEV(expression string) bool {
	return kevIdentRE.MatchString(expression)
}
