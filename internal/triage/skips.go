package triage

import "time"

// Skip codes say why a policy-failing CVE was not sent to the model.
const (
	// SkipExempt: an active not_affected statement already covers the CVE.
	SkipExempt = "exempt"
	// SkipNotInUse: only_in_use is on and the repository is not running anywhere.
	SkipNotInUse = "not_in_use"
	// SkipNotInScans: the CVE is no longer in any current scan of the repository.
	SkipNotInScans = "not_in_scans"
	// SkipCached: the last run is still valid for the same commits and packages.
	SkipCached = "cached"
	// SkipBudget: the daily token budget stopped the session before this CVE.
	SkipBudget = "budget"
)

// Skip is the latest reason one repository and CVE was left alone.
type Skip struct {
	Code   string
	Detail string
	At     time.Time
}

func skipKey(repository, cve string) string {
	return repository + "\n" + cve
}

// noteSkip remembers why a CVE was skipped. The next accepted job or stored run clears it.
func (s *Service) noteSkip(repository, cve, code, detail string) {
	if s == nil || repository == "" || cve == "" {
		return
	}
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	if s.skips == nil {
		s.skips = map[string]Skip{}
	}
	at := time.Now().UTC()
	if s.now != nil {
		at = s.now()
	}
	s.skips[skipKey(repository, cve)] = Skip{Code: code, Detail: detail, At: at}
}

func (s *Service) clearSkip(repository, cve string) {
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	delete(s.skips, skipKey(repository, cve))
}

// Skips returns the recorded skip reasons keyed by repository and CVE.
// Skip reasons live in memory, so a restart forgets them.
func (s *Service) Skips() map[string]Skip {
	out := map[string]Skip{}
	if s == nil {
		return out
	}
	s.skipMu.Lock()
	defer s.skipMu.Unlock()
	for key, skip := range s.skips {
		out[key] = skip
	}
	return out
}

// SkipKey is the key format used by Skips.
func SkipKey(repository, cve string) string {
	return skipKey(repository, cve)
}
