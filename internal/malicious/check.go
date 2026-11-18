package malicious

import (
	"github.com/daimoniac/suppline/internal/types"
)

// Check matches a CycloneDX SBOM against the current snapshot. It returns the
// check outcome and the image's language packages, which the caller records
// so the image can be matched again when advisories change. Packages are
// returned even when the index is unavailable. When the SBOM cannot be read
// the check is unavailable and no packages are returned.
func (s *Service) Check(sbom []byte) (*types.MaliciousCheck, []types.PackageRef, error) {
	packages, err := PackagesFromCycloneDX(sbom)
	if err != nil {
		return &types.MaliciousCheck{Status: types.MaliciousCheckUnavailable}, nil, err
	}
	snapshot := s.Snapshot()
	return CheckPackages(snapshot, packages), PackageRefs(packages), nil
}

// CheckPackages matches packages against a snapshot.
func CheckPackages(snapshot Snapshot, packages []Package) *types.MaliciousCheck {
	check := &types.MaliciousCheck{Status: string(snapshot.Status)}
	if snapshot.Status == StatusUnavailable {
		return check
	}
	check.Commit = snapshot.Commit
	check.SnapshotAt = snapshot.SyncedAt.Unix()
	for _, finding := range snapshot.Index.Match(packages) {
		check.Findings = append(check.Findings, types.MaliciousFinding{
			ID:          finding.ID,
			Ecosystem:   finding.Ecosystem,
			PackageName: finding.PackageName,
			Version:     finding.Version,
			PURL:        finding.PURL,
			Summary:     finding.Summary,
			URL:         finding.URL,
		})
	}
	return check
}

// PackageRefs converts packages for storage.
func PackageRefs(packages []Package) []types.PackageRef {
	refs := make([]types.PackageRef, 0, len(packages))
	for _, pkg := range packages {
		refs = append(refs, types.PackageRef{Ecosystem: pkg.Ecosystem, Name: pkg.Name, Version: pkg.Version, PURL: pkg.PURL})
	}
	return refs
}

// Packages converts stored package references back for matching.
func Packages(refs []types.PackageRef) []Package {
	packages := make([]Package, 0, len(refs))
	for _, ref := range refs {
		packages = append(packages, Package{Ecosystem: ref.Ecosystem, Name: ref.Name, Version: ref.Version, PURL: ref.PURL})
	}
	return packages
}
