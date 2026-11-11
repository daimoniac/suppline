package triage

import (
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
)

// resolveGroup picks one representative digest for a repository and builds one
// job per CVE that should actually be triaged. CVEs absent from current scans
// are skipped. With onlyInUse, a CVE that is only on idle digests is skipped.
func resolveGroup(records []*statestore.ScanRecord, repository string, cves []string, onlyInUse bool) []Job {
	repository = strings.TrimSpace(repository)
	wanted := make([]string, 0, len(cves))
	seenCVE := make(map[string]struct{}, len(cves))
	for _, cve := range cves {
		cve = strings.TrimSpace(cve)
		if cve == "" {
			continue
		}
		if _, ok := seenCVE[cve]; ok {
			continue
		}
		seenCVE[cve] = struct{}{}
		wanted = append(wanted, cve)
	}
	if repository == "" || len(wanted) == 0 {
		return nil
	}

	byDigest := map[string]*digestAccum{}
	var order []string
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.Repository) != repository {
			continue
		}
		digest := strings.TrimSpace(record.Digest)
		if digest == "" {
			continue
		}
		acc, ok := byDigest[digest]
		if !ok {
			acc = &digestAccum{info: DigestFact{Digest: digest}}
			byDigest[digest] = acc
			order = append(order, digest)
		}
		acc.add(record, seenCVE)
	}
	if len(order) == 0 {
		return nil
	}

	var inUse []DigestFact
	var idle []DigestFact
	for _, digest := range order {
		fact := byDigest[digest].info
		if fact.InUse {
			inUse = append(inUse, fact)
		} else {
			idle = append(idle, fact)
		}
	}
	sortDigests(inUse)
	sortDigests(idle)
	if onlyInUse && len(inUse) == 0 {
		return nil
	}

	repPool := inUse
	if len(repPool) == 0 {
		repPool = digestsWithCVEs(append(append([]DigestFact{}, inUse...), idle...), byDigest, seenCVE)
	}
	if len(repPool) == 0 {
		return nil
	}
	rep := repPool[0]

	jobs := make([]Job, 0, len(wanted))
	for _, cve := range wanted {
		if !cveReported(byDigest, cve) {
			continue
		}
		if onlyInUse && !cveOnDigests(byDigest, inUse, cve) {
			continue
		}
		jobs = append(jobs, jobForCVE(repository, cve, rep, inUse, byDigest))
	}
	if len(jobs) == 0 {
		return nil
	}
	return jobs
}

type digestAccum struct {
	info       DigestFact
	cvePkgs    map[string][]PackageFact
	severity   map[string]string
	detail     map[string]string
	failed     map[string]bool
	placement  string
	tagFromUse bool
}

func (d *digestAccum) add(record *statestore.ScanRecord, wanted map[string]struct{}) {
	if record.ImageCreatedAt > d.info.ImageCreatedAt {
		d.info.ImageCreatedAt = record.ImageCreatedAt
	}
	if record.RuntimeUsed {
		d.info.InUse = true
		if n := placementCount(record.Runtime); n > d.info.Placements {
			d.info.Placements = n
			d.placement = placementText(record.Repository, record.Tag, record.Digest, record.Runtime)
		}
		if !d.tagFromUse && strings.TrimSpace(record.Tag) != "" {
			d.info.Tag = strings.TrimSpace(record.Tag)
			d.tagFromUse = true
		}
	} else if d.info.Tag == "" {
		d.info.Tag = strings.TrimSpace(record.Tag)
	}
	if d.cvePkgs == nil {
		d.cvePkgs = map[string][]PackageFact{}
		d.severity = map[string]string{}
		d.detail = map[string]string{}
		d.failed = map[string]bool{}
	}
	for _, finding := range record.PolicyFailureFindings {
		id := strings.TrimSpace(finding.CVEID)
		if id == "" {
			continue
		}
		d.failed[id] = true
		if _, ok := wanted[id]; !ok {
			continue
		}
		if finding.PackageName == "" {
			continue
		}
		d.cvePkgs[id] = addPackage(d.cvePkgs[id], PackageFact{Name: finding.PackageName})
	}
	for _, vuln := range record.Vulnerabilities {
		id := strings.TrimSpace(vuln.CVEID)
		if _, ok := wanted[id]; !ok {
			continue
		}
		d.cvePkgs[id] = addPackage(d.cvePkgs[id], PackageFact{
			Name:      vuln.PackageName,
			Installed: vuln.InstalledVersion,
			Fixed:     vuln.FixedVersion,
		})
		if severityRank(vuln.Severity) > severityRank(d.severity[id]) {
			d.severity[id] = strings.ToUpper(strings.TrimSpace(vuln.Severity))
		}
		if strings.TrimSpace(vuln.Description) != "" && d.detail[id] == "" {
			d.detail[id] = vuln.Description
		}
	}
}

func jobForCVE(repository, cve string, rep DigestFact, inUse []DigestFact, byDigest map[string]*digestAccum) Job {
	var packages []PackageFact
	severity := ""
	description := ""
	repAcc := byDigest[rep.Digest]
	if repAcc != nil {
		description = repAcc.detail[cve]
		severity = repAcc.severity[cve]
	}
	listed := make([]DigestFact, 0, len(inUse))
	for _, digest := range inUse {
		acc := byDigest[digest.Digest]
		item := digest
		item.Packages = nil
		if acc != nil {
			item.Packages = append([]PackageFact(nil), acc.cvePkgs[cve]...)
			packages = mergePackages(packages, acc.cvePkgs[cve])
			if severityRank(acc.severity[cve]) > severityRank(severity) {
				severity = acc.severity[cve]
			}
			if description == "" {
				description = acc.detail[cve]
			}
		}
		listed = append(listed, item)
	}
	idleDigests := make([]string, 0, len(byDigest))
	for digest, acc := range byDigest {
		if acc == nil || acc.info.InUse {
			continue
		}
		idleDigests = append(idleDigests, digest)
	}
	sort.Strings(idleDigests)
	for _, digest := range idleDigests {
		acc := byDigest[digest]
		packages = mergePackages(packages, acc.cvePkgs[cve])
		if severityRank(acc.severity[cve]) > severityRank(severity) {
			severity = acc.severity[cve]
		}
		if description == "" {
			description = acc.detail[cve]
		}
	}
	primary := PackageFact{}
	for _, fact := range packages {
		if kernelPackage(fact.Name) {
			primary = fact
			break
		}
	}
	if primary.Name == "" && len(packages) > 0 {
		primary = packages[0]
	}
	if repAcc != nil {
		for _, fact := range repAcc.cvePkgs[cve] {
			if fact.Name == primary.Name && (fact.Installed != "" || fact.Fixed != "") {
				primary = fact
				break
			}
		}
	}
	image := repository
	if rep.Tag != "" {
		image = repository + ":" + rep.Tag
	}
	return Job{
		Repository:    repository,
		CVEID:         cve,
		PackageName:   primary.Name,
		Version:       primary.Installed,
		FixedVersion:  primary.Fixed,
		Severity:      severity,
		Description:   description,
		ImageRef:      image,
		Tag:           rep.Tag,
		Digest:        rep.Digest,
		Packages:      packages,
		InUse:         listed,
		PlacementText: repAcc.placementText(),
	}
}

func (d *digestAccum) placementText() string {
	if d == nil {
		return ""
	}
	return d.placement
}

func cveReported(byDigest map[string]*digestAccum, cve string) bool {
	for _, acc := range byDigest {
		if acc == nil {
			continue
		}
		if len(acc.cvePkgs[cve]) > 0 || acc.failed[cve] || acc.detail[cve] != "" || acc.severity[cve] != "" {
			return true
		}
	}
	return false
}

func cveOnDigests(byDigest map[string]*digestAccum, digests []DigestFact, cve string) bool {
	for _, digest := range digests {
		acc := byDigest[digest.Digest]
		if acc == nil {
			continue
		}
		if len(acc.cvePkgs[cve]) > 0 || acc.failed[cve] || acc.severity[cve] != "" {
			return true
		}
	}
	return false
}

func digestsWithCVEs(digests []DigestFact, byDigest map[string]*digestAccum, wanted map[string]struct{}) []DigestFact {
	var out []DigestFact
	for _, digest := range digests {
		acc := byDigest[digest.Digest]
		if acc == nil {
			continue
		}
		for cve := range wanted {
			if len(acc.cvePkgs[cve]) > 0 || acc.failed[cve] {
				out = append(out, digest)
				break
			}
		}
	}
	sortDigests(out)
	return out
}

func sortDigests(list []DigestFact) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].InUse != list[j].InUse {
			return list[i].InUse
		}
		if list[i].ImageCreatedAt != list[j].ImageCreatedAt {
			return list[i].ImageCreatedAt > list[j].ImageCreatedAt
		}
		if list[i].Placements != list[j].Placements {
			return list[i].Placements > list[j].Placements
		}
		return list[i].Digest < list[j].Digest
	})
}

func addPackage(list []PackageFact, fact PackageFact) []PackageFact {
	fact.Name = strings.TrimSpace(fact.Name)
	fact.Installed = strings.TrimSpace(fact.Installed)
	fact.Fixed = strings.TrimSpace(fact.Fixed)
	if fact.Name == "" && fact.Installed == "" && fact.Fixed == "" {
		return list
	}
	for i, have := range list {
		if have.Name != fact.Name {
			continue
		}
		if have.Installed == fact.Installed && have.Fixed == fact.Fixed {
			return list
		}
		if have.Installed == "" && have.Fixed == "" {
			list[i] = fact
			return list
		}
		if fact.Installed == "" && fact.Fixed == "" {
			return list
		}
	}
	return append(list, fact)
}

func mergePackages(dst, src []PackageFact) []PackageFact {
	for _, fact := range src {
		dst = addPackage(dst, fact)
	}
	return dst
}

func placementCount(inv statestore.RuntimeInventory) int {
	n := 0
	for _, namespaces := range inv {
		for _, images := range namespaces {
			n += len(images)
		}
	}
	return n
}

func severityRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// placementText renders where one digest is running, capped like the historic prompt.
func placementText(repository, tag, digest string, inv statestore.RuntimeInventory) string {
	if len(inv) == 0 {
		return ""
	}
	var b strings.Builder
	count := 0
	for cluster, namespaces := range inv {
		for namespace, images := range namespaces {
			for _, image := range images {
				ref := image.ImageRef
				if ref == "" {
					ref = repository
				}
				imageTag := image.Tag
				if imageTag == "" {
					imageTag = tag
				}
				imageDigest := image.Digest
				if imageDigest == "" {
					imageDigest = digest
				}
				b.WriteString(cluster + "/" + namespace + " " + ref + ":" + imageTag + " " + imageDigest + "\n")
				count++
				if count >= 20 {
					return b.String()
				}
			}
		}
	}
	return b.String()
}
