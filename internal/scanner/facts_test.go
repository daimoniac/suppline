package scanner

import (
	"encoding/json"
	"testing"
)

func TestFindingsFromTrivyReadsDistroFacts(t *testing.T) {
	const raw = `{
		"Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04", "EOSL": true}},
		"Results": [{
			"Vulnerabilities": [
				{
					"VulnerabilityID": "CVE-2026-1",
					"PkgName": "openssl",
					"InstalledVersion": "1",
					"FixedVersion": "2",
					"Severity": "CRITICAL",
					"Status": "affected",
					"VendorSeverity": {"ubuntu": "low", "nvd": 4},
					"CVSS": {
						"ubuntu": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
						"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
					}
				},
				{
					"VulnerabilityID": "CVE-2026-2",
					"PkgName": "libc",
					"InstalledVersion": "1",
					"Severity": "CRITICAL",
					"Status": "will_not_fix",
					"VendorSeverity": {"nvd": "CRITICAL"},
					"CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
				},
				{
					"VulnerabilityID": "CVE-2026-3",
					"PkgName": "brotli",
					"InstalledVersion": "1",
					"Severity": "HIGH",
					"CVSS": {"redhat": {"V2Vector": "AV:P/AC:L/Au:N/C:P/I:N/A:N"}}
				}
			]
		}]
	}`

	var response trivyScanResponse
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatal(err)
	}
	vulns, eosl := findingsFromTrivy(response)
	if !eosl {
		t.Fatal("OS end of life was not read")
	}
	if len(vulns) != 3 {
		t.Fatalf("findings = %d", len(vulns))
	}
	if vulns[0].VendorStatus != "affected" || vulns[0].VendorSeverity != "LOW" || vulns[0].AttackVector != "LOCAL" {
		t.Fatalf("ubuntu finding = %+v", vulns[0])
	}
	if vulns[1].VendorSeverity != "" || vulns[1].AttackVector != "ADJACENT" || vulns[1].VendorStatus != "will_not_fix" {
		t.Fatalf("nvd-only finding = %+v", vulns[1])
	}
	if vulns[2].AttackVector != "" || vulns[2].VendorSeverity != "" {
		t.Fatalf("unrelated source must not fill ubuntu facts: %+v", vulns[2])
	}
}

func TestDistroSeverityFollowsOSFamilyAlias(t *testing.T) {
	vendors := trivyVendorSeverity{"redhat": "MEDIUM", "nvd": "CRITICAL"}
	if got := distroSeverity("rocky", vendors); got != "MEDIUM" {
		t.Fatalf("rocky severity = %q", got)
	}
	if got := distroSeverity("", vendors); got != "" {
		t.Fatalf("missing OS family severity = %q", got)
	}
}

func TestVendorSeverityAcceptsNumericCodes(t *testing.T) {
	var vendors trivyVendorSeverity
	if err := json.Unmarshal([]byte(`{"debian": 3, "ubuntu": "medium"}`), &vendors); err != nil {
		t.Fatal(err)
	}
	if vendors["debian"] != "HIGH" || vendors["ubuntu"] != "MEDIUM" {
		t.Fatalf("severities = %#v", vendors)
	}
}
