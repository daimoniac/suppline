package vulnurl

import "testing"

func TestNormalizeRefURL_AVDLegacy(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{
			"https://avd.aquasec.com/nvd/cve-2025-68431",
			"https://avd.aquasec.com/nvd/2025/cve-2025-68431/",
		},
		{
			"https://avd.aquasec.com/nvd/cve-2025-68431/",
			"https://avd.aquasec.com/nvd/2025/cve-2025-68431/",
		},
		{
			"https://avd.aquasec.com/nvd/CVE-2025-68431",
			"https://avd.aquasec.com/nvd/2025/cve-2025-68431/",
		},
		{
			"https://avd.aquasec.com/nvd/2025/cve-2025-68431/",
			"https://avd.aquasec.com/nvd/2025/cve-2025-68431/",
		},
		{
			"https://nvd.nist.gov/vuln/detail/CVE-2025-68431",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-68431",
		},
		{"", ""},
	}
	for _, tt := range tests {
		got := NormalizeRefURL(tt.in)
		if got != tt.want {
			t.Errorf("NormalizeRefURL(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}
