package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCVETolerationUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantID    string
		wantStmt  string
		wantExp   *int64
		wantErr   bool
		errSubstr string
	}{
		{
			name: "with valid RFC3339 timestamp",
			yaml: `
id: CVE-2025-15467
statement: tolerating openssl issue until end of february
expires_at: 2026-02-28T23:59:59Z
`,
			wantID:   "CVE-2025-15467",
			wantStmt: "tolerating openssl issue until end of february",
			wantExp:  func() *int64 { t := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC).Unix(); return &t }(),
			wantErr:  false,
		},
		{
			name: "with date-only format",
			yaml: `
id: CVE-2025-99999
statement: date only format
expires_at: 2026-02-28
`,
			wantID:   "CVE-2025-99999",
			wantStmt: "date only format",
			wantExp:  func() *int64 { t := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC).Unix(); return &t }(),
			wantErr:  false,
		},
		{
			name: "without expires_at",
			yaml: `
id: CVE-2024-12345
statement: permanent toleration
`,
			wantID:   "CVE-2024-12345",
			wantStmt: "permanent toleration",
			wantExp:  nil,
			wantErr:  false,
		},
		{
			name: "with timezone offset",
			yaml: `
id: CVE-2024-99999
statement: testing timezone
expires_at: 2026-03-01T00:00:00-05:00
`,
			wantID:   "CVE-2024-99999",
			wantStmt: "testing timezone",
			wantExp:  func() *int64 { t := time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC).Unix(); return &t }(),
			wantErr:  false,
		},
		{
			name: "with invalid date - Feb 29 non-leap year",
			yaml: `
id: CVE-2024-00001
statement: bad date
expires_at: 2026-02-29
`,
			wantErr:   true,
			errSubstr: "invalid expires_at format",
		},
		{
			name: "with invalid timestamp format",
			yaml: `
id: CVE-2024-00002
statement: bad format
expires_at: Feb 28, 2026
`,
			wantErr:   true,
			errSubstr: "invalid expires_at format",
		},
		{
			name: "with empty expires_at",
			yaml: `
id: CVE-2024-00002
statement: empty expiry
expires_at: ""
`,
			wantID:   "CVE-2024-00002",
			wantStmt: "empty expiry",
			wantExp:  nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tol CVEToleration
			err := yaml.Unmarshal([]byte(tt.yaml), &tol)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errSubstr != "" && err != nil {
					if !contains(err.Error(), tt.errSubstr) {
						t.Errorf("error = %v, want error containing %q", err, tt.errSubstr)
					}
				}
				return
			}

			if tol.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", tol.ID, tt.wantID)
			}

			if tol.Statement != tt.wantStmt {
				t.Errorf("Statement = %q, want %q", tol.Statement, tt.wantStmt)
			}

			if (tol.ExpiresAt == nil) != (tt.wantExp == nil) {
				t.Errorf("ExpiresAt nil = %v, want nil = %v", tol.ExpiresAt == nil, tt.wantExp == nil)
				return
			}

			if tol.ExpiresAt != nil && tt.wantExp != nil {
				if *tol.ExpiresAt != *tt.wantExp {
					t.Errorf("ExpiresAt = %d (%s), want %d (%s)",
						*tol.ExpiresAt, time.Unix(*tol.ExpiresAt, 0).UTC(),
						*tt.wantExp, time.Unix(*tt.wantExp, 0).UTC())
				}
			}
		})
	}
}

func TestCVETolerationUnmarshalYAML_InArray(t *testing.T) {
	// Test parsing an array of tolerations like it appears in actual config
	yamlContent := `
- id: CVE-2025-15467
  statement: tolerating openssl issue until end of february
  expires_at: 2026-02-28T23:59:59Z
- id: CVE-2024-12345
  statement: permanent toleration
`

	var tolerations []CVEToleration
	err := yaml.Unmarshal([]byte(yamlContent), &tolerations)
	if err != nil {
		t.Fatalf("UnmarshalYAML() error = %v", err)
	}

	if len(tolerations) != 2 {
		t.Fatalf("got %d tolerations, want 2", len(tolerations))
	}

	// Check first toleration with expiry
	if tolerations[0].ID != "CVE-2025-15467" {
		t.Errorf("tolerations[0].ID = %q, want %q", tolerations[0].ID, "CVE-2025-15467")
	}
	if tolerations[0].ExpiresAt == nil {
		t.Error("tolerations[0].ExpiresAt is nil, want non-nil")
	} else {
		expectedTime := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC).Unix()
		if *tolerations[0].ExpiresAt != expectedTime {
			t.Errorf("tolerations[0].ExpiresAt = %d, want %d", *tolerations[0].ExpiresAt, expectedTime)
		}
	}

	// Check second toleration without expiry
	if tolerations[1].ID != "CVE-2024-12345" {
		t.Errorf("tolerations[1].ID = %q, want %q", tolerations[1].ID, "CVE-2024-12345")
	}
	if tolerations[1].ExpiresAt != nil {
		t.Errorf("tolerations[1].ExpiresAt = %v, want nil", tolerations[1].ExpiresAt)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestToleratedCVE_JSONSerialization(t *testing.T) {
	expiresAt := time.Date(2026, 3, 1, 23, 59, 59, 0, time.UTC).Unix()

	tolerated := ToleratedCVE{
		CVEID:       "CVE-2025-15467",
		Statement:   "tolerating openssl issue until end of february",
		ToleratedAt: time.Now().Unix(),
		ExpiresAt:   &expiresAt,
	}

	// Use encoding/json to test serialization
	data, err := json.Marshal(tolerated)
	if err != nil {
		t.Fatalf("Failed to marshal ToleratedCVE: %v", err)
	}

	jsonStr := string(data)

	// Verify all fields are present
	if !strings.Contains(jsonStr, "CVEID") {
		t.Error("JSON should contain CVEID field")
	}
	if !strings.Contains(jsonStr, "CVE-2025-15467") {
		t.Error("JSON should contain CVE ID value")
	}
	if !strings.Contains(jsonStr, "Statement") {
		t.Error("JSON should contain Statement field")
	}
	if !strings.Contains(jsonStr, "tolerating openssl issue") {
		t.Error("JSON should contain statement value")
	}
	if !strings.Contains(jsonStr, "ToleratedAt") {
		t.Error("JSON should contain ToleratedAt field")
	}
	if !strings.Contains(jsonStr, "ExpiresAt") {
		t.Error("JSON should contain ExpiresAt field")
	}

	// Verify ExpiresAt is not null
	if strings.Contains(jsonStr, `"ExpiresAt":null`) {
		t.Errorf("ExpiresAt should not be null in JSON, got: %s", jsonStr)
	}

	// Unmarshal and verify
	var decoded ToleratedCVE
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ToleratedCVE: %v", err)
	}

	if decoded.CVEID != "CVE-2025-15467" {
		t.Errorf("CVEID = %s, want CVE-2025-15467", decoded.CVEID)
	}
	if decoded.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil after unmarshal")
	} else if *decoded.ExpiresAt != expiresAt {
		t.Errorf("ExpiresAt = %d, want %d", *decoded.ExpiresAt, expiresAt)
	}
}

func TestToleratedCVE_JSONSerializationWithNilExpiry(t *testing.T) {
	tolerated := ToleratedCVE{
		CVEID:       "CVE-2024-99999",
		Statement:   "permanent toleration",
		ToleratedAt: time.Now().Unix(),
		ExpiresAt:   nil,
	}

	data, err := json.Marshal(tolerated)
	if err != nil {
		t.Fatalf("Failed to marshal ToleratedCVE: %v", err)
	}

	jsonStr := string(data)

	// Verify ExpiresAt is null when nil
	if !strings.Contains(jsonStr, `"ExpiresAt":null`) {
		t.Errorf("ExpiresAt should be null in JSON when nil, got: %s", jsonStr)
	}

	// Unmarshal and verify
	var decoded ToleratedCVE
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ToleratedCVE: %v", err)
	}

	if decoded.ExpiresAt != nil {
		t.Errorf("ExpiresAt should be nil after unmarshal, got %v", decoded.ExpiresAt)
	}
}
