package config

import "testing"

func TestNormalizeBasePath(t *testing.T) {
	valid := map[string]string{
		"":              "",
		"/":             "",
		"  ":            "",
		"/suppline":     "/suppline",
		"/suppline/":    "/suppline",
		" /tools/sup/ ": "/tools/sup",
		"/a-b_c.d/v1":   "/a-b_c.d/v1",
	}
	for in, want := range valid {
		got, err := NormalizeBasePath(in)
		if err != nil {
			t.Errorf("NormalizeBasePath(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"suppline", "/sup?x=1", "/sup#a", "/a//b", "/a/../b", "/./a", "/a b", "/a\"b"} {
		if got, err := NormalizeBasePath(in); err == nil {
			t.Errorf("NormalizeBasePath(%q) = %q, want error", in, got)
		}
	}
}
