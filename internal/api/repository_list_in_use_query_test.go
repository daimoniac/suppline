package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRepositoryListInUseQuery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		wantNil  bool
		wantTrue bool
	}{
		{name: "no_query", raw: "", wantNil: true},
		{name: "mode_all", raw: "?in_use_mode=all", wantNil: true},
		{name: "mode_in_use", raw: "?in_use_mode=in_use", wantTrue: true},
		{name: "mode_in_use_upper", raw: "?in_use_mode=IN_USE", wantTrue: true},
		{name: "mode_in_use_newer", raw: "?in_use_mode=in_use_newer", wantTrue: true},
		{name: "mode_in_use_newer_hyphen", raw: "?in_use_mode=in-use-newer", wantTrue: true},
		{name: "mode_not_in_use", raw: "?in_use_mode=not_in_use", wantTrue: false},
		{name: "mode_out", raw: "?in_use_mode=out", wantTrue: false},
		{name: "in_use_wins_false", raw: "?in_use=false&in_use_mode=in_use", wantTrue: false},
		{name: "in_use_wins_zero", raw: "?in_use=0&in_use_mode=in_use", wantTrue: false},
		{name: "in_use_wins_true", raw: "?in_use=true&in_use_mode=not_in_use", wantTrue: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/repositories"+tc.raw, nil)
			got := parseRepositoryListInUseQuery(req)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil")
			}
			if *got != tc.wantTrue {
				t.Fatalf("expected %v, got %v", tc.wantTrue, *got)
			}
		})
	}
}
