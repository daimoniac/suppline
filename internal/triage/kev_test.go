package triage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

func TestKEVFallsBackWhenPrimaryIsForbidden(t *testing.T) {
	var userAgents []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgents = append(userAgents, r.Header.Get("User-Agent"))
		if r.URL.Path == "/primary" {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-1234"}]}`))
	}))
	defer server.Close()

	cache := &KEVCache{
		URL:         server.URL + "/primary",
		FallbackURL: server.URL + "/fallback",
		TTL:         time.Hour,
		Client:      server.Client(),
	}
	hit, err := cache.Contains(context.Background(), "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("expected CVE from the fallback feed")
	}
	miss, err := cache.Contains(context.Background(), "CVE-2024-9999")
	if err != nil || miss {
		t.Fatalf("miss=%v err=%v", miss, err)
	}
	if len(userAgents) != 2 || userAgents[0] == "" || userAgents[1] == "" {
		t.Fatalf("user agents = %v", userAgents)
	}
}

func TestShouldSkipRetriesKEVFeedFailure(t *testing.T) {
	last := &statestore.TriageRun{
		Status:       StatusRejected,
		Reasoning:    "CISA KEV feed unavailable: CISA KEV feed status 403",
		RepoSHAsJSON: "same",
		CVEHash:      "same",
		CreatedAt:    time.Now(),
	}
	if ShouldSkip(last, false, "same", "same", time.Hour, time.Now()) {
		t.Fatal("a KEV feed failure should be retried")
	}
}
