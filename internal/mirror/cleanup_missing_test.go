package mirror

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
)

// A target that was never copied to has no repository yet. registry:3 answers
// the tag listing of such a repository with 404 NAME_UNKNOWN. There is nothing
// to clean, and a first start must not report that as a failure.
func TestCleanupTags_TargetNotCreatedYet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	host := mustHost(t, ts.URL)
	rc := regclient.New(regclient.WithConfigHost(rcconfig.Host{Name: host, Hostname: host, TLS: rcconfig.TLSDisabled}))

	m := &runner{rc: rc, log: slog.Default()}
	if err := m.cleanupTags(context.Background(), host+"/never-copied:1.0"); err != nil {
		t.Fatalf("cleanupTags on a missing repository = %v, want nil", err)
	}
}
