package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	suppErrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/statestore"
)

type failingScans struct {
	statestore.StateStoreQuery
	err error
}

func (f failingScans) ListScansWithTotal(context.Context, statestore.ScanFilter) ([]*statestore.ScanRecord, int, error) {
	return nil, 0, f.err
}

// During a PostgreSQL switchover a request fails on a dropped connection.
// 503 with Retry-After tells clients to try again; 500 says something is broken.
func TestStoreErrorsDuringOutageAnswer503(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantRetry  bool
	}{
		{"connection lost", suppErrors.NewTransientf("query: FATAL: terminating connection due to administrator command (SQLSTATE 57P01)"), http.StatusServiceUnavailable, true},
		{"real failure", errors.New("column does not exist"), http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := tasksTestServer(t, failingScans{err: tc.err}, nil)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Retry-After") != ""; got != tc.wantRetry {
				t.Fatalf("Retry-After present = %v, want %v", got, tc.wantRetry)
			}
		})
	}
}
