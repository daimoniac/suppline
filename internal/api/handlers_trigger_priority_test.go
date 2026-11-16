package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/scanenqueue"
)

// A digest triggered through the API must be dequeued ahead of regular
// discovery scans that were already waiting in the queue.
func TestHandleTriggerScan_DigestJumpsDiscoveryBacklog(t *testing.T) {
	cfg := &config.APIConfig{Enabled: true, Port: 8080}
	taskQueue := queue.NewInMemoryQueue(100)
	enqueuer := scanenqueue.New(taskQueue, nil)
	server := NewAPIServerWithEnqueuer(cfg, mockAttestationConfig(), &mockStateStore{}, taskQueue, enqueuer, mockRegsyncConfig(), observability.NewLogger("error"))

	backlog := scanenqueue.Image{Repository: "example/backlog", Digest: "sha256:backlog", Tag: "v1"}
	if _, err := enqueuer.EnqueueDiscovery(t.Context(), backlog, scanenqueue.DiscoveryScan); err != nil {
		t.Fatalf("EnqueueDiscovery() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/trigger", strings.NewReader(`{"digest":"sha256:abc123"}`))
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	first, err := taskQueue.Dequeue(t.Context())
	if err != nil {
		t.Fatalf("Dequeue() error = %v", err)
	}
	if first.Digest != "sha256:abc123" {
		t.Errorf("first dequeued digest = %q, want the triggered digest sha256:abc123", first.Digest)
	}
	if first.Priority != queue.PriorityHigh {
		t.Errorf("triggered task priority = %d, want PriorityHigh", first.Priority)
	}
}
