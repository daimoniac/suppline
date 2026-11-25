package worker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	suppErrors "github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/queue"
)

func finishWithLog(t *testing.T, err error) (string, float64, error) {
	t.Helper()
	var buf bytes.Buffer
	w := NewImageWorker(newMockQueue(1), nil, nil, nil, nil, nil, DefaultConfig(), slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	observer := &recordingTaskObserver{finished: make(chan error, 1)}
	w.SetTaskObserver(observer)
	before := testutil.ToFloat64(observability.GetMetrics().WorkerErrors)
	w.finishTask(context.Background(), 1, &queue.ScanTask{ID: "t", Repository: "r", Digest: "sha256:d"}, err)
	return buf.String(), testutil.ToFloat64(observability.GetMetrics().WorkerErrors) - before, <-observer.finished
}

// A digest that lost all its tags, or a manifest deleted upstream, is
// cleaned up by the pipeline. That is an expected outcome, not a failure.
func TestFinishTask_ImageGoneIsNotAnError(t *testing.T) {
	gone := suppErrors.NewManifestNotFoundf("no live tags for digest sha256:d in repository r")
	logs, errs, observed := finishWithLog(t, gone)
	if strings.Contains(logs, `"level":"ERROR"`) {
		t.Fatalf("logged an error for a vanished image:\n%s", logs)
	}
	if !strings.Contains(logs, "image is gone from the registry") {
		t.Fatalf("no info line for the dropped task:\n%s", logs)
	}
	if errs != 0 {
		t.Fatalf("WorkerErrors grew by %v, want 0", errs)
	}
	if observed == nil {
		t.Fatal("observer got nil; a scan request waiting on this digest must learn it is gone")
	}
}

func TestFinishTask_FailureIsAnError(t *testing.T) {
	logs, errs, _ := finishWithLog(t, suppErrors.NewPermanentf("scanner exploded"))
	if !strings.Contains(logs, `"level":"ERROR"`) || errs != 1 {
		t.Fatalf("errors=%v logs:\n%s", errs, logs)
	}
}
