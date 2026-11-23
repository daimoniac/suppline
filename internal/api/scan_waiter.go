package api

import (
	"context"
	"sync"

	"github.com/daimoniac/suppline/internal/queue"
)

// ScanRequestWaiter lets scan-request handlers wait for the next finished task
// of a repository digest. The worker reports every finished task to it.
type ScanRequestWaiter struct {
	mu sync.Mutex
	// next holds the signal the next finished task of a key closes.
	next map[string]*scanFinish
	// requested marks keys a scan request queued that have not finished yet.
	requested map[string]bool
	// failed keeps the error of a requested task that finished without a
	// scan record, so a later poll can report it.
	failed    map[string]error
	closed    chan struct{}
	closeOnce sync.Once
}

// scanFinish is closed when a task of its key finishes. err is the task's
// error, or nil when it succeeded.
type scanFinish struct {
	done chan struct{}
	err  error
}

// NewScanRequestWaiter creates an empty waiter.
func NewScanRequestWaiter() *ScanRequestWaiter {
	return &ScanRequestWaiter{
		next:      map[string]*scanFinish{},
		requested: map[string]bool{},
		failed:    map[string]error{},
		closed:    make(chan struct{}),
	}
}

func waitKey(repository, digest string) string {
	return repository + "\n" + digest
}

// watch returns the signal of the next task of repository@digest to finish.
func (w *ScanRequestWaiter) watch(repository, digest string) *scanFinish {
	key := waitKey(repository, digest)
	w.mu.Lock()
	defer w.mu.Unlock()
	finish, ok := w.next[key]
	if !ok {
		finish = &scanFinish{done: make(chan struct{})}
		w.next[key] = finish
	}
	return finish
}

// request records that a scan request queued repository@digest.
func (w *ScanRequestWaiter) request(repository, digest string) {
	key := waitKey(repository, digest)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.requested[key] = true
	delete(w.failed, key)
}

// outstanding reports whether a requested scan of repository@digest has not
// finished yet, and the error of the last requested one that failed.
func (w *ScanRequestWaiter) outstanding(repository, digest string) (bool, error) {
	key := waitKey(repository, digest)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.requested[key], w.failed[key]
}

// Finished implements worker.TaskObserver.
func (w *ScanRequestWaiter) Finished(_ context.Context, task *queue.ScanTask, err error) {
	if w == nil || task == nil {
		return
	}
	key := waitKey(task.Repository, task.Digest)
	w.mu.Lock()
	finish := w.next[key]
	delete(w.next, key)
	if w.requested[key] {
		delete(w.requested, key)
		if err != nil {
			w.failed[key] = err
		}
	}
	if err == nil {
		delete(w.failed, key)
	}
	w.mu.Unlock()
	if finish != nil {
		finish.err = err
		close(finish.done)
	}
}

// Close releases every waiting request; they answer "still queued".
func (w *ScanRequestWaiter) Close() {
	w.closeOnce.Do(func() { close(w.closed) })
}
