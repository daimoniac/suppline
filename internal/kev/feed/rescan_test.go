package feed

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeFinder struct {
	mu     sync.Mutex
	images []Image
	err    error
	asked  [][]string
}

func (f *fakeFinder) ImagesWithCVEs(_ context.Context, ids []string) ([]Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, append([]string(nil), ids...))
	return f.images, f.err
}

func (f *fakeFinder) peekAsked() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.asked...)
}

type fakeQueue struct {
	mu     sync.Mutex
	queued []Image
}

func (q *fakeQueue) RescanKEV(_ context.Context, image Image) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queued = append(q.queued, image)
	return nil
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queued)
}

type countingCounter struct{ n int }

func (c *countingCounter) Inc() { c.n++ }

func TestSyncReportsAddedCVEsButNotTheFirstLoad(t *testing.T) {
	body := `{"vulnerabilities":[{"cveID":"CVE-2024-1234"}]}`
	server := feedServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	service := NewService(Config{FeedURL: server.URL}, nil, nil, nil)
	var got [][]string
	service.OnAdded(func(_ context.Context, added []string) { got = append(got, added) })

	service.Sync(context.Background())
	if len(got) != 0 {
		t.Fatalf("the first load is not an addition, got %v", got)
	}
	service.Sync(context.Background())
	if len(got) != 0 {
		t.Fatalf("an unchanged catalog adds nothing, got %v", got)
	}
	body = `{"vulnerabilities":[{"cveID":"CVE-2024-1234"},{"cveID":"cve-2026-0002"},{"cveID":"CVE-2026-0001"}]}`
	service.Sync(context.Background())
	if want := [][]string{{"CVE-2026-0001", "CVE-2026-0002"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("added = %v, want %v", got, want)
	}
}

func TestRescannerQueuesOncePerDigestWhenPolicyReadsKEV(t *testing.T) {
	finder := &fakeFinder{images: []Image{
		{Repository: "reg/app", Digest: "sha256:a", Tag: "1.0"},
		{Repository: "reg/app", Digest: "sha256:a", Tag: "latest"}, // same digest, second tag
		{Repository: "reg/app", Digest: "sha256:b", Tag: "2.0"},
		{Repository: "reg/other", Digest: "sha256:c", Tag: "1"},
	}}
	queue := &fakeQueue{}
	counter := &countingCounter{}
	usesKEV := func(repository string) bool { return repository == "reg/app" }
	rescanner := NewRescanner(finder, queue, usesKEV, counter, nil)

	if err := rescanner.Process(context.Background(), []string{"CVE-2026-0001"}); err != nil {
		t.Fatal(err)
	}
	want := []Image{{Repository: "reg/app", Digest: "sha256:a", Tag: "1.0"}, {Repository: "reg/app", Digest: "sha256:b", Tag: "2.0"}}
	if !reflect.DeepEqual(queue.queued, want) || counter.n != 2 {
		t.Fatalf("queued = %v (count %d), want %v", queue.queued, counter.n, want)
	}
}

func TestRescannerRunCoalescesAndRetriesAfterError(t *testing.T) {
	finder := &fakeFinder{err: errors.New("db down")}
	queue := &fakeQueue{}
	rescanner := NewRescanner(finder, queue, func(string) bool { return true }, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rescanner.Run(ctx)

	rescanner.Notify(ctx, []string{"CVE-2026-0002", "CVE-2026-0001"})
	waitFor(t, func() bool { return len(rescanner.peek()) == 2 && len(finder.peekAsked()) == 1 })

	finder.mu.Lock()
	finder.err = nil
	finder.images = []Image{{Repository: "reg/app", Digest: "sha256:a", Tag: "1"}}
	finder.mu.Unlock()
	rescanner.Notify(ctx, []string{"CVE-2026-0003"})
	waitFor(t, func() bool { return queue.count() == 1 })
	asked := finder.peekAsked()
	if last := asked[len(asked)-1]; !reflect.DeepEqual(last, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}) {
		t.Fatalf("the retry must include the CVEs from the failed run, asked %v", last)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *Rescanner) peek() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.pending))
	for id := range r.pending {
		ids = append(ids, id)
	}
	return ids
}
