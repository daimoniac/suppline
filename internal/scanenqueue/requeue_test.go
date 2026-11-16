package scanenqueue

import (
	"context"
	"sort"
	"testing"

	"github.com/daimoniac/suppline/internal/statestore"
)

func newRequeueStore(t *testing.T) *statestore.SQLiteStore {
	t.Helper()
	store, err := statestore.NewSQLiteStore(t.TempDir() + "/requeue.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, scan := range []struct{ repo, digest, tag string }{
		{"team/app", "sha256:a", "v1"},
		{"team/app", "sha256:a", "v2"}, // second tag, same digest
		{"team/app", "sha256:b", "v3"},
		{"team/app-old", "sha256:c", "v1"}, // name contains team/app
		{"other/x", "sha256:d", "v1"},
	} {
		if err := store.RecordScan(context.Background(), &statestore.ScanRecord{
			Repository: scan.repo, Digest: scan.digest, Tag: scan.tag,
			PolicyPassed: true, PolicyStatus: "passed",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func submittedImages(q *capturingQueue) []string {
	out := make([]string, 0, len(q.submitted))
	for _, task := range q.submitted {
		out = append(out, task.Repository+"@"+task.Digest)
	}
	sort.Strings(out)
	return out
}

func TestRequeue(t *testing.T) {
	tests := []struct {
		name     string
		pageSize int
		run      func(*Enqueuer) (int, error)
		want     []string
	}{
		{
			name: "one repository, exact name, once per digest",
			run: func(e *Enqueuer) (int, error) {
				return e.RequeueRepositories(context.Background(), []string{"team/app"})
			},
			want: []string{"team/app@sha256:a", "team/app@sha256:b"},
		},
		{
			name: "repository name matches ignoring case",
			run: func(e *Enqueuer) (int, error) {
				return e.RequeueRepositories(context.Background(), []string{"Team/App-Old"})
			},
			want: []string{"team/app-old@sha256:c"},
		},
		{
			name: "several repositories and an empty name",
			run: func(e *Enqueuer) (int, error) {
				return e.RequeueRepositories(context.Background(), []string{"other/x", "", "team/app-old"})
			},
			want: []string{"other/x@sha256:d", "team/app-old@sha256:c"},
		},
		{
			name: "unknown repository queues nothing",
			run: func(e *Enqueuer) (int, error) {
				return e.RequeueRepositories(context.Background(), []string{"nope/none"})
			},
			want: []string{},
		},
		{
			name:     "all repositories across pages",
			pageSize: 2,
			run: func(e *Enqueuer) (int, error) {
				return e.RequeueAll(context.Background())
			},
			want: []string{"other/x@sha256:d", "team/app-old@sha256:c", "team/app@sha256:a", "team/app@sha256:b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taskQueue := &capturingQueue{}
			enqueuer := New(taskQueue, newRequeueStore(t))
			enqueuer.pageSize = tt.pageSize

			n, err := tt.run(enqueuer)
			if err != nil {
				t.Fatalf("requeue error = %v", err)
			}
			got := submittedImages(taskQueue)
			if n != len(tt.want) || len(got) != len(tt.want) {
				t.Fatalf("queued %d %v, want %v", n, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("queued %v, want %v", got, tt.want)
				}
			}
			for _, task := range taskQueue.submitted {
				if !task.IsRescan {
					t.Errorf("task %s@%s IsRescan = false, want true", task.Repository, task.Digest)
				}
			}
		})
	}
}

func TestRequeueWithoutStore(t *testing.T) {
	enqueuer := New(&capturingQueue{}, nil)
	if _, err := enqueuer.RequeueRepositories(context.Background(), []string{"team/app"}); err == nil {
		t.Fatal("RequeueRepositories() without a store returned nil error")
	}
}
