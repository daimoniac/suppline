package statestore

import (
	"testing"
	"time"
)

func TestInstancesListsLiveInstancesAndMarksTheLeader(t *testing.T) {
	url := testDatabaseURL(t)
	a := openStore(t, url)
	b := openStore(t, url)
	ctx := t.Context()

	lock := a.LeaderLock()
	t.Cleanup(func() { _ = lock.Release(ctx) })
	if got, err := lock.TryAcquire(ctx); err != nil || !got {
		t.Fatalf("TryAcquire = %v, %v", got, err)
	}
	if err := lock.Advertise(ctx, "holder-a", "http://10.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}

	started := time.Unix(1_800_000_000, 0)
	for _, in := range []Instance{
		{Holder: "holder-a", Hostname: "pod-a", Address: "http://10.0.0.1:8080", Version: "v1", StartedAt: started, Status: "healthy"},
		{Holder: "holder-b", Hostname: "pod-b", Address: "http://10.0.0.2:8080", Version: "v1", StartedAt: started, Status: "unhealthy"},
	} {
		if err := b.Heartbeat(ctx, in); err != nil {
			t.Fatalf("Heartbeat %s: %v", in.Holder, err)
		}
	}
	// A row nobody refreshed for a while belongs to a dead instance.
	if _, err := b.db.ExecContext(ctx, `
		INSERT INTO instances (holder, hostname, address, version, started_at, seen_at)
		VALUES ('ghost', 'pod-gone', 'http://10.0.0.9:8080', 'v0', 0, 0)`); err != nil {
		t.Fatal(err)
	}

	got, err := b.ListInstances(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListInstances = %+v, want pod-a and pod-b", got)
	}
	byHost := map[string]Instance{}
	for _, in := range got {
		byHost[in.Hostname] = in
	}
	if !byHost["pod-a"].Leader || byHost["pod-b"].Leader {
		t.Fatalf("leader flags a=%v b=%v, want only pod-a", byHost["pod-a"].Leader, byHost["pod-b"].Leader)
	}
	if byHost["pod-a"].Status != "healthy" || byHost["pod-b"].Status != "unhealthy" {
		t.Fatalf("statuses a=%q b=%q", byHost["pod-a"].Status, byHost["pod-b"].Status)
	}
	if !byHost["pod-b"].StartedAt.Equal(started) || byHost["pod-b"].SeenAt.IsZero() {
		t.Fatalf("pod-b = %+v", byHost["pod-b"])
	}

	if err := b.RemoveInstance(ctx, "holder-b"); err != nil {
		t.Fatal(err)
	}
	// Once the leader's session ends its row is no longer the leader.
	if err := lock.Release(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = b.ListInstances(ctx, 30*time.Second)
	if err != nil || len(got) != 1 || got[0].Hostname != "pod-a" || got[0].Leader {
		t.Fatalf("after removing pod-b and releasing the lock: %+v, %v", got, err)
	}
}
