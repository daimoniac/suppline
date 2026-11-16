package main

import (
	"testing"
	"time"
)

// hetzner-1, 2026-11-16: cortex memcached pods moved to a new digest at 09:53,
// but the agent kept reporting the old digests until it restarted at 10:21,
// because stale entries were only evicted on the 24h refresh.
func TestEvictStaleDropsGoneImagesWithinTTL(t *testing.T) {
	const ttl = time.Hour
	buffer := newInventoryBuffer()
	old := clusterImageInput{Namespace: "monitoring", ImageRef: "docker.io/hostingmaloonde/memcached", Tag: "1.6.45", Digest: "sha256:old"}
	current := clusterImageInput{Namespace: "monitoring", ImageRef: "docker.io/hostingmaloonde/memcached", Tag: "1.6.45", Digest: "sha256:new"}

	// The old digest was last seen 61 minutes ago, before its pods were replaced.
	buffer.Observe(old)
	setLastSeen(buffer, old, time.Now().UTC().Add(-61*time.Minute))

	// A full listing 20 minutes ago touched only the image that is still running.
	refreshedAt := time.Now().UTC().Add(-20 * time.Minute)
	buffer.TouchAll([]clusterImageInput{current})
	setLastSeen(buffer, current, refreshedAt)
	buffer.MarkRefreshed(refreshedAt)

	if !buffer.EvictStale(ttl, time.Now().UTC()) {
		t.Fatal("EvictStale reported no change")
	}
	snapshot := buffer.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Digest != "sha256:new" {
		t.Fatalf("snapshot = %+v, want only the running digest", snapshot)
	}
}

// Without a listing younger than the TTL, a long-running pod that produced no
// watch events looks the same as a deleted one, so nothing may be evicted.
func TestEvictStaleKeepsEntriesWithoutRecentRefresh(t *testing.T) {
	const ttl = time.Hour
	buffer := newInventoryBuffer()
	img := clusterImageInput{Namespace: "default", ImageRef: "nginx", Tag: "1.27", Digest: "sha256:a"}
	buffer.Observe(img)
	setLastSeen(buffer, img, time.Now().UTC().Add(-3*time.Hour))

	if buffer.EvictStale(ttl, time.Now().UTC()) {
		t.Fatal("evicted without any refresh")
	}
	buffer.MarkRefreshed(time.Now().UTC().Add(-2 * time.Hour))
	if buffer.EvictStale(ttl, time.Now().UTC()) {
		t.Fatal("evicted although the last refresh is older than the TTL")
	}
	if len(buffer.Snapshot()) != 1 {
		t.Fatal("entry was dropped")
	}
}

func TestEffectiveRefreshInterval(t *testing.T) {
	cases := []struct {
		refresh, ttl, want time.Duration
	}{
		{24 * time.Hour, time.Hour, 30 * time.Minute},
		{10 * time.Minute, time.Hour, 10 * time.Minute},
		{24 * time.Hour, 24 * time.Hour, 12 * time.Hour},
		{time.Hour, time.Minute, time.Minute},
	}
	for _, tc := range cases {
		if got := effectiveRefreshInterval(tc.refresh, tc.ttl, nil); got != tc.want {
			t.Errorf("effectiveRefreshInterval(%v, %v) = %v, want %v", tc.refresh, tc.ttl, got, tc.want)
		}
	}
}

func setLastSeen(b *inventoryBuffer, img clusterImageInput, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.seen[imageKey(img)]
	entry.lastSeen = at
	b.seen[imageKey(img)] = entry
}
