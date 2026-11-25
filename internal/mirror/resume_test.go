package mirror

import (
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
)

func TestDecideStartup(t *testing.T) {
	// cron schedules run in local time, like the mirror's cron.
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.Local)
	at := func(d time.Duration) *int64 { v := now.Add(-d).Unix(); return &v }
	hourly := config.SyncEntry{Interval: config.Duration(time.Hour)}
	// Every day at 04:00.
	nightly := config.SyncEntry{Schedule: "0 4 * * *"}

	cases := []struct {
		name      string
		entry     config.SyncEntry
		last      *statestore.MirrorSync
		run       bool
		firstCopy time.Duration
	}{
		{"never synced", hourly, nil, true, 0},
		{"row without finish", hourly, &statestore.MirrorSync{Status: "never"}, true, 0},
		{"last sync failed", hourly, &statestore.MirrorSync{Status: "failed", FinishedAt: at(time.Minute)}, true, 0},
		{"fresh success", hourly, &statestore.MirrorSync{Status: "ok", FinishedAt: at(20 * time.Minute)}, false, 40 * time.Minute},
		{"stale success", hourly, &statestore.MirrorSync{Status: "ok", FinishedAt: at(61 * time.Minute)}, true, 0},
		{"finish in the future", hourly, &statestore.MirrorSync{Status: "ok", FinishedAt: at(-time.Minute)}, true, 0},
		{"cron synced after last fire", nightly, &statestore.MirrorSync{Status: "ok", FinishedAt: at(7 * time.Hour)}, false, 0},
		{"cron fired since last sync", nightly, &statestore.MirrorSync{Status: "ok", FinishedAt: at(9 * time.Hour)}, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideStartup(tc.entry, tc.last, now)
			if got.run != tc.run || got.firstCopyIn != tc.firstCopy {
				t.Fatalf("decideStartup = {run:%v firstCopyIn:%v reason:%q}, want run=%v firstCopyIn=%v",
					got.run, got.firstCopyIn, got.reason, tc.run, tc.firstCopy)
			}
		})
	}
}

func TestResumedEverySchedule(t *testing.T) {
	start := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	s := resumedEvery{first: start.Add(40 * time.Minute), every: time.Hour}
	first := s.Next(start)
	if !first.Equal(start.Add(40 * time.Minute)) {
		t.Fatalf("first run at %v, want 12:40", first)
	}
	if second := s.Next(first); !second.Equal(first.Add(time.Hour)) {
		t.Fatalf("second run at %v, want 13:40", second)
	}
}
