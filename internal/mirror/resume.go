package mirror

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
)

// startupDecision says whether a sync entry's startup pass over missing tags
// runs, and when an interval entry's first scheduled copy is due.
type startupDecision struct {
	run bool
	// firstCopyIn delays an interval entry's first copy; zero keeps the
	// usual "one interval from now".
	firstCopyIn time.Duration
	reason      string
}

// decideStartup continues the schedule the previous process (or leader)
// left in mirror_syncs instead of starting it over (ADR 0004). Every
// failover would otherwise cost a full pass over every upstream registry.
// An entry runs at once when it never synced, its last sync failed, its key
// is new (the config changed), or its next run is already due.
func decideStartup(entry config.SyncEntry, last *statestore.MirrorSync, now time.Time) startupDecision {
	if last == nil || last.FinishedAt == nil {
		return startupDecision{run: true, reason: "never synced"}
	}
	if last.Status != "ok" {
		return startupDecision{run: true, reason: "last sync " + last.Status}
	}
	finished := time.Unix(*last.FinishedAt, 0)
	if entry.Schedule != "" {
		schedule, err := cron.ParseStandard(entry.Schedule)
		if err != nil {
			return startupDecision{run: true, reason: "unparsable schedule"}
		}
		if !schedule.Next(finished).After(now) {
			return startupDecision{run: true, reason: "schedule fired since the last sync"}
		}
		return startupDecision{reason: "synced since the schedule last fired"}
	}
	interval := time.Duration(entry.Interval)
	if interval <= 0 {
		return startupDecision{run: true}
	}
	since := now.Sub(finished)
	if since >= interval || since < 0 {
		return startupDecision{run: true, reason: "interval elapsed"}
	}
	return startupDecision{firstCopyIn: interval - since, reason: "synced within the interval"}
}

// startupPlan reads the stored sync rows. A nil plan runs every entry.
func (m *runner) startupPlan(ctx context.Context) map[string]*statestore.MirrorSync {
	if m.store == nil {
		return nil
	}
	rows, err := m.store.ListMirrorSyncs(ctx)
	if err != nil {
		m.log.Warn("cannot read stored mirror syncs; running the startup pass for every entry", "error", err.Error())
		return nil
	}
	plan := make(map[string]*statestore.MirrorSync, len(rows))
	for i := range rows {
		row := rows[i].MirrorSync
		plan[row.Key] = &row
	}
	return plan
}

// resumedEvery fires first at first, then every interval: an @every schedule
// that continues where the previous process left off.
type resumedEvery struct {
	first time.Time
	every time.Duration
}

func (s resumedEvery) Next(t time.Time) time.Time {
	if t.Before(s.first) {
		return s.first
	}
	return t.Add(s.every - time.Duration(t.Nanosecond()))
}
