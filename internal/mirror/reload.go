package mirror

import (
	"reflect"

	"github.com/daimoniac/suppline/internal/config"
)

// mirrorSettingsChanged reports whether next copies differently from prev.
// Fields only suppline's scanning reads (vex, policy, rescan and worker
// settings, triage) are ignored.
func mirrorSettingsChanged(prev, next *config.RegsyncConfig) bool {
	if prev == nil || next == nil {
		return prev != next
	}
	return !reflect.DeepEqual(mirrorView(prev), mirrorView(next))
}

type mirrorSettings struct {
	creds    []config.RegistryCredential
	defaults config.Defaults
	sync     []config.SyncEntry
}

func mirrorView(cfg *config.RegsyncConfig) mirrorSettings {
	view := mirrorSettings{creds: cfg.Creds, defaults: cfg.Defaults}
	d := &view.defaults
	d.RescanInterval = ""
	d.WorkerPollInterval = ""
	d.WorkerConcurrency = 0
	d.WorkerRetryAttempts = 0
	d.WorkerRetryBackoff = ""
	d.QueueBufferSize = 0
	d.SCAIValidityExtension = ""
	d.CreateVulnerabilityAttestation = nil
	d.CreateSBOMAttestation = nil
	d.Policy = nil
	d.VEXRepo = nil
	d.VEX = nil
	// In-place entries are never copied, so adding or editing one does not
	// restart the mirror.
	entries := cfg.MirrorEntries()
	view.sync = make([]config.SyncEntry, len(entries))
	for i, entry := range entries {
		entry.VEX = nil
		entry.VEXAuto = nil
		entry.RescanInterval = ""
		entry.SCAIValidityExtension = ""
		entry.Policy = nil
		entry.VEXRepo = nil
		entry.Ignore = false
		entry.CreateVulnerabilityAttestation = nil
		entry.CreateSBOMAttestation = nil
		view.sync[i] = entry
	}
	return view
}
