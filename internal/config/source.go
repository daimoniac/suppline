package config

// Source returns the running configuration snapshot. Call it once per decision
// instead of holding the result: a config reload or edit publishes a new
// snapshot and never changes one already returned.
type Source func() *RegsyncConfig

// Static returns a Source that always yields cfg. Use it where nothing
// reloads the configuration, such as tests and one-shot tools.
func Static(cfg *RegsyncConfig) Source {
	return func() *RegsyncConfig { return cfg }
}
