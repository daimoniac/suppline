package attestation

import "sync"

// keyedLock serializes work per key. The zero value is ready to use, and a key's
// entry is dropped when nobody holds or waits for it.
//
// Attestations of one image are written one at a time. A registry without the OCI
// referrers API keeps an image's referrers in a single fallback tag that is read,
// changed and written back, so two writers at once lose each other's entries.
type keyedLock struct {
	mu      sync.Mutex
	entries map[string]*keyedLockEntry
}

type keyedLockEntry struct {
	mu   sync.Mutex
	refs int
}

// lock blocks until the key is free and returns the function that releases it.
func (k *keyedLock) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.entries == nil {
		k.entries = make(map[string]*keyedLockEntry)
	}
	entry := k.entries[key]
	if entry == nil {
		entry = &keyedLockEntry{}
		k.entries[key] = entry
	}
	entry.refs++
	k.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		k.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(k.entries, key)
		}
		k.mu.Unlock()
	}
}

// size is the number of keys held or awaited. Tests use it.
func (k *keyedLock) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}
