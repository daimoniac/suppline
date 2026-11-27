package attestation

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKeyedLockSerializesOneKey(t *testing.T) {
	var locks keyedLock
	var inside, overlaps int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := locks.lock("sha256:aaa")
			if atomic.AddInt32(&inside, 1) > 1 {
				atomic.AddInt32(&overlaps, 1)
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&inside, -1)
			unlock()
		}()
	}
	wg.Wait()
	if overlaps != 0 {
		t.Errorf("%d holders overlapped on one key", overlaps)
	}
	if n := locks.size(); n != 0 {
		t.Errorf("%d entries left after every holder finished", n)
	}
}

func TestKeyedLockLetsKeysRunTogether(t *testing.T) {
	var locks keyedLock
	unlockA := locks.lock("a")
	defer unlockA()

	got := make(chan struct{})
	go func() {
		unlockB := locks.lock("b")
		unlockB()
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a held key blocked a different key")
	}
}
