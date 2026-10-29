package mirror

import (
	"context"
	"sync"
)

// gate limits how many sync copies run at once.
// Higher priority (missing copies) is released before lower priority, FIFO within a level.
type gate struct {
	max     int
	mu      sync.Mutex
	active  int
	waiting []waiter
}

type waiter struct {
	priority int
	ready    chan struct{}
}

func newGate(max int) *gate {
	if max < 1 {
		max = 1
	}
	return &gate{max: max}
}

// Acquire blocks until a slot is free. The returned function releases it and is idempotent.
func (g *gate) Acquire(ctx context.Context, priority int) (func(), error) {
	g.mu.Lock()
	if g.active < g.max && len(g.waiting) == 0 {
		g.active++
		g.mu.Unlock()
		return g.releaser(), nil
	}
	w := waiter{priority: priority, ready: make(chan struct{})}
	g.waiting = insertWaiter(g.waiting, w)
	g.grantLocked()
	g.mu.Unlock()

	select {
	case <-ctx.Done():
		g.mu.Lock()
		waiting := waiterPending(g.waiting, w.ready)
		if waiting {
			g.waiting = removeWaiter(g.waiting, w.ready)
		}
		g.mu.Unlock()
		if !waiting {
			g.releaser()()
		}
		return nil, ctx.Err()
	case <-w.ready:
		return g.releaser(), nil
	}
}

func (g *gate) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.active > 0 {
				g.active--
			}
			g.grantLocked()
		})
	}
}

func (g *gate) grantLocked() {
	for g.active < g.max && len(g.waiting) > 0 {
		w := g.waiting[0]
		g.waiting = g.waiting[1:]
		g.active++
		close(w.ready)
	}
}

func insertWaiter(queue []waiter, w waiter) []waiter {
	for i, cur := range queue {
		if w.priority > cur.priority {
			queue = append(queue, waiter{})
			copy(queue[i+1:], queue[i:])
			queue[i] = w
			return queue
		}
	}
	return append(queue, w)
}

func waiterPending(queue []waiter, ready chan struct{}) bool {
	for _, cur := range queue {
		if cur.ready == ready {
			return true
		}
	}
	return false
}

func removeWaiter(queue []waiter, ready chan struct{}) []waiter {
	for i, cur := range queue {
		if cur.ready == ready {
			return append(queue[:i], queue[i+1:]...)
		}
	}
	return queue
}
