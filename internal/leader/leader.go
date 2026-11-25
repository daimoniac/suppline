// Package leader elects one active suppline per database (ADR 0004).
//
// Every instance runs an Elector. The one that takes the lock advertises
// its address and starts the leader-only components; the others retry. A
// leader that can no longer prove it holds the lock exits the process
// instead of stepping down: it may hold half-started components, queued
// tasks and waiters, and a restart drops all of that at once.
package leader

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Locker is the election lock. statestore.LeaderLock implements it.
type Locker interface {
	// TryAcquire takes the lock without waiting.
	TryAcquire(ctx context.Context) (bool, error)
	// Check fails unless this instance still holds the lock.
	Check(ctx context.Context) error
	// Advertise records this instance as the leader, reachable at address.
	Advertise(ctx context.Context, holder, address string) error
	// Release gives up the lock.
	Release(ctx context.Context) error
}

// Defaults from ADR 0004: with PostgreSQL dropping a dead client's session
// after about 25 s, a standby takes over about 30 s after a crash.
const (
	DefaultRetryInterval = 5 * time.Second
	DefaultCheckInterval = 5 * time.Second
	DefaultCheckTimeout  = 3 * time.Second
)

// Config configures an Elector.
type Config struct {
	Lock Locker
	// Holder identifies this instance in the leader row and in logs.
	Holder string
	// Address is where standbys reach this instance's API.
	Address string
	// OnElected starts the leader-only components. It runs once, must not
	// block, and gets a context that ends when the Elector stops.
	OnElected func(ctx context.Context)
	// OnLost runs right before Exit after the lock is lost.
	OnLost func(err error)

	RetryInterval time.Duration
	CheckInterval time.Duration
	CheckTimeout  time.Duration
	Logger        *slog.Logger
	// Exit ends the process after the lock is lost. Default os.Exit.
	Exit func(code int)
}

// Elector runs the election for one instance.
type Elector struct {
	cfg     Config
	elected chan struct{}
}

// New validates cfg and fills in defaults.
func New(cfg Config) (*Elector, error) {
	if cfg.Lock == nil {
		return nil, errors.New("leader: Lock is required")
	}
	if cfg.OnElected == nil {
		return nil, errors.New("leader: OnElected is required")
	}
	if cfg.Holder == "" {
		cfg.Holder = NewHolderID()
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = DefaultRetryInterval
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = DefaultCheckTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Exit == nil {
		cfg.Exit = os.Exit
	}
	return &Elector{cfg: cfg, elected: make(chan struct{})}, nil
}

// Holder returns this instance's identity.
func (e *Elector) Holder() string { return e.cfg.Holder }

// Elected is closed once this instance leads.
func (e *Elector) Elected() <-chan struct{} { return e.elected }

// Run campaigns until this instance leads, then guards the lock until ctx
// ends. It returns ctx's error. It does not release the lock: the caller
// stops the leader-only components first, then calls Release.
func (e *Elector) Run(ctx context.Context) error {
	log := e.cfg.Logger.With("holder", e.cfg.Holder)
	log.Info("standing by for leadership", "address", e.cfg.Address)
	if err := e.campaign(ctx, log); err != nil {
		return err
	}

	log.Info("elected leader", "address", e.cfg.Address)
	close(e.elected)
	e.cfg.OnElected(ctx)

	ticker := time.NewTicker(e.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		checkCtx, cancel := context.WithTimeout(ctx, e.cfg.CheckTimeout)
		err := e.cfg.Lock.Check(checkCtx)
		cancel()
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Error("lost leadership; exiting so a standby can take over", "error", err)
		if e.cfg.OnLost != nil {
			e.cfg.OnLost(err)
		}
		e.cfg.Exit(1)
		return fmt.Errorf("leadership lost: %w", err)
	}
}

func (e *Elector) campaign(ctx context.Context, log *slog.Logger) error {
	for {
		won, err := e.try(ctx)
		if err != nil {
			log.Warn("leader election attempt failed", "error", err)
		}
		if won {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.cfg.RetryInterval):
		}
	}
}

// try takes the lock and advertises. Without the advertisement standbys
// cannot reach this instance, so a failed one gives the lock back.
func (e *Elector) try(ctx context.Context) (bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, e.cfg.CheckTimeout)
	defer cancel()
	won, err := e.cfg.Lock.TryAcquire(attemptCtx)
	if err != nil || !won {
		return false, err
	}
	if err := e.cfg.Lock.Advertise(attemptCtx, e.cfg.Holder, e.cfg.Address); err != nil {
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), e.cfg.CheckTimeout)
		defer cancelRelease()
		_ = e.cfg.Lock.Release(releaseCtx)
		return false, err
	}
	return true, nil
}

// Release gives up the lock. Call it after the leader-only components have
// stopped.
func (e *Elector) Release(ctx context.Context) error {
	return e.cfg.Lock.Release(ctx)
}

// NewHolderID returns the hostname plus a random suffix, so two processes on
// one host, or a restarted pod, never share an identity.
func NewHolderID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "suppline"
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return host + "-" + hex.EncodeToString(b)
}
