// Package scanenqueue translates scan intent into queued scan tasks.
package scanenqueue

import (
	"context"
	"fmt"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/queue"
	"github.com/daimoniac/suppline/internal/types"
)

// Enqueuer constructs and submits scan tasks.
type Enqueuer struct {
	taskQueue     queue.TaskQueue
	regsyncConfig *config.RegsyncConfig
	now           func() time.Time
}

// Image identifies the image to scan.
type Image struct {
	Repository string
	Digest     string
	Tag        string
}

// DiscoveryKind describes why discovery requested a scan.
type DiscoveryKind uint8

const (
	// DiscoveryScan is a normal scan for a changed image or a conservative
	// scan requested after discovery could not read scan state.
	DiscoveryScan DiscoveryKind = iota
	// DiscoveryFirstScan is the first known scan of an image.
	DiscoveryFirstScan
	// DiscoveryRescan is an interval-driven scan of an existing image.
	DiscoveryRescan
)

// New creates an Enqueuer backed by taskQueue.
func New(taskQueue queue.TaskQueue, regsyncConfig *config.RegsyncConfig) *Enqueuer {
	return &Enqueuer{
		taskQueue:     taskQueue,
		regsyncConfig: regsyncConfig,
		now:           time.Now,
	}
}

// EnqueueDiscovery submits a scan requested by registry discovery.
func (e *Enqueuer) EnqueueDiscovery(ctx context.Context, image Image, kind DiscoveryKind) (*queue.ScanTask, error) {
	isRescan := kind == DiscoveryRescan
	isFirstScan := kind == DiscoveryFirstScan
	return e.enqueue(ctx, image, isRescan, isFirstScan, queue.PriorityNormal)
}

// EnqueueRescan submits an explicit rescan request.
func (e *Enqueuer) EnqueueRescan(ctx context.Context, image Image) (*queue.ScanTask, error) {
	return e.enqueue(ctx, image, true, false, queue.PriorityNormal)
}

// EnqueueUrgentRescan submits a rescan that must jump ahead of regular scans,
// such as the startup rescan of failed images that are running in a cluster.
func (e *Enqueuer) EnqueueUrgentRescan(ctx context.Context, image Image) (*queue.ScanTask, error) {
	return e.enqueue(ctx, image, true, false, queue.PriorityHigh)
}

func (e *Enqueuer) enqueue(ctx context.Context, image Image, isRescan, isFirstScan bool, priority queue.TaskPriority) (*queue.ScanTask, error) {
	idTime := e.now()
	enqueuedAt := e.now()

	task := &queue.ScanTask{
		ID:            fmt.Sprintf("%s-%d", image.Digest, idTime.Unix()),
		Repository:    image.Repository,
		Digest:        image.Digest,
		Tag:           image.Tag,
		EnqueuedAt:    enqueuedAt,
		Attempts:      0,
		IsRescan:      isRescan,
		IsFirstScan:   isFirstScan,
		Priority:      priority,
		VEXStatements: e.vexStatementsFor(image.Repository),
		UseVEXRepo:    e.useVEXRepoFor(image.Repository),
	}

	if err := e.taskQueue.Enqueue(ctx, task); err != nil {
		return nil, err
	}
	return task, nil
}

func (e *Enqueuer) vexStatementsFor(repository string) []types.VEXStatement {
	if e.regsyncConfig == nil {
		return nil
	}
	return e.regsyncConfig.GetVEXStatementsForTarget(repository)
}

func (e *Enqueuer) useVEXRepoFor(repository string) bool {
	if e.regsyncConfig == nil {
		return false
	}
	return e.regsyncConfig.GetVEXRepoForTarget(repository)
}
