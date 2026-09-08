// Package scanenqueue translates scan intent into queued scan tasks.
package scanenqueue

import (
	"context"
	"fmt"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/queue"
)

// Enqueuer constructs and submits scan tasks.
type Enqueuer struct {
	taskQueue queue.TaskQueue
	catalog   catalog.Catalog
	now       func() time.Time
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
	return NewWithCatalog(taskQueue, catalog.NewConfigCatalog(regsyncConfig))
}

// NewWithCatalog creates an Enqueuer using the repository-policy catalog.
func NewWithCatalog(taskQueue queue.TaskQueue, policyCatalog catalog.Catalog) *Enqueuer {
	return &Enqueuer{
		taskQueue: taskQueue,
		catalog:   policyCatalog,
		now:       time.Now,
	}
}

// EnqueueDiscovery submits a scan requested by registry discovery.
func (e *Enqueuer) EnqueueDiscovery(ctx context.Context, image Image, kind DiscoveryKind) (*queue.ScanTask, error) {
	isRescan := kind == DiscoveryRescan
	isFirstScan := kind == DiscoveryFirstScan
	priority := queue.PriorityNormal
	if isRescan || isFirstScan {
		priority = queue.PriorityHigh
	}
	return e.enqueue(ctx, image, isRescan, isFirstScan, priority)
}

// EnqueueRescan submits an explicit rescan request at regular priority, so it
// stays behind urgent rescans and the discovery stream.
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

	var evidence catalog.Evidence
	if e.catalog != nil {
		evidence = e.catalog.ResolveEvidence(image.Repository)
	}

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
		VEXStatements: evidence.VEXStatements,
		UseVEXRepo:    evidence.UseVEXRepo,
	}

	if err := e.taskQueue.Enqueue(ctx, task); err != nil {
		return nil, err
	}
	return task, nil
}
