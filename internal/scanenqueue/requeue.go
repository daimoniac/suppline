package scanenqueue

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/statestore"
)

// ScanLister reads the current scan of each repository tag.
type ScanLister interface {
	ListScans(ctx context.Context, filter statestore.ScanFilter) ([]*statestore.ScanRecord, error)
}

// requeuePageSize bounds one ListScans read while requeueing.
const requeuePageSize = 500

func (e *Enqueuer) requeuePage() int {
	if e.pageSize > 0 {
		return e.pageSize
	}
	return requeuePageSize
}

// RequeueRepositories submits a rescan for every current image of the named
// repositories, once per repository@digest. Names match exactly, ignoring case.
// It returns how many images were submitted. A listing failure stops the
// requeue; enqueue failures are skipped and returned joined with the count.
func (e *Enqueuer) RequeueRepositories(ctx context.Context, repositories []string) (int, error) {
	queued := 0
	seen := map[string]struct{}{}
	var errs []error
	for _, repository := range repositories {
		if repository == "" {
			continue
		}
		n, err := e.requeue(ctx, repository, seen)
		queued += n
		if err != nil {
			errs = append(errs, err)
			if isListError(err) {
				return queued, errors.Join(errs...)
			}
		}
	}
	return queued, errors.Join(errs...)
}

// RequeueAll submits a rescan for every current image of every repository.
func (e *Enqueuer) RequeueAll(ctx context.Context) (int, error) {
	return e.requeue(ctx, "", map[string]struct{}{})
}

type listError struct{ err error }

func (e listError) Error() string { return e.err.Error() }
func (e listError) Unwrap() error { return e.err }

func isListError(err error) bool {
	var le listError
	return errors.As(err, &le)
}

// requeue pages through the current scans matching repository ("" = all).
func (e *Enqueuer) requeue(ctx context.Context, repository string, seen map[string]struct{}) (int, error) {
	if e.scans == nil {
		return 0, listError{fmt.Errorf("requeue %q: no scan store configured", repository)}
	}
	queued := 0
	var errs []error
	page := e.requeuePage()
	for offset := 0; ; offset += page {
		scans, err := e.scans.ListScans(ctx, statestore.ScanFilter{
			Repository: repository,
			SortBy:     "repository_asc",
			Limit:      page,
			Offset:     offset,
		})
		if err != nil {
			errs = append(errs, listError{fmt.Errorf("requeue %q: list scans: %w", repository, err)})
			return queued, errors.Join(errs...)
		}
		for _, scan := range scans {
			// The store filter is a substring match; requeue only the named repository.
			if repository != "" && !strings.EqualFold(scan.Repository, repository) {
				continue
			}
			key := scan.Repository + "@" + scan.Digest
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if _, err := e.EnqueueRescan(ctx, Image{Repository: scan.Repository, Digest: scan.Digest, Tag: scan.Tag}); err != nil {
				errs = append(errs, fmt.Errorf("requeue %s: %w", key, err))
				continue
			}
			queued++
		}
		if len(scans) < page {
			return queued, errors.Join(errs...)
		}
	}
}
