// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// GenerationCgroupCloseRequest describes one irreversible close of an original
// lease. ExpectedRevision is this close journal's revision, not the sandbox's
// resource revision. A new close compares against zero and advances to one.
type GenerationCgroupCloseRequest struct {
	Path             string    `json:"path"`
	Generation       string    `json:"generation"`
	OperationID      string    `json:"operation_id"`
	ExpectedRevision uint64    `json:"expected_revision"`
	Deadline         time.Time `json:"deadline"`
}

type generationCgroupClosure struct {
	Request       GenerationCgroupCloseRequest   `json:"request"`
	Revision      uint64                         `json:"revision"`
	Identity      CgroupIdentity                 `json:"identity"`
	Parent        CgroupIdentity                 `json:"parent"`
	Scope         generationLeaseScope           `json:"scope"`
	Closed        bool                           `json:"closed"`
	Continuations []GenerationCgroupCloseRequest `json:"continuations,omitempty"`
}

// GenerationLeaseSnapshot copies the original persisted binding and close
// request. It never adopts the current directory or transfers kernel authority.
type GenerationLeaseSnapshot struct {
	Identity      CgroupIdentity
	CloseRequest  *GenerationCgroupCloseRequest
	Closed        bool
	Continuations []GenerationCgroupCloseRequest
}

func (c *CgroupManager) InspectGenerationLease(path, generation string) (GenerationLeaseSnapshot, error) {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if !validLeaseGeneration(generation) || !belongsToRoot(path, c.rootName) || !c.usingID.Has(path) || c.leaseOwners[path] != generation {
		return GenerationLeaseSnapshot{}, fmt.Errorf("original generation lease ownership unavailable: %w", errord.ErrFailedPrecondition)
	}
	identity, known := c.leaseIdentities[path]
	scope, scoped := c.leaseScopes[path]
	current, err := c.generationScope()
	if !known || !scoped || identity.Path != path || identity.Device == 0 || identity.Inode == 0 || !scope.valid() || err != nil || current != scope {
		return GenerationLeaseSnapshot{}, fmt.Errorf("original generation lease binding or scope unavailable: %w", errord.ErrFailedPrecondition)
	}
	snapshot := GenerationLeaseSnapshot{Identity: identity}
	if record, closing := c.leaseClosures[path]; closing {
		request := record.Request
		if request.Path != path || request.Generation != generation || record.Identity != identity || record.Scope != scope {
			return GenerationLeaseSnapshot{}, fmt.Errorf("original close request differs from its lease: %w", errord.ErrFailedPrecondition)
		}
		snapshot.CloseRequest = &request
		snapshot.Closed = record.Closed
		snapshot.Continuations = append([]GenerationCgroupCloseRequest(nil), record.Continuations...)
	}
	return snapshot, nil
}

// ClosedGenerationCgroup holds the original kernel objects for native runtime
// verification. Directory is nil after restart recovery by original-parent
// absence; that proof needs a matching native parent-verification protocol.
// Neither proof is a full sandbox retirement or authority to release node budget.
type ClosedGenerationCgroup struct {
	Directory      *os.File
	Parent         *os.File
	Identity       CgroupIdentity
	ParentIdentity CgroupIdentity
}

func (p *ClosedGenerationCgroup) Close() error {
	var errs []error
	if p.Directory != nil {
		errs = append(errs, p.Directory.Close())
		p.Directory = nil
	}
	if p.Parent != nil {
		errs = append(errs, p.Parent.Close())
		p.Parent = nil
	}
	return errors.Join(errs...)
}

// generationDirectory uses pinned original objects for every physical effect.
// openGenerationDirectory is an optional backend capability: no path fallback.
type generationDirectory interface {
	parentIdentity() CgroupIdentity
	verify() error
	absent() (bool, error)
	drain(context.Context) error
	remove() error
	proof() (*ClosedGenerationCgroup, error)
	close() error
}

type generationDirectoryBackend interface {
	openGenerationDirectory(CgroupIdentity, generationLeaseScope, *CgroupIdentity, bool) (generationDirectory, error)
}

func sameCloseRequest(a, b GenerationCgroupCloseRequest) bool {
	return a.Path == b.Path && a.Generation == b.Generation && a.OperationID == b.OperationID &&
		a.ExpectedRevision == b.ExpectedRevision && a.Deadline.Equal(b.Deadline)
}

const generationCloseContinuationLimit = 128

// ValidateGenerationCloseContinuations checks immutable original ownership and
// a bounded, unique, revision-ordered continuation history. It grants no physical
// authority: the lease, original directory and observation scope are still checked.
func ValidateGenerationCloseContinuations(original GenerationCgroupCloseRequest, continuations []GenerationCgroupCloseRequest) error {
	if len(continuations) > generationCloseContinuationLimit {
		return fmt.Errorf("original cgroup close continuation history is full")
	}
	seen := map[string]bool{original.OperationID: true}
	deadline := original.Deadline
	for i, request := range continuations {
		if request.Path != original.Path || request.Generation != original.Generation ||
			!validLeaseGeneration(request.OperationID) || seen[request.OperationID] ||
			request.ExpectedRevision != uint64(i+1) || !request.Deadline.After(deadline) {
			return fmt.Errorf("original cgroup close continuation identity, revision or deadline differs")
		}
		seen[request.OperationID] = true
		deadline = request.Deadline
	}
	return nil
}

// CloseForGeneration permanently drains and removes one generation's cgroup.
// It persists the complete intent before any effect and the closed result before
// returning proof. The lease remains occupied until the caller has separately
// cleaned the native runtime and other resources and calls RecycleForGeneration.
func (c *CgroupManager) CloseForGeneration(ctx context.Context, request GenerationCgroupCloseRequest) (*ClosedGenerationCgroup, error) {
	return c.closeForGeneration(ctx, request, nil)
}

// ContinueCloseForGeneration authorizes another bounded attempt after the
// previous deadline. The original request never changes. A new operation and
// revision are saved before effects; exact retry resolves that same attempt.
func (c *CgroupManager) ContinueCloseForGeneration(ctx context.Context, original, continuation GenerationCgroupCloseRequest) (*ClosedGenerationCgroup, error) {
	return c.closeForGeneration(ctx, original, &continuation)
}

func (c *CgroupManager) closeForGeneration(ctx context.Context, request GenerationCgroupCloseRequest, continuation *GenerationCgroupCloseRequest) (*ClosedGenerationCgroup, error) {
	if ctx == nil || !belongsToRoot(request.Path, c.rootName) || !validLeaseGeneration(request.Generation) ||
		!validLeaseGeneration(request.OperationID) || request.ExpectedRevision != 0 || request.Deadline.IsZero() {
		return nil, fmt.Errorf("invalid original cgroup close request: %w", errord.ErrInvalidArgument)
	}
	if continuation != nil && continuation.ExpectedRevision == 0 {
		return nil, fmt.Errorf("close continuation must carry its own revision: %w", errord.ErrInvalidArgument)
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if !c.usingID.Has(request.Path) || c.leaseOwners[request.Path] != request.Generation || c.db == nil {
		return nil, fmt.Errorf("original cgroup close ownership or store unavailable: %w", errord.ErrFailedPrecondition)
	}
	identity, known := c.leaseIdentities[request.Path]
	scope, scoped := c.leaseScopes[request.Path]
	current, err := c.generationScope()
	if !known || !scoped || !scope.valid() || err != nil || current != scope {
		return nil, fmt.Errorf("original cgroup close identity or observation scope unavailable: %w", errord.ErrFailedPrecondition)
	}
	backend, ok := c.ops.(generationDirectoryBackend)
	if !ok {
		return nil, fmt.Errorf("original-directory cgroup close unsupported: %w", errord.ErrFailedPrecondition)
	}
	original, pending := c.leaseClosures[request.Path]
	if pending && (!sameCloseRequest(request, original.Request) || original.Identity != identity || original.Scope != scope) {
		return nil, fmt.Errorf("original cgroup close request differs from its persisted intent: %w", errord.ErrFailedPrecondition)
	}
	var parent *CgroupIdentity
	if pending {
		parent = &original.Parent
	} else if continuation == nil {
		if err := closeContextError(ctx, request.Deadline); err != nil {
			return nil, err
		}
	}
	active := request
	if len(original.Continuations) != 0 {
		active = original.Continuations[len(original.Continuations)-1]
	}
	appendContinuation := false
	if continuation != nil && !sameCloseRequest(*continuation, active) {
		if original.Closed || time.Now().Before(active.Deadline) ||
			continuation.ExpectedRevision != uint64(1+len(original.Continuations)) {
			return nil, fmt.Errorf("original close continuation requires the expired current revision: %w", errord.ErrFailedPrecondition)
		}
		proposed := append(append([]GenerationCgroupCloseRequest(nil), original.Continuations...), *continuation)
		if err := ValidateGenerationCloseContinuations(request, proposed); err != nil {
			return nil, err
		}
		if err := closeContextError(ctx, continuation.Deadline); err != nil {
			return nil, err
		}
		appendContinuation = true
	} else if continuation == nil && len(original.Continuations) != 0 && !original.Closed {
		return nil, fmt.Errorf("original close has a separately authorized continuation: %w", errord.ErrFailedPrecondition)
	}
	if continuation != nil && !appendContinuation && !pending {
		return nil, fmt.Errorf("original close continuation cannot borrow an unprepared lease: %w", errord.ErrFailedPrecondition)
	}
	if continuation != nil {
		active = *continuation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := backend.openGenerationDirectory(identity, scope, parent, pending)
	if err != nil {
		return nil, err
	}
	defer directory.close()
	if !pending {
		original = generationCgroupClosure{Request: request, Revision: 1, Identity: identity, Parent: directory.parentIdentity(), Scope: scope}
		if c.leaseClosures == nil {
			c.leaseClosures = make(map[string]generationCgroupClosure)
		}
		c.leaseClosures[request.Path] = original
	}
	if appendContinuation {
		original.Continuations = append(append([]GenerationCgroupCloseRequest(nil), original.Continuations...), *continuation)
		original.Revision = uint64(1 + len(original.Continuations))
		c.leaseClosures[request.Path] = original
	}
	// Also rewrite an in-memory intent after an uncertain StoreRaw. There are
	// no effects until this particular write reports success.
	if err := c.storeLeaseState("", ""); err != nil {
		return nil, err
	}
	absent, err := directory.absent()
	if err != nil {
		return nil, err
	}
	if original.Closed && !absent {
		return nil, fmt.Errorf("completed original cgroup close is not physically absent: %w", errord.ErrFailedPrecondition)
	}
	if !absent {
		if err := closeContextError(ctx, active.Deadline); err != nil {
			return nil, err
		}
		bounded, cancel := context.WithDeadline(ctx, active.Deadline)
		defer cancel()
		if err := directory.verify(); err != nil {
			return nil, err
		}
		if err := directory.drain(bounded); err != nil {
			return nil, err
		}
		if err := closeContextError(bounded, active.Deadline); err != nil {
			return nil, err
		}
		if err := directory.remove(); err != nil {
			return nil, err
		}
		absent, err = directory.absent()
		if err != nil || !absent {
			return nil, errors.Join(errors.New("original cgroup removal is not confirmed"), err)
		}
	}
	original.Closed = true
	// Publish only the proposed completion. A failed store keeps the local
	// intent unknown even if the group really disappeared; retry is read-only.
	before := c.leaseClosures[request.Path]
	c.leaseClosures[request.Path] = original
	if err := c.storeLeaseState("", ""); err != nil {
		c.leaseClosures[request.Path] = before
		return nil, err
	}
	return directory.proof()
}

func closeContextError(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *CgroupManager) restoreGenerationClosures(records map[string]generationCgroupClosure) error {
	for path, record := range records {
		request := record.Request
		if request.Path != path || request.Generation != c.leaseOwners[path] ||
			!validLeaseGeneration(request.OperationID) || request.ExpectedRevision != 0 || request.Deadline.IsZero() ||
			record.Revision != uint64(1+len(record.Continuations)) || record.Identity != c.leaseIdentities[path] || record.Scope != c.leaseScopes[path] ||
			!record.Scope.valid() || record.Parent.Path != filepath.Dir(path) || record.Parent.Device == 0 || record.Parent.Inode == 0 {
			return fmt.Errorf("original cgroup close journal is inconsistent: %w", errord.ErrFailedPrecondition)
		}
		if err := ValidateGenerationCloseContinuations(request, record.Continuations); err != nil {
			return err
		}
	}
	c.leaseClosures = records
	return nil
}

// The caller's resource teardown has already completed. Closing the group
// never admitted it to the idle cache and never released this lease itself.
func (c *CgroupManager) recycleClosedGeneration(path, generation string) error {
	original := c.leaseClosures[path]
	if !original.Closed || original.Request.Generation != generation {
		return fmt.Errorf("original cgroup close is still unconfirmed: %w", errord.ErrFailedPrecondition)
	}
	scope, err := c.generationScope()
	if err != nil || scope != original.Scope {
		return fmt.Errorf("closed cgroup original scope changed: %w", errord.ErrFailedPrecondition)
	}
	backend, ok := c.ops.(generationDirectoryBackend)
	if !ok {
		return fmt.Errorf("closed cgroup original backend unavailable: %w", errord.ErrFailedPrecondition)
	}
	directory, err := backend.openGenerationDirectory(original.Identity, original.Scope, &original.Parent, true)
	if err != nil {
		return err
	}
	defer directory.close()
	absent, err := directory.absent()
	if err != nil || !absent {
		return errors.Join(errors.New("closed original cgroup absence cannot authorize release"), err)
	}
	if err := c.completeLeaseRelease(path, generation); err != nil {
		return err
	}
	// Remove only bookkeeping and original inotify subscriptions. There is no
	// path-based kill/reset/delete and no cached re-use of a killed group.
	c.cgroups.Pop(path)
	c.oom.Remove(path)
	c.mu.Lock()
	c.total--
	c.mu.Unlock()
	return nil
}
