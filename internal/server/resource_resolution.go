// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// ResolveResourceOperation never writes resource limits or takes ownership of a
// freeze. It reads the original terminal result, or durably consumes an expired
// unstarted command's revision under the same physical lock as its dispatch.
// An unavailable, open or mismatched outcome remains unknown to the caller.
func (h *sandboxService) ResolveResourceOperation(ctx context.Context, req *runtime.ResolveResourceOperationRequest) (*runtime.ResizeResourcesResponse, error) {
	if req == nil || req.Original == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "original resource request is required")
	}
	kind := resourceOperationGrow
	if req.Shrink {
		kind = resourceOperationShrink
	}
	r := req.Original
	m, err := normalizeResourceMutation(kind, r.SandboxID, r.ResourceGeneration, r.Expected, r.Target, r.DeadlineUnixMs, r.OperationID, r.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resource recovery is incomplete")
	}
	release, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resource service is shutting down")
	}
	defer release()
	unlock, err := h.resourceLocks.acquire(ctx, m.SandboxID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	defer unlock()
	state, outcome, err := h.resolveResourceOperation(m)
	if err != nil {
		return nil, err
	}
	if outcome != nil {
		return h.replayResourceOperation(m, state, outcome)
	}
	// There is no previous accepted intent. Expiry alone is not proof for the
	// scheduler: persist a closed revision before returning unchanged limits.
	if time.Now().UnixMilli() < m.DeadlineUnixMs {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "unstarted resource command has not expired")
	}
	before, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return nil, err
	}
	if !before.ResourceRevisionKnown || before.ResourceRevision != m.ExpectedRevision ||
		before.ResourceOperationPending || before.ResourceGeneration != m.ResourceGeneration ||
		!h.resourceOperationSucceeded(before, m.Expected, true) {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "original unfrozen source limits and revision are not proven")
	}
	// events.frozen=false alone cannot exclude an outstanding foreign request.
	freeze, err := h.readShrinkFreezeState(m.SandboxID)
	if err != nil {
		return nil, err
	}
	if !freeze.RequestKnown || freeze.RequestFrozen || !freeze.EventsKnown || freeze.Frozen {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "original source has unknown or foreign freeze state")
	}
	if err := ctx.Err(); err != nil {
		return nil, errord.ToGRPC(err)
	}
	if err := h.openResourceOperationIntent(state, m, false, before); err != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "persist expired resource fence: %v", err)
	}
	// A crash or failed close leaves a durable, non-freezing intent. The
	// ordinary identity-checked recovery loop closes it from actual readback.
	if err := h.closeResourceOperation(state, resourceOutcomePartial, "expired command fenced without physical writes", snapshotResourceReadback(before)); err != nil {
		h.scheduleResourceStateHeal()
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "persist resource fence completion: %v", err)
	}
	actual, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return nil, err
	}
	return h.resourceOperationResponse(state, m, actual)
}
