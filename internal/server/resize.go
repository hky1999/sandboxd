// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

const resourceGenerationLabel = config.ResourceGenerationLabel

// limitsMatch requires proven observations: an unknown memory limit is a
// legacy fallback number that must not pass as the enforced hard limit.
func limitsMatch(stats *runtime.StatsResponse, limits *runtime.ResourceLimits) bool {
	return stats.CpuLimitsKnown && stats.MemoryLimitKnown && stats.CpuQuotaUsec == limits.CpuQuotaUsec &&
		stats.CpuPeriodUsec == limits.CpuPeriodUsec && stats.MemoryLimitBytes == limits.MemoryLimitBytes
}

// executeResourceGrow applies a scheduler-approved monotonic increase. Global
// admission remains the scheduler's responsibility; this endpoint owns
// identity, revisions, ceilings and truthful readback, including partial
// writes. It never lowers a live limit.
func (h *sandboxService) executeResourceGrow(ctx context.Context, m *resourceMutationRequest) (*runtime.ResizeResourcesResponse, error) {
	// Resolve identity, revision and replay before observing limits: a
	// recorded outcome is served regardless of what the physical limits are
	// now, because it is the journal's answer, not a fresh decision.
	state, outcome, err := h.resolveResourceOperation(m)
	if err != nil {
		return nil, err
	}
	if outcome != nil {
		return h.replayResourceOperation(m, state, outcome)
	}
	current, err := h.sandboxManager.Get(m.SandboxID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if err := h.elasticTargetWithinPolicy(current.Metadata.Labels, m.Target); err != nil {
		return nil, err
	}
	before, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return nil, err
	}
	if !before.CpuLimitsKnown || before.CpuQuotaUsec <= 0 || before.CpuPeriodUsec == 0 {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective CPU limits are unknown or unlimited")
	}
	if !before.MemoryLimitKnown {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective memory limit is unknown")
	}
	if m.Target.CpuPeriodUsec != before.CpuPeriodUsec || m.Target.CpuQuotaUsec < before.CpuQuotaUsec || m.Target.MemoryLimitBytes < before.MemoryLimitBytes {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resize cannot lower limits or change CPU period")
	}
	// A fresh operation must compare strictly against the live limits: only
	// the replay of an already-completed identical operation is exempt from
	// the expected-revision compare, and that path returned above.
	if !limitsMatch(before, m.Expected) {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective limits changed; refresh Stats and admission")
	}
	if before.FrozenKnown && before.Frozen {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox is frozen; reconcile the resource operation first")
	}
	facts, err := h.physicalResources(current.Metadata)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	// On the cgroup v2 backend, grow additionally refuses any outstanding
	// freeze request — even one the events file has not confirmed yet — and a
	// failed freeze read is fail-closed there: the backend that owns the
	// freezer must be able to prove the sandbox is not frozen before a write.
	// Backends without the freezer (cgroup v1) keep their existing behavior
	// and skip the check.
	cgroup := facts.Resources[config.ResourceNameCgroup]
	if h.cgroupMgr.SupportsMemoryShrink() {
		freezeState, freezeErr := h.cgroupMgr.ReadFreeze(cgroup)
		if freezeErr != nil {
			return nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
				"read freeze state for sandbox %s on the cgroup v2 backend failed; refusing the write: %v", m.SandboxID, freezeErr)
		}
		if !freezeState.RequestKnown || freezeState.RequestFrozen || !freezeState.EventsKnown || freezeState.Frozen {
			return nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
				"sandbox %s has a pending freeze request or is frozen; grow refuses to take it over (request known=%t frozen=%t, events known=%t frozen=%t)",
				m.SandboxID, freezeState.RequestKnown, freezeState.RequestFrozen, freezeState.EventsKnown, freezeState.Frozen)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errord.ToGRPC(err)
	}
	if time.Now().UnixMilli() >= m.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	// Persist the next revision and the full command before any write; a
	// partial or unknown outcome keeps the advanced revision.
	if err := h.openResourceOperationIntent(state, m, false, before); err != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "persist resource operation intent: %v", err)
	}
	// resourceStats already validated the managed cgroup and manager.
	updateErr := h.cgroupMgr.Prepare(facts.Resources[config.ResourceNameCgroup], &runtime.LinuxSandboxResources{
		CpuQuota: m.Target.CpuQuotaUsec, CpuPeriod: m.Target.CpuPeriodUsec,
		MemoryLimitInBytes: int64(m.Target.MemoryLimitBytes),
	})
	after, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		// An RPC error after a write is explicitly an uncertain outcome. The
		// scheduler must retain its reservation and reconcile via Stats; the
		// journal stays open at the advanced revision until then.
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resize readback failed after possible write: %v (update: %v)", readErr, updateErr)
	}
	if err := h.closeGrowOperation(state, m, updateErr, after); err != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "record resource operation outcome: %v", err)
	}
	// The response must describe the durably closed operation, so the
	// observation is retaken after the journal close under the same lock; a
	// failure to retake it is an uncertain answer, never a stale pending one.
	final, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable,
			"operation %s outcome is recorded but the final readback failed: %v", m.OperationID, readErr)
	}
	return h.resourceOperationResponse(state, m, final)
}

// closeGrowOperation durably closes the grow operation. A failed, unproven or
// frozen outcome is recorded as partial with the advanced revision; a
// persistence failure leaves the record open for reconciliation. Complete
// demands the same full readback contract as shrink: limits, the enforced
// page-aligned memory.high, and a proven unfrozen sandbox.
func (h *sandboxService) closeGrowOperation(state *resourceOperationState, m *resourceMutationRequest, updateErr error, after *runtime.StatsResponse) error {
	complete := updateErr == nil && h.resourceOperationSucceeded(after, m.Target, true)
	message := ""
	if updateErr != nil {
		message = updateErr.Error()
	} else if !complete {
		switch {
		case !after.CpuLimitsKnown || !after.MemoryLimitKnown || !after.MemoryHighKnown:
			message = "effective limits or high unknown after possible write"
		case !after.FrozenKnown:
			message = "frozen state unknown after possible write"
		case after.Frozen:
			message = "sandbox is frozen after possible write"
		default:
			message = "effective limits did not match target"
		}
	}
	outcome := resourceOutcomePartial
	if complete {
		outcome = resourceOutcomeComplete
	}
	return h.closeResourceOperation(state, outcome, message, snapshotResourceReadback(after))
}

// replayResourceOperation serves the recorded outcome of an already-executed
// operation without re-executing it. A recorded complete is only repeated
// when the CURRENT physical readback still verifies the target limits, the
// enforced high and an unfrozen sandbox at the same revision: any later
// external perturbation downgrades the replay to a conservative non-complete
// answer instead of repeating a success the cgroup no longer proves.
func (h *sandboxService) replayResourceOperation(m *resourceMutationRequest, state *resourceOperationState, outcome *resourceRecordedOutcome) (*runtime.ResizeResourcesResponse, error) {
	actual, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "operation %s replay readback failed: %v", m.OperationID, err)
	}
	response := &runtime.ResizeResourcesResponse{Actual: actual, Complete: outcome.Complete}
	if outcome.Complete && !h.resourceOperationSucceeded(actual, m.Target, true) {
		response.Complete = false
		response.UpdateError = fmt.Sprintf(
			"operation %s completed earlier but the current physical readback no longer verifies the recorded target", m.OperationID)
	} else if outcome.Message != "" {
		response.UpdateError = outcome.Message
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": m.SandboxID, "operation_id": m.OperationID,
		"kind": m.Kind, "complete": response.Complete,
	}).Info("scheduler resource operation replayed")
	return response, nil
}

// resourceOperationResponse builds the terminal response after a durable
// outcome was recorded: the observation is taken after the journal close and
// carries the closed record's revision, operation identity and pending=false.
func (h *sandboxService) resourceOperationResponse(state *resourceOperationState, m *resourceMutationRequest, after *runtime.StatsResponse) (*runtime.ResizeResourcesResponse, error) {
	response := &runtime.ResizeResourcesResponse{
		Actual:   after,
		Complete: state.LastOutcome == resourceOutcomeComplete,
	}
	if !response.Complete && state.LastOutcomeMessage != "" {
		response.UpdateError = state.LastOutcomeMessage
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": m.SandboxID, "resource_generation": m.ResourceGeneration,
		"operation_id": m.OperationID, "kind": m.Kind,
		"revision": state.Revision, "memory_limit_bytes": after.MemoryLimitBytes,
		"memory_high_bytes": after.MemoryHighBytes, "complete": response.Complete,
		"update_error": response.UpdateError,
	}).Info("scheduler resource operation")
	return response, nil
}

// ResizeResources executes a node-budgeted memory/CPU increase under the
// revision contract: operation ID, expected revision fingerprint, durable
// intent before the write, and truthful partial outcomes.
func (h *sandboxService) ResizeResources(ctx context.Context, req *runtime.ResizeResourcesRequest) (*runtime.ResizeResourcesResponse, error) {
	if req == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resize request is required")
	}
	m, err := normalizeResourceMutation(resourceOperationGrow,
		req.SandboxID, req.ResourceGeneration, req.Expected, req.Target,
		req.DeadlineUnixMs, req.OperationID, req.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if time.Now().UnixMilli() >= req.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	// Preserve expiry through service/lock queues, independently of the gRPC
	// deadline which a delayed intermediary could otherwise start afresh.
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(req.DeadlineUnixMs))
	defer cancel()
	return h.runResourceOperation(ctx, m)
}

// ShrinkResources executes a node-budgeted memory decrease with an unchanged
// CPU allocation. It is a separate RPC and a separate fingerprint kind: the
// request never travels through the grow-only semantics.
func (h *sandboxService) ShrinkResources(ctx context.Context, req *runtime.ShrinkResourcesRequest) (*runtime.ResizeResourcesResponse, error) {
	if req == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "shrink request is required")
	}
	m, err := normalizeResourceMutation(resourceOperationShrink,
		req.SandboxID, req.ResourceGeneration, req.Expected, req.Target,
		req.DeadlineUnixMs, req.OperationID, req.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	if time.Now().UnixMilli() >= req.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(req.DeadlineUnixMs))
	defer cancel()
	return h.runResourceOperation(ctx, m)
}

// runResourceOperation holds the shared admission and the per-sandbox
// physical resource lock for one resource command.
func (h *sandboxService) runResourceOperation(ctx context.Context, m *resourceMutationRequest) (*runtime.ResizeResourcesResponse, error) {
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
	if m.Kind == resourceOperationGrow {
		return h.executeResourceGrow(ctx, m)
	}
	return h.executeResourceShrink(ctx, m)
}
