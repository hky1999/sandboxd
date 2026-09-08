// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

// Bounded sub-deadlines of the shrink sequence. The freeze confirmation and
// the cleanup unfreeze are their own budgets, independent of the original
// RPC's cancellation. The command deadline and context govern admission, the
// pre-freeze steps, and are rechecked after the freeze is confirmed — both
// before the frozen readback and immediately before the first memory write;
// only the cleanup unfreeze itself is deliberately exempt so a cancelled or
// expired command never abandons a freeze it owns.
const (
	shrinkFreezeConfirmTimeout = 500 * time.Millisecond
	shrinkFreezePollInterval   = 10 * time.Millisecond
	shrinkCleanupTimeout       = 2 * time.Second
)

// executeResourceShrink lowers only the memory limits of one running
// incarnation. CPU numbers must equal the live limits exactly. The write
// window is guarded by the host cgroup freezer: the request bit is written
// only after the durable intent, and every exit path either confirms the
// sandbox is unfrozen or leaves an owned freeze intent behind for recovery —
// a failure is never reported as if nothing was written.
//
// Caller holds the incarnation's physical resource lock.
func (h *sandboxService) executeResourceShrink(ctx context.Context, m *resourceMutationRequest) (*runtime.ResizeResourcesResponse, error) {
	if err := h.shrinkPreconditions(m); err != nil {
		return nil, err
	}
	// Resolve identity, revision and replay before the observation checks: a
	// recorded outcome is served even when the physical limits already equal
	// the target, because the journal — not the current numbers — answers a
	// repeated operation ID.
	state, outcome, err := h.resolveResourceOperation(m)
	if err != nil {
		return nil, err
	}
	if outcome != nil {
		return h.replayResourceOperation(m, state, outcome)
	}
	before, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return nil, err
	}
	if err := h.validateShrinkObservation(m, before); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errord.ToGRPC(err)
	}
	if time.Now().UnixMilli() >= m.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	freeze, err := h.readShrinkFreezeState(m.SandboxID)
	if err != nil {
		return nil, err
	}
	// The freeze must start from a proven unfrozen state with no outstanding
	// request: an already frozen sandbox (either fact) is never adopted, and
	// no foreign freeze request is overridden.
	if !freeze.RequestKnown || freeze.RequestFrozen || !freeze.EventsKnown || freeze.Frozen {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s is not proven unfrozen before shrink (request known=%t frozen=%t, events known=%t frozen=%t)",
			m.SandboxID, freeze.RequestKnown, freeze.RequestFrozen, freeze.EventsKnown, freeze.Frozen)
	}

	// Durable intent first: next revision, freeze ownership, original and
	// target limits. A crash from here on is recovered by unfreezing this
	// exact incarnation only.
	if err := h.openResourceOperationIntent(state, m, true, before); err != nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "persist shrink intent: %v", err)
	}

	if err := h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath(m.SandboxID), true); err != nil {
		// The write failed: the kernel may or may not have applied it. Run
		// the bounded unfreeze cleanup and record the truthful outcome.
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			fmt.Sprintf("write freeze request: %v", err))
	}
	if err := h.advanceResourceStage(state, resourceStageFreezeWritten); err != nil {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			fmt.Sprintf("persist freeze stage: %v", err))
	}
	frozen, err := h.confirmFreeze(ctx, m.SandboxID, shrinkFreezeConfirmTimeout)
	if err != nil || !frozen {
		// A D-state task can block the kernel from reaching frozen: undo our
		// own request, report the observed state, and never lower limits.
		reason := fmt.Sprintf("freeze not confirmed within %s", shrinkFreezeConfirmTimeout)
		if err != nil {
			reason = fmt.Sprintf("confirm freeze: %v", err)
		}
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout, reason)
	}
	if err := h.advanceResourceStage(state, resourceStageFrozen); err != nil {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			fmt.Sprintf("persist frozen stage: %v", err))
	}
	return h.applyShrinkWhileFrozen(ctx, state, m)
}

// shrinkPreconditions checks the shrink-only request shape beyond the shared
// normalization: CPU numbers are exactly the expected ones, the target memory
// is below the expected memory, the backend is cgroup v2, and a memory.high
// ratio is configured so the target soft limit exists.
func (h *sandboxService) shrinkPreconditions(m *resourceMutationRequest) error {
	if m.Target.CpuQuotaUsec != m.Expected.CpuQuotaUsec || m.Target.CpuPeriodUsec != m.Expected.CpuPeriodUsec {
		return errord.ToGRPCf(errord.ErrInvalidArgument, "shrink must keep the CPU allocation unchanged")
	}
	if m.Target.MemoryLimitBytes >= m.Expected.MemoryLimitBytes {
		return errord.ToGRPCf(errord.ErrInvalidArgument, "shrink target memory must be below the expected memory limit")
	}
	if h.cgroupMgr == nil {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "shrink requires the cgroup manager")
	}
	if !h.cgroupMgr.SupportsMemoryShrink() {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "shrink requires the cgroup v2 backend")
	}
	if h.memoryHighRatio() <= 0 {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "shrink requires a configured memory.high ratio")
	}
	return nil
}

// validateShrinkObservation enforces the pre-freeze conditions on a proven
// observation: the runtime is runsc, expected limits equal the live limits,
// the target respects the floor and ceiling of the persisted elastic policy,
// the target is strictly below the current limit, the enforced high is in
// effect, and current usage, limits, high and frozen state are all known.
// Nothing here may rely on a legacy fallback number.
func (h *sandboxService) validateShrinkObservation(m *resourceMutationRequest, before *runtime.StatsResponse) error {
	current, err := h.sandboxManager.Get(m.SandboxID)
	if err != nil {
		return errord.ToGRPC(err)
	}
	if current.Metadata.RuntimeHandler != config.RuntimeNameRunsc {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"runtime %q does not support shrink", current.Metadata.RuntimeHandler)
	}
	if !before.CpuLimitsKnown || !before.MemoryLimitKnown || !before.MemoryUsageKnown ||
		!before.MemoryHighKnown || !before.FrozenKnown {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"shrink requires known current usage, limits, high and frozen state")
	}
	if !limitsMatch(before, m.Expected) {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "effective limits changed; refresh Stats and admission")
	}
	if m.Target.MemoryLimitBytes >= before.MemoryLimitBytes {
		return errord.ToGRPCf(errord.ErrInvalidArgument, "shrink target must be below the current limit")
	}
	// The enforced high must be in effect for the current limit; the target
	// high derives from the same node policy.
	if !h.memoryHighMatches(before, before.MemoryLimitBytes) {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "memory.high does not match the node policy for the current limit")
	}
	if before.Frozen {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox is already frozen")
	}
	return h.elasticTargetWithinPolicy(current.Metadata.Labels, m.Target)
}

func (h *sandboxService) sandboxCgroupPath(sandboxID string) string {
	current, err := h.sandboxManager.Get(sandboxID)
	if err != nil || current.Metadata == nil {
		return ""
	}
	facts, err := h.physicalResources(current.Metadata)
	if err != nil {
		return ""
	}
	return facts.Resources[config.ResourceNameCgroup]
}

func (h *sandboxService) readShrinkFreezeState(sandboxID string) (cgroupmanager.FreezeState, error) {
	cgroup := h.sandboxCgroupPath(sandboxID)
	if cgroup == "" {
		return cgroupmanager.FreezeState{}, errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox %s cgroup is unavailable", sandboxID)
	}
	state, err := h.cgroupMgr.ReadFreeze(cgroup)
	if err != nil {
		return cgroupmanager.FreezeState{}, errord.ToGRPCf(errord.ErrFailedPrecondition, "read freeze state: %v", err)
	}
	return state, nil
}

// confirmFreeze polls the kernel-confirmed frozen state within a fixed
// budget and remains abortable by the command context. The request bit alone
// is never accepted as "frozen", and a confirmed frozen reading is honored
// even if the context expires in the same instant. Only this confirmation
// follows the RPC context: the later unfreeze cleanup deliberately does not.
func (h *sandboxService) confirmFreeze(ctx context.Context, sandboxID string, budget time.Duration) (bool, error) {
	deadline := time.Now().Add(budget)
	for {
		state, err := h.readShrinkFreezeState(sandboxID)
		if err != nil {
			return false, err
		}
		if state.EventsKnown && state.Frozen {
			return true, nil
		}
		if !state.RequestKnown || !state.RequestFrozen {
			return false, fmt.Errorf("freeze request no longer set while confirming (request known=%t frozen=%t)",
				state.RequestKnown, state.RequestFrozen)
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		time.Sleep(shrinkFreezePollInterval)
	}
}

// cleanupShrinkFreeze releases this operation's freeze request with its own
// bounded budget — independent of the original RPC's cancellation — and
// confirms the kernel reached the unfrozen state.
func (h *sandboxService) cleanupShrinkFreeze(sandboxID string) error {
	cgroup := h.sandboxCgroupPath(sandboxID)
	if cgroup == "" {
		return fmt.Errorf("sandbox %s cgroup is unavailable during freeze cleanup", sandboxID)
	}
	if err := h.cgroupMgr.WriteFreeze(cgroup, false); err != nil {
		return fmt.Errorf("release freeze request: %w", err)
	}
	deadline := time.Now().Add(shrinkCleanupTimeout)
	for {
		state, err := h.readShrinkFreezeState(sandboxID)
		if err != nil {
			return fmt.Errorf("confirm unfrozen: %w", err)
		}
		// Both freeze facts must be proven released: an unreadable request bit
		// or a request that is still set is not an unfrozen sandbox, whatever
		// the events file currently says.
		if state.RequestKnown && !state.RequestFrozen && state.EventsKnown && !state.Frozen {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("sandbox %s did not confirm the released freeze request and unfrozen state within %s (request known=%t frozen=%t, events known=%t frozen=%t)",
				sandboxID, shrinkCleanupTimeout, state.RequestKnown, state.RequestFrozen, state.EventsKnown, state.Frozen)
		}
		time.Sleep(shrinkFreezePollInterval)
	}
}

// abortShrinkBeforeWrites ends a shrink that never issued a memory write. It
// always attempts the bounded cleanup of its own freeze request; if the
// sandbox cannot be proven unfrozen, the journal stays open for background
// recovery and the RPC returns an uncertain error instead of a fake no-op.
func (h *sandboxService) abortShrinkBeforeWrites(state *resourceOperationState, m *resourceMutationRequest, outcome, cause string) (*runtime.ResizeResourcesResponse, error) {
	if cleanupErr := h.cleanupShrinkFreeze(m.SandboxID); cleanupErr != nil {
		h.scheduleResourceStateHeal()
		return nil, errord.ToGRPCf(errord.ErrUnavailable,
			"shrink aborted (%s) and freeze cleanup failed; operation %s stays pending: %v", cause, m.OperationID, cleanupErr)
	}
	after, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		h.scheduleResourceStateHeal()
		return nil, errord.ToGRPCf(errord.ErrUnavailable,
			"shrink aborted (%s) and readback failed; operation %s stays pending: %v", cause, m.OperationID, readErr)
	}
	if err := h.closeResourceOperation(state, outcome, cause, snapshotResourceReadback(after)); err != nil {
		h.scheduleResourceStateHeal()
		return nil, errord.ToGRPCf(errord.ErrUnavailable,
			"shrink aborted (%s) and the outcome could not be recorded; operation %s stays pending: %v", cause, m.OperationID, err)
	}
	// The response must describe the durably closed record, so the
	// observation is retaken after the close under the same lock.
	closed, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		h.scheduleResourceStateHeal()
		return nil, errord.ToGRPCf(errord.ErrUnavailable,
			"shrink aborted (%s) and the outcome is recorded but the final readback failed: %v", cause, readErr)
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": m.SandboxID, "operation_id": m.OperationID,
		"outcome": outcome, "cause": cause, "revision": state.Revision,
	}).Info("scheduler resource shrink aborted before lowering limits")
	return &runtime.ResizeResourcesResponse{Actual: closed, Complete: false, UpdateError: cause}, nil
}

// applyShrinkWhileFrozen runs between the confirmed freeze and the confirmed
// unfreeze: the safety margin is re-checked against a fresh observation of
// the frozen sandbox, memory.high is lowered before memory.max, the result is
// read back, and — only when everything matches — the freeze is released.
func (h *sandboxService) applyShrinkWhileFrozen(ctx context.Context, state *resourceOperationState, m *resourceMutationRequest) (*runtime.ResizeResourcesResponse, error) {
	// The command's expiry is rechecked after the freeze is confirmed and
	// before any memory write: an expired or cancelled command must not start
	// lowering limits. Only the bounded unfreeze cleanup below is exempt —
	// it releases the freeze this operation already owns.
	if err := ctx.Err(); err != nil {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			fmt.Sprintf("command expired while frozen: %v", err))
	}
	if time.Now().UnixMilli() >= m.DeadlineUnixMs {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			"command deadline expired while frozen")
	}
	frozenStats, err := h.resourceStats(m.SandboxID)
	if err != nil {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout, fmt.Sprintf("frozen readback: %v", err))
	}
	if !frozenStats.MemoryUsageKnown || !frozenStats.MemoryLimitKnown || !frozenStats.MemoryHighKnown ||
		!frozenStats.CpuLimitsKnown || !frozenStats.FrozenKnown || !frozenStats.Frozen {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			"frozen readback is unknown or the sandbox is not frozen")
	}
	if !limitsMatch(frozenStats, m.Expected) {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			"limits changed after freeze")
	}
	targetHigh, _ := h.expectedMemoryHighBytes(m.Target.MemoryLimitBytes)
	headroom := h.shrinkHeadroomBytes()
	// current + headroom ≤ targetHigh, written without overflow; a target
	// high smaller than the headroom itself can never satisfy the margin.
	if targetHigh < headroom || frozenStats.MemoryUsageBytes > targetHigh-headroom {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeUnsafeHeadroom, fmt.Sprintf(
			"frozen usage %d + headroom %d does not fit target memory.high %d; refusing to shrink below the working set",
			frozenStats.MemoryUsageBytes, headroom, targetHigh))
	}

	cgroup := h.sandboxCgroupPath(m.SandboxID)
	if cgroup == "" {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout, "cgroup is unavailable while frozen")
	}
	// The command's expiry is rechecked one final time immediately before the
	// first memory write: a cancellation or deadline arrival during the frozen
	// readback above must not start lowering limits.
	if err := ctx.Err(); err != nil {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			fmt.Sprintf("command expired while frozen: %v", err))
	}
	if time.Now().UnixMilli() >= m.DeadlineUnixMs {
		return h.abortShrinkBeforeWrites(state, m, resourceOutcomeFreezeTimeout,
			"command deadline expired while frozen")
	}
	// Fixed order: memory.high first, then memory.max. A write error leaves a
	// truthful partial state that the readback reports.
	writeErr := h.cgroupMgr.WriteMemoryLimits(cgroup, targetHigh, m.Target.MemoryLimitBytes)
	if advanceErr := h.advanceResourceStage(state, resourceStageApplied); advanceErr != nil {
		// The applied stage could not be recorded even though writes may have
		// landed; keep the record open at the frozen stage for recovery.
		logrus.WithFields(logrus.Fields{
			"sandbox_id": m.SandboxID, "operation_id": m.OperationID,
			"write_error": fmt.Sprintf("%v", writeErr), "advance_error": advanceErr,
		}).Warn("scheduler shrink stage persistence failed; deferring to recovery")
		return h.leaveShrinkPending(m, fmt.Errorf("persist applied stage: %w (update: %v)", advanceErr, writeErr))
	}
	after, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		return h.leaveShrinkPending(m, fmt.Errorf("shrink readback failed after possible write: %v", readErr))
	}
	verified := writeErr == nil && h.limitsAndHighVerified(after, m.Target)
	if !verified {
		// A partial write is not a no-op: attempt to restore the original
		// controls — never above the original max — and keep the honest
		// partial outcome with the advanced revision.
		if restoreErr := h.cgroupMgr.WriteMemoryLimits(cgroup, state.OldMemoryHighBytes, state.OldMemoryMaxBytes); restoreErr != nil {
			logrus.WithError(restoreErr).Warnf(
				"restore original memory limits for sandbox %s after partial shrink failed", m.SandboxID)
		}
		if after, readErr = h.resourceStats(m.SandboxID); readErr != nil {
			return h.leaveShrinkPending(m, fmt.Errorf("shrink readback failed after restore: %v", readErr))
		}
	}
	// The unfreeze is its own bounded cleanup; only a confirmed unfreeze
	// plus verified limits may complete.
	if cleanupErr := h.cleanupShrinkFreeze(m.SandboxID); cleanupErr != nil {
		return h.leaveShrinkPending(m, fmt.Errorf("freeze cleanup after writes: %v", cleanupErr))
	}
	final, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		return h.leaveShrinkPending(m, fmt.Errorf("final shrink readback: %v", readErr))
	}
	complete := verified && h.resourceOperationSucceeded(final, m.Target, true)
	message := ""
	if writeErr != nil {
		message = writeErr.Error()
	} else if !complete {
		message = "effective limits did not verify after shrink"
	}
	outcome := resourceOutcomePartial
	if complete {
		outcome = resourceOutcomeComplete
	}
	if closeErr := h.closeResourceOperation(state, outcome, message, snapshotResourceReadback(final)); closeErr != nil {
		return h.leaveShrinkPending(m, fmt.Errorf("record shrink outcome: %v", closeErr))
	}
	// The response must describe the durably closed record: retake the
	// observation after the close under the same lock.
	closed, readErr := h.resourceStats(m.SandboxID)
	if readErr != nil {
		return h.leaveShrinkPending(m, fmt.Errorf("outcome recorded but the final readback failed: %v", readErr))
	}
	response := &runtime.ResizeResourcesResponse{Actual: closed, Complete: complete}
	if message != "" {
		response.UpdateError = message
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": m.SandboxID, "operation_id": m.OperationID,
		"revision": state.Revision, "memory_limit_bytes": closed.MemoryLimitBytes,
		"memory_high_bytes": closed.MemoryHighBytes, "complete": complete,
	}).Info("scheduler resource shrink")
	return response, nil
}

// limitsAndHighVerified checks the hard limits and the enforced soft limit
// while the sandbox is still intentionally frozen.
func (h *sandboxService) limitsAndHighVerified(stats *runtime.StatsResponse, target *runtime.ResourceLimits) bool {
	return limitsVerified(stats, target) && h.memoryHighMatches(stats, target.MemoryLimitBytes)
}

// leaveShrinkPending reports an uncertain outcome: the journal stays open
// with the owned freeze intent, background recovery keeps retrying, and the
// operation must never be presented as a success or a no-op.
func (h *sandboxService) leaveShrinkPending(m *resourceMutationRequest, cause error) (*runtime.ResizeResourcesResponse, error) {
	h.scheduleResourceStateHeal()
	logrus.WithFields(logrus.Fields{
		"sandbox_id": m.SandboxID, "operation_id": m.OperationID, "cause": cause,
	}).Warn("scheduler resource shrink left pending for background recovery")
	return nil, errord.ToGRPCf(errord.ErrUnavailable,
		"operation %s stays pending on sandbox %s; reconciliation required: %v", m.OperationID, m.SandboxID, cause)
}
