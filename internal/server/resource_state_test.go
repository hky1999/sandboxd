// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// A damaged journal keeps the incarnation fail-closed: Stats reports an open
// operation (it can hide an owned freeze) and both RPCs reject; startup
// recovery leaves the file untouched instead of guessing.
func TestCorruptResourceStateFailsClosed(t *testing.T) {
	h, c, request := newShrinkService(t)
	_, path := h.resourceStatePath("elastic", "generation-1")
	require.NoError(t, os.WriteFile(path, []byte(`{"schema_version":1,"sandbox_id":`), 0600))
	stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, err)
	require.False(t, stats.ResourceRevisionKnown)
	require.True(t, stats.ResourceOperationPending)
	require.Empty(t, stats.ResourceOperationID)
	_, err = h.ShrinkResources(context.Background(), request)
	require.ErrorContains(t, err, "damaged")
	_, err = h.ResizeResources(context.Background(), &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-grow-1", ExpectedRevision: 1,
		Expected: request.Expected, Target: request.Expected,
	})
	require.ErrorContains(t, err, "damaged")
	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	_, readErr := os.Stat(path)
	require.NoError(t, readErr, "the damaged record must be retained as evidence")
	require.Zero(t, c.freezeWrites)
}

// A truncated-but-absent record is different from a legacy incarnation only
// in age: both are unknown state, and unknown never becomes a guessed
// revision. (The missing-record behavior is covered by the resize suite.)
func TestResourceStateDoubleInitializationIsRefused(t *testing.T) {
	h, _, _ := newShrinkService(t)
	require.ErrorContains(t, h.initResourceOperationState("elastic", "generation-1", "fresh-path"),
		"already exists")
}

// A crash between the durable freeze intent and the journal close is healed
// at startup: only the incarnation whose identity still matches is unfrozen,
// the physical readback is recorded, and the revision stays advanced.
func TestStartupRecoveryUnfreezesOwnedIntentAndClosesRecord(t *testing.T) {
	h, c, request := newShrinkService(t)
	// Simulate the crash point: intent persisted, freeze confirmed, memory
	// writes issued, no journal close.
	before, err := h.resourceStats("elastic")
	require.NoError(t, err)
	state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, loadErr)
	require.Equal(t, resourceStateLoaded, result)
	m := &resourceMutationRequest{
		Kind: resourceOperationShrink, SandboxID: "elastic", ResourceGeneration: "generation-1",
		Expected: request.Expected, Target: request.Target,
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-shrink-crash", ExpectedRevision: 1,
	}
	require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
	require.NoError(t, h.advanceResourceStage(state, resourceStageFreezeWritten))
	require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))
	require.NoError(t, h.advanceResourceStage(state, resourceStageFrozen))
	require.NoError(t, h.cgroupMgr.WriteMemoryLimits(h.sandboxCgroupPath("elastic"),
		mustHigh(t, h, request.Target.MemoryLimitBytes), request.Target.MemoryLimitBytes))
	require.NoError(t, h.advanceResourceStage(state, resourceStageApplied))
	requested, events := c.freezeStateSnapshot()
	require.True(t, requested)
	require.True(t, events)

	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	requested, events = c.freezeStateSnapshot()
	require.False(t, requested, "recovery releases the owned freeze request")
	require.False(t, events, "recovery confirms the unfrozen state")
	state, result, loadErr = h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, loadErr)
	require.Equal(t, resourceStateLoaded, result)
	require.False(t, state.open())
	require.Equal(t, uint64(2), state.Revision, "recovery keeps the advanced revision")
	require.Equal(t, resourceOutcomeComplete, state.LastOutcome,
		"the physically landed target verifies against the readback")
	// The next operation runs under the recovered revision with a fresh ID.
	next := &runtime.ShrinkResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-shrink-2", ExpectedRevision: 2,
		Expected: request.Target,
		Target:   &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 128 * 1024 * 1024},
	}
	response, err := h.ShrinkResources(context.Background(), next)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, uint64(3), response.Actual.ResourceRevision)
}

// A record whose incarnation no longer matches is never unfrozen: the
// generation, cgroup path, or inode changing means the record describes a
// retired incarnation. The evidence is retained, not deleted.
func TestStartupRecoveryIgnoresForeignOrMissingIncarnations(t *testing.T) {
	t.Run("generation changed", func(t *testing.T) {
		h, c, request := newShrinkService(t)
		before, err := h.resourceStats("elastic")
		require.NoError(t, err)
		state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		m := &resourceMutationRequest{
			Kind: resourceOperationShrink, SandboxID: "elastic", ResourceGeneration: "generation-1",
			Expected: request.Expected, Target: request.Target,
			DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
			OperationID:    "operation-shrink-foreign", ExpectedRevision: 1,
		}
		require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
		require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))
		// The ID now belongs to a newer incarnation.
		require.NoError(t, h.sandboxManager.UpdateLabels("elastic",
			map[string]string{resourceGenerationLabel: "generation-2"}))
		require.NoError(t, h.recoverResourceOperationStates(context.Background()))
		_, events := c.freezeStateSnapshot()
		require.True(t, events, "a foreign incarnation is never touched")
		state, result, loadErr = h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		require.True(t, state.open(), "the record stays open as retained evidence")
	})
	t.Run("sandbox missing", func(t *testing.T) {
		h, _, request := newShrinkService(t)
		before, err := h.resourceStats("elastic")
		require.NoError(t, err)
		state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		m := &resourceMutationRequest{
			Kind: resourceOperationShrink, SandboxID: "elastic", ResourceGeneration: "generation-1",
			Expected: request.Expected, Target: request.Target,
			DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
			OperationID:    "operation-shrink-gone", ExpectedRevision: 1,
		}
		require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
		require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))
		h.sandboxManager.Delete("elastic")
		require.NoError(t, h.recoverResourceOperationStates(context.Background()))
		state, result, loadErr = h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		require.True(t, state.open(), "a missing sandbox alone never closes or deletes the record")
	})
}

// A sandbox frozen without any owned record — an external freeze — is never
// unfrozen by recovery, and a closed record is left alone entirely.
func TestStartupRecoveryDoesNotUnfreezeForeignFreeze(t *testing.T) {
	h, c, request := newShrinkService(t)
	// Complete a shrink normally, then an external actor freezes the cgroup.
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))
	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	_, events := c.freezeStateSnapshot()
	require.True(t, events, "no owned intent means no unfreeze")
	state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, loadErr)
	require.Equal(t, resourceStateLoaded, result)
	require.False(t, state.open())
}

// The elastic creation hook initializes revision 1 before the runtime handler
// runs; without elastic resources the incarnation stays revision-less and
// operations are rejected rather than guessed.
func TestElasticStartInitializesRevisionBeforeHandler(t *testing.T) {
	h, c, _ := newShrinkService(t)
	handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	annotations := map[string]string{
		elasticResourcesLabel:   elasticTestRequest(t).Labels[elasticResourcesLabel],
		resourceGenerationLabel: "generation-fresh",
	}
	start := svc.StartConfig{
		ID: "fresh", CgroupPath: t.TempDir(),
		Resources:   &runtime.LinuxSandboxResources{CpuQuota: 50000, CpuPeriod: 100000, MemoryLimitInBytes: 512 * 1024 * 1024},
		Annotations: annotations,
	}
	metadata := &runtime.SandboxMetadata{
		ID: "fresh", RuntimeHandler: "runsc", Labels: annotations,
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
	}
	require.NoError(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
	require.True(t, handler.started)
	state, result, err := h.loadResourceOperationState("fresh", "generation-fresh")
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, uint64(1), state.Revision)
	require.False(t, state.open())
	require.Equal(t, start.CgroupPath, state.CgroupPath)
	require.NotZero(t, state.CgroupInode)

	// A non-elastic sandbox gets no journal record at all; its start config
	// still carries the real resources a production start would pass.
	plain := svc.StartConfig{
		ID:         "plain",
		CgroupPath: t.TempDir(),
		Resources: &runtime.LinuxSandboxResources{
			CpuQuota: 50000, CpuPeriod: 100000, MemoryLimitInBytes: 512 * 1024 * 1024,
		},
	}
	plainMetadata := &runtime.SandboxMetadata{
		ID: "plain", RuntimeHandler: "runsc",
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
	}
	require.NoError(t, h.sandboxManager.StoreMetadata("plain", plainMetadata))
	require.NoError(t, h.startSandboxRuntime(context.Background(), "runsc", plain, plainMetadata))
	require.NoError(t, h.sandboxManager.StoreMetadata("plain", &runtime.SandboxMetadata{
		ID: "plain", RuntimeHandler: "runsc",
		ResourceFacts: map[string]string{config.ResourceNameCgroup: plain.CgroupPath},
	}))
	stats, err := h.resourceStats("plain")
	require.NoError(t, err)
	require.False(t, stats.ResourceRevisionKnown)
	require.Zero(t, c.freezeWrites)
}

// Retiring an incarnation through the physical delete closes and removes its
// journal record; the delete is the only authority for that.
func TestRetiredIncarnationRecordIsRemovedAfterDelete(t *testing.T) {
	h, c, request := newShrinkService(t)
	// Leave an open owned freeze, then delete the sandbox through the
	// physical path.
	before, err := h.resourceStats("elastic")
	require.NoError(t, err)
	state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, loadErr)
	require.Equal(t, resourceStateLoaded, result)
	m := &resourceMutationRequest{
		Kind: resourceOperationShrink, SandboxID: "elastic", ResourceGeneration: "generation-1",
		Expected: request.Expected, Target: request.Target,
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-shrink-retire", ExpectedRevision: 1,
	}
	require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
	require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))
	require.NoError(t, h.deleteSandboxRuntime(context.Background(), "elastic", "generation-1"))
	_, path := h.resourceStatePath("elastic", "generation-1")
	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	require.Zero(t, c.memoryWrites)
	// The owned freeze was released before the runtime delete ran, so the
	// handler's control path never met a frozen Sentry.
	requested, events := c.freezeStateSnapshot()
	require.False(t, requested)
	require.False(t, events)
}

func mustHigh(t *testing.T, h *sandboxService, limitBytes uint64) uint64 {
	t.Helper()
	high, unlimited := h.expectedMemoryHighBytes(limitBytes)
	require.False(t, unlimited)
	return high
}

// The journal directory lives under the daemon root with restrictive modes,
// never inside sandbox-writable state.
func TestResourceStateJournalLayout(t *testing.T) {
	h, _, _ := newShrinkService(t)
	dir := h.resourceStateDir()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	_, path := h.resourceStatePath("elastic", "generation-1")
	record, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), record.Mode().Perm())
	require.Equal(t, filepath.Join(h.config.RootDir, "scheduler-resource-states"), dir)
	// No temp names leak after a successful publication.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, len(entry.Name()) > 0 && entry.Name()[0] == '.',
			"temporary journal name leaked: %s", entry.Name())
	}
}
