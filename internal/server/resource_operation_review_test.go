// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// A fresh grow must compare strictly against the live limits. Once the grow
// landed (live == target), a new operation claiming the old expected limits
// is stale — only the replay of the identical completed operation ID may
// answer with the recorded result.
func TestGrowFreshOperationRequiresStrictExpectedMatch(t *testing.T) {
	h, c, request := newResizeService(t)
	response, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.False(t, response.Actual.ResourceOperationPending)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)

	// The identical request replays through the real RPC entry point.
	replay, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, replay.Complete)
	require.Equal(t, uint64(2), replay.Actual.ResourceRevision)
	require.Equal(t, "operation-grow-1", replay.Actual.ResourceOperationID)
	require.False(t, replay.Actual.ResourceOperationPending)
	require.Equal(t, 1, c.writes)

	// A fresh operation under the CURRENT revision whose expected limits are
	// the pre-grow values, with the target equal to the live limits, must be
	// rejected by the strict expected compare itself — live==target never
	// substitutes for expected==live.
	fresh := proto.Clone(request).(*runtime.ResizeResourcesRequest)
	fresh.OperationID = "operation-grow-wrong-expected"
	fresh.ExpectedRevision = 2                          // the current revision; no stale-revision exit
	fresh.Expected.MemoryLimitBytes = 512 * 1024 * 1024 // the pre-grow value
	_, err = h.ResizeResources(context.Background(), fresh)
	require.ErrorContains(t, err, "effective limits changed")
	require.Equal(t, 1, c.writes)
}

// Grow refuses a proven-frozen sandbox up front, and a write whose readback
// finds the sandbox frozen is a truthful partial — never a complete.
func TestGrowRejectsFrozenSandboxAndRequiresUnfrozenComplete(t *testing.T) {
	h, c, request := newResizeService(t)
	c.mu.Lock()
	c.eventsFrozen, c.eventsKnown = true, true
	c.mu.Unlock()
	_, err := h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "sandbox is frozen")
	require.Zero(t, c.writes)

	// Unfreeze, then freeze again after the write lands: the outcome must
	// stay partial because complete demands a proven unfrozen readback.
	h2, c2, request2 := newResizeService(t)
	c2.onPrepare = func() {
		c2.mu.Lock()
		c2.eventsFrozen = true
		c2.mu.Unlock()
	}
	response, err := h2.ResizeResources(context.Background(), request2)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "frozen")
	require.Equal(t, request2.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	require.False(t, response.Actual.ResourceOperationPending)
	state, result, loadErr := h2.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, loadErr)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, resourceOutcomePartial, state.LastOutcome)
}

// A recorded complete is only repeated while the current physical readback
// still proves it: external perturbation downgrades the replay to a
// conservative non-complete answer with an honest reason.
func TestReplayDoesNotRepeatCompleteAfterExternalPerturbation(t *testing.T) {
	t.Run("shrink", func(t *testing.T) {
		h, c, request := newShrinkService(t)
		response, err := h.ShrinkResources(context.Background(), request)
		require.NoError(t, err)
		require.True(t, response.Complete)
		// An external actor raises the hard limit after the fact.
		c.mu.Lock()
		c.stats.MemoryLimitBytes = 512 * 1024 * 1024
		c.stats.MemoryHighBytes = cgroupmanager.MemoryHighBytes(512*1024*1024, 0.8)
		c.mu.Unlock()
		replay, err := h.ShrinkResources(context.Background(), request)
		require.NoError(t, err)
		require.False(t, replay.Complete)
		require.Contains(t, replay.UpdateError, "no longer verifies")
		require.False(t, replay.Actual.ResourceOperationPending)
		require.Equal(t, 1, c.memoryWrites, "the replay must not re-execute")
	})
	t.Run("grow", func(t *testing.T) {
		h, c, request := newResizeService(t)
		_, err := h.ResizeResources(context.Background(), request)
		require.NoError(t, err)
		c.mu.Lock()
		c.stats.MemoryLimitBytes = 512 * 1024 * 1024
		c.stats.MemoryHighBytes = cgroupmanager.MemoryHighBytes(512*1024*1024, 0.8)
		c.mu.Unlock()
		replay, err := h.ResizeResources(context.Background(), request)
		require.NoError(t, err)
		require.False(t, replay.Complete)
		require.Contains(t, replay.UpdateError, "no longer verifies")
		require.Equal(t, 1, c.writes)
	})
}

// The command deadline and the RPC cancellation are enforced between the
// confirmed freeze and the first memory write: no limits move, the own freeze
// is released by the independent bounded cleanup, and the durable outcome is
// a closed, non-complete terminal with the advanced revision.
func TestShrinkDeadlineAndCancellationStopWritesAfterFreeze(t *testing.T) {
	t.Run("absolute deadline expires while frozen", func(t *testing.T) {
		h, c, request := newShrinkService(t)
		request.DeadlineUnixMs = time.Now().Add(300 * time.Millisecond).UnixMilli()
		c.onWriteFreeze = func(frozen bool) {
			if frozen {
				// The freeze is confirmed, then the deadline passes before
				// any memory write is considered.
				time.Sleep(400 * time.Millisecond)
			}
		}
		response, err := h.ShrinkResources(context.Background(), request)
		require.NoError(t, err)
		// Both the context deadline and the absolute deadline produce the
		// same terminal semantics; only the wording races between them.
		require.False(t, response.Complete)
		require.Contains(t, response.UpdateError, "expired while frozen")
		require.Zero(t, c.memoryWrites, "an expired command must not start lowering limits")
		require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
		require.False(t, response.Actual.Frozen, "the independent cleanup unfroze the sandbox")
		require.False(t, response.Actual.ResourceOperationPending)
		require.Equal(t, uint64(2), response.Actual.ResourceRevision)
		requested, events := c.freezeStateSnapshot()
		require.False(t, requested)
		require.False(t, events)
	})
	t.Run("rpc cancelled after frozen", func(t *testing.T) {
		h, c, request := newShrinkService(t)
		ctx, cancel := context.WithCancel(context.Background())
		c.onWriteFreeze = func(frozen bool) {
			if frozen {
				cancel()
			}
		}
		response, err := h.ShrinkResources(ctx, request)
		require.NoError(t, err)
		require.False(t, response.Complete)
		require.Contains(t, response.UpdateError, "expired while frozen")
		require.Zero(t, c.memoryWrites)
		requested, events := c.freezeStateSnapshot()
		require.False(t, requested, "cleanup is independent of the RPC cancellation")
		require.False(t, events)
		require.False(t, response.Actual.ResourceOperationPending)
	})
}

// Pause, Resume and Checkpoint refuse to start while this daemon owns an open
// or unparsable resource operation: their Sentry round-trips could hang under
// the physical lock against our own frozen sandbox and wedge recovery. The
// refusal never releases anyone's freeze.
func TestPauseResumeCheckpointRejectPendingResourceOperation(t *testing.T) {
	freezer := func() *fakeTaskFreezer { return &fakeTaskFreezer{Handler: svc.NewFakeRuntimeHandler()} }

	t.Run("open operation", func(t *testing.T) {
		h, c, request := newShrinkService(t)
		h.serviceHandler.Set("runsc", freezer())
		before, err := h.resourceStats("elastic")
		require.NoError(t, err)
		state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		m := &resourceMutationRequest{
			Kind: resourceOperationShrink, SandboxID: "elastic", ResourceGeneration: "generation-1",
			Expected: request.Expected, Target: request.Target,
			DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
			OperationID:    "operation-shrink-pending", ExpectedRevision: 1,
		}
		require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
		// The pending record may even be frozen by us right now.
		require.NoError(t, h.cgroupMgr.WriteFreeze(h.sandboxCgroupPath("elastic"), true))

		_, err = h.Pause(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.ErrorContains(t, err, "pending")
		_, err = h.Resume(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.ErrorContains(t, err, "pending")
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		_, events := c.freezeStateSnapshot()
		require.True(t, events, "the refusal must not unfreeze on its own")

		// Once reconciliation closes the record, Pause runs again.
		c.mu.Lock()
		c.requestFrozen, c.eventsFrozen = false, false
		c.mu.Unlock()
		open, failures := h.healOpenResourceStates(context.Background())
		require.Zero(t, open)
		require.Zero(t, failures)
		_, err = h.Pause(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.NoError(t, err)
	})
	t.Run("damaged record", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		h.serviceHandler.Set("runsc", freezer())
		_, path := h.resourceStatePath("elastic", "generation-1")
		require.NoError(t, os.WriteFile(path, []byte("{truncated"), 0600))
		_, err := h.Pause(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.ErrorContains(t, err, "damaged")
		_, err = h.Resume(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.ErrorContains(t, err, "damaged")
		require.ErrorContains(t, h.rejectUnclosedResourceOperation("elastic"), "damaged")
	})
	t.Run("closed and legacy records stay pausable", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		pauser := freezer()
		h.serviceHandler.Set("runsc", pauser)
		require.NoError(t, h.rejectUnclosedResourceOperation("elastic"))
		_, err := h.Pause(context.Background(), &runtime.PauseRequest{ID: "elastic"})
		require.NoError(t, err)
		require.Equal(t, 1, pauser.paused)
	})
}

// Stats exposes the absolute cgroup directory only when the incarnation's
// revision record verifies against the live cgroup identity; legacy, damaged
// and mismatched records leave it empty.
func TestStatsMemoryCgroupPathRequiresVerifiedIdentity(t *testing.T) {
	t.Run("verified", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
		require.NoError(t, err)
		require.NotEmpty(t, stats.MemoryCgroupPath)
		current, err := h.sandboxManager.Get("elastic")
		require.NoError(t, err)
		require.Equal(t, current.Metadata.ResourceFacts[config.ResourceNameCgroup], stats.MemoryCgroupPath)
	})
	t.Run("legacy record", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		_, path := h.resourceStatePath("elastic", "generation-1")
		require.NoError(t, os.Remove(path))
		stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
		require.NoError(t, err)
		require.Empty(t, stats.MemoryCgroupPath)
		require.False(t, stats.ResourceRevisionKnown)
	})
	t.Run("damaged record", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		_, path := h.resourceStatePath("elastic", "generation-1")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))
		stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
		require.NoError(t, err)
		require.Empty(t, stats.MemoryCgroupPath)
		require.True(t, stats.ResourceOperationPending)
	})
	t.Run("identity mismatch", func(t *testing.T) {
		h, _, _ := newShrinkService(t)
		state, result, err := h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, err)
		require.Equal(t, resourceStateLoaded, result)
		state.CgroupInode = state.CgroupInode + 1 // a recycled directory
		require.NoError(t, h.saveResourceOperationState(state))
		stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
		require.NoError(t, err)
		require.Empty(t, stats.MemoryCgroupPath)
		require.True(t, stats.ResourceRevisionKnown, "the revision facts survive; only the locator is withheld")
	})
}

// The revision must remain incrementable: an exhausted UINT64_MAX revision
// refuses new operations instead of wrapping to a value stale commands could
// re-match.
func TestExhaustedRevisionRefusesOperations(t *testing.T) {
	h, c, request := newShrinkService(t)
	state, result, err := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, result)
	state.Revision = ^uint64(0)
	require.NoError(t, h.saveResourceOperationState(state))
	request.ExpectedRevision = ^uint64(0)
	_, err = h.ShrinkResources(context.Background(), request)
	require.ErrorContains(t, err, "exhausted")
	require.Zero(t, c.freezeWrites)
	grow := &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-grow-overflow", ExpectedRevision: ^uint64(0),
		Expected: request.Expected, Target: request.Expected,
	}
	_, err = h.ResizeResources(context.Background(), grow)
	require.ErrorContains(t, err, "exhausted")
	require.Zero(t, c.writes)
}

// A cancellation arriving during the frozen readback — after the entry
// checks but before the memory writes — must still stop the writes: the
// expiry is rechecked immediately before WriteMemoryLimits. The own freeze is
// released by the independent cleanup either way.
func TestShrinkCancellationDuringFrozenReadbackStopsWrites(t *testing.T) {
	h, c, request := newShrinkService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.onStats = func() {
		requestFrozen, eventsFrozen := c.freezeStateSnapshot()
		if requestFrozen && eventsFrozen {
			// This is the fresh frozen readback: cancel the command now,
			// between the entry checks and the memory writes.
			cancel()
		}
	}
	response, err := h.ShrinkResources(ctx, request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "expired while frozen")
	require.Zero(t, c.memoryWrites, "a cancellation during the frozen readback must not lower limits")
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.False(t, response.Actual.Frozen)
	require.False(t, response.Actual.ResourceOperationPending)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	requested, events := c.freezeStateSnapshot()
	require.False(t, requested)
	require.False(t, events)
}

// Grow refuses a sandbox with an outstanding freeze request even when the
// kernel has not confirmed it yet: it never takes over someone else's
// freeze.
func TestGrowRejectsPendingFreezeRequest(t *testing.T) {
	h, c, request := newResizeService(t)
	c.mu.Lock()
	c.requestFrozen = true // requested, not yet confirmed
	c.mu.Unlock()
	_, err := h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "refuses to take it over")
	require.Zero(t, c.writes)

	// An unreadable request bit is equally disqualifying when the backend
	// exposes the freezer.
	h2, c2, request2 := newResizeService(t)
	c2.mu.Lock()
	c2.requestKnown = false
	c2.mu.Unlock()
	_, err = h2.ResizeResources(context.Background(), request2)
	require.ErrorContains(t, err, "refuses to take it over")
	require.Zero(t, c2.writes)
}

// The cleanup unfreeze is only proven when BOTH freeze facts read back
// released: an unreadable request bit keeps the operation pending instead of
// claiming an unfrozen sandbox.
func TestShrinkCleanupRequiresReadableReleasedRequestBit(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.onWriteFreeze = func(frozen bool) {
		if !frozen {
			// The unfreeze write lands, but the request bit becomes
			// unreadable before the confirmation poll.
			c.mu.Lock()
			c.requestKnown = false
			c.mu.Unlock()
		}
	}
	_, err := h.ShrinkResources(context.Background(), request)
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, 1, c.memoryWrites, "the writes themselves proceeded")
	stats, statsErr := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, statsErr)
	require.True(t, stats.ResourceOperationPending, "an unprovable release stays UNKNOWN")
	// The kernel recovers; reconciliation closes the record afterwards. Drop
	// the fault hook first so the heal's own unfreeze write is not broken.
	c.mu.Lock()
	c.onWriteFreeze = nil
	c.requestKnown = true
	c.requestFrozen = false
	c.mu.Unlock()
	open, failures := h.healOpenResourceStates(context.Background())
	require.Zero(t, open)
	require.Zero(t, failures)
	stats, statsErr = h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, statsErr)
	require.False(t, stats.ResourceOperationPending)
}

// On the cgroup v2 backend a failed freeze read is fail-closed for grow: no
// write and no revision advance. Backends without the freezer (cgroup v1)
// keep their existing behavior and skip the check.
func TestGrowFreezeReadFailureIsFailClosedOnV2Only(t *testing.T) {
	t.Run("v2 read error rejects", func(t *testing.T) {
		h, c, request := newResizeService(t)
		c.mu.Lock()
		c.failFreezeRead = true
		c.mu.Unlock()
		_, err := h.ResizeResources(context.Background(), request)
		require.ErrorContains(t, err, "read freeze state")
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Zero(t, c.writes, "no write without a proven unfrozen sandbox")
		state, result, loadErr := h.loadResourceOperationState("elastic", "generation-1")
		require.NoError(t, loadErr)
		require.Equal(t, resourceStateLoaded, result)
		require.Equal(t, uint64(1), state.Revision, "the revision must not advance")
		require.False(t, state.open())
	})
	t.Run("v1 backend skips the freeze gate", func(t *testing.T) {
		h, c, request := newResizeService(t)
		c.mu.Lock()
		c.shrinkSupported = false // cgroup v1 shape: no freezer capability
		c.mu.Unlock()
		response, err := h.ResizeResources(context.Background(), request)
		require.NoError(t, err)
		require.True(t, response.Complete)
		require.Equal(t, 1, c.writes)
		require.Zero(t, c.freezeWrites)
	})
}
