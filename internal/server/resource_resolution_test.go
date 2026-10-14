// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"os"
	"testing"
	"time"
)

func TestResolveResourceOperationFencesExpiredUndeliveredCommand(t *testing.T) {
	h, c, original := newResizeService(t)
	original.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
	request := &runtime.ResolveResourceOperationRequest{Original: original}
	got, err := h.ResolveResourceOperation(context.Background(), request)
	require.NoError(t, err)
	require.False(t, got.Complete, "unchanged limits are not target completion")
	require.Equal(t, original.Expected.MemoryLimitBytes, got.Actual.MemoryLimitBytes)
	require.Equal(t, original.ExpectedRevision+1, got.Actual.ResourceRevision)
	require.Equal(t, original.OperationID, got.Actual.ResourceOperationID)
	require.False(t, got.Actual.ResourceOperationPending)
	require.True(t, got.Actual.FrozenKnown)
	require.False(t, got.Actual.Frozen)
	require.Zero(t, c.writes)
	require.Zero(t, c.memoryWrites)
	require.Zero(t, c.freezeWrites)
	again, err := h.ResolveResourceOperation(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, got.Actual.ResourceRevision, again.Actual.ResourceRevision)
	state, loaded, err := h.loadResourceOperationState(original.SandboxID, original.ResourceGeneration)
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, loaded)
	require.False(t, state.open())
	require.Equal(t, original.OperationID, state.LastOperationID)
	late := proto.Clone(original).(*runtime.ResizeResourcesRequest)
	late.DeadlineUnixMs = time.Now().Add(time.Second).UnixMilli()
	_, err = h.ResizeResources(context.Background(), late)
	require.Error(t, err, "renewing a fenced command cannot create a late effect")
	require.Zero(t, c.writes)
	next := proto.Clone(late).(*runtime.ResizeResourcesRequest)
	next.OperationID = "later-authorized-growth"
	next.ExpectedRevision = got.Actual.ResourceRevision
	result, err := h.ResizeResources(context.Background(), next)
	require.NoError(t, err)
	require.True(t, result.Complete, "a new authorization may use the advanced revision")
}
func TestResolveResourceOperationReadsCompletedCommandWithoutReexecution(t *testing.T) {
	h, c, original := newResizeService(t)
	applied, err := h.ResizeResources(context.Background(), original)
	require.NoError(t, err)
	writes := c.writes
	got, err := h.ResolveResourceOperation(context.Background(), &runtime.ResolveResourceOperationRequest{Original: original})
	require.NoError(t, err)
	require.True(t, got.Complete)
	require.Equal(t, applied.Actual.ResourceRevision, got.Actual.ResourceRevision)
	require.Equal(t, writes, c.writes)
}
func TestResolveResourceOperationRejectsUnexpiredAndForeignCommands(t *testing.T) {
	for _, name := range []string{"unexpired", "generation", "revision", "limits", "frozen", "unknown-freeze"} {
		t.Run(name, func(t *testing.T) {
			h, c, original := newResizeService(t)
			original.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
			switch name {
			case "unexpired":
				original.DeadlineUnixMs = time.Now().Add(time.Second).UnixMilli()
			case "generation":
				original.ResourceGeneration = "foreign"
			case "revision":
				original.ExpectedRevision++
			case "limits":
				original.Expected.MemoryLimitBytes++
			case "frozen":
				c.requestFrozen = true
				c.eventsFrozen = true
			case "unknown-freeze":
				c.requestKnown = false
			}
			_, err := h.ResolveResourceOperation(context.Background(), &runtime.ResolveResourceOperationRequest{Original: original})
			require.Error(t, err)
			state, _, err := h.loadResourceOperationState("elastic", "generation-1")
			require.NoError(t, err)
			require.Equal(t, uint64(1), state.Revision)
			require.Zero(t, c.writes)
			require.Zero(t, c.memoryWrites)
			require.Zero(t, c.freezeWrites)
		})
	}
}

func TestResourceRecoveryDoesNotPublishAnObsoletePreLockSnapshot(t *testing.T) {
	h, c, original := newResizeService(t)
	m, err := normalizeResourceMutation(resourceOperationGrow, original.SandboxID, original.ResourceGeneration, original.Expected, original.Target, original.DeadlineUnixMs, original.OperationID, original.ExpectedRevision)
	require.NoError(t, err)
	state, _, err := h.resolveResourceOperation(m)
	require.NoError(t, err)
	before, err := h.resourceStats(original.SandboxID)
	require.NoError(t, err)
	require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
	obsolete := *state
	require.NoError(t, h.closeResourceOperation(state, resourceOutcomePartial, "no writes", snapshotResourceReadback(before)))
	next := proto.Clone(original).(*runtime.ResizeResourcesRequest)
	next.ExpectedRevision = 2
	next.OperationID = "next-growth"
	applied, err := h.ResizeResources(context.Background(), next)
	require.NoError(t, err)
	require.Equal(t, uint64(3), applied.Actual.ResourceRevision)
	// A delayed scanner must not thaw a later owner's freeze or rewind the
	// terminal journal using the snapshot taken before acquiring its lock.
	c.requestFrozen = true
	c.eventsFrozen = true
	freezes := c.freezeWrites
	require.NoError(t, h.reconcileOpenResourceState(context.Background(), &obsolete, time.Second))
	current, _, err := h.loadResourceOperationState(original.SandboxID, original.ResourceGeneration)
	require.NoError(t, err)
	require.Equal(t, uint64(3), current.Revision)
	require.Equal(t, next.OperationID, current.LastOperationID)
	require.Equal(t, freezes, c.freezeWrites)
}

func TestResolveResourceOperationFencesExpiredShrinkWithoutTakingFreeze(t *testing.T) {
	h, c, shrink := newShrinkService(t)
	request := &runtime.ResolveResourceOperationRequest{Shrink: true, Original: &runtime.ResizeResourcesRequest{
		SandboxID: shrink.SandboxID, ResourceGeneration: shrink.ResourceGeneration,
		Expected: shrink.Expected, Target: shrink.Target, ExpectedRevision: shrink.ExpectedRevision,
		DeadlineUnixMs: time.Now().Add(-time.Second).UnixMilli(), OperationID: shrink.OperationID,
	}}
	result, err := h.ResolveResourceOperation(context.Background(), request)
	require.NoError(t, err)
	require.False(t, result.Complete)
	require.Equal(t, shrink.Expected.MemoryLimitBytes, result.Actual.MemoryLimitBytes)
	require.Equal(t, shrink.ExpectedRevision+1, result.Actual.ResourceRevision)
	require.Zero(t, c.writes)
	require.Zero(t, c.memoryWrites)
	require.Zero(t, c.freezeWrites)
	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	replay, err := h.ResolveResourceOperation(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, result.Actual.ResourceRevision, replay.Actual.ResourceRevision)
	require.Zero(t, c.freezeWrites)
}
func TestResolveResourceOperationRejectsChangesToEveryOriginalFingerprintField(t *testing.T) {
	h, c, original := newResizeService(t)
	original.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
	_, err := h.ResolveResourceOperation(context.Background(), &runtime.ResolveResourceOperationRequest{Original: original})
	require.NoError(t, err)
	for which := 0; which < 10; which++ {
		changed := proto.Clone(original).(*runtime.ResizeResourcesRequest)
		wrapped := &runtime.ResolveResourceOperationRequest{Original: changed}
		switch which {
		case 0:
			changed.DeadlineUnixMs++
		case 1:
			changed.ExpectedRevision++
		case 2:
			changed.Expected.CpuQuotaUsec++
		case 3:
			changed.Expected.CpuPeriodUsec++
		case 4:
			changed.Expected.MemoryLimitBytes++
		case 5:
			changed.Target.CpuQuotaUsec++
		case 6:
			changed.Target.CpuPeriodUsec++
		case 7:
			changed.Target.MemoryLimitBytes++
		case 8:
			wrapped.Shrink = true
		case 9:
			changed.ResourceGeneration = "foreign"
		}
		_, err = h.ResolveResourceOperation(context.Background(), wrapped)
		require.Error(t, err, "field %d", which)
		require.Zero(t, c.writes)
		require.Zero(t, c.memoryWrites)
		require.Zero(t, c.freezeWrites)
	}
}
func TestResolveResourceOperationKeepsPendingOrUnavailableJournalUnknown(t *testing.T) {
	for _, which := range []string{"pending", "missing", "corrupt"} {
		t.Run(which, func(t *testing.T) {
			h, c, original := newResizeService(t)
			original.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
			_, path := h.resourceStatePath(original.SandboxID, original.ResourceGeneration)
			if which == "pending" {
				m, err := normalizeResourceMutation(resourceOperationGrow, original.SandboxID, original.ResourceGeneration, original.Expected, original.Target, original.DeadlineUnixMs, original.OperationID, original.ExpectedRevision)
				require.NoError(t, err)
				state, _, err := h.resolveResourceOperation(m)
				require.NoError(t, err)
				before, err := h.resourceStats(original.SandboxID)
				require.NoError(t, err)
				require.NoError(t, h.openResourceOperationIntent(state, m, false, before))
			} else if which == "missing" {
				require.NoError(t, os.Remove(path))
			} else {
				require.NoError(t, os.WriteFile(path, []byte("broken journal"), 0600))
			}
			_, err := h.ResolveResourceOperation(context.Background(), &runtime.ResolveResourceOperationRequest{Original: original})
			require.Error(t, err)
			require.Zero(t, c.writes)
			require.Zero(t, c.memoryWrites)
			require.Zero(t, c.freezeWrites)
		})
	}
}
func TestResourceRecoveryDoesNotActAfterJournalDisappearsOrIsDamaged(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		h, c, original := newResizeService(t)
		m, err := normalizeResourceMutation(resourceOperationGrow, original.SandboxID, original.ResourceGeneration, original.Expected, original.Target, original.DeadlineUnixMs, original.OperationID, original.ExpectedRevision)
		require.NoError(t, err)
		state, _, err := h.resolveResourceOperation(m)
		require.NoError(t, err)
		before, err := h.resourceStats(original.SandboxID)
		require.NoError(t, err)
		require.NoError(t, h.openResourceOperationIntent(state, m, true, before))
		_, path := h.resourceStatePath(original.SandboxID, original.ResourceGeneration)
		if corrupt {
			require.NoError(t, os.WriteFile(path, []byte("broken journal"), 0600))
		} else {
			require.NoError(t, os.Remove(path))
		}
		require.Error(t, h.reconcileOpenResourceState(context.Background(), state, time.Second))
		require.Zero(t, c.freezeWrites)
	}
}
