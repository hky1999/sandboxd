// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
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

// newShrinkService provisions one elastic incarnation whose policy floor is
// 128 MiB and whose live limit is already grown to 512 MiB, so a shrink to
// 256 MiB stays above the floor. The fake kernel confirms freeze requests
// unless a test disables it.
func newShrinkService(t *testing.T) (*sandboxService, *resizeCgroups, *runtime.ShrinkResourcesRequest) {
	t.Helper()
	h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	h.config.CPULimitMode = config.CPULimitModeQuota
	h.config.ResourceConfig.MemoryHighRatio = 0.8
	cgroupPath := t.TempDir()
	policy := elasticResourcePolicy{
		Version: 1,
		CPU:     elasticBounds{Initial: 500, Ceiling: 8000},
		Memory:  elasticBounds{Initial: 128, Ceiling: 8192},
	}
	labels := map[string]string{elasticResourcesLabel: mustMarshalPolicy(t, policy)}
	labels[resourceGenerationLabel] = "generation-1"
	require.NoError(t, h.sandboxManager.StoreMetadata("elastic", &runtime.SandboxMetadata{
		ID: "elastic", RuntimeHandler: "runsc", Labels: labels,
		ResourceFacts: map[string]string{config.ResourceNameCgroup: cgroupPath},
	}))
	c := &resizeCgroups{
		highRatio: 0.8, requestKnown: true, eventsKnown: true,
		autoFreezeConfirm: true, shrinkSupported: true,
		stats: cgroupmanager.Stats{
			CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true,
			MemoryLimitBytes: 512 * 1024 * 1024, MemoryLimitKnown: true,
			MemoryUsageBytes: 64 * 1024 * 1024, MemoryUsageKnown: true,
		},
	}
	c.applyMemoryHigh(c.stats.MemoryLimitBytes)
	h.cgroupMgr = c
	require.NoError(t, h.initResourceOperationState("elastic", "generation-1", cgroupPath))
	request := &runtime.ShrinkResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-shrink-1", ExpectedRevision: 1,
		Expected: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 512 * 1024 * 1024},
		Target:   &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 256 * 1024 * 1024},
	}
	return h, c, request
}

func mustMarshalPolicy(t *testing.T, policy elasticResourcePolicy) string {
	t.Helper()
	raw, err := json.Marshal(policy)
	require.NoError(t, err)
	return string(raw)
}

// The complete path freezes through the host cgroup only, writes memory.high
// before memory.max, confirms the unfreeze, and only then reports complete at
// the advanced revision.
func TestShrinkResourcesCompletePath(t *testing.T) {
	h, c, request := newShrinkService(t)
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, uint64(256*1024*1024), response.Actual.MemoryLimitBytes)
	require.Equal(t, cgroupmanager.MemoryHighBytes(256*1024*1024, 0.8), response.Actual.MemoryHighBytes)
	require.True(t, response.Actual.MemoryHighKnown)
	require.False(t, response.Actual.MemoryHighUnlimited)
	require.Equal(t, int64(50000), response.Actual.CpuQuotaUsec) // CPU untouched
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	require.Equal(t, "operation-shrink-1", response.Actual.ResourceOperationID)
	require.False(t, response.Actual.ResourceOperationPending)
	require.True(t, response.Actual.FrozenKnown)
	require.False(t, response.Actual.Frozen)
	// Freeze was requested and released; the kernel facts ended unfrozen.
	requested, events := c.freezeStateSnapshot()
	require.False(t, requested)
	require.False(t, events)
	require.Equal(t, 2, c.freezeWrites) // freeze + unfreeze
	require.Equal(t, 1, c.memoryWrites)
	// The durable outcome is complete at revision 2.
	state, result, err := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, uint64(2), state.Revision)
	require.Equal(t, resourceOutcomeComplete, state.LastOutcome)
	require.False(t, state.open())
}

// A completed shrink replays its recorded outcome; the same operation ID under
// any other request — or on the grow RPC — is a conflict, not a re-execution.
func TestShrinkReplayAndOperationIDConflicts(t *testing.T) {
	h, c, request := newShrinkService(t)
	_, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, 1, c.memoryWrites)
	// Same request: replay the proven result without touching the cgroup.
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, 1, c.memoryWrites)
	require.Equal(t, 2, c.freezeWrites)
	// Same ID, different target: fingerprint conflict.
	conflict := proto.Clone(request).(*runtime.ShrinkResourcesRequest)
	conflict.Target.MemoryLimitBytes = 384 * 1024 * 1024
	_, err = h.ShrinkResources(context.Background(), conflict)
	require.ErrorContains(t, err, "already used by a different request")
	// Same ID on the grow RPC: the kind is part of the fingerprint.
	asGrow := &runtime.ResizeResourcesRequest{
		SandboxID: conflict.SandboxID, ResourceGeneration: conflict.ResourceGeneration,
		DeadlineUnixMs: conflict.DeadlineUnixMs,
		OperationID:    conflict.OperationID, ExpectedRevision: conflict.ExpectedRevision,
		Expected: conflict.Expected, Target: conflict.Expected,
	}
	_, err = h.ResizeResources(context.Background(), asGrow)
	require.ErrorContains(t, err, "already used by a different request")
	require.Equal(t, 1, c.memoryWrites)
	// Stale revision (the ABA replay): rejected before any write.
	stale := proto.Clone(request).(*runtime.ShrinkResourcesRequest)
	stale.OperationID = "operation-shrink-2"
	_, err = h.ShrinkResources(context.Background(), stale)
	require.ErrorContains(t, err, "stale resource revision")
	require.Equal(t, 1, c.memoryWrites)
}

// 128→512→256 followed by a grow back to 512: replaying the first-round grow
// must be rejected by the revision compare — the real ABA replay.
func TestShrinkThenGrowRejectsOldOperationReplay(t *testing.T) {
	h, c, shrink := newShrinkService(t)
	_, err := h.ShrinkResources(context.Background(), shrink)
	require.NoError(t, err)
	grow := &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-grow-1", ExpectedRevision: 2,
		Expected: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 256 * 1024 * 1024},
		Target:   &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 512 * 1024 * 1024},
	}
	response, err := h.ResizeResources(context.Background(), grow)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, uint64(3), response.Actual.ResourceRevision)
	// Replay of the shrink at its old revision: stale.
	oldShrink := proto.Clone(shrink).(*runtime.ShrinkResourcesRequest)
	_, err = h.ShrinkResources(context.Background(), oldShrink)
	require.ErrorContains(t, err, "stale resource revision")
	// Replay of a first-round grow at revision 1: stale.
	ancientGrow := proto.Clone(grow).(*runtime.ResizeResourcesRequest)
	ancientGrow.OperationID = "operation-grow-ancient"
	ancientGrow.ExpectedRevision = 1
	_, err = h.ResizeResources(context.Background(), ancientGrow)
	require.ErrorContains(t, err, "stale resource revision")
	require.Equal(t, 1, c.memoryWrites)
}

// Shrink-only shape violations are rejected before the intent is persisted:
// CPU changes, targets at or above the current limit, and targets below the
// policy floor.
func TestShrinkRejectsInvalidTargetsBeforeIntent(t *testing.T) {
	cases := map[string]func(*runtime.ShrinkResourcesRequest){
		"cpu change":     func(r *runtime.ShrinkResourcesRequest) { r.Target.CpuQuotaUsec = 100000 },
		"cpu period":     func(r *runtime.ShrinkResourcesRequest) { r.Target.CpuPeriodUsec = 200000 },
		"memory grow":    func(r *runtime.ShrinkResourcesRequest) { r.Target.MemoryLimitBytes = 768 * 1024 * 1024 },
		"memory equal":   func(r *runtime.ShrinkResourcesRequest) { r.Target.MemoryLimitBytes = r.Expected.MemoryLimitBytes },
		"below floor":    func(r *runtime.ShrinkResourcesRequest) { r.Target.MemoryLimitBytes = 64 * 1024 * 1024 },
		"stale expected": func(r *runtime.ShrinkResourcesRequest) { r.Expected.MemoryLimitBytes = 256 * 1024 * 1024 },
		"missing opid":   func(r *runtime.ShrinkResourcesRequest) { r.OperationID = "" },
		"blank revision": func(r *runtime.ShrinkResourcesRequest) { r.ExpectedRevision = 0 },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			h, c, request := newShrinkService(t)
			modify(request)
			_, err := h.ShrinkResources(context.Background(), request)
			require.Error(t, err)
			require.Zero(t, c.freezeWrites)
			require.Zero(t, c.memoryWrites)
		})
	}
}

// Unproven observations never reach the freeze: unknown usage, unknown high,
// unknown frozen state, or a foreign/already-set freeze are all rejected
// pre-intent without unfreezing anything.
func TestShrinkRejectsUnknownOrForeignFreezeState(t *testing.T) {
	cases := map[string]func(c *resizeCgroups){
		"unknown usage":  func(c *resizeCgroups) { c.stats.MemoryUsageKnown = false },
		"unknown high":   func(c *resizeCgroups) { c.stats.MemoryHighKnown = false },
		"unknown frozen": func(c *resizeCgroups) { c.eventsKnown = false },
		"already frozen": func(c *resizeCgroups) {
			c.requestFrozen, c.eventsFrozen = true, true
		},
		"freeze requested only": func(c *resizeCgroups) { c.requestFrozen = true },
		"stale high": func(c *resizeCgroups) {
			c.stats.MemoryHighBytes = 1 << 20
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			h, c, request := newShrinkService(t)
			spoil(c)
			_, err := h.ShrinkResources(context.Background(), request)
			require.Error(t, err)
			require.Zero(t, c.freezeWrites, "no freeze request may be issued")
			require.Zero(t, c.memoryWrites)
			state, result, readErr := h.loadResourceOperationState("elastic", "generation-1")
			require.NoError(t, readErr)
			require.Equal(t, resourceStateLoaded, result)
			require.False(t, state.open(), "no intent may be persisted")
		})
	}
}

// The runtime gate: only runsc sandboxes shrink; other runtimes are rejected
// explicitly, never silently degraded.
func TestShrinkRejectsNonRunscRuntime(t *testing.T) {
	h, c, _ := newShrinkService(t)
	// A second, non-runsc incarnation with the same elastic shape: the
	// runtime gate must reject it explicitly before any freeze or write.
	policy := elasticResourcePolicy{
		Version: 1, CPU: elasticBounds{500, 8000}, Memory: elasticBounds{128, 8192},
	}
	labels := map[string]string{
		elasticResourcesLabel:   mustMarshalPolicy(t, policy),
		resourceGenerationLabel: "generation-kata",
	}
	cgroupPath := t.TempDir()
	require.NoError(t, h.sandboxManager.StoreMetadata("katabox", &runtime.SandboxMetadata{
		ID: "katabox", RuntimeHandler: "kata", Labels: labels,
		ResourceFacts: map[string]string{config.ResourceNameCgroup: cgroupPath},
	}))
	require.NoError(t, h.initResourceOperationState("katabox", "generation-kata", cgroupPath))
	_, err := h.ShrinkResources(context.Background(), &runtime.ShrinkResourcesRequest{
		SandboxID: "katabox", ResourceGeneration: "generation-kata",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-shrink-kata", ExpectedRevision: 1,
		Expected: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 512 * 1024 * 1024},
		Target:   &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 256 * 1024 * 1024},
	})
	require.ErrorContains(t, err, "does not support shrink")
	require.Zero(t, c.freezeWrites)
	require.Zero(t, c.memoryWrites)
}

// A freeze that the kernel never confirms is undone: no memory write, no
// complete, the revision stays advanced, and the sandbox ends unfrozen.
func TestShrinkFreezeTimeoutUnwindsOwnRequest(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.autoFreezeConfirm = false // the kernel never reaches frozen
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "freeze not confirmed")
	require.Zero(t, c.memoryWrites)
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision, "partial outcomes keep the advanced revision")
	require.False(t, response.Actual.ResourceOperationPending)
	requested, _ := c.freezeStateSnapshot()
	require.False(t, requested, "the own freeze request must be released")
	state, result, readErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, readErr)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, resourceOutcomeFreezeTimeout, state.LastOutcome)
}

// Frozen usage that does not fit under the target high with the node headroom
// is a refusal, not a forced shrink: no write, released freeze, revision
// advanced with the unsafe outcome.
func TestShrinkRefusesWorkingSetBelowTargetHigh(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.onWriteFreeze = func(frozen bool) {
		if frozen {
			// The workload still holds memory after the freeze.
			c.mu.Lock()
			c.stats.MemoryUsageBytes = 220 * 1024 * 1024
			c.mu.Unlock()
		}
	}
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "does not fit target memory.high")
	require.Zero(t, c.memoryWrites)
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.False(t, response.Actual.ResourceOperationPending)
	state, result, readErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, readErr)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, resourceOutcomeUnsafeHeadroom, state.LastOutcome)
}

// A write that lands memory.high but fails memory.max is a truthful partial:
// the original controls are restored (never above the original max), the
// freeze is released, the revision stays advanced, and complete stays false.
func TestShrinkPartialWriteRestoresOriginalLimits(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.partialHighWrite = true
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "memory.max write failed")
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.Equal(t, cgroupmanager.MemoryHighBytes(512*1024*1024, 0.8), response.Actual.MemoryHighBytes)
	require.False(t, response.Actual.Frozen)
	require.False(t, response.Actual.ResourceOperationPending)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	// high write + restore = two ordered writes.
	require.Equal(t, 2, c.memoryWrites)
	state, result, readErr := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, readErr)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, resourceOutcomePartial, state.LastOutcome)
	require.False(t, state.open())
}

// A full write failure is still not a no-op: readback reflects whatever the
// cgroup holds, the sandbox is unfrozen, and the outcome is partial.
func TestShrinkWriteFailureKeepsHonestPartial(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.failMemoryWrite = true
	response, err := h.ShrinkResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "memory.max write failed")
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.False(t, response.Actual.Frozen)
}

// An unfreeze that cannot be confirmed leaves the operation pending: the RPC
// is an uncertain error, Stats reports the operation as open, new operations
// are rejected, and background reconciliation closes it once the kernel
// answers.
func TestShrinkUnfreezeFailureLeavesPendingForRecovery(t *testing.T) {
	h, c, request := newShrinkService(t)
	c.onWriteFreeze = func(frozen bool) {
		if frozen {
			// The freeze file goes offline once the sandbox is frozen: the
			// later cleanup unfreeze write fails and the sandbox stays
			// frozen.
			c.mu.Lock()
			c.failFreezeWrite = true
			c.mu.Unlock()
		}
	}
	_, err := h.ShrinkResources(context.Background(), request)
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err))
	stats, statsErr := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, statsErr)
	require.True(t, stats.ResourceOperationPending)
	require.Equal(t, "operation-shrink-1", stats.ResourceOperationID)
	require.True(t, stats.ResourceRevisionKnown)
	require.Equal(t, uint64(2), stats.ResourceRevision)
	// New operations are rejected until reconciliation closes the record.
	next := proto.Clone(request).(*runtime.ShrinkResourcesRequest)
	next.OperationID, next.ExpectedRevision = "operation-shrink-2", 2
	next.Expected.MemoryLimitBytes = 256 * 1024 * 1024
	next.Target.MemoryLimitBytes = 128 * 1024 * 1024
	_, err = h.ShrinkResources(context.Background(), next)
	require.ErrorContains(t, err, "unclosed resource operation")
	// The scheduler can still observe the sandbox — frozen, with the new
	// limits the completed writes already enforce.
	require.True(t, stats.Frozen)
	require.Equal(t, uint64(256*1024*1024), stats.MemoryLimitBytes)
	// The kernel recovers; the self-heal pass closes the record.
	c.mu.Lock()
	c.failFreezeWrite = false
	c.eventsFrozen = false
	c.requestFrozen = false
	c.mu.Unlock()
	open, failures := h.healOpenResourceStates(context.Background())
	require.Zero(t, open)
	require.Zero(t, failures)
	stats, statsErr = h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, statsErr)
	require.False(t, stats.ResourceOperationPending)
	require.False(t, stats.Frozen)
	require.Equal(t, uint64(256*1024*1024), stats.MemoryLimitBytes)
	// Replay now returns the recorded recovered outcome — still not a success
	// claim fabricated by recovery.
	response, replayErr := h.ShrinkResources(context.Background(), request)
	require.NoError(t, replayErr)
	require.True(t, response.Complete) // the physical readback verified the target
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
}

// The freeze window is exclusive with Pause/Resume: an external pause request
// waits for the shrink's physical lock instead of interleaving.
func TestShrinkFreezeWindowExcludesPause(t *testing.T) {
	h, c, request := newShrinkService(t)
	freezer := &fakeTaskFreezer{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", freezer)
	inFreeze, proceed := make(chan struct{}), make(chan struct{})
	c.onWriteFreeze = func(frozen bool) {
		if frozen {
			close(inFreeze)
			<-proceed
		}
	}
	done := make(chan error, 1)
	go func() { _, err := h.ShrinkResources(context.Background(), request); done <- err }()
	<-inFreeze
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := h.Pause(ctx, &runtime.PauseRequest{ID: "elastic"})
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	require.Zero(t, freezer.paused, "pause must not run while the shrink holds the lock")
	close(proceed)
	require.NoError(t, <-done)
	_, err = h.Pause(context.Background(), &runtime.PauseRequest{ID: "elastic"})
	require.NoError(t, err)
	require.Equal(t, 1, freezer.paused)
}

type fakeTaskFreezer struct {
	svc.Handler
	paused  int
	resumed int
}

func (f *fakeTaskFreezer) Pause(context.Context, string) error {
	f.paused++
	return nil
}

func (f *fakeTaskFreezer) Resume(context.Context, string) error {
	f.resumed++
	return nil
}

// Cancelling the original RPC inside the freeze window stops any new memory
// write but never skips the bounded cleanup: gRPC cancellation cannot leave
// this daemon's own freeze behind.
func TestShrinkCleanupSurvivesRPCCancellation(t *testing.T) {
	h, c, request := newShrinkService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.onWriteFreeze = func(frozen bool) {
		if frozen {
			cancel()
		}
	}
	response, err := h.ShrinkResources(ctx, request)
	require.NoError(t, err)
	require.False(t, response.Complete, "a cancelled command must not lower limits")
	require.Zero(t, c.memoryWrites)
	require.Equal(t, uint64(512*1024*1024), response.Actual.MemoryLimitBytes)
	require.False(t, response.Actual.Frozen)
	require.False(t, response.Actual.ResourceOperationPending)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	requested, events := c.freezeStateSnapshot()
	require.False(t, requested, "the cleanup unfreeze still ran")
	require.False(t, events)
	require.Equal(t, 2, c.freezeWrites)
}
