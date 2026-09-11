// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// resizeCgroups is the in-memory cgroup backend for the resource operation
// tests. It simulates the kernel-controlled facts the server can only
// observe: freeze request/event bits, memory.high/max writes, and per-file
// write failures for partial outcomes.
type resizeCgroups struct {
	stats        cgroupmanager.Stats
	writes       int
	memoryWrites int
	freezeWrites int
	failUpdate   bool
	failReadback bool
	noWrite      bool
	onPrepare    func()
	onStats      func()
	highRatio    float64

	mu                sync.Mutex
	requestFrozen     bool
	eventsFrozen      bool
	requestKnown      bool
	eventsKnown       bool
	autoFreezeConfirm bool // the kernel reaches the requested state instantly
	failFreezeRead    bool
	shrinkSupported   bool // the v2 freezer capability; false shapes a v1 backend
	failFreezeWrite   bool
	failMemoryWrite   bool // apply nothing, return an error
	partialHighWrite  bool // apply memory.high only, return an error
	onWriteFreeze     func(frozen bool)
}

func (c *resizeCgroups) ReadMemoryLimit(string) (int64, error) { return 0, nil }

func (*resizeCgroups) Allocate() (string, error)    { return "/sandbox/lease", nil }
func (*resizeCgroups) Recycle(string) error         { return nil }
func (*resizeCgroups) ShutDown() error              { return nil }
func (c *resizeCgroups) SupportsMemoryShrink() bool { return c.shrinkSupported }

func (c *resizeCgroups) Stats(name string) (cgroupmanager.Stats, error) {
	if c.onStats != nil {
		c.onStats()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failReadback && c.writes+c.memoryWrites > 0 {
		return cgroupmanager.Stats{}, errors.New("stats offline")
	}
	result := c.stats
	result.Frozen, result.FrozenKnown = c.eventsFrozen, c.eventsKnown
	// The v2 backend names the absolute directory it read; the fake's cgroup
	// paths are already absolute temp directories.
	result.MemoryCgroupPath = name
	return result, nil
}

// applyMemoryHigh mirrors the node policy so the fake enforces the same
// page-aligned value the server derives.
func (c *resizeCgroups) applyMemoryHigh(maxBytes uint64) {
	if c.highRatio > 0 {
		c.stats.MemoryHighBytes = cgroupmanager.MemoryHighBytes(maxBytes, c.highRatio)
		c.stats.MemoryHighKnown, c.stats.MemoryHighUnlimited = true, false
		return
	}
	c.stats.MemoryHighBytes = 0
	c.stats.MemoryHighKnown, c.stats.MemoryHighUnlimited = true, true
}

func (c *resizeCgroups) Prepare(_ string, r *runtime.LinuxSandboxResources) error {
	if c.onPrepare != nil {
		c.onPrepare()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if !c.noWrite {
		c.stats.CPUQuotaUsec, c.stats.CPUPeriodUsec = r.CpuQuota, r.CpuPeriod
		c.stats.MemoryLimitBytes = uint64(r.MemoryLimitInBytes)
		c.applyMemoryHigh(c.stats.MemoryLimitBytes)
	}
	if c.failUpdate {
		return errors.New("memory.high write failed")
	}
	return nil
}

func (c *resizeCgroups) CgroupIdentity(name string) (cgroupmanager.CgroupIdentity, error) {
	info, err := os.Stat(name)
	if err != nil {
		return cgroupmanager.CgroupIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return cgroupmanager.CgroupIdentity{}, errors.New("no inode identity")
	}
	return cgroupmanager.CgroupIdentity{Path: name, Inode: stat.Ino, Device: uint64(stat.Dev)}, nil
}

func (c *resizeCgroups) ReadFreeze(string) (cgroupmanager.FreezeState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failFreezeRead {
		return cgroupmanager.FreezeState{}, errors.New("freeze files unreadable")
	}
	return cgroupmanager.FreezeState{
		RequestKnown: c.requestKnown, RequestFrozen: c.requestFrozen,
		EventsKnown: c.eventsKnown, Frozen: c.eventsFrozen,
	}, nil
}

func (c *resizeCgroups) WriteFreeze(_ string, frozen bool) error {
	c.mu.Lock()
	c.freezeWrites++
	if c.failFreezeWrite {
		c.mu.Unlock()
		return errors.New("freeze file offline")
	}
	c.requestFrozen = frozen
	if c.autoFreezeConfirm {
		c.eventsFrozen = frozen
	}
	hook := c.onWriteFreeze
	c.mu.Unlock()
	// The hook runs outside the lock so tests can block inside it.
	if hook != nil {
		hook(frozen)
	}
	return nil
}

func (c *resizeCgroups) WriteMemoryLimits(_ string, highBytes, maxBytes uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.memoryWrites++
	if c.failMemoryWrite {
		return errors.New("memory.max write failed")
	}
	// Fixed shrink order observable by tests: memory.high lands first.
	c.stats.MemoryHighBytes, c.stats.MemoryHighKnown, c.stats.MemoryHighUnlimited = highBytes, true, false
	if c.partialHighWrite {
		return errors.New("memory.max write failed after memory.high")
	}
	c.stats.MemoryLimitBytes = maxBytes
	return nil
}

// freezeStateSnapshot copies the simulated kernel freeze facts.
func (c *resizeCgroups) freezeStateSnapshot() (requestFrozen, eventsFrozen bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestFrozen, c.eventsFrozen
}

func newResizeService(t *testing.T) (*sandboxService, *resizeCgroups, *runtime.ResizeResourcesRequest) {
	t.Helper()
	h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	h.config.CPULimitMode = config.CPULimitModeQuota
	h.config.ResourceConfig.MemoryHighRatio = 0.8
	// The revision journal binds the cgroup's inode identity, so the fake
	// backend needs a real directory to stat.
	cgroupPath := t.TempDir()
	labels := elasticTestRequest(t).Labels
	labels[resourceGenerationLabel] = "generation-1"
	require.NoError(t, h.sandboxManager.StoreMetadata("elastic", &runtime.SandboxMetadata{
		ID: "elastic", RuntimeHandler: "runsc", Labels: labels,
		ResourceFacts: map[string]string{config.ResourceNameCgroup: cgroupPath},
	}))
	c := &resizeCgroups{
		highRatio: 0.8, requestKnown: true, eventsKnown: true, shrinkSupported: true,
		stats: cgroupmanager.Stats{
			CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true,
			MemoryLimitBytes: 512 * 1024 * 1024, MemoryLimitKnown: true,
			MemoryUsageBytes: 64 * 1024 * 1024, MemoryUsageKnown: true,
		},
	}
	c.applyMemoryHigh(c.stats.MemoryLimitBytes)
	h.cgroupMgr = c
	// The incarnation is created with a proven revision of 1.
	require.NoError(t, h.initResourceOperationState("elastic", "generation-1", cgroupPath))
	request := &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-grow-1", ExpectedRevision: 1,
		Expected: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 512 * 1024 * 1024},
		Target:   &runtime.ResourceLimits{CpuQuotaUsec: 100000, CpuPeriodUsec: 100000, MemoryLimitBytes: 1024 * 1024 * 1024},
	}
	return h, c, request
}

func TestResizeResourcesGrowthReadbackAndIdempotentRetry(t *testing.T) {
	h, c, request := newResizeService(t)
	response, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, int64(100000), response.Actual.CpuQuotaUsec)
	require.Equal(t, uint64(1024*1024*1024), response.Actual.MemoryLimitBytes)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	require.True(t, response.Actual.ResourceRevisionKnown)
	require.Equal(t, "operation-grow-1", response.Actual.ResourceOperationID)
	require.False(t, response.Actual.ResourceOperationPending)
	// The revision advances exactly once per executed operation.
	state, result, err := h.loadResourceOperationState("elastic", "generation-1")
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, uint64(2), state.Revision)
	// An identical retry replays the recorded outcome; it never re-executes
	// the write under the revision contract.
	response, err = h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	require.Equal(t, 1, c.writes)
	// A fresh operation under the new revision may re-issue the same targets,
	// which is what repairs a stale memory.high after a partial write.
	followUp := proto.Clone(request).(*runtime.ResizeResourcesRequest)
	followUp.OperationID, followUp.ExpectedRevision = "operation-grow-2", 2
	followUp.Expected = proto.Clone(request.Target).(*runtime.ResourceLimits)
	response, err = h.ResizeResources(context.Background(), followUp)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, uint64(3), response.Actual.ResourceRevision)
	require.Equal(t, 2, c.writes)
}

func TestResizeResourcesRejectsStaleAndInvalidRequestsBeforeWrite(t *testing.T) {
	cases := map[string]func(*runtime.ResizeResourcesRequest){
		"stale generation": func(r *runtime.ResizeResourcesRequest) { r.ResourceGeneration = "old" },
		"stale expected":   func(r *runtime.ResizeResourcesRequest) { r.Expected.MemoryLimitBytes++ },
		"cpu ceiling":      func(r *runtime.ResizeResourcesRequest) { r.Target.CpuQuotaUsec = 900000 },
		"memory ceiling":   func(r *runtime.ResizeResourcesRequest) { r.Target.MemoryLimitBytes = 9000 * 1024 * 1024 },
		"cpu period":       func(r *runtime.ResizeResourcesRequest) { r.Target.CpuPeriodUsec = 200000 },
		"decrease":         func(r *runtime.ResizeResourcesRequest) { r.Target.MemoryLimitBytes = 128 * 1024 * 1024 },
		"missing target":   func(r *runtime.ResizeResourcesRequest) { r.Target = nil },
		"missing opid":     func(r *runtime.ResizeResourcesRequest) { r.OperationID = "" },
		"blank revision":   func(r *runtime.ResizeResourcesRequest) { r.ExpectedRevision = 0 },
		"stale revision": func(r *runtime.ResizeResourcesRequest) {
			r.ExpectedRevision = 2 // the incarnation is still on revision 1
		},
		"opid control character": func(r *runtime.ResizeResourcesRequest) {
			r.OperationID = "operation-grow-1\x00"
		},
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			h, c, request := newResizeService(t)
			modify(request)
			_, err := h.ResizeResources(context.Background(), request)
			require.Error(t, err)
			require.Zero(t, c.writes)
		})
	}
}

// An incarnation without revision state (created before this contract, or
// with the journal removed) must reject bidirectional operations instead of
// guessing an initial revision; Stats reports the revision as unknown.
func TestResizeRejectsIncarnationsWithoutProvenRevision(t *testing.T) {
	h, c, request := newResizeService(t)
	_, path := h.resourceStatePath("elastic", "generation-1")
	require.NoError(t, os.Remove(path))
	stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, err)
	require.False(t, stats.ResourceRevisionKnown)
	require.Zero(t, stats.ResourceRevision)
	require.False(t, stats.ResourceOperationPending)
	_, err = h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "no proven resource revision")
	require.Zero(t, c.writes)
}

func TestResizeResourcesReportsPartialWritesAndUncertainReadback(t *testing.T) {
	h, c, request := newResizeService(t)
	c.failUpdate = true
	response, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "memory.high")
	require.Equal(t, request.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	// A partial outcome keeps the advanced revision and closes the operation:
	// the controller reconciles through Stats, not by re-running the command.
	require.Equal(t, uint64(2), response.Actual.ResourceRevision)
	require.False(t, response.Actual.ResourceOperationPending)
	c.failUpdate = false
	// Replaying the partial operation returns the recorded outcome without
	// another write; a fresh operation under the new revision repairs it.
	response, err = h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "memory.high")
	require.Equal(t, 1, c.writes)
	followUp := proto.Clone(request).(*runtime.ResizeResourcesRequest)
	followUp.OperationID, followUp.ExpectedRevision = "operation-grow-2", 2
	followUp.Expected = proto.Clone(request.Target).(*runtime.ResourceLimits)
	response, err = h.ResizeResources(context.Background(), followUp)
	require.NoError(t, err)
	require.True(t, response.Complete)
	h, c, request = newResizeService(t)
	c.failReadback = true
	_, err = h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "after possible write")
	require.Equal(t, 1, c.writes)
	// The journal stays open: an uncertain readback is UNKNOWN, and a new
	// operation must not run until reconciliation closes it. Restore the
	// backend's readability first — the point is what Stats observes about
	// the still-open record, not the backend failure itself.
	c.failReadback = false
	stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, err)
	require.True(t, stats.ResourceOperationPending)
	require.Equal(t, "operation-grow-1", stats.ResourceOperationID)
	_, err = h.ResizeResources(context.Background(), &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(),
		OperationID:    "operation-grow-2", ExpectedRevision: 2,
		Expected: request.Expected, Target: request.Target,
	})
	require.ErrorContains(t, err, "unclosed resource operation")
	require.Equal(t, 1, c.writes)
	// Reconciliation (here: the startup-style scan with the backend back
	// online) closes the record with the physically verified outcome.
	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	stats, err = h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, err)
	require.False(t, stats.ResourceOperationPending)
	require.Equal(t, uint64(1024*1024*1024), stats.MemoryLimitBytes)
	h, c, request = newResizeService(t)
	c.noWrite = true
	response, err = h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
}

func TestResizeConcurrentDifferentTargetsCannotSpendSameExpectedLimits(t *testing.T) {
	h, c, request := newResizeService(t)
	other := proto.Clone(request).(*runtime.ResizeResourcesRequest)
	other.Target.MemoryLimitBytes = 2048 * 1024 * 1024
	errors := make(chan error, 2)
	for _, req := range []*runtime.ResizeResourcesRequest{request, other} {
		go func(r *runtime.ResizeResourcesRequest) {
			_, err := h.ResizeResources(context.Background(), r)
			errors <- err
		}(req)
	}
	err1, err2 := <-errors, <-errors
	require.True(t, (err1 == nil) != (err2 == nil))
	require.Equal(t, 1, c.writes)
}

func TestPhysicalLockSerializesAnIDAndDoesNotBlockOtherInstances(t *testing.T) {
	var locks physicalLocks
	unlock, err := locks.acquire(context.Background(), "a")
	require.NoError(t, err)
	other, err := locks.acquire(context.Background(), "b")
	require.NoError(t, err)
	other()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = locks.acquire(ctx, "a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	unlock()
	unlock()
	require.Empty(t, locks.keys)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := locks.acquire(context.Background(), "a")
			if err == nil {
				unlock()
			}
		}()
	}
	wg.Wait()
	require.Empty(t, locks.keys)
}

func TestResizeReusedSandboxIDRejectsOldPhysicalGeneration(t *testing.T) {
	h, c, request := newResizeService(t)
	require.NoError(t, h.sandboxManager.UpdateLabels("elastic", map[string]string{resourceGenerationLabel: "generation-2"}))
	stats, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "elastic"})
	require.NoError(t, err)
	require.Equal(t, "generation-2", stats.ResourceGeneration)
	_, err = h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "stale resource generation")
	require.Zero(t, c.writes)
}

func TestDeleteCannotRecycleWhileResizeWritesAndReadsBack(t *testing.T) {
	h, c, request := newResizeService(t)
	entered, proceed := make(chan struct{}), make(chan struct{})
	c.onPrepare = func() { close(entered); <-proceed }
	done := make(chan error, 1)
	go func() { _, err := h.ResizeResources(context.Background(), request); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := h.deleteSandboxRuntime(ctx, request.SandboxID)
	close(proceed)
	resizeErr := <-done
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, resizeErr)
	_, err = h.sandboxManager.Get(request.SandboxID)
	require.NoError(t, err)
}

func TestResizeCannotRunDuringPhysicalRecovery(t *testing.T) {
	h, c, request := newResizeService(t)
	h.recoveryReady.Store(false)
	_, err := h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "recovery is incomplete")
	require.Zero(t, c.writes)
}

func TestResizeResourcesOverGRPCPreservesIdentityAndReadback(t *testing.T) {
	h, counters, request := newResizeService(t)
	counters.stats.CPUPressureKnown = true
	counters.stats.CPUPeriods = 25
	counters.stats.CPUThrottledPeriods = 4
	counters.stats.CPUThrottledNanos = 123000
	counters.stats.MemoryPressureKnown = true
	counters.stats.MemoryHighEvents = 9
	counters.stats.MemoryOOMEvents = 2
	counters.stats.MemoryOOMKillEvents = 1
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	runtime.RegisterSandboxServiceServer(server, h)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///sandboxd-local-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := runtime.NewSandboxServiceClient(conn)
	before, err := client.Stats(ctx, &runtime.StatsRequest{ID: request.SandboxID})
	require.NoError(t, err)
	require.Equal(t, request.ResourceGeneration, before.ResourceGeneration)
	require.NotEmpty(t, before.ElasticPolicy)
	require.True(t, before.CpuPressureKnown)
	require.Equal(t, uint64(25), before.CpuPeriods)
	require.Equal(t, uint64(4), before.CpuThrottledPeriods)
	require.Equal(t, uint64(123000), before.CpuThrottledNs)
	require.True(t, before.MemoryPressureKnown)
	require.Equal(t, uint64(9), before.MemoryHighEvents)
	require.Equal(t, uint64(2), before.MemoryOomEvents)
	require.Equal(t, uint64(1), before.MemoryOomKillEvents)
	response, err := client.ResizeResources(ctx, request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, request.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	require.Equal(t, before.ResourceGeneration, response.Actual.ResourceGeneration)
	// Even an otherwise idempotent request must not execute after its original
	// command deadline; the RPC transport must preserve this field.
	request.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
	_, err = client.ResizeResources(ctx, request)
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
}

type observedStartHandler struct {
	svc.Handler
	beforeStart func()
	started     bool
}

func (h *observedStartHandler) Start(context.Context, svc.StartConfig) error {
	if h.beforeStart != nil {
		h.beforeStart()
	}
	h.started = true
	return nil
}

func TestElasticReadbackMustPassBeforeRuntimeStart(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "applied", true: "setter_noop"}[mismatch], func(t *testing.T) {
			h, c, _ := newResizeService(t)
			handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
			h.serviceHandler.Set("runsc", handler)
			c.noWrite = mismatch
			c.stats.CPUQuotaUsec = 800000
			c.stats.MemoryLimitBytes = 8192 * 1024 * 1024
			c.applyMemoryHigh(c.stats.MemoryLimitBytes)
			// A distinct generation: the fixture already proved revision 1
			// for generation-1, and one incarnation is initialized once.
			annotations := elasticTestRequest(t).Labels
			annotations[resourceGenerationLabel] = "generation-readback"
			start := svc.StartConfig{
				ID: "elastic", CgroupPath: t.TempDir(),
				Resources:   &runtime.LinuxSandboxResources{CpuQuota: 50000, CpuPeriod: 100000, MemoryLimitInBytes: 512 * 1024 * 1024},
				Annotations: annotations,
			}
			metadata := &runtime.SandboxMetadata{
				ID: "elastic", RuntimeHandler: "runsc", Labels: annotations,
				PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
			}
			err := h.startSandboxRuntime(context.Background(), "runsc", start, metadata)
			if mismatch {
				require.ErrorContains(t, err, "readback does not match")
				require.False(t, handler.started)
			} else {
				require.NoError(t, err)
				require.True(t, handler.started)
			}
		})
	}
}

func TestResizeCommandExpiryRejectsUndeliveredAndQueuedWrites(t *testing.T) {
	for _, delta := range []time.Duration{0, -time.Second, 2 * time.Minute} {
		t.Run(delta.String(), func(t *testing.T) {
			h, c, req := newResizeService(t)
			req.DeadlineUnixMs = 0
			if delta != 0 {
				req.DeadlineUnixMs = time.Now().Add(delta).UnixMilli()
			}
			_, err := h.ResizeResources(context.Background(), req)
			require.Error(t, err)
			require.Zero(t, c.writes)
		})
	}
	t.Run("resource lock queue", func(t *testing.T) {
		h, c, req := newResizeService(t)
		unlock, err := h.resourceLocks.acquire(context.Background(), req.SandboxID)
		require.NoError(t, err)
		defer unlock()
		req.DeadlineUnixMs = time.Now().Add(100 * time.Millisecond).UnixMilli()
		_, err = h.ResizeResources(context.Background(), req)
		require.Equal(t, codes.DeadlineExceeded, status.Code(err))
		require.Zero(t, c.writes)
	})
	t.Run("expiry after readback before write", func(t *testing.T) {
		h, c, req := newResizeService(t)
		req.DeadlineUnixMs = time.Now().Add(100 * time.Millisecond).UnixMilli()
		read := false
		c.onStats = func() {
			read = true
			time.Sleep(time.Until(time.UnixMilli(req.DeadlineUnixMs).Add(10 * time.Millisecond)))
		}
		_, err := h.ResizeResources(context.Background(), req)
		require.True(t, read)
		require.Equal(t, codes.DeadlineExceeded, status.Code(err))
		require.Zero(t, c.writes)
	})
}
