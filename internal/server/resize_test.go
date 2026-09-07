// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type resizeCgroups struct {
	stats        cgroupmanager.Stats
	writes       int
	failUpdate   bool
	failReadback bool
	noWrite      bool
	onPrepare    func()
}

func (*resizeCgroups) Allocate() (string, error) { return "/sandbox/lease", nil }
func (*resizeCgroups) Recycle(string) error      { return nil }
func (*resizeCgroups) ShutDown() error           { return nil }
func (c *resizeCgroups) Stats(string) (cgroupmanager.Stats, error) {
	if c.failReadback && c.writes > 0 {
		return cgroupmanager.Stats{}, errors.New("stats offline")
	}
	return c.stats, nil
}
func (c *resizeCgroups) Prepare(_ string, r *runtime.LinuxSandboxResources) error {
	if c.onPrepare != nil {
		c.onPrepare()
	}
	c.writes++
	if !c.noWrite {
		c.stats.CPUQuotaUsec, c.stats.CPUPeriodUsec = r.CpuQuota, r.CpuPeriod
		c.stats.MemoryLimitBytes = uint64(r.MemoryLimitInBytes)
	}
	if c.failUpdate {
		return errors.New("memory.high write failed")
	}
	return nil
}

func newResizeService(t *testing.T) (*sandboxService, *resizeCgroups, *runtime.ResizeResourcesRequest) {
	t.Helper()
	h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	h.config.CPULimitMode = config.CPULimitModeQuota
	labels := elasticTestRequest(t).Labels
	labels[resourceGenerationLabel] = "generation-1"
	require.NoError(t, h.sandboxManager.StoreMetadata("elastic", &runtime.SandboxMetadata{
		ID: "elastic", RuntimeHandler: "runsc", Labels: labels,
		ResourceFacts: map[string]string{config.ResourceNameCgroup: "/sandbox/lease"},
	}))
	c := &resizeCgroups{stats: cgroupmanager.Stats{
		CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true,
		MemoryLimitBytes: 512 * 1024 * 1024,
	}}
	h.cgroupMgr = c
	request := &runtime.ResizeResourcesRequest{
		SandboxID: "elastic", ResourceGeneration: "generation-1",
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
	require.Equal(t, "generation-1", response.Actual.ResourceGeneration)
	require.Contains(t, response.Actual.ElasticPolicy, "ceiling")
	response, err = h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, 2, c.writes) // repeat also repairs memory.high after a partial write
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

func TestResizeResourcesReportsPartialWritesAndUncertainReadback(t *testing.T) {
	h, c, request := newResizeService(t)
	c.failUpdate = true
	response, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.Contains(t, response.UpdateError, "memory.high")
	require.Equal(t, request.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	c.failUpdate = false
	response, err = h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	h, c, request = newResizeService(t)
	c.failReadback = true
	_, err = h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "after possible write")
	require.Equal(t, 1, c.writes)
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
	h, _, request := newResizeService(t)
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
	response, err := client.ResizeResources(ctx, request)
	require.NoError(t, err)
	require.True(t, response.Complete)
	require.Equal(t, request.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	require.Equal(t, before.ResourceGeneration, response.Actual.ResourceGeneration)
}

type observedStartHandler struct {
	svc.Handler
	started bool
}

func (h *observedStartHandler) Start(context.Context, svc.StartConfig) error {
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
			start := svc.StartConfig{
				ID: "elastic", CgroupPath: "/sandbox/lease",
				Resources:   &runtime.LinuxSandboxResources{CpuQuota: 50000, CpuPeriod: 100000, MemoryLimitInBytes: 512 * 1024 * 1024},
				Annotations: elasticTestRequest(t).Labels,
			}
			err := h.startSandboxRuntime(context.Background(), "runsc", start)
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
