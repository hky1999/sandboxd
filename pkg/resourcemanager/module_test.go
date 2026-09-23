// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resourcemanager

import (
	"errors"
	"sync"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/xpumanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubNodeResourceManager struct {
	mu      sync.Mutex
	cpu     int64
	mem     int64
	stopped atomic.Bool
	err     error
	detail  NodeResourceDetail
}

// setErr / setState take the stub lock so test-driven state changes are
// ordered against in-flight reads (race-detector clean).
func (s *stubNodeResourceManager) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *stubNodeResourceManager) setState(cpu, mem int64, detail NodeResourceDetail) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cpu, s.mem, s.detail = cpu, mem, detail
}

type stubXPUProvider struct {
	resources []xpumanager.Resource
}

type stubEphemeralStorageProvider struct {
	capacity    uint64
	allocatable uint64
}

func (s stubEphemeralStorageProvider) EphemeralStorageCapacity() (uint64, uint64, error) {
	return s.capacity, s.allocatable, nil
}

func (s stubXPUProvider) Resources() []xpumanager.Resource {
	return s.resources
}

func (s *stubNodeResourceManager) GetNodeResourceDetail() NodeResourceDetail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.detail
}

func (s *stubNodeResourceManager) GetAvailableResource() (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, 0, s.err
	}
	return s.cpu, s.mem, nil
}

func (s *stubNodeResourceManager) Stop() {
	s.stopped.Store(true)
}

func TestModuleCapacityReportsCachedAvailable(t *testing.T) {
	// Capacity must mirror the cached availability the refresh loop computes
	// and serves over the socket: availCpu is stored in cores and scaled back
	// to millicores, availMem passes through as bytes.
	m := &Module{availCpu: 47, availMem: 318 << 30}
	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(47000), cpuMilli)
	assert.Equal(t, int64(318<<30), memBytes)
}

func TestModuleCapacityZeroBeforeFirstRefresh(t *testing.T) {
	// Before any refresh, the cache is zero; the collector treats (0, 0) as
	// "no data" and skips observing, so the metric is absent rather than 0.
	m := &Module{}
	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(0), cpuMilli)
	assert.Equal(t, int64(0), memBytes)
}

func TestTransientMemoryReservationAffectsAdvertisedCapacity(t *testing.T) {
	m := &Module{availCpu: 4, availMem: 8 << 30}
	releaseFirst, ok := m.ReserveTransientMemory("checkpoint-a", 3<<30)
	assert.True(t, ok)
	_, ok = m.ReserveTransientMemory("checkpoint-b", 6<<30)
	assert.False(t, ok)
	releaseSecond, ok := m.ReserveTransientMemory("checkpoint-b", 5<<30)
	assert.True(t, ok)

	cpuMilli, memBytes := m.Capacity()
	assert.Equal(t, int64(4000), cpuMilli)
	assert.Zero(t, memBytes)

	releaseSecond()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(5<<30), memBytes)

	releaseFirst()
	releaseFirst()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(8<<30), memBytes)

	releaseThird, ok := m.ReserveTransientMemory("checkpoint-c", 2<<30)
	assert.True(t, ok)
	m.ReleaseTransientMemory("checkpoint-c")
	releaseThird()
	_, memBytes = m.Capacity()
	assert.Equal(t, int64(8<<30), memBytes)
}

func TestModuleServesAvailableResourceOverUnixSocket(t *testing.T) {
	resourceManager := &stubNodeResourceManager{cpu: 2500, mem: 5 << 30}
	sockPath := filepath.Join(t.TempDir(), "resource.sock")
	m := &Module{
		nodeResource: resourceManager,
		sockPath:     sockPath,
		stopCh:       make(chan struct{}),
		xpu: stubXPUProvider{resources: []xpumanager.Resource{{
			Type:         "gpu",
			ProductModel: "l20",
			DeviceIDs:    []uint32{0, 2},
		}}},
	}
	require.NoError(t, m.Start())
	m.SetEphemeralStorageProvider(stubEphemeralStorageProvider{
		capacity:    200 << 30,
		allocatable: 150 << 30,
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}
	assert.Eventually(t, func() bool {
		resp, err := client.Get("http://sandboxd/resource")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		var info resourceInfo
		if err := json.Unmarshal(body, &info); err != nil {
			return false
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			return false
		}
		if _, ok := fields["storage"]; !ok {
			return false
		}
		if _, ok := fields["ephemeral_storage"]; ok {
			return false
		}
		return info.Cpu == 2 && info.Mem == 5<<30 &&
			assert.Equal(t, uint64(150<<30), *info.Storage) &&
			assert.Equal(t, []string{storageQuotaFeature}, info.Features) &&
			assert.Equal(t, []xpumanager.Resource{{
				Type:         "gpu",
				ProductModel: "l20",
				DeviceIDs:    []uint32{0, 2},
			}}, info.Xpu)
	}, time.Second, 10*time.Millisecond)

	m.Stop()
	assert.True(t, resourceManager.stopped.Load())
}

// Module must satisfy the metrics CapacityProvider so the collector can read
// the socket-aligned availability figure.
var _ CapacityProvider = (*Module)(nil)


// Success -> provider error -> recovery: the socket never serves a stale
// payload as known. On error BOTH the physical fields and the advertised
// availability go unknown/zero; on recovery fresh (different) values are
// served, proving a real refresh happened. No background loop runs: the
// stub's mutex makes state changes and refreshes sequentially observable.
func TestModuleSocketServesUnknownDuringProviderOutage(t *testing.T) {
	resourceManager := &stubNodeResourceManager{
		cpu: 2500, mem: 5 << 30,
		detail: NodeResourceDetail{
			TotalCPUMilli: 4000, TotalMemBytes: 16 << 30,
			UsedCPUCores: 1.25, UsedMemBytes: 2 << 30, Known: true,
		},
	}
	sockPath := filepath.Join(t.TempDir(), "resource.sock")
	m := &Module{
		nodeResource: resourceManager,
		sockPath:     sockPath,
		stopCh:       make(chan struct{}),
	}
	// Bind the listener without the refresh goroutine so test refreshes
	// are the only writers.
	require.NoError(t, m.startListener())

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}
	get := func() (int, resourceInfo) {
		resp, err := client.Get("http://sandboxd/resource")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var info resourceInfo
		require.NoError(t, json.Unmarshal(body, &info))
		return resp.StatusCode, info
	}

	// Healthy phase: known physical values and real availability served.
	m.refreshOnce()
	code, info := get()
	if code != http.StatusOK || !info.UsedKnown || info.UsedMem != 2<<30 {
		t.Fatalf("healthy phase: code=%d usedKnown=%v usedMem=%d", code, info.UsedKnown, info.UsedMem)
	}
	if info.Cpu != 2500 || info.Mem != 5<<30 {
		t.Fatalf("healthy phase availability: cpu=%d mem=%d", info.Cpu, info.Mem)
	}

	// Provider outage: physical fields unknown AND availability zeroed.
	resourceManager.setErr(errors.New("provider down"))
	m.refreshOnce()
	code, info = get()
	if code != http.StatusOK {
		t.Fatalf("outage phase returned %d, want 200 with unknown fields", code)
	}
	if info.UsedKnown || info.UsedMem != 0 || info.UsedCpu != 0 {
		t.Fatalf("outage phase served stale physical data: usedKnown=%v usedMem=%d usedCpu=%v",
			info.UsedKnown, info.UsedMem, info.UsedCpu)
	}
	if info.Cpu != 0 || info.Mem != 0 {
		t.Fatalf("outage phase kept stale availability: cpu=%d mem=%d", info.Cpu, info.Mem)
	}

	// Recovery with DIFFERENT values proves a fresh refresh, not a replay.
	resourceManager.setState(1800, 3<<30,
		NodeResourceDetail{TotalCPUMilli: 4000, TotalMemBytes: 16 << 30,
			UsedCPUCores: 0.5, UsedMemBytes: 1 << 30, Known: true})
	m.refreshOnce()
	code, info = get()
	if code != http.StatusOK || !info.UsedKnown || info.UsedMem != 1<<30 {
		t.Fatalf("recovery phase: code=%d usedKnown=%v usedMem=%d", code, info.UsedKnown, info.UsedMem)
	}
	if info.Cpu != 1800 || info.Mem != 3<<30 {
		t.Fatalf("recovery phase availability: cpu=%d mem=%d", info.Cpu, info.Mem)
	}
}

// Over-age snapshots must be refused (503) instead of served stale, and
// become servable again after a fresh refresh.
func TestModuleSocketRefusesStaleSnapshot(t *testing.T) {
	resourceManager := &stubNodeResourceManager{cpu: 2500, mem: 5 << 30}
	sockPath := filepath.Join(t.TempDir(), "resource.sock")
	m := &Module{
		nodeResource:    resourceManager,
		sockPath:        sockPath,
		stopCh:          make(chan struct{}),
		stalenessWindow: 50 * time.Millisecond,
	}
	require.NoError(t, m.startListener())
	defer m.Stop()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}
	m.refreshOnce()
	resp, err := client.Get("http://sandboxd/resource")
	require.NoError(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh snapshot served %d, want 200", resp.StatusCode)
	}

	time.Sleep(80 * time.Millisecond) // exceed the 50ms test window
	resp, err = client.Get("http://sandboxd/resource")
	require.NoError(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stale snapshot served %d, want 503", resp.StatusCode)
	}

	m.refreshOnce() // recovery re-arms the window
	resp, err = client.Get("http://sandboxd/resource")
	require.NoError(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-refresh snapshot served %d, want 200", resp.StatusCode)
	}
}
