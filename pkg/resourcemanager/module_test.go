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
	cpu     int64
	mem     int64
	stopped atomic.Bool
	err     error
	detail  NodeResourceDetail
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
	return s.detail
}

func (s *stubNodeResourceManager) GetAvailableResource() (int64, int64, error) {
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
// payload as known. On error the physical fields go unknown/zero; on
// recovery the fresh values are served again.
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
	require.NoError(t, m.Start())
	defer m.Stop()

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

	// Healthy phase: known physical values are served.
	m.refreshOnce()
	code, info := get()
	if code != http.StatusOK || !info.UsedKnown || info.UsedMem != 2<<30 {
		t.Fatalf("healthy phase: code=%d usedKnown=%v usedMem=%d", code, info.UsedKnown, info.UsedMem)
	}

	// Provider outage: values must not stay stale-as-known.
	resourceManager.err = errors.New("provider down")
	m.refreshOnce()
	code, info = get()
	if code != http.StatusOK {
		t.Fatalf("outage phase returned %d, want 200 with unknown fields", code)
	}
	if info.UsedKnown || info.UsedMem != 0 || info.UsedCpu != 0 {
		t.Fatalf("outage phase served stale data: usedKnown=%v usedMem=%d usedCpu=%v",
			info.UsedKnown, info.UsedMem, info.UsedCpu)
	}

	// Recovery: fresh values served again.
	resourceManager.err = nil
	m.refreshOnce()
	code, info = get()
	if code != http.StatusOK || !info.UsedKnown || info.UsedMem != 2<<30 {
		t.Fatalf("recovery phase: code=%d usedKnown=%v usedMem=%d", code, info.UsedKnown, info.UsedMem)
	}
}
