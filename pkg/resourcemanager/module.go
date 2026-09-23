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
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/xpumanager"
	"github.com/sirupsen/logrus"
)

// Module owns node-resource reporting in either cgroup or Kubernetes watch
// mode. It runs the periodic refresh loop and serves the Unix-domain
// `/resource` endpoint consumed by an external scheduler.
//
// Lifecycle:
//   - NewModule constructs the underlying NodeResourceManager.
//   - Start launches the refresh loop and HTTP listener on sockPath.
//   - Stop closes the listener and drains the background loops.
//   - Healthy reports whether at least one successful refresh has occurred
//     within the staleness window.
type Module struct {
	nodeResource NodeResourceManager
	sockPath     string

	mu                        sync.RWMutex
	availCpu                  int64
	availMem                  int64
	totalCpu                  float64
	totalMem                  int64
	usedCpu                   float64
	usedMem                   int64
	usedKnown                 bool
	reservedCpu               float64
	reservedMem               int64
	xpu                       xpuProvider
	ephemeralStorage          ephemeralStorageProvider
	ephemeralStorageCapacity  uint64
	ephemeralStorageAvailable uint64
	ephemeralStorageReady     bool
	transientMemory           map[string]int64

	lastRefresh atomic.Int64 // unix-nano of most recent successful refresh
	// stalenessWindow overrides Healthy()'s 30s window when positive
	// (tests only; zero means the default).
	stalenessWindow time.Duration
	listener    net.Listener
	stopCh      chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup

	collectorShutdown func(context.Context) error
	collector         *Collector
}

// resourceInfo is the JSON payload served by the /resource endpoint. CPU is
// reported in scheduler cores, while memory and writable storage use bytes.
type resourceInfo struct {
	Cpu      int64                 `json:"cpu"`
	Mem      int64                 `json:"mem"`
	Xpu      []xpumanager.Resource `json:"xpu"`
	Storage  *uint64               `json:"storage,omitempty"`
	Features []string              `json:"features"`
	// Total/used node resources for consumers that need real usage math
	// (scheduler-side usage-aware admission). CPU is cores, memory bytes.
	// used* are PHYSICAL usage (cgroup of sandboxd), NOT pod requests;
	// zero is a valid value, so these fields carry no omitempty.
	// UsedKnown=false means the physical read failed: consumers must treat
	// the sample as unknown, never as zero. Reserved* expose pod requests
	// separately (informational). Legacy consumers keep reading cpu/mem
	// (available).
	TotalCpu   float64 `json:"totalCpu"`
	TotalMem   int64   `json:"totalMem"`
	UsedCpu    float64 `json:"usedCpu"`
	UsedMem    int64   `json:"usedMem"`
	UsedKnown  bool    `json:"usedKnown"`
	ReservedCpu  float64 `json:"reservedCpu,omitempty"`
	ReservedMem  int64   `json:"reservedMem,omitempty"`
}

type xpuProvider interface {
	Resources() []xpumanager.Resource
}

type ephemeralStorageProvider interface {
	EphemeralStorageCapacity() (capacityBytes, allocatableBytes uint64, err error)
}

const storageQuotaFeature = "storage-quota-v1"

// NewModule constructs the configured node-resource module. sockPath is the
// Unix socket exposed to the external collector.
func NewModule(sockPath, provider string) (*Module, error) {
	nrm, err := NewNodeResourceManager(provider)
	if err != nil {
		return nil, err
	}

	m := &Module{
		nodeResource:    nrm,
		sockPath:        sockPath,
		stopCh:          make(chan struct{}),
		transientMemory: make(map[string]int64),
	}

	// OTLP metrics push is best-effort: a missing collector at startup must
	// not block sandboxd from coming up.
	//
	// The collector reads m (not nrm directly) so node.cpu.limit /
	// node.memory.total report the same node-available figure the Module
	// caches and serves over the resource socket — see Module.Capacity.
	if collector, cerr := NewCollector(context.Background(), m); cerr != nil {
		logrus.Warnf("resourcemanager: metrics collector init failed: %v", cerr)
	} else {
		m.collector = collector
		m.collectorShutdown = collector.Shutdown
	}

	return m, nil
}

// SetSandboxMetricsSource connects the node metrics collector to sandbox
// lifecycle state once the sandbox manager is ready.
func (m *Module) SetSandboxMetricsSource(source SandboxMetricsSource) {
	if m.collector != nil {
		m.collector.SetSandboxMetricsSource(source)
	}
}

// SetXPUProvider adds the node-local accelerator inventory to /resource.
func (m *Module) SetXPUProvider(provider xpuProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.xpu = provider
}

// SetEphemeralStorageProvider adds filestore writable-layer capacity and its
// capability marker to /resource. The first refresh is synchronous so a
// scheduler querying immediately after sandboxd startup sees a complete node
// resource snapshot.
func (m *Module) SetEphemeralStorageProvider(provider ephemeralStorageProvider) {
	m.mu.Lock()
	m.ephemeralStorage = provider
	m.mu.Unlock()
	m.refreshEphemeralStorage()
}

// SetCgroupStatsReader routes all cgroup-backed OTel metrics through the
// CgroupManager's auto-selected v1/v2 implementation.
func (m *Module) SetCgroupStatsReader(
	reader func(string) (cgroupmanager.Stats, error),
) {
	if m.collector != nil {
		m.collector.SetCgroupStatsReader(reader)
	}
}

// MarkSandboxStopped records a terminal sandbox state for asynchronous export.
func (m *Module) MarkSandboxStopped(target sandbox.MetricsTarget) {
	if m.collector != nil {
		m.collector.MarkSandboxStopped(target)
	}
}

// Start launches the refresh loop and HTTP server. It returns once the
// listener is bound so external collectors can use the socket immediately.
func (m *Module) Start() error {
	if err := m.startListener(); err != nil {
		return err
	}
	// startListener already launched the serve goroutine; add the refresh
	// loop so production gets both. wg accounting: serve (+1) in
	// startListener, refresh (+1) here.
	m.startRefreshLoop()
	return nil
}

// startListener binds the socket and registers the /resource handler
// WITHOUT launching the refresh loop; tests use it so their explicit
// refreshOnce calls are the only cache writers. Start wires the loop on
// top.
func (m *Module) startListener() error {
	if _, err := os.Stat(m.sockPath); err == nil {
		os.Remove(m.sockPath)
	}
	ln, err := net.Listen("unix", m.sockPath)
	if err != nil {
		return err
	}
	m.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		// Never serve a payload whose physical fields are stale: an
		// over-age snapshot is explicit unknown data, so consumers cannot
		// refresh old observations into fresh samples.
		if !m.Healthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("resource snapshot stale\n"))
			return
		}
		m.mu.RLock()
		info := resourceInfo{
			Cpu:      m.availCpu,
			Mem:      availableAfterTransientReservations(m.availMem, m.transientMemory),
			Xpu:      []xpumanager.Resource{},
			Features: []string{},
			TotalCpu:   m.totalCpu,
			TotalMem:   m.totalMem,
			UsedCpu:    m.usedCpu,
			UsedMem:    m.usedMem,
			UsedKnown:  m.usedKnown,
			ReservedCpu:  m.reservedCpu,
			ReservedMem:  m.reservedMem,
		}
		if m.xpu != nil {
			info.Xpu = m.xpu.Resources()
		}
		if m.ephemeralStorageReady {
			storageBytes := m.ephemeralStorageAvailable
			info.Storage = &storageBytes
			info.Features = append(info.Features, storageQuotaFeature)
		}
		m.mu.RUnlock()
		body, _ := json.Marshal(info)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	m.wg.Add(1)
	go m.serve(mux)
	return nil
}

// startRefreshLoop launches only the background refresh goroutine.
func (m *Module) startRefreshLoop() {
	m.wg.Add(1)
	go m.refreshLoop()
}

// Stop closes the unix listener and waits for the refresh loop to drain.
// Safe to call from any goroutine; idempotent. The previous select+close
// pattern races on concurrent callers (two goroutines can both pass the
// default branch and double-close stopCh, panicking). sync.Once gives a
// true single-shot close; wg.Wait stays outside so every caller blocks
// until the background loops have actually exited, not just until the
// first caller observed stopCh as closed.
func (m *Module) Stop() {
	m.closeOnce.Do(func() {
		close(m.stopCh)
		if m.nodeResource != nil {
			m.nodeResource.Stop()
		}
		if m.listener != nil {
			_ = m.listener.Close()
		}
		if m.collectorShutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.collectorShutdown(ctx)
		}
	})
	m.wg.Wait()
}

// Healthy reports whether the latest provider refresh was within the
// staleness window. The window is a variable only so tests can age a
// snapshot deterministically without sleeping.
func (m *Module) Healthy() bool {
	ts := m.lastRefresh.Load()
	if ts == 0 {
		return false
	}
	window := m.stalenessWindow
	if window <= 0 {
		window = 30 * time.Second
	}
	return time.Since(time.Unix(0, ts)) < window
}

// Capacity returns the node's currently-available CPU (millicores) and memory
// (bytes) — the same figure the refresh loop computes via
// GetAvailableResource and serves over the /resource socket. It
// satisfies metrics.CapacityProvider so node.cpu.limit / node.memory.total
// report exactly what the resource manager tells the proxy is schedulable,
// rather than a static box size.
//
// Reading the cached values here (instead of calling GetAvailableResource
// again) keeps the metric in lockstep with the socket and avoids
// re-triggering the underlying computation's smoothing/state side effects.
// availCpu is stored in cores (the refresh loop already divided by 1000), so
// scale back to millicores to match the CapacityProvider contract. Returns
// (0, 0) before the first successful refresh, which the collector treats as
// "no data yet" and skips.
func (m *Module) Capacity() (int64, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.availCpu * 1000, availableAfterTransientReservations(m.availMem, m.transientMemory)
}

// ReserveTransientMemory atomically removes short-lived runtime overhead from
// the node capacity advertised to the scheduler. It fails when the refreshed
// available capacity cannot cover the request. The returned release function
// is idempotent so callers can use it on every terminal path.
func (m *Module) ReserveTransientMemory(owner string, bytes int64) (func(), bool) {
	if m == nil || owner == "" || bytes <= 0 {
		return func() {}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transientMemory == nil {
		m.transientMemory = make(map[string]int64)
	}
	if _, exists := m.transientMemory[owner]; exists ||
		bytes > availableAfterTransientReservations(m.availMem, m.transientMemory) {
		return func() {}, false
	}
	m.transientMemory[owner] = bytes
	return func() { m.ReleaseTransientMemory(owner) }, true
}

// ReleaseTransientMemory returns a short-lived reservation to advertised node
// capacity. It is idempotent so both the operation and a later sandbox delete
// can safely release the same owner.
func (m *Module) ReleaseTransientMemory(owner string) {
	if m == nil || owner == "" {
		return
	}
	m.mu.Lock()
	delete(m.transientMemory, owner)
	m.mu.Unlock()
}

func availableAfterTransientReservations(available int64, reservations map[string]int64) int64 {
	for _, reserved := range reservations {
		if reserved <= 0 {
			continue
		}
		if reserved >= available {
			return 0
		}
		available -= reserved
	}
	return available
}

func (m *Module) serve(mux *http.ServeMux) {
	defer m.wg.Done()
	srv := &http.Server{Handler: mux}
	// http.Serve returns when the listener is closed; that is the canonical
	// shutdown path, so log only at debug level.
	if err := srv.Serve(m.listener); err != nil && err != http.ErrServerClosed {
		logrus.Debugf("resourcemanager: /resource http server stopped: %v", err)
	}
}

func (m *Module) refreshLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	m.refreshOnce()
	for {
		select {
		case <-ticker.C:
			m.refreshOnce()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Module) refreshOnce() {
	cpu, mem, err := m.nodeResource.GetAvailableResource()
	if err != nil {
		// A failed refresh invalidates the cached physical facts entirely:
		// keeping the previous usedKnown=true would let the /resource
		// handler serve stale data as fresh samples.
		logrus.Errorf("resourcemanager: refresh failed: %v", err)
		m.mu.Lock()
		m.usedKnown = false
		m.usedCpu, m.usedMem = 0, 0
		// Stale availability must not keep authorizing admissions either.
		m.availCpu, m.availMem = 0, 0
		m.mu.Unlock()
		return
	}
	// Wire format expects CPU in cores; underlying manager returns
	// millicores (see standalone main.go for the same division).
	cpu /= 1000
	detail := m.nodeResource.GetNodeResourceDetail()
	m.mu.Lock()
	m.availCpu = cpu
	m.availMem = mem
	m.totalCpu = float64(detail.TotalCPUMilli) / 1000.0
	m.totalMem = detail.TotalMemBytes
	m.usedCpu = detail.UsedCPUCores
	m.usedMem = detail.UsedMemBytes
	// A failed physical read keeps NOTHING known: serving the previous
	// values with usedKnown=true would refresh stale data into new
	// samples on the consumer side.
	m.usedKnown = detail.Known
	if !detail.Known {
		m.usedCpu, m.usedMem = 0, 0
	}
	m.reservedCpu = float64(detail.ReservedCPUMilli) / 1000.0
	m.reservedMem = detail.ReservedMemBytes
	m.mu.Unlock()
	m.lastRefresh.Store(time.Now().UnixNano())
	logrus.Debugf("resourcemanager: avail cpu=%d cores mem=%d bytes", cpu, mem)
	m.refreshEphemeralStorage()
}

func (m *Module) refreshEphemeralStorage() {
	m.mu.RLock()
	provider := m.ephemeralStorage
	m.mu.RUnlock()
	if provider == nil {
		return
	}
	capacity, allocatable, err := provider.EphemeralStorageCapacity()
	if err != nil {
		logrus.Errorf("resourcemanager: ephemeral storage refresh failed: %v", err)
		return
	}
	m.mu.Lock()
	m.ephemeralStorageCapacity = capacity
	m.ephemeralStorageAvailable = allocatable
	m.ephemeralStorageReady = true
	m.mu.Unlock()
	logrus.Debugf(
		"resourcemanager: ephemeral storage capacity=%d bytes allocatable=%d bytes",
		capacity,
		allocatable,
	)
}
