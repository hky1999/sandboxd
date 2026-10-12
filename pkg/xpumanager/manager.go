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

// Package xpumanager discovers node accelerators and owns the local,
// fail-closed device leases used to validate scheduler allocations.
package xpumanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
)

const (
	TypeGPU = "gpu"

	AllocationAnnotation = "sandbox.akernel.dev/xpu-allocation"
)

// Resource is the stable XPU capacity shape exported from /resource.
type Resource struct {
	Type         string   `json:"type"`
	ProductModel string   `json:"product_model"`
	DeviceIDs    []uint32 `json:"device_ids"`
}

// Device contains provider-private identity for one scheduler-visible ID.
type Device struct {
	ID           uint32
	UUID         string
	ProductModel string
}

type leaseRecord struct {
	SandboxID  string   `json:"sandbox_id"`
	Generation string   `json:"generation,omitempty"`
	Type       string   `json:"type"`
	DeviceIDs  []uint32 `json:"device_ids"`
	DeviceUUID []string `json:"device_uuids"`
}

// Manager owns an immutable discovery snapshot and UUID-keyed leases.
type Manager struct {
	mu sync.RWMutex

	runscBinary string
	sandboxRoot string
	run         commandRunner
	stat        statFunc

	devices   map[uint32]Device
	resources []Resource
	leases    map[string]string
	healthy   bool
	reason    error

	generationStore   store.DbStore
	generationOwner   *generationJournalOwner
	generationRecords map[string]generationLeaseRecord
	generationDigest  string
}

// New discovers the local NVIDIA inventory. Discovery failure is intentionally
// non-fatal for sandboxd: CPU-only nodes stay usable and advertise no XPU.
func New(runscBinary, sandboxRoot string) *Manager {
	manager := newManager(runscBinary, sandboxRoot)
	if err := manager.discoverNVIDIA(); err != nil {
		manager.reason = err
		logrus.Infof("xpumanager: NVIDIA GPU support unavailable: %v", err)
		return manager
	}
	if err := manager.restoreLeases(); err != nil {
		manager.healthy = false
		manager.resources = nil
		manager.reason = err
		logrus.Errorf("xpumanager: refusing GPU allocations after lease recovery failure: %v", err)
		return manager
	}
	manager.healthy = true
	logrus.Infof("xpumanager: discovered %d schedulable NVIDIA GPU(s)", len(manager.devices))
	return manager
}

func newManager(runscBinary, sandboxRoot string) *Manager {
	return &Manager{
		runscBinary: runscBinary,
		sandboxRoot: sandboxRoot,
		run:         runCommand,
		stat:        os.Stat,
		devices:     make(map[uint32]Device),
		leases:      make(map[string]string),
	}
}

// Resources returns a deep copy of the stable capacity inventory. Active
// leases never alter this list.
func (m *Manager) Resources() []Resource {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.healthy {
		return []Resource{}
	}
	resources := make([]Resource, len(m.resources))
	for index := range m.resources {
		resources[index] = m.resources[index]
		resources[index].DeviceIDs = append([]uint32(nil), m.resources[index].DeviceIDs...)
	}
	return resources
}

// ReservedAnnotation reports whether key stores provider-owned allocation
// state. Callers must not be able to forge recovery metadata through labels.
func ReservedAnnotation(key string) bool {
	return key == AllocationAnnotation
}

// Acquire validates and atomically leases all requested devices.
func (m *Manager) Acquire(sandboxID string, allocations []*api.XpuAllocation) (*svc.SpecUpdates, error) {
	if len(allocations) == 0 {
		return nil, nil
	}
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required for XPU allocation")
	}
	if len(allocations) != 1 || allocations[0] == nil {
		return nil, errors.New("exactly one XPU allocation is supported")
	}
	allocation := allocations[0]
	if strings.ToLower(strings.TrimSpace(allocation.Type)) != TypeGPU {
		return nil, fmt.Errorf("unsupported XPU type %q", allocation.Type)
	}
	if len(allocation.DeviceIds) == 0 {
		return nil, errors.New("XPU device IDs must not be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generationOwner != nil {
		return nil, errors.New("managed device allocation requires its original generation")
	}
	record, err := m.resolveLeaseLocked(sandboxID, allocations)
	if err != nil {
		return nil, err
	}
	for _, uuid := range record.DeviceUUID {
		m.leases[uuid] = sandboxID
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode GPU lease: %w", err)
	}
	return nvidiaSpecUpdates(record.DeviceUUID, recordJSON), nil
}

// Resolve only; the generation path must persist ownership before leasing.
// Caller holds m.mu. Empty allocations are an explicit CPU-only request.
func (m *Manager) resolveLeaseLocked(sandboxID string, allocations []*api.XpuAllocation) (leaseRecord, error) {
	if len(allocations) == 0 {
		return leaseRecord{SandboxID: sandboxID}, nil
	}
	if len(allocations) != 1 || allocations[0] == nil {
		return leaseRecord{}, errors.New("exactly one XPU allocation is supported")
	}
	allocation := allocations[0]
	if strings.ToLower(strings.TrimSpace(allocation.Type)) != TypeGPU {
		return leaseRecord{}, fmt.Errorf("unsupported XPU type %q", allocation.Type)
	}
	if len(allocation.DeviceIds) == 0 {
		return leaseRecord{}, errors.New("XPU device IDs must not be empty")
	}
	if !m.healthy {
		if m.reason != nil {
			return leaseRecord{}, fmt.Errorf("GPU support is unavailable: %w", m.reason)
		}
		return leaseRecord{}, errors.New("GPU support is unavailable")
	}

	seen := make(map[uint32]struct{}, len(allocation.DeviceIds))
	devices := make([]Device, 0, len(allocation.DeviceIds))
	for _, id := range allocation.DeviceIds {
		if _, duplicate := seen[id]; duplicate {
			return leaseRecord{}, fmt.Errorf("duplicate GPU device ID %d", id)
		}
		seen[id] = struct{}{}
		device, ok := m.devices[id]
		if !ok {
			return leaseRecord{}, fmt.Errorf("GPU device ID %d is not in the node inventory", id)
		}
		if owner, leased := m.leases[device.UUID]; leased && owner != sandboxID {
			return leaseRecord{}, fmt.Errorf("GPU device ID %d is already leased by sandbox %s", id, owner)
		}
		devices = append(devices, device)
	}
	model := devices[0].ProductModel
	for _, device := range devices[1:] {
		if device.ProductModel != model {
			return leaseRecord{}, errors.New("all GPU devices in one allocation must have the same product model")
		}
	}

	uuids := make([]string, len(devices))
	for index, device := range devices {
		uuids[index] = device.UUID
	}
	return leaseRecord{
		SandboxID:  sandboxID,
		Type:       TypeGPU,
		DeviceIDs:  append([]uint32(nil), allocation.DeviceIds...),
		DeviceUUID: append([]string(nil), uuids...),
	}, nil
}

// Release releases all UUID leases owned by sandboxID. It is idempotent.
func (m *Manager) Release(sandboxID string) {
	if sandboxID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generationOwner != nil {
		if err := m.checkGenerationJournalLocked(); err != nil {
			logrus.WithError(err).Warn("preserve unknown device ownership during legacy release")
			return
		}
		for _, record := range m.generationRecords {
			if record.SandboxID == sandboxID && record.State != "released" {
				logrus.Warn("legacy device release cannot retire a generation-owned allocation")
				return
			}
		}
	}
	for uuid, owner := range m.leases {
		if owner == sandboxID {
			delete(m.leases, uuid)
		}
	}
}

func (m *Manager) restoreLeases() error {
	entries, err := os.ReadDir(m.sandboxRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read sandbox root %s: %w", m.sandboxRoot, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), config.SandboxIDPrefix) {
			continue
		}
		configPath := filepath.Join(m.sandboxRoot, entry.Name(), config.SandboxSpecFile)
		data, err := os.ReadFile(configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("read XPU lease from %s: %w", configPath, err)
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			return fmt.Errorf("parse XPU lease from %s: %w", configPath, err)
		}
		raw := spec.Annotations[AllocationAnnotation]
		if raw == "" {
			continue
		}
		var record leaseRecord
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return fmt.Errorf("parse XPU allocation annotation in %s: %w", configPath, err)
		}
		if record.SandboxID != entry.Name() || record.Type != TypeGPU ||
			len(record.DeviceIDs) == 0 || len(record.DeviceIDs) != len(record.DeviceUUID) {
			return fmt.Errorf("invalid XPU allocation annotation in %s", configPath)
		}
		if m.generationOwner != nil && record.Generation != "" {
			original, ok := m.generationRecords[record.Generation]
			if !ok || original.SandboxID != record.SandboxID || !original.Allocated || !reflect.DeepEqual(original.Lease, record) {
				return fmt.Errorf("original generation device annotation differs in %s", configPath)
			}
			if original.State == "released" {
				continue // A leftover spec cannot revive an independently retired lease.
			}
			if original.State != "active" {
				return fmt.Errorf("device allocation is unconfirmed in %s", configPath)
			}
		}
		for index, id := range record.DeviceIDs {
			device, ok := m.devices[id]
			if !ok || device.UUID != record.DeviceUUID[index] {
				return fmt.Errorf("GPU identity changed for device ID %d in %s", id, configPath)
			}
			if m.generationOwner != nil && record.Generation == "" && m.leases[device.UUID] != "" {
				return fmt.Errorf("legacy device annotation overlaps generation ownership in %s", configPath)
			}
			if owner, duplicate := m.leases[device.UUID]; duplicate && owner != record.SandboxID {
				return fmt.Errorf("GPU UUID %s is assigned to both %s and %s", device.UUID, owner, record.SandboxID)
			}
			m.leases[device.UUID] = record.SandboxID
		}
	}
	return nil
}

func buildResources(devices map[uint32]Device) []Resource {
	byModel := make(map[string][]uint32)
	for id, device := range devices {
		byModel[device.ProductModel] = append(byModel[device.ProductModel], id)
	}
	models := make([]string, 0, len(byModel))
	for model := range byModel {
		models = append(models, model)
	}
	sort.Strings(models)
	resources := make([]Resource, 0, len(models))
	for _, model := range models {
		ids := byModel[model]
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		resources = append(resources, Resource{
			Type:         TypeGPU,
			ProductModel: model,
			DeviceIDs:    ids,
		})
	}
	return resources
}
