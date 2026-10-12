// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

type generationDeviceLeaseManager interface {
	AcquireForGeneration(string, string, []*runtime.XpuAllocation) (*svc.SpecUpdates, error)
	ReleaseIfGeneration(string, string) error
	ConfirmReleasedForGeneration(string, string) error
}

func (h *sandboxService) acquireDeviceLease(id, generation string, allocations []*runtime.XpuAllocation) (*svc.SpecUpdates, error) {
	if generation != "" {
		manager, ok := h.xpuMgr.(generationDeviceLeaseManager)
		if !ok || manager == nil {
			return nil, fmt.Errorf("original device generation capability is unavailable")
		}
		return manager.AcquireForGeneration(id, generation, allocations)
	}
	if len(allocations) == 0 {
		return nil, nil
	}
	if h.xpuMgr == nil {
		return nil, fmt.Errorf("XPU manager is not configured")
	}
	return h.xpuMgr.Acquire(id, allocations)
}

// Called only after runtime absence was checked. A returned release alone
// cannot acknowledge the progress step: independently read its durable proof.
func (h *sandboxService) releaseDeviceLease(id, generation string) error {
	if generation == "" {
		if h.xpuMgr != nil {
			h.xpuMgr.Release(id)
		}
		return nil
	}
	manager, ok := h.xpuMgr.(generationDeviceLeaseManager)
	if !ok || manager == nil {
		return fmt.Errorf("original device generation capability is unavailable")
	}
	if err := manager.ReleaseIfGeneration(id, generation); err != nil {
		return fmt.Errorf("release original device lease: %w", err)
	}
	if err := manager.ConfirmReleasedForGeneration(id, generation); err != nil {
		return fmt.Errorf("confirm original device release: %w", err)
	}
	return nil
}

func (h *sandboxService) verifyRetirementDeviceCompletion(record *retirementProgress) error {
	if record == nil {
		return nil
	}
	if record.DeviceProtocol != 1 {
		return fmt.Errorf("legacy device acknowledgement has no original completion protocol")
	}
	manager, ok := h.xpuMgr.(generationDeviceLeaseManager)
	if !ok || manager == nil {
		return fmt.Errorf("original device completion capability is unavailable")
	}
	return manager.ConfirmReleasedForGeneration(record.SandboxID, record.Generation)
}
