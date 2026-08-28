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

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/protobuf/proto"
)

const minimumFirecrackerCheckpointHeadroom = int64(512 * 1024 * 1024)

const firecrackerCheckpointCleanupTimeout = 20 * time.Second

func firecrackerCheckpointReservationOwner(sandboxID string) string {
	return "firecracker-checkpoint:" + sandboxID
}

func firecrackerCheckpointHeadroom(guestMemory int64) int64 {
	if guestMemory <= 0 {
		return 0
	}
	if guestMemory > math.MaxInt64/3*2 {
		return math.MaxInt64
	}
	headroom := guestMemory + guestMemory/2
	if headroom < minimumFirecrackerCheckpointHeadroom {
		return minimumFirecrackerCheckpointHeadroom
	}
	return headroom
}

func addResourceMemory(resource *runtime.LinuxSandboxResources, bytes int64) {
	if resource == nil || bytes <= 0 {
		return
	}
	resource.MemoryLimitInBytes = saturatingAdd(resource.MemoryLimitInBytes, bytes)
	if resource.MemorySwapLimitInBytes > 0 {
		resource.MemorySwapLimitInBytes = saturatingAdd(resource.MemorySwapLimitInBytes, bytes)
	}
}

func saturatingAdd(value, increment int64) int64 {
	if increment <= 0 {
		return value
	}
	if value > math.MaxInt64-increment {
		return math.MaxInt64
	}
	return value + increment
}

func (h *sandboxService) withTransientFirecrackerCheckpointMemory(
	ctx context.Context,
	runtimeName string,
	sandboxID string,
	cgroupPath string,
	guestResources *runtime.LinuxSandboxResources,
	handler svc.Handler,
	operation func() error,
) error {
	if runtimeName != config.RuntimeNameFirecracker {
		return operation()
	}
	releaseSlot, err := h.acquireFirecrackerCheckpointMemorySlot(ctx)
	if err != nil {
		return err
	}
	defer releaseSlot()

	if h.cgroupMgr == nil || cgroupPath == "" {
		return fmt.Errorf("Firecracker checkpoint requires a managed cgroup")
	}
	if h.resourceMod == nil {
		return errors.New("Firecracker checkpoint requires node memory reservation")
	}
	normalResources := guestResources
	if provider, ok := handler.(svc.HostResourcesProvider); ok {
		normalResources = provider.HostResources(guestResources)
	} else if guestResources != nil {
		normalResources = proto.Clone(guestResources).(*runtime.LinuxSandboxResources)
	}
	headroom := int64(0)
	if guestResources != nil {
		headroom = firecrackerCheckpointHeadroom(guestResources.MemoryLimitInBytes)
	}
	if normalResources == nil || headroom == 0 {
		return operation()
	}
	expandedResources := proto.Clone(normalResources).(*runtime.LinuxSandboxResources)
	addResourceMemory(expandedResources, headroom)
	releaseReservation, reserved := h.resourceMod.ReserveTransientMemory(
		firecrackerCheckpointReservationOwner(sandboxID),
		headroom,
	)
	if !reserved {
		return fmt.Errorf(
			"insufficient node memory for Firecracker checkpoint: need %d bytes of transient headroom",
			headroom,
		)
	}
	if err := h.cgroupMgr.Prepare(cgroupPath, expandedResources); err != nil {
		releaseReservation()
		return fmt.Errorf("raise Firecracker checkpoint cgroup memory limit: %w", err)
	}
	operationErr := operation()
	if err := h.cgroupMgr.Prepare(cgroupPath, normalResources); err == nil {
		releaseReservation()
		return operationErr
	} else {
		limitErr := fmt.Errorf("restore Firecracker cgroup memory limit: %w", err)
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			firecrackerCheckpointCleanupTimeout,
		)
		deleteErr := handler.Delete(cleanupCtx, sandboxID)
		cancel()
		if deleteErr == nil {
			releaseReservation()
			return errors.Join(
				operationErr,
				limitErr,
				fmt.Errorf(
					"stopped Firecracker sandbox %s after cgroup rollback failure",
					sandboxID,
				),
			)
		}
		return errors.Join(
			operationErr,
			limitErr,
			fmt.Errorf(
				"stop Firecracker sandbox %s after cgroup rollback failure: %w; node memory reservation retained",
				sandboxID,
				deleteErr,
			),
		)
	}
}

func (h *sandboxService) acquireFirecrackerCheckpointMemorySlot(
	ctx context.Context,
) (func(), error) {
	h.firecrackerCheckpointMemorySlotMu.Lock()
	if h.firecrackerCheckpointMemorySlot == nil {
		h.firecrackerCheckpointMemorySlot = make(chan struct{}, 1)
	}
	slot := h.firecrackerCheckpointMemorySlot
	h.firecrackerCheckpointMemorySlotMu.Unlock()

	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
