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
	"os"
	"sort"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"google.golang.org/protobuf/proto"
)

const physicalIntentCleanupTimeout = 20 * time.Second

func (h *sandboxService) recoverPhysicalState(ctx context.Context) error {
	if err := h.fsMgr.Restore(h.sandboxManager.HasPhysicalRecord); err != nil {
		return fmt.Errorf("restore sandbox filesystem state: %w", err)
	}
	if err := h.reconcilePhysicalIntents(ctx); err != nil {
		return fmt.Errorf("reconcile sandbox physical intents: %w", err)
	}
	if err := h.restoreSandboxNetworkFacts(); err != nil {
		return fmt.Errorf("restore sandbox network facts: %w", err)
	}
	return nil
}

// reconcilePhysicalIntents removes creation attempts that never reached the
// durable COMMITTED boundary. A successful Restore response is emitted only
// after COMMITTED, so retaining an INTENT can never be required for replay.
func (h *sandboxService) reconcilePhysicalIntents(ctx context.Context) error {
	intents := h.sandboxManager.ListPhysicalIntents()
	sort.Slice(intents, func(i, j int) bool {
		return intents[i].ID < intents[j].ID
	})
	for _, metadata := range intents {
		if err := h.reconcilePhysicalIntent(ctx, metadata); err != nil {
			return err
		}
	}
	return nil
}

func (h *sandboxService) reconcileRestoreIntent(
	ctx context.Context,
	request *runtime.StartRequest,
	expectedIdentity *runtime.RestoreIdentity,
) error {
	if request == nil || request.SandboxID == "" {
		return nil
	}
	for _, metadata := range h.sandboxManager.ListPhysicalIntents() {
		if metadata.ID != request.SandboxID {
			continue
		}
		if expectedIdentity == nil || !proto.Equal(metadata.RestoreIdentity, expectedIdentity) {
			return fmt.Errorf(
				"sandbox %s restore identity conflicts with physical intent: %w",
				request.SandboxID,
				errord.ErrFailedPrecondition,
			)
		}
		return h.reconcilePhysicalIntent(ctx, metadata)
	}
	return nil
}

func (h *sandboxService) reconcilePhysicalIntent(
	ctx context.Context,
	metadata *runtime.SandboxMetadata,
) error {
	if metadata == nil || metadata.ID == "" || metadata.RuntimeHandler == "" {
		return fmt.Errorf("physical intent metadata is incomplete: %w", errord.ErrFailedPrecondition)
	}
	handler, ok := h.serviceHandler.Get(metadata.RuntimeHandler)
	if !ok {
		return fmt.Errorf("runtime handler %q for intent %s is unavailable: %w",
			metadata.RuntimeHandler, metadata.ID, errord.ErrUnavailable)
	}

	cleanupCtx, cancel := context.WithTimeout(ctx, physicalIntentCleanupTimeout)
	defer cancel()
	states, err := handler.List(cleanupCtx)
	if err != nil {
		return fmt.Errorf("list runtime facts for physical intent %s: %w", metadata.ID, err)
	}
	runtimeExists := false
	for _, state := range states {
		if state != nil && state.ID == metadata.ID {
			runtimeExists = true
			break
		}
	}
	if runtimeExists {
		if err := handler.Delete(cleanupCtx, metadata.ID); err != nil &&
			!errors.Is(err, errord.ErrNotFound) {
			return fmt.Errorf("delete runtime for physical intent %s: %w", metadata.ID, err)
		}
	} else if cleaner, ok := handler.(svc.PreparedStateCleaner); ok {
		if err := cleaner.CleanupPreparedState(cleanupCtx, metadata.ID); err != nil {
			return fmt.Errorf("cleanup prepared runtime state for physical intent %s: %w", metadata.ID, err)
		}
	}
	if h.xpuMgr != nil {
		h.xpuMgr.Release(metadata.ID)
	}
	if h.fsMgr != nil {
		if err := h.fsMgr.Release(metadata.ID); err != nil {
			return fmt.Errorf("release filesystem for physical intent %s: %w", metadata.ID, err)
		}
	}

	resources, err := h.physicalResources(metadata)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("collect resources for physical intent %s: %w", metadata.ID, err)
	}
	if cleanupErr := h.cleanupPhysicalDnatFacts(metadata, resources); cleanupErr != nil {
		return cleanupErr
	}
	if h.networkMgr != nil {
		h.networkMgr.releaseDnatPorts(metadata.ID)
	}
	if err == nil {
		if err := h.releaseStartResources(resources); err != nil {
			return fmt.Errorf("release resources for physical intent %s: %w", metadata.ID, err)
		}
	}

	h.sandboxManager.CleanSandboxRoot(metadata.ID)
	h.sandboxManager.ReleaseID(metadata.ID)
	return nil
}

func (h *sandboxService) physicalResources(
	metadata *runtime.SandboxMetadata,
) (sandbox.OccupiedResource, error) {
	if metadata != nil && len(metadata.ResourceFacts) > 0 {
		resources := sandbox.OccupiedResource{
			ID:        metadata.ID,
			Resources: make(map[string]string, len(metadata.ResourceFacts)),
		}
		for name, value := range metadata.ResourceFacts {
			resources.Resources[name] = value
		}
		return resources, nil
	}
	return h.sandboxManager.CollectResourceByID(metadata.ID)
}

func (h *sandboxService) cleanupPhysicalDnatFacts(
	metadata *runtime.SandboxMetadata,
	resources sandbox.OccupiedResource,
) error {
	if h.networkMgr == nil || metadata == nil || len(metadata.Ports) == 0 {
		return nil
	}
	encoded, ok := resources.Resources[config.ResourceNameInterface]
	if !ok {
		return nil
	}
	network, err := networkmanager.NewNetResource(encoded)
	if err != nil {
		return fmt.Errorf("decode network resource for physical intent %s: %w",
			metadata.ID, err)
	}
	if network.Ip == nil {
		return fmt.Errorf("physical intent %s network IP is missing: %w",
			metadata.ID, errord.ErrFailedPrecondition)
	}
	if err := h.networkMgr.cleanupPersistedDnatRules(
		metadata.ID, metadata.Ports, network.Ip.String()); err != nil {
		return fmt.Errorf("cleanup DNAT facts for physical intent %s: %w", metadata.ID, err)
	}
	return nil
}

func (h *sandboxService) persistPhysicalResourceFacts(
	metadata *runtime.SandboxMetadata,
	facts map[string]string,
) error {
	if metadata == nil {
		return fmt.Errorf("physical metadata is required: %w", errord.ErrInvalidArgument)
	}
	metadata.ResourceFacts = make(map[string]string, len(facts))
	for name, value := range facts {
		metadata.ResourceFacts[name] = value
	}
	return h.sandboxManager.PersistMetadata(metadata.ID, metadata)
}
