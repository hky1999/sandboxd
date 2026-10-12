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
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const physicalIntentCleanupTimeout = 20 * time.Second
const physicalIntentMetadataLimit = 4 * 1024 * 1024

func (h *sandboxService) recoverPhysicalState(ctx context.Context) error {
	owners := h.sandboxManager.ListPhysicalIntents()
	for _, c := range h.sandboxManager.List() {
		if c == nil || c.Metadata == nil {
			return fmt.Errorf("published physical ownership is incomplete")
		}
		owners = append(owners, proto.Clone(c.Metadata).(*runtime.SandboxMetadata))
	}
	if err := h.fsMgr.ValidatePhysicalOwners(owners); err != nil {
		return fmt.Errorf("validate original filesystem owners: %w", err)
	}
	if err := h.fsMgr.Restore(h.sandboxManager.HasPhysicalRecord); err != nil {
		return fmt.Errorf("restore sandbox filesystem state: %w", err)
	}
	if err := h.reconcilePhysicalIntents(ctx); err != nil {
		return fmt.Errorf("reconcile sandbox physical intents: %w", err)
	}
	if err := h.restoreSandboxNetworkFacts(); err != nil {
		return fmt.Errorf("restore sandbox network facts: %w", err)
	}
	// Resource-operation recovery runs last, still before recoveryReady: it
	// releases only this daemon's own verified freeze intents and leaves
	// anything unresolvable fail-closed with a diagnostic.
	if err := h.recoverResourceOperationStates(ctx); err != nil {
		return fmt.Errorf("recover resource operation states: %w", err)
	}
	return nil
}

// reconcilePhysicalIntents removes creation attempts that never reached the
// durable COMMITTED boundary. A successful Restore response is emitted only
// after COMMITTED, so retaining an INTENT can never be required for replay.
func (h *sandboxService) reconcilePhysicalIntents(ctx context.Context) error {
	intents := h.sandboxManager.ListPhysicalIntents()
	histories, err := h.failedCreationRetirementSnapshots(ctx)
	if err != nil {
		return err
	}
	type identity struct{ id, generation string }
	seen := make(map[identity]*runtime.SandboxMetadata, len(intents))
	for _, metadata := range intents {
		seen[identity{metadata.ID, metadata.Labels[resourceGenerationLabel]}] = metadata
	}
	for _, metadata := range histories {
		key := identity{metadata.ID, metadata.Labels[resourceGenerationLabel]}
		if current := seen[key]; current != nil {
			if !proto.Equal(current, metadata) {
				return fmt.Errorf("original physical intent differs from retirement history")
			}
			continue
		}
		seen[key] = metadata
		intents = append(intents, metadata)
	}
	sort.Slice(intents, func(i, j int) bool {
		if intents[i].ID == intents[j].ID {
			return intents[i].Labels[resourceGenerationLabel] < intents[j].Labels[resourceGenerationLabel]
		}
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
	if metadata == nil || !config.IsValidSandboxID(metadata.ID) || metadata.RuntimeHandler == "" ||
		metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
		return fmt.Errorf("physical intent metadata is incomplete: %w", errord.ErrFailedPrecondition)
	}
	metadata = proto.Clone(metadata).(*runtime.SandboxMetadata)
	cleanupCtx, cancel := context.WithTimeout(ctx, physicalIntentCleanupTimeout)
	defer cancel()
	unlock, err := h.resourceLocks.acquire(cleanupCtx, metadata.ID)
	if err != nil {
		return err
	}
	defer unlock()
	return h.reconcilePhysicalIntentLocked(cleanupCtx, metadata)
}

// Caller holds the same physical lock used by creation and conditional delete.
// Both explicit reconciliation and DeleteIfGeneration enter this one path;
// acquiring the non-reentrant lock again here would deadlock failed cleanup.
func (h *sandboxService) reconcilePhysicalIntentLocked(ctx context.Context, metadata *runtime.SandboxMetadata) error {
	if metadata == nil || !config.IsValidSandboxID(metadata.ID) || metadata.RuntimeHandler == "" ||
		metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
		return fmt.Errorf("physical intent metadata is incomplete: %w", errord.ErrFailedPrecondition)
	}
	metadata = proto.Clone(metadata).(*runtime.SandboxMetadata)
	cleanupCtx, cancel := context.WithTimeout(ctx, physicalIntentCleanupTimeout)
	defer cancel()
	generation := metadata.Labels[resourceGenerationLabel]
	if generation != "" {
		receipt, err := h.readRetirement(metadata.ID, generation)
		if err != nil {
			return err
		}
		if receipt != nil && receipt.Complete {
			return h.forgetCompletedFailedCreationIntent(metadata.ID, generation)
		}
		if complete, err := h.resumeRetirementCompletion(metadata.ID, generation); err != nil {
			return err
		} else if complete {
			return h.sandboxManager.ForgetRetiredPhysicalIntent(metadata)
		}
	}
	if err := h.verifyOriginalPhysicalIntent(metadata); err != nil {
		return err
	}
	resources, resourceErr := h.physicalResources(metadata)
	if resourceErr != nil && (generation != "" || !errors.Is(resourceErr, os.ErrNotExist)) {
		return fmt.Errorf("collect original resources for physical intent %s: %w", metadata.ID, resourceErr)
	}
	var progress *retirementProgress
	if generation != "" {
		prepared, err := h.beginRetirementProgress(metadata, resources)
		if err != nil {
			return err
		}
		progress = prepared
		if err := h.writeRetirement(metadata.ID, generation, false); err != nil {
			return err
		}
	}
	verify := func() error {
		if err := cleanupCtx.Err(); err != nil {
			return err
		}
		if err := h.verifyOriginalPhysicalIntent(metadata); err != nil {
			return err
		}
		return h.verifyRetirementProgressSnapshot(progress)
	}
	if err := verify(); err != nil {
		return err
	}
	handler, ok := h.serviceHandler.Get(metadata.RuntimeHandler)
	if !ok || handler == nil {
		return fmt.Errorf("runtime handler %q for intent %s is unavailable: %w",
			metadata.RuntimeHandler, metadata.ID, errord.ErrUnavailable)
	}

	states, err := handler.List(cleanupCtx)
	if err != nil {
		return fmt.Errorf("list runtime facts for physical intent %s: %w", metadata.ID, err)
	}
	runtimeCount := 0
	for _, state := range states {
		if state == nil {
			return fmt.Errorf("physical intent runtime inventory is incomplete: %w", errord.ErrUnavailable)
		}
		if state.ID == metadata.ID {
			runtimeCount++
		}
	}
	if runtimeCount > 1 {
		return fmt.Errorf("physical intent runtime inventory is ambiguous: %w", errord.ErrUnavailable)
	}
	if err := verify(); err != nil {
		return err
	}
	if runtimeCount == 1 {
		if err := h.retireOriginalRuntime(cleanupCtx, handler, metadata, progress); err != nil && !errors.Is(err, errord.ErrNotFound) {
			return fmt.Errorf("delete original intent runtime %s: %w", metadata.ID, err)
		}
	} else {
		if err := h.confirmAbsentRuntimeCgroup(cleanupCtx, handler, progress); err != nil {
			return err
		}
		if cleaner, ok := handler.(svc.PreparedStateCleaner); ok {
			if err := cleaner.CleanupPreparedState(cleanupCtx, metadata.ID); err != nil {
				return fmt.Errorf("cleanup prepared runtime state %s: %w", metadata.ID, err)
			}
		}
	}
	// A returned Delete/cleanup alone does not prove physical absence. Check
	// fresh inventory and the original durable identity before any recycling.
	states, err = handler.List(cleanupCtx)
	if err != nil {
		return fmt.Errorf("verify runtime absence for physical intent %s: %w", metadata.ID, err)
	}
	for _, state := range states {
		if state == nil || state.ID == metadata.ID {
			return fmt.Errorf("physical intent runtime absence is unconfirmed: %w", errord.ErrUnavailable)
		}
	}
	if err := verify(); err != nil {
		return err
	}
	if err := h.completeRetirementProgressStep(progress, "runtime"); err != nil {
		return err
	}
	// Failed creation retains any installed policy together with its endpoint.
	// Disconnect the original lease before removing ACLs, and never allow a
	// failed ACL cleanup to return that endpoint to the idle pool.
	if resourceErr == nil {
		if err := h.deactivateStartNetwork(resources); err != nil {
			return fmt.Errorf("deactivate network for physical intent %s: %w", metadata.ID, err)
		}
	}
	if err := h.completeRetirementProgressStep(progress, "network_disconnected"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if h.fsMgr != nil {
		var fsErr error
		if generation != "" {
			fsErr = h.fsMgr.ReleaseIfGeneration(metadata.ID, generation)
		} else {
			fsErr = h.fsMgr.Release(metadata.ID)
		}
		if fsErr != nil {
			return fmt.Errorf("release filesystem for physical intent %s: %w", metadata.ID, fsErr)
		}
	} else if progress != nil {
		return fmt.Errorf("original filesystem manager is unavailable")
	}
	if err := h.completeRetirementProgressStep(progress, "filesystem"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if h.aclMgr != nil {
		h.aclMu.Lock()
		aclErr := h.aclMgr.Remove(metadata.ID)
		h.aclMu.Unlock()
		if aclErr != nil {
			return fmt.Errorf("remove network ACL for physical intent %s: %w", metadata.ID, aclErr)
		}
	}
	if err := h.completeRetirementProgressStep(progress, "acl"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := h.releaseDeviceLease(metadata.ID, generation); err != nil {
		return err
	}
	if err := h.completeRetirementProgressStep(progress, "devices"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}

	if cleanupErr := h.cleanupPhysicalDnatFacts(metadata, resources); cleanupErr != nil {
		return cleanupErr
	}
	if h.networkMgr != nil {
		h.networkMgr.releaseDnatPorts(metadata.ID)
	}
	if err := h.completeRetirementProgressStep(progress, "dnat"); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if resourceErr == nil {
		if err := h.releaseStartResources(resources); err != nil {
			return fmt.Errorf("release resources for physical intent %s: %w", metadata.ID, err)
		}
	}
	if err := h.completeRetirementProgressStep(progress, "resources"); err != nil {
		return err
	}
	if progress != nil {
		return h.finishFailedCreationRetirement(cleanupCtx, metadata, progress)
	}

	h.sandboxManager.CleanSandboxRoot(metadata.ID)
	h.sandboxManager.ReleaseID(metadata.ID)
	return nil
}

// Caller holds the per-sandbox physical lock. Hidden in-memory intents can
// lag a COMMITTED disk write, so neither that cache nor ID equality alone
// authorizes cleanup: require the complete original durable metadata too.
func (h *sandboxService) verifyOriginalPhysicalIntent(metadata *runtime.SandboxMetadata) error {
	if _, err := h.sandboxManager.Get(metadata.ID); !errors.Is(err, errord.ErrNotFound) {
		return fmt.Errorf("physical intent is published or unavailable: %w", errord.ErrFailedPrecondition)
	}
	root := filepath.Join(h.config.RootDir, "containers", metadata.ID)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("physical intent directory is unavailable: %w", errord.ErrFailedPrecondition)
	}
	f, err := os.OpenFile(filepath.Join(root, config.SandboxMetaFile), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("read original physical intent: %w", err)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > physicalIntentMetadataLimit {
		return fmt.Errorf("physical intent metadata is not a bounded regular file: %w", errord.ErrFailedPrecondition)
	}
	data, err := io.ReadAll(io.LimitReader(f, physicalIntentMetadataLimit+1))
	if err != nil {
		return err
	}
	if len(data) > physicalIntentMetadataLimit {
		return fmt.Errorf("physical intent metadata exceeds its bound: %w", errord.ErrFailedPrecondition)
	}
	current := &runtime.SandboxMetadata{}
	if err := proto.Unmarshal(data, current); err != nil {
		return fmt.Errorf("decode original physical intent: %w", err)
	}
	if !proto.Equal(current, metadata) {
		return fmt.Errorf("physical intent identity or facts changed: %w", errord.ErrFailedPrecondition)
	}
	return nil
}

func (h *sandboxService) physicalResources(
	metadata *runtime.SandboxMetadata,
) (sandbox.OccupiedResource, error) {
	if metadata == nil || metadata.ID == "" {
		return sandbox.OccupiedResource{}, fmt.Errorf("physical resource identity is missing: %w", errord.ErrFailedPrecondition)
	}
	if metadata != nil && len(metadata.ResourceFacts) > 0 {
		resources := sandbox.OccupiedResource{
			ID:         metadata.ID,
			Generation: metadata.Labels[resourceGenerationLabel],
			Resources:  make(map[string]string, len(metadata.ResourceFacts)),
		}
		for name, value := range metadata.ResourceFacts {
			resources.Resources[name] = value
		}
		return resources, nil
	}
	resources, err := h.sandboxManager.CollectResourceByID(metadata.ID)
	if err != nil {
		return resources, err
	}
	generation := metadata.Labels[resourceGenerationLabel]
	if resources.Generation != "" && resources.Generation != generation {
		return resources, fmt.Errorf("physical resource spec generation changed: %w", errord.ErrFailedPrecondition)
	}
	resources.Generation = generation
	return resources, nil
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
		return fmt.Errorf("physical intent %s DNAT cleanup lacks its original network resource: %w",
			metadata.ID, errord.ErrFailedPrecondition)
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
