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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	// The side-effect imports register the available NAT backends before
	// InterfaceManager initialization while avoiding an import cycle.
	_ "github.com/inclusionAI/sandboxd/pkg/networkmanager/bpfnat"
	_ "github.com/inclusionAI/sandboxd/pkg/networkmanager/bridge"
	"github.com/inclusionAI/sandboxd/pkg/resourcemanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/inclusionAI/sandboxd/pkg/volumemanager"
	"github.com/inclusionAI/sandboxd/pkg/xpumanager"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type SandboxService interface {
	runtime.SandboxServiceServer
	Run() error
	Shutdown()
	Ready() bool
	RegisterServer(*grpc.Server)
}

var _ SandboxService = &sandboxService{}

type xpuLeaseManager interface {
	Acquire(string, []*runtime.XpuAllocation) (*svc.SpecUpdates, error)
	Release(string)
}

type sandboxCgroups interface {
	Allocate() (string, error)
	Recycle(string) error
	AllocateForGeneration(string) (string, error)
	RecycleForGeneration(string, string) error
	Prepare(string, *runtime.LinuxSandboxResources) error
	Stats(string) (cgroupmanager.Stats, error)
	CgroupIdentity(string) (cgroupmanager.CgroupIdentity, error)
	ReadMemoryLimit(string) (int64, error)
	ReadFreeze(string) (cgroupmanager.FreezeState, error)
	WriteFreeze(string, bool) error
	WriteMemoryLimits(string, uint64, uint64) error
	SupportsMemoryShrink() bool
	ShutDown() error
}

// sandboxService implements SandboxService.
type sandboxService struct {
	// config is the sandbox service config
	config         config.Config
	serviceHandler cmap.ConcurrentMap[string, svc.Handler]

	sandboxManager *sandbox.Manager

	// Resource and infrastructure managers owned by the server. SandboxManager
	// receives only the cgroup manager reference it needs for OOM monitoring;
	// allocation, release, and shutdown stay in server-owned managers.
	cgroupMgr    sandboxCgroups
	interfaceMgr *networkmanager.InterfaceManager
	networkMgr   *networkManager
	aclMgr       *networkacl.Manager
	resourceMod  *resourcemanager.Module
	imageMod     *imagemanager.Module
	imageSvc     imageapi.Service
	volumeMgr    *volumemanager.Module
	xpuMgr       xpuLeaseManager

	store store.DbStore

	runtime.UnimplementedSandboxServiceServer

	fsMgr *fsManager

	checkpointState   *checkpointstate.Coordinator
	operationCtx      context.Context
	operationCancel   context.CancelFunc
	operationMu       sync.Mutex
	operationWG       sync.WaitGroup
	operationStopping bool

	ready                             atomic.Bool
	recoveryReady                     atomic.Bool
	deleteGroup                       singleflight.Group
	resourceLocks                     physicalLocks
	retirementMu                      sync.Mutex
	retirementProgressJournal         *retirementProgressJournal
	startOperationMu                  sync.Mutex
	startJournal                      *startOperationJournal
	aclMu                             sync.Mutex
	checkpointMu                      sync.Mutex
	checkpointing                     map[string]struct{}
	firecrackerCheckpointMemorySlotMu sync.Mutex
	firecrackerCheckpointMemorySlot   chan struct{}

	// resourceStateMu serializes resource-state journal publication across
	// sandboxes and guards the self-heal loop's lazy start.
	resourceStateMu          sync.Mutex
	resourceStateHeal        chan struct{}
	resourceStateHealStarted bool
}

// loadRuntimeHandlers loads runtime handlers with exponential backoff.
// It blocks until all configured runtimes are loaded or timeout is reached.
func (h *sandboxService) loadRuntimeHandlers() {
	logrus.Debugf("loading runtime handlers: %v", h.config.PluginConfig.RuntimeConfig.RuntimeBinary)

	// Disk path "containers" is retained for state-recovery compatibility.
	sandboxesRoot := filepath.Join(h.config.RootDir, "containers")
	if err := os.MkdirAll(sandboxesRoot, 0755); err != nil {
		logrus.Errorf("create sandboxes dir failed: %v", err)
	}

	const maxWait = 30 * time.Second
	backoff := 100 * time.Millisecond
	deadline := time.Now().Add(maxWait)

	for {
		allLoaded := true
		for runtimeName, runtimeBin := range h.config.PluginConfig.RuntimeConfig.RuntimeBinary {
			if h.config.DisableCgroup && runtimeName != config.RuntimeNameRunsc {
				logrus.Warnf(
					"runtime %v is not registered: experimental cgroup-disabled "+
						"mode currently supports only runsc",
					runtimeName,
				)
				continue
			}
			if h.serviceHandler.Has(runtimeName) {
				continue
			}
			handler, err := newRuntimeHandler(h.config, runtimeBin, runtimeName)
			if err != nil {
				if runtimeName == config.RuntimeNameRunsc {
					logrus.Warnf("load required runtime %v handler failed: %v", runtimeName, err)
					allLoaded = false
				} else {
					// Optional runtimes are node capabilities. A node that does
					// not meet their host requirements remains ready and omits
					// them from ListAvailableRuntimes.
					logrus.Warnf("optional runtime %v is unavailable: %v", runtimeName, err)
				}
				continue
			}
			logrus.Infof("loaded runtime handler for %v", runtimeName)
			h.serviceHandler.Set(runtimeName, handler)
		}

		if allLoaded || time.Now().After(deadline) {
			if !allLoaded {
				logrus.Errorf("timeout waiting for runtime handlers after %v", maxWait)
			}
			return
		}

		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func (h *sandboxService) Ready() bool {
	return h.Healthy()
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (h *sandboxService) startSandboxRuntime(
	ctx context.Context,
	runtimeName string,
	startConfig svc.StartConfig,
	metadata *runtime.SandboxMetadata,
) (err error) {
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("StartSandbox failed, traceID: %v, spanId: %v, err: %v", traceID, spanID, err)
		}
	}()

	if err = h.checkRuntime(runtimeName); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("check runtime failed: %v", err)
		return fmt.Errorf("runtime %q is not available: %w", runtimeName, err)
	}

	handler, ok := h.serviceHandler.Get(runtimeName)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	if startConfig.CgroupPath != "" {
		if h.cgroupMgr == nil {
			return errors.New("cgroup manager is not configured")
		}
		hostResources := startConfig.Resources
		if provider, ok := handler.(svc.HostResourcesProvider); ok {
			hostResources = provider.HostResources(startConfig.Resources)
		}
		if err = h.cgroupMgr.Prepare(startConfig.CgroupPath, hostResources); err != nil {
			return fmt.Errorf("prepare cgroup %s: %w", startConfig.CgroupPath, err)
		}
	}

	if startConfig.CheckpointDir != "" {
		if managed, ok := handler.(svc.ManagedCheckpointHandler); ok {
			// The scheduler line restores through the managed interface so
			// the paired writable-layer artifact is applied with the state.
			imagePath := filepath.Join(startConfig.CheckpointDir, "checkpoint.img")
			err = h.withTransientFirecrackerCheckpointMemory(
				ctx,
				runtimeName,
				startConfig.ID,
				startConfig.CgroupPath,
				startConfig.Resources,
				handler,
				false,
				func() error { return managed.Restore(ctx, startConfig, imagePath) },
			)
		} else if checkpointHandler, ok := handler.(svc.CheckpointHandler); ok {
			err = h.withTransientFirecrackerCheckpointMemory(
				ctx,
				runtimeName,
				startConfig.ID,
				startConfig.CgroupPath,
				startConfig.Resources,
				handler,
				false,
				func() error { return checkpointHandler.Restore(ctx, startConfig) },
			)
		} else {
			return errord.ToGRPCf(
				errord.ErrNotImplemented,
				"runtime %q does not support checkpoint restore",
				runtimeName,
			)
		}
	} else {
		if err = h.verifyPreparedElasticLimits(startConfig, "start", metadata); err != nil {
			return err
		}
		if err = h.initializeResourceRevision(startConfig, metadata); err != nil {
			return err
		}
		err = handler.Start(ctx, startConfig)
	}
	if err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler create sandbox failed: %v", err)
		return errors.Join(errord.ToGRPC(err), svc.ErrRuntimeCreationUnconfirmed)
	}

	logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("StartSandbox %s success, traceID: %v, spanId: %v, cost: %v", startConfig.ID, traceID, spanID, time.Since(start).String())
	return nil
}

func (h *sandboxService) restoreSandboxRuntime(
	ctx context.Context,
	runtimeName string,
	startConfig svc.StartConfig,
	checkpointImage string,
	metadata *runtime.SandboxMetadata,
) (err error) {
	if err = h.checkRuntime(runtimeName); err != nil {
		return fmt.Errorf("runtime %q is not available: %w", runtimeName, err)
	}
	handler, ok := h.serviceHandler.Get(runtimeName)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}
	restoreHandler, ok := handler.(svc.ManagedCheckpointHandler)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}
	if startConfig.CgroupPath != "" {
		if h.cgroupMgr == nil {
			return errors.New("cgroup manager is not configured")
		}
		hostResources := startConfig.Resources
		if provider, ok := handler.(svc.HostResourcesProvider); ok {
			hostResources = provider.HostResources(startConfig.Resources)
		}
		if err = h.cgroupMgr.Prepare(startConfig.CgroupPath, hostResources); err != nil {
			return fmt.Errorf("prepare cgroup %s: %w", startConfig.CgroupPath, err)
		}
	}
	if err = h.verifyPreparedElasticLimits(startConfig, "restore", metadata); err != nil {
		return err
	}
	if err = h.initializeResourceRevision(startConfig, metadata); err != nil {
		return err
	}
	if err := restoreHandler.Restore(ctx, startConfig, checkpointImage); err != nil {
		if errors.Is(err, svc.ErrRestoreCleanupIncomplete) {
			return err
		}
		return errors.Join(errord.ToGRPC(err), svc.ErrRuntimeCreationUnconfirmed)
	}
	return nil
}

func (h *sandboxService) deleteSandboxRuntime(ctx context.Context, sandboxID string, generation ...string) (err error) {
	expected := ""
	if len(generation) > 0 {
		expected = generation[0]
	}
	unlock, err := h.resourceLocks.acquire(ctx, sandboxID)
	if err != nil {
		return err
	}
	defer unlock()
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("DeleteSandbox %s failed, traceID: %v, spanId: %v, err: %v", sandboxID, traceID, spanID, err)
		} else {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("DeleteSandbox %s success, traceID: %v, spanId: %v, cost: %v", sandboxID, traceID, spanID, time.Since(start).String())
		}
	}()

	if expected != "" {
		receipt, readErr := h.readRetirement(sandboxID, expected)
		if readErr != nil {
			return readErr
		}
		if receipt != nil && receipt.Complete {
			return h.forgetCompletedFailedCreationIntent(sandboxID, expected)
		}
		// An unpublished INTENT is still a physical owner. Conditional cleanup
		// may reconcile only this original generation under the already-held
		// physical lock; legacy Delete must not silently adopt such an intent.
		for _, metadata := range h.sandboxManager.ListPhysicalIntents() {
			if metadata.ID != sandboxID {
				continue
			}
			if metadata.Labels[resourceGenerationLabel] != expected {
				return errord.ToGRPCf(errord.ErrFailedPrecondition, "physical intent resource generation changed before delete")
			}
			return h.reconcilePhysicalIntentLocked(ctx, metadata)
		}
		if completed, err := h.resumeRetirementCompletion(sandboxID, expected); err != nil {
			return err
		} else if completed {
			return nil
		}
	}

	c, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) && expected == "" {
			return nil
		}
		return errord.ToGRPC(err)
	}

	if c == nil || c.Metadata == nil {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox %s metadata is missing before delete", sandboxID)
	}

	if expected != "" && (c.Metadata == nil || c.Metadata.Labels[resourceGenerationLabel] != expected) {
		return errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox resource generation changed before delete")
	}

	// A daemon-owned freeze from an unfinished shrink must be released before
	// the runtime handler is asked to delete the sandbox: runsc's control
	// path needs a responsive Sentry, and a frozen cgroup would hang it. Only
	// this daemon's own still-valid intent for this exact incarnation is
	// released; a foreign freeze is left for the runtime to report.
	if generation := c.Metadata.GetLabels()[resourceGenerationLabel]; generation != "" {
		h.releaseOwnedFreezeForDelete(sandboxID, generation)
	}

	if h.checkRuntime(c.Metadata.RuntimeHandler) != nil {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	handler, ok := h.serviceHandler.Get(c.Metadata.RuntimeHandler)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	resource, err := h.physicalResources(c.Metadata)
	if err != nil {
		return err
	}
	var progress *retirementProgress
	if expected != "" {
		progress, err = h.beginRetirementProgress(proto.Clone(c.Metadata).(*runtime.SandboxMetadata), resource)
		if err != nil {
			return err
		}
	}

	// Preserve the last daemon-owned observations of a scheduler-managed
	// generation across the physical delete: external polls can no longer see
	// intermediate generations once park/eviction retires them. One fresh
	// attempt ID correlates the before- and after-runtime-delete records, and
	// every capture binds to an immutable snapshot of the metadata selected
	// under this physical lock — never to a pointer that could move later in
	// the attempt. Capture precedes the pending receipt and the runtime
	// handler alike, for legacy Delete on a generated sandbox just as for
	// DeleteIfGeneration; sandboxes without a generation label keep the
	// unconditional-delete behavior unchanged.
	deleteAttemptID, deleteGeneration := "", ""
	var deleteSnapshot *runtime.SandboxMetadata
	if generation := c.Metadata.GetLabels()[resourceGenerationLabel]; generation != "" {
		deleteAttemptID, deleteGeneration = uuid.NewString(), generation
		deleteSnapshot = proto.Clone(c.Metadata).(*runtime.SandboxMetadata)
		if err := h.captureRetirementResources(sandboxID, deleteGeneration, deleteAttemptID,
			retirementResourcePhaseBeforeDelete, deleteSnapshot); err != nil {
			return err
		}
	}

	if expected != "" {
		if err := h.writeRetirement(sandboxID, expected, false); err != nil {
			return err
		}
	}

	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	err = handler.Delete(ctx, sandboxID)
	if err != nil && !errors.Is(err, errord.ErrNotFound) {
		metrics.RecordRuntimeCallResult("delete", "failed", c.Metadata.RuntimeHandler)
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler force delete sandbox failed: %v", err)
		return errord.ToGRPC(err)
	}
	metrics.RecordRuntimeCallResult("delete", "success", c.Metadata.RuntimeHandler)
	if progress != nil {
		states, err := handler.List(ctx)
		if err != nil {
			return fmt.Errorf("verify original runtime absence: %w", err)
		}
		for _, state := range states {
			if state == nil || state.ID == sandboxID {
				return fmt.Errorf("original runtime absence is unconfirmed")
			}
		}
		if err := h.completeRetirementProgressStep(progress, "runtime"); err != nil {
			return err
		}
	}
	if h.resourceMod != nil {
		h.resourceMod.ReleaseTransientMemory(
			firecrackerCheckpointReservationOwner(sandboxID),
		)
	}
	// The runtime handler's own cleanup does not recycle the daemon-owned
	// cgroup, so one more observation against the same attempt snapshot is
	// still possible before resource release. It remains observation evidence
	// — its physical_deletion_confirmed field is permanently false; only a
	// separate completion receipt proves full cleanup. Persistence failure stops release
	// and the receipt here, leaving the recoverable unknown state for a retry
	// under a fresh attempt ID.
	if deleteAttemptID != "" {
		if err := h.captureRetirementResources(sandboxID, deleteGeneration, deleteAttemptID,
			retirementResourcePhaseAfterDelete, deleteSnapshot); err != nil {
			return err
		}
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	if err := h.deactivateStartNetwork(resource); err != nil {
		return err
	}
	if err := h.completeRetirementProgressStep(progress, "network_disconnected"); err != nil {
		return err
	}

	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	var fsReleaseErr error
	if deleteGeneration != "" {
		fsReleaseErr = h.fsMgr.ReleaseIfGeneration(sandboxID, deleteGeneration)
	} else {
		fsReleaseErr = h.fsMgr.Release(sandboxID)
	}
	if fsReleaseErr != nil {
		return fsReleaseErr
	}
	if err := h.completeRetirementProgressStep(progress, "filesystem"); err != nil {
		return err
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	if h.aclMgr != nil {
		h.aclMu.Lock()
		aclErr := h.aclMgr.Remove(sandboxID)
		h.aclMu.Unlock()
		if aclErr != nil {
			return fmt.Errorf("remove network ACL for sandbox %s: %w", sandboxID, aclErr)
		}
	}
	if err := h.completeRetirementProgressStep(progress, "acl"); err != nil {
		return err
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	if h.xpuMgr != nil {
		h.xpuMgr.Release(sandboxID)
	}
	if err := h.completeRetirementProgressStep(progress, "devices"); err != nil {
		return err
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	if progress != nil {
		if err := h.cleanupPhysicalDnatFacts(c.Metadata, resource); err != nil {
			return err
		}
	} else if h.networkMgr != nil {
		h.networkMgr.cleanupDnatRules(sandboxID)
	}
	if h.networkMgr != nil {
		h.networkMgr.releaseDnatPorts(sandboxID)
	}
	if err := h.completeRetirementProgressStep(progress, "dnat"); err != nil {
		return err
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	if err := h.releaseStartResources(resource); err != nil {
		return err
	}
	if err := h.completeRetirementProgressStep(progress, "resources"); err != nil {
		return err
	}
	if progress != nil {
		if _, err := h.verifyRetirementProgressRoot(progress, false); err != nil {
			return err
		}
		progress.RootPending = true
		if err := h.writeRetirementProgress(progress); err != nil {
			return err
		}
	}

	h.sandboxManager.Delete(sandboxID)
	if expected != "" {
		root, err := util.JoinWithinRoot(filepath.Join(h.config.RootDir, "containers"), sandboxID)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("sandbox metadata retirement not confirmed: %v", err)
		}
		if err := syncRetirementDirectory(filepath.Dir(root)); err != nil {
			return err
		}
		if err := h.completeRetirementProgressStep(progress, "root"); err != nil {
			return err
		}
		if err := h.writeRetirement(sandboxID, expected, true); err != nil {
			return err
		}
	}
	if deleteGeneration != "" {
		// The physical delete is the authority that this incarnation — and
		// with it any resource operation it still owned — is finished. Close
		// and drop the revision journal only now; a missing sandbox alone
		// never justified this elsewhere.
		h.retireResourceOperationState(sandboxID, deleteGeneration)
	}
	return nil
}

// deleteSandbox coalesces concurrent delete requests for the same sandbox.
// Cleanup runs independently from the initiating caller's cancellation so a
// timed-out RPC cannot leave a partially deleted sandbox for another caller to
// release again.
func (h *sandboxService) deleteSandbox(ctx context.Context, sandboxID string, generation ...string) error {
	expected := ""
	if len(generation) > 0 {
		expected = generation[0]
	}
	// Legacy and conditional deletes, and different generations, must not share receipts.
	key, _ := json.Marshal([2]string{sandboxID, expected})
	resultCh := h.deleteGroup.DoChan(string(key), func() (interface{}, error) {
		cleanupCtx := context.WithoutCancel(ctx)
		if h.checkpointState != nil {
			if err := h.checkpointState.BeginDelete(sandboxID); err != nil {
				return nil, err
			}
			defer h.checkpointState.EndDelete(sandboxID)
		}

		return nil, h.deleteSandboxRuntime(cleanupCtx, sandboxID, expected)
	})

	select {
	case result := <-resultCh:
		return result.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *sandboxService) List(ctx context.Context, request *runtime.ListSandboxesRequest) (*runtime.ListSandboxesResponse, error) {
	response := new(runtime.ListSandboxesResponse)
	if request == nil {
		return response, errord.ToGRPC(errord.ErrInvalidArgument)
	}

	sandboxes := h.sandboxManager.List()
	for idx := range sandboxes {
		current := sandboxes[idx]
		if current == nil {
			continue
		}
		status := current.ApiStatus()
		if sandboxStatusMatchesListRequest(status, request) {
			response.Sandboxes = append(response.Sandboxes, status)
		}
	}
	if request.ID != "" && len(response.Sandboxes) == 0 {
		return response, errord.ToGRPC(errord.ErrNotFound)
	}
	return response, nil
}

func sandboxStatusMatchesListRequest(
	status *runtime.SandboxStatus,
	request *runtime.ListSandboxesRequest,
) bool {
	if status == nil {
		return false
	}
	if request.ID != "" && status.ID != request.ID {
		return false
	}
	if len(request.Selector) == 0 {
		return true
	}
	if status.Labels == nil {
		return false
	}
	for key, value := range request.Selector {
		if value != "" && status.Labels[key] != value {
			return false
		}
	}
	return true
}

func (h *sandboxService) Stats(ctx context.Context, request *runtime.StatsRequest) (*runtime.StatsResponse, error) {
	if request == nil || request.ID == "" {
		return nil, errord.ToGRPC(errord.ErrInvalidArgument)
	}
	unlock, err := h.resourceLocks.acquire(ctx, request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	defer unlock()
	return h.resourceStats(request.ID)
}

// Caller holds resourceLocks for id until the physical read has completed.
func (h *sandboxService) resourceStats(id string) (*runtime.StatsResponse, error) {
	if h.config.DisableCgroup {
		return nil, errord.ToGRPC(fmt.Errorf(
			"sandbox stats require per-sandbox cgroups: %w",
			errord.ErrFailedPrecondition,
		))
	}

	// Look up the sandbox to verify it exists.
	current, err := h.sandboxManager.Get(id)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}

	// Get the cgroup path from the sandbox's OCI spec.
	resource, err := h.physicalResources(current.Metadata)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	cgroupPath, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupPath == "" {
		return nil, errord.ToGRPC(fmt.Errorf("cgroup path not found for sandbox %s", id))
	}

	if h.cgroupMgr == nil {
		return nil, errord.ToGRPC(errors.New("cgroup manager is not configured"))
	}
	cgroupStats, err := h.cgroupMgr.Stats(cgroupPath)
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("stat cgroup %s failed: %v", cgroupPath, err))
	}
	generation := current.Metadata.GetLabels()[resourceGenerationLabel]
	operation := h.observeResourceOperationState(id, generation, cgroupPath, cgroupStats.MemoryCgroupPath)
	return &runtime.StatsResponse{
		ResourceGeneration:  generation,
		CpuPressureKnown:    cgroupStats.CPUPressureKnown,
		CpuPeriods:          cgroupStats.CPUPeriods,
		CpuThrottledPeriods: cgroupStats.CPUThrottledPeriods,
		CpuThrottledNs:      cgroupStats.CPUThrottledNanos,
		MemoryPressureKnown: cgroupStats.MemoryPressureKnown,
		MemoryHighEvents:    cgroupStats.MemoryHighEvents,
		MemoryOomEvents:     cgroupStats.MemoryOOMEvents,
		MemoryOomKillEvents: cgroupStats.MemoryOOMKillEvents,

		ElasticPolicy:       current.Metadata.GetLabels()[elasticResourcesLabel],
		CpuUsageNs:          cgroupStats.CPUUsageNanos,
		CpuQuotaUsec:        cgroupStats.CPUQuotaUsec,
		CpuPeriodUsec:       cgroupStats.CPUPeriodUsec,
		CpuLimitsKnown:      cgroupStats.CPULimitsKnown,
		CpuKernelNs:         cgroupStats.CPUKernelNanos,
		CpuUserNs:           cgroupStats.CPUUserNanos,
		CpuUsageKnown:       cgroupStats.CPUUsageKnown,
		MemoryUsageBytes:    cgroupStats.MemoryUsageBytes,
		MemoryUsageKnown:    cgroupStats.MemoryUsageKnown,
		MemoryLimitBytes:    cgroupStats.MemoryLimitBytes,
		MemoryLimitKnown:    cgroupStats.MemoryLimitKnown,
		MemoryMaxUsageBytes: cgroupStats.MemoryMaxUsageBytes,
		MemoryPeakKnown:     cgroupStats.MemoryPeakKnown,

		MemoryHighBytes:          cgroupStats.MemoryHighBytes,
		MemoryHighKnown:          cgroupStats.MemoryHighKnown,
		MemoryHighUnlimited:      cgroupStats.MemoryHighUnlimited,
		Frozen:                   cgroupStats.Frozen,
		FrozenKnown:              cgroupStats.FrozenKnown,
		ResourceRevision:         operation.Revision,
		ResourceRevisionKnown:    operation.RevisionKnown,
		ResourceOperationID:      operation.OperationID,
		ResourceOperationPending: operation.OperationOpen,
		MemoryCgroupPath:         operation.CgroupPath,
	}, nil
}

func supportsCheckpointRestore(handler svc.Handler) bool {
	_, managed := handler.(svc.ManagedCheckpointHandler)
	_, compatibility := handler.(svc.CheckpointHandler)
	return managed || compatibility
}

// ListAvailableRuntimes returns a stable snapshot of runtime classes whose
// handlers initialized successfully. Configured classes that failed to load
// are absent from serviceHandler and therefore from this list.
func (h *sandboxService) ListAvailableRuntimes(
	_ context.Context,
	_ *runtime.ListAvailableRuntimesRequest,
) (*runtime.ListAvailableRuntimesResponse, error) {
	if !h.Healthy() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "sandbox service is not ready")
	}
	runtimeClasses := h.serviceHandler.Keys()
	sort.Strings(runtimeClasses)
	runtimes := make([]*runtime.RuntimeInfo, 0, len(runtimeClasses))
	for _, runtimeClass := range runtimeClasses {
		info := &runtime.RuntimeInfo{RuntimeClass: runtimeClass}
		handler, ok := h.serviceHandler.Get(runtimeClass)
		if !ok {
			logrus.Debugf(
				"runtime handler %q disappeared while listing capabilities",
				runtimeClass,
			)
			runtimes = append(runtimes, info)
			continue
		}
		if supportsCheckpointRestore(handler) {
			info.SupportsCheckpointRestore = true
		}
		if provider, ok := handler.(svc.CheckpointRestoreCapabilitiesProvider); ok {
			capabilities := provider.CheckpointRestoreCapabilities()
			info.CheckpointHandoffPath = capabilities.CheckpointHandoffPath
			info.RestoreEnvPath = capabilities.RestoreEnvPath
		}
		runtimes = append(runtimes, info)
	}

	return &runtime.ListAvailableRuntimesResponse{
		RuntimeClasses: runtimeClasses,
		Runtimes:       runtimes,
	}, nil
}

func (h *sandboxService) Run() error {
	logrus.Infof("sandbox service run at %s", h.config.RootDir)
	for {
		if err := h.imageMod.ReconcileRecoveredDaemons(); err != nil {
			logrus.WithError(err).Warn("distillfs recovery is incomplete; retrying")
			time.Sleep(time.Second)
			continue
		}
		break
	}
	h.recoveryReady.Store(true)
	h.sandboxManager.Start()
	return nil
}

func (h *sandboxService) Shutdown() {
	logrus.Info("sandbox service shutting down: cleaning up sandboxes")
	h.stopCheckpointOperations()

	// 1. Force-delete all running sandboxes with per-sandbox timeout.
	sandboxes := h.sandboxManager.List()
	for _, c := range sandboxes {
		if c == nil || c.Metadata == nil {
			continue
		}
		id := c.Metadata.ID
		if err := h.deleteSandbox(context.Background(), id); err != nil {
			logrus.Warnf("shutdown: failed to delete sandbox %s: %v", id, err)
		}

	}

	h.fsMgr.Shutdown()

	// 2. Stop sandbox manager (stops event loop + monitors).
	h.sandboxManager.Stop()

	// 3. Stop resource managers owned by the server.
	if h.cgroupMgr != nil {
		if err := h.cgroupMgr.ShutDown(); err != nil {
			logrus.Warnf("shutdown: failed to stop cgroup manager: %v", err)
		}
	}
	if h.aclMgr != nil {
		if err := h.aclMgr.Close(); err != nil {
			logrus.Warnf("shutdown: failed to stop network ACL manager: %v", err)
		}
	}
	if h.interfaceMgr != nil {
		if err := h.interfaceMgr.ShutDown(); err != nil {
			logrus.Warnf("shutdown: failed to stop interface manager: %v", err)
		}
	}

	// Tear infrastructure modules down in reverse dependency order.
	// SandboxManager / runsc handlers are already torn down above;
	// here we drop the underlying infrastructure modules:
	//   ImageManager  -> drains distillfs + persists mount_records.db
	//   ResourceMod   -> closes /var/run/resource.sock + stops the K8s
	//                    watcher; safe to call even when Start was a no-op
	//   VolumeMgr     -> unmounts the bounded filestore
	if h.imageMod != nil {
		h.imageMod.Stop()
	}
	if h.resourceMod != nil {
		h.resourceMod.Stop()
	}
	if h.volumeMgr != nil {
		if err := h.volumeMgr.Stop(); err != nil {
			logrus.Warnf("shutdown: failed to unmount filestore: %v", err)
		}
	}
	logrus.Info("sandbox service shutdown complete")
	h.closeStartOperationJournal()
	h.closeRetirementProgressJournal()
}

func (h *sandboxService) acquireCheckpointOperation() (func(), bool) {
	h.operationMu.Lock()
	defer h.operationMu.Unlock()
	if h.operationStopping {
		return nil, false
	}
	h.operationWG.Add(1)
	return h.operationWG.Done, true
}

func (h *sandboxService) stopCheckpointOperations() {
	h.operationMu.Lock()
	h.operationStopping = true
	if h.operationCancel != nil {
		h.operationCancel()
	}
	h.operationMu.Unlock()
	h.operationWG.Wait()
}

// Healthy aggregates each module's Healthy() signal into a single boolean
// for the process-level health endpoint. A module that has not
// been constructed (e.g. legacy code path) is treated as not unhealthy:
// only an explicit false from a live module flips the result.
func (h *sandboxService) Healthy() bool {
	if !h.recoveryReady.Load() || !h.ready.Load() {
		return false
	}
	if h.resourceMod != nil && !h.resourceMod.Healthy() {
		return false
	}
	if h.imageMod != nil && !h.imageMod.Healthy() {
		return false
	}
	if h.volumeMgr != nil && !h.volumeMgr.Healthy() {
		return false
	}
	return true
}

func (h *sandboxService) RegisterServer(server *grpc.Server) {
	runtime.RegisterSandboxServiceServer(server, h)
}

// NewSandboxService creates a new sandbox service.
// root is the working root directory; configPath is the path to config.toml.
// resetStateIfPodChanged wipes persisted state when sandboxd starts in a
// different pod than the one that wrote it. The hostname is used as the pod
// identity (k8s sets it to the pod name; same pod across in-sandbox service
// restarts, different pod across pod recreation). The stamp lives next to the
// bbolt store so it shares the state's lifetime.
//
// Without this, a recreated pod that reuses a hostPath volume would inherit
// the previous pod's registrations, sandbox OCI bundles, and bbolt
// buckets, causing register-with-same-name to silently no-op.
func resetStateIfPodChanged(storeDir, rootDir, imageManagerRoot string) error {
	current, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}
	stampPath := filepath.Join(storeDir, ".pod_host")
	if stored, err := os.ReadFile(stampPath); err == nil && string(stored) == current {
		return nil
	}

	logrus.Infof("pod identity changed (hostname=%q): wiping persisted state in %s, %s, %s", current, storeDir, rootDir, imageManagerRoot)
	if err := os.RemoveAll(storeDir); err != nil {
		return fmt.Errorf("remove storeDir %s: %w", storeDir, err)
	}
	// "containers" is the established on-disk directory name used by the
	// sandbox manager and runsc handler for state recovery.
	for _, sub := range []string{"containers"} {
		p := filepath.Join(rootDir, sub)
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	// Tie image-manager cleanup to the same pod-identity stamp as the rest of
	// sandboxd state so process restarts preserve mount recovery data.
	if imageManagerRoot != "" {
		if err := os.RemoveAll(imageManagerRoot); err != nil {
			return fmt.Errorf("remove imageManagerRoot %s: %w", imageManagerRoot, err)
		}
	}
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		return fmt.Errorf("recreate storeDir %s: %w", storeDir, err)
	}
	return os.WriteFile(stampPath, []byte(current), 0644)
}

func resetMetadataIfResourceStateIncompatible(storePath string) error {
	if _, err := os.Stat(storePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat metadata db %s: %w", storePath, err)
	}

	db := store.NewStoreImp(storePath)
	for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
		data, err := db.LoadRaw(key)
		if err != nil {
			if errord.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("load raw metadata bucket %s: %w", key, err)
		}

		var state struct {
			Items []string `json:"items"`
		}
		if err := json.Unmarshal(data, &state); err != nil {
			logrus.Warnf("metadata db %s has incompatible %s bucket (%v); removing stale db", storePath, key, err)
			if err := os.Remove(storePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove incompatible metadata db %s: %w", storePath, err)
			}
			return nil
		}
	}
	return nil
}

func NewSandboxService(root, configPath string) (result SandboxService, retErr error) {
	// if root dir is not exist, create it
	if _, err := os.Stat(root); os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0755); err != nil {
			return nil, err
		}
	}

	// read and unmarshal config.toml
	var cfg config.Config
	cfg.RuntimeConfig.FilestoreOvercommitRatio = config.DefaultFilestoreOvercommitRatio
	if configBytes, err := os.ReadFile(configPath); err != nil {
		return nil, err
	} else if err := toml.NewDecoder(bytes.NewReader(configBytes)).Decode(&cfg); err != nil {
		return nil, err
	}
	if err := validateRuntimeFilestore(cfg.RuntimeConfig); err != nil {
		return nil, err
	}
	runscPlatform, err := config.NormalizeRunscPlatform(cfg.RuntimeConfig.Runsc.Platform)
	if err != nil {
		return nil, fmt.Errorf("runtime configuration: %w", err)
	}
	cfg.RuntimeConfig.Runsc.Platform = runscPlatform

	cpuLimitMode, err := config.NormalizeCPULimitMode(cfg.CPULimitMode)
	if err != nil {
		return nil, fmt.Errorf("resource configuration: %w", err)
	}
	cfg.CPULimitMode = cpuLimitMode

	natBackend, err := resolveNATBackend(cfg.NatBackend)
	if err != nil {
		return nil, fmt.Errorf("network configuration: %w", err)
	}
	cfg.NatBackend = natBackend
	if configurable, ok := networkmanager.NetworkManagers[natBackend].(networkmanager.ConfigurableNetworkManager); ok {
		if err := configurable.Configure(networkmanager.BackendConfig{
			Device:          cfg.BpfnatDevice,
			EnableLocalDNAT: cfg.EnableLocalDNAT,
		}); err != nil {
			return nil, fmt.Errorf("configure NAT backend %s: %w", natBackend, err)
		}
	}

	if err := resetStateIfPodChanged(cfg.StoreDir, cfg.RootDir, cfg.ImageManagerRoot); err != nil {
		return nil, fmt.Errorf("reset state on pod change: %w", err)
	}
	storePath := filepath.Join(cfg.StoreDir, "metadata.db")
	if err := resetMetadataIfResourceStateIncompatible(storePath); err != nil {
		return nil, fmt.Errorf("reset incompatible metadata: %w", err)
	}
	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
		return nil, fmt.Errorf("create sandbox root: %w", err)
	}
	xpuMgr := xpumanager.New(
		cfg.RuntimeConfig.RuntimeBinary[config.RuntimeNameRunsc],
		sandboxRoot,
	)

	// The optional node-resource module comes up first so its external resource
	// socket is visible before image, volume, and sandbox initialization. Gated
	// on [plugin.node_resource]: deployments that don't report node resources
	// omit the section, Kubernetes deployments use the default provider, and
	// standalone deployments can explicitly select the read-only cgroup
	// provider. A configured provider's init/bind failure is fatal and lets
	// systemd restart sandboxd.
	// Held in a local because s.resourceMod is back-filled once s exists below.
	var nodeResMod *resourcemanager.Module
	if cfg.SockPath != "" {
		sockPath := cfg.SockPath
		mod, merr := resourcemanager.NewModule(sockPath, cfg.NodeResourceConfig.Provider)
		if merr != nil {
			return nil, fmt.Errorf("node-resource module init: %w", merr)
		}
		mod.SetXPUProvider(xpuMgr)
		// Configure the (default-off) observation fault control BEFORE
		// Start: the listener serves concurrently, so Enabled/Path must be
		// immutable by the time any HTTP read consults them.
		mod.SetObservationFault(cfg.NodeResourceConfig.EnableObservationFault,
			cfg.NodeResourceConfig.ObservationFaultPath)
		if serr := mod.Start(); serr != nil {
			// NewModule already started the OTel collector's periodic-reader
			// goroutine; if Start then fails to bind /var/run/resource.sock we
			// must drain that collector so it doesn't outlive sandboxd's init.
			mod.Stop()
			return nil, fmt.Errorf("node-resource module start: %w", serr)
		}
		nodeResMod = mod
		provider := cfg.NodeResourceConfig.Provider
		if provider == "" {
			provider = resourcemanager.ProviderKubernetes
		}
		logrus.Infof("node-resource module ready, provider=%s sock=%s", provider, sockPath)
		defer func() {
			if retErr != nil {
				mod.Stop()
			}
		}()
	} else {
		logrus.Infof("node-resource module disabled (no [plugin.node_resource] config)")
	}

	// Construct the in-process image manager before sandboxService so mount and
	// rootfs consumers share one Service. Initialization is fatal because
	// sandboxd cannot manage rootfs or S3/OCI mounts without it.
	imgMod, err := imagemanager.NewModule(imagemanager.Config{
		Root:              cfg.ImageManagerRoot,
		DistillFsBin:      cfg.DistillFsBin,
		OSSTemplate:       cfg.OSSTemplate,
		NydusTemplate:     cfg.NydusTemplate,
		NydusSuffix:       cfg.NydusSuffix,
		OSSAuthsPath:      cfg.OSSAuthsPath,
		RegistryAuthsPath: cfg.RegistryAuthsPath,
		CgroupMemoryLimit: cfg.CgroupMemoryLimit,
		ChunkDBSize:       cfg.ChunkDBSize,
		DisableCgroup:     cfg.DisableCgroup,
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: %w", err)
	}
	// On any subsequent init failure, roll infrastructure modules back in
	// reverse construction order. defer-LIFO gives the reverse-order
	// Clean up initialized modules if construction fails.
	// Without these, Restart=always would loop with leaked distillfs
	// goroutines / bbolt handles, an XFS mount still attached, and
	// resource-manager's OTel collector still pushing metrics.
	defer func() {
		if retErr != nil {
			imgMod.Stop()
		}
	}()
	imgSvc := imgMod.Service()

	stateStore := store.NewStoreImp(storePath)
	if err := checkpoint.CleanupStaging(filepath.Join(cfg.RootDir, "checkpoints")); err != nil {
		return nil, fmt.Errorf("cleanup checkpoint staging directories: %w", err)
	}
	operationCtx, operationCancel := context.WithCancel(context.Background())
	s := &sandboxService{
		config:                            cfg,
		store:                             stateStore,
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		serviceHandler:                    cmap.New[svc.Handler](),
		fsMgr:                             newFSManager(imgSvc, stateStore),
		imageMod:                          imgMod,
		imageSvc:                          imgSvc,
		resourceMod:                       nodeResMod,
		xpuMgr:                            xpuMgr,
		checkpointState:                   checkpointstate.NewCoordinator(),
		operationCtx:                      operationCtx,
		operationCancel:                   operationCancel,
	}

	// VolumeManager comes up before runtime handlers. An ordinary directory is
	// the default; a configured bounded filesystem must be established fully.
	s.volumeMgr = volumemanager.NewModule(
		cfg.RuntimeConfig.FilestoreDir,
		cfg.RuntimeConfig.FilestoreDirSize,
		cfg.RuntimeConfig.FilestoreXFSEnabled,
		cfg.RuntimeConfig.FilestoreOvercommitRatio,
		cfg.RuntimeConfig.LoopDeviceDir,
	)
	if vErr := s.volumeMgr.Start(); vErr != nil {
		return nil, fmt.Errorf("volumemanager: %w", vErr)
	}
	defer func() {
		if retErr != nil {
			if vErr := s.volumeMgr.Stop(); vErr != nil {
				logrus.Warnf("init rollback: volumemanager Stop failed: %v", vErr)
			}
		}
	}()
	s.loadRuntimeHandlers()
	if nodeResMod != nil && cfg.RuntimeConfig.FilestoreDir != "" {
		nodeResMod.SetEphemeralStorageProvider(s.volumeMgr)
	}

	// Prepare resource modules directly. Each
	// pool runs its own single maintenance goroutine (demand-driven create +
	// periodic shrink), started inside its constructor. The pool ceiling is the
	// converged MaxSandboxLimit shared across cgroup and interface (1 sandbox =
	// 1 cgroup + 1 interface).
	maxSandboxLimit := networkmanager.MaxSandboxLimit(cfg.MaxInstanceNum)
	var cgroupMgr *cgroupmanager.CgroupManager
	if !cfg.DisableCgroup && cfg.CgroupCacheSize > 0 {
		cgroupMgr, err = cgroupmanager.NewCgroupManager(s.store, cfg.ResourceConfig, maxSandboxLimit)
		if err != nil {
			return nil, err
		}
		s.cgroupMgr = cgroupMgr
		metrics.RecordResourceGauge("cgroup", float64(cgroupMgr.CacheSizeLimit()))
		if nodeResMod != nil {
			nodeResMod.SetCgroupStatsReader(cgroupMgr.Stats)
		}
		defer func() {
			if retErr != nil {
				_ = cgroupMgr.ShutDown()
			}
		}()
	} else if cfg.DisableCgroup {
		logrus.Warn(
			"EXPERIMENTAL: cgroup management is disabled; only runsc is " +
				"available, and per-sandbox CPU, memory, and pids limits " +
				"are not enforced",
		)
	}

	var interfaceMgr *networkmanager.InterfaceManager
	if cfg.InterfaceCacheSize > 0 {
		interfaceMgr, err = networkmanager.NewInterfaceManager(
			s.store,
			cfg.IPRange,
			maxSandboxLimit,
			cfg.InterfaceCacheSize,
			cfg.NatBackend,
			sandboxRoot,
		)
		if err != nil {
			return nil, err
		}
		s.interfaceMgr = interfaceMgr
		metrics.RecordResourceGauge("interface", float64(interfaceMgr.CacheSizeLimit()))
		defer func() {
			if retErr != nil {
				_ = interfaceMgr.ShutDown()
			}
		}()
	}
	s.networkMgr = newNetworkManager(interfaceMgr, cfg.NatBackend, cfg.EnableLocalDNAT)
	if err := s.networkMgr.configureHostPortRange(cfg.HostPortStart, cfg.HostPortCount); err != nil {
		return nil, err
	}
	if cfg.EnableLocalDNAT {
		logrus.Info("local DNAT forwarding enabled for callers sharing sandboxd's network namespace")
	}
	if cfg.EnableNetworkACL {
		if interfaceMgr == nil {
			return nil, errors.New("network ACL requires interface management")
		}
		s.aclMgr, err = networkacl.New(networkacl.Config{
			Backend:                            cfg.NatBackend,
			BridgeIP:                           interfaceMgr.BridgeIp,
			ResolverPath:                       cfg.ResolvConfPath,
			Store:                              s.store,
			DNSProxyConcurrencyLimit:           cfg.DNSProxyConcurrencyLimit,
			DNSProxyPerSandboxConcurrencyLimit: cfg.DNSProxyPerSandboxConcurrencyLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize network ACL: %w", err)
		}
		defer func() {
			if retErr != nil {
				_ = s.aclMgr.Close()
			}
		}()
	}
	logrus.Debugf("resource modules init success with config: %v", cfg.PluginConfig.ResourceConfig)

	// create root dir if not exist
	if err = os.MkdirAll(cfg.RootDir, 0755); err != nil {
		return nil, err
	}

	healthChan := make(chan bool)

	if s.sandboxManager, err = sandbox.NewManager(
		cfg.RootDir,
		s.serviceHandler,
		healthChan,
		cgroupMgr,
		maxSandboxLimit,
	); err != nil {
		return nil, err
	}
	if nodeResMod != nil {
		nodeResMod.SetSandboxMetricsSource(s.sandboxManager)
		s.sandboxManager.OnSandboxStopped = nodeResMod.MarkSandboxStopped
	}
	if err := s.recoverPhysicalState(context.Background()); err != nil {
		return nil, err
	}
	if s.aclMgr != nil {
		bindings, bindErr := s.activeACLBindings()
		if bindErr != nil {
			return nil, bindErr
		}
		if err := s.aclMgr.Restore(bindings); err != nil {
			return nil, fmt.Errorf("restore network ACL state: %w", err)
		}
	}

	// health check from sandbox manager housekeeping.
	go func() {
		for ready := range healthChan {
			s.ready.Store(ready)
		}
	}()

	return s, nil
}

func (h *sandboxService) restoreSandboxNetworkFacts() error {
	portFacts := make(map[string][]string)
	dnatFacts := make(map[string]restoredDnatFact)
	for _, current := range h.sandboxManager.List() {
		if current == nil || current.Metadata == nil || len(current.Metadata.Ports) == 0 {
			continue
		}
		sandboxID := current.Metadata.ID
		resources, err := h.physicalResources(current.Metadata)
		if err != nil {
			return fmt.Errorf("collect network resource for sandbox %s: %w", sandboxID, err)
		}
		encoded, ok := resources.Resources[config.ResourceNameInterface]
		if !ok {
			return fmt.Errorf("sandbox %s has persisted ports but no network resource", sandboxID)
		}
		network, err := networkmanager.NewNetResource(encoded)
		if err != nil {
			return fmt.Errorf("decode network resource for sandbox %s: %w", sandboxID, err)
		}
		portFacts[sandboxID] = clonePorts(current.Metadata.Ports)
		dnatFacts[sandboxID] = restoredDnatFact{
			ports:    clonePorts(current.Metadata.Ports),
			targetIP: network.Ip.String(),
		}
	}
	if err := h.networkMgr.restoreDnatPortFacts(portFacts); err != nil {
		return err
	}
	return h.networkMgr.restoreDnatRuleFacts(dnatFacts)
}

func (h *sandboxService) activeACLBindings() (map[string]networkacl.Binding, error) {
	bindings := make(map[string]networkacl.Binding)
	for _, current := range h.sandboxManager.List() {
		if current == nil || current.Metadata == nil {
			continue
		}
		if current.Metadata.RuntimeHandler == config.RuntimeNameRunc {
			continue
		}
		sandboxID := current.Metadata.ID
		resources, err := h.physicalResources(current.Metadata)
		if err != nil {
			return nil, fmt.Errorf("collect network resource for sandbox %s: %w", sandboxID, err)
		}
		encoded, ok := resources.Resources[config.ResourceNameInterface]
		if !ok {
			return nil, fmt.Errorf("sandbox %s has no network resource", sandboxID)
		}
		network, err := networkmanager.NewNetResource(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode network resource for sandbox %s: %w", sandboxID, err)
		}
		if network.Interface == nil || network.Interface.Name == "" {
			return nil, fmt.Errorf("sandbox %s network endpoint is missing", sandboxID)
		}
		bindings[sandboxID] = networkacl.Binding{
			SandboxID: sandboxID,
			IP:        network.Ip,
			HostVeth:  network.Interface.Name,
		}
	}
	return bindings, nil
}

func validateRuntimeFilestore(runtimeConfig config.RuntimeConfig) error {
	_, runscEnabled := runtimeConfig.RuntimeBinary[config.RuntimeNameRunsc]
	_, runcEnabled := runtimeConfig.RuntimeBinary[config.RuntimeNameRunc]
	_, firecrackerEnabled := runtimeConfig.RuntimeBinary[config.RuntimeNameFirecracker]
	if (runscEnabled || runcEnabled || firecrackerEnabled) &&
		strings.TrimSpace(runtimeConfig.FilestoreDir) == "" {
		return errors.New("runsc, runc, and firecracker require plugin.runtime.filestore_dir")
	}
	if err := config.ValidateFilestoreOvercommitRatio(runtimeConfig.FilestoreOvercommitRatio); err != nil {
		return fmt.Errorf("plugin.runtime: %w", err)
	}
	return nil
}

func (h *sandboxService) Delete(ctx context.Context, request *runtime.DeleteRequest) (response *runtime.DeleteResponse, err error) {
	if request == nil || request.ID == "" {
		return response, errord.ToGRPC(errord.ErrInvalidArgument)
	}
	err = h.deleteSandbox(ctx, request.ID)
	return response, err
}

// DeleteIfGeneration requires a physical identity match under the same lock as
// Start/Resize/Delete, or replays a completed durable receipt for that generation.
// Missing sandbox state without such a receipt remains unknown.
func (h *sandboxService) DeleteIfGeneration(ctx context.Context, request *runtime.DeleteIfGenerationRequest) (*runtime.DeleteIfGenerationResponse, error) {
	if request == nil || request.ID == "" || request.ExpectedGeneration == "" || len(request.ExpectedGeneration) > 128 {
		return nil, errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if err := h.deleteSandbox(ctx, request.ID, request.ExpectedGeneration); err != nil {
		return nil, err
	}
	return &runtime.DeleteIfGenerationResponse{RetiredGeneration: request.ExpectedGeneration}, nil
}

func (h *sandboxService) SetNetworkPolicy(
	_ context.Context,
	request *runtime.SetNetworkPolicyRequest,
) (*runtime.SetNetworkPolicyResponse, error) {
	if request == nil || strings.TrimSpace(request.SandboxID) == "" {
		return nil, errord.ToGRPC(fmt.Errorf("sandbox ID is required: %w", errord.ErrInvalidArgument))
	}
	policy, err := networkacl.NormalizePolicy(request.NetworkPolicy)
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("invalid network policy: %v: %w", err, errord.ErrInvalidArgument))
	}
	if h.aclMgr == nil {
		return nil, errord.ToGRPC(fmt.Errorf("network ACL is disabled: %w", errord.ErrFailedPrecondition))
	}

	h.aclMu.Lock()
	defer h.aclMu.Unlock()
	current, err := h.sandboxManager.Get(request.SandboxID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if current.Metadata != nil && current.Metadata.RuntimeHandler == config.RuntimeNameRunc {
		return nil, errord.ToGRPC(fmt.Errorf(
			"network ACL is not supported by runtime runc: %w",
			errord.ErrFailedPrecondition,
		))
	}
	if current.Status == nil || current.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, errord.ToGRPC(fmt.Errorf("sandbox %s is not running: %w", request.SandboxID, errord.ErrFailedPrecondition))
	}
	if err := h.aclMgr.SetPolicy(request.SandboxID, policy); err != nil {
		return nil, errord.ToGRPC(err)
	}
	return &runtime.SetNetworkPolicyResponse{}, nil
}

// resourcesToLinux converts a StartRequest.Resources map (CPU millicore, Memory MB)
// to LinuxSandboxResources. Returns defaults if the map is nil or empty.
func resourcesToLinux(
	resources map[string]float64,
	cpuLimitMode string,
) *runtime.LinuxSandboxResources {
	const (
		defaultCPUMillicores    = float64(500)
		minimumCPUQuota         = int64(1000)
		defaultMemoryLimitBytes = int64(4 * 1024 * 1024 * 1024) // 4GB
	)

	res := &runtime.LinuxSandboxResources{
		MemoryLimitInBytes: defaultMemoryLimitBytes,
	}
	cpuMillicores := defaultCPUMillicores

	if cpu, ok := resources["CPU"]; ok && cpu > 0 {
		cpuMillicores = cpu
	}

	if cpuLimitMode == config.CPULimitModeQuota {
		quota := math.Ceil(cpuMillicores * float64(config.DefaultCPUPeriodMicros) / 1000)
		if quota < float64(minimumCPUQuota) {
			quota = float64(minimumCPUQuota)
		}
		if quota >= float64(math.MaxInt64) {
			res.CpuQuota = math.MaxInt64
		} else {
			res.CpuQuota = int64(quota)
		}
		res.CpuPeriod = config.DefaultCPUPeriodMicros
	} else {
		// CPU is in millicore (1000 = 1 core). Convert to cpu.shares (1024 = 1 core).
		res.CpuShares = uint64(cpuMillicores * 1024 / 1000)
		if res.CpuShares < 2 {
			res.CpuShares = 2 // minimum cpu.shares
		}
	}

	if mem, ok := resources["Memory"]; ok && mem > 0 {
		// Memory is in MB.
		res.MemoryLimitInBytes = int64(mem * 1024 * 1024)
	}

	return res
}

type ExtraConfig struct {
	// NetworkStack selects the in-sandbox network stack. The open-source runsc
	// adapter supports gVisor netstack only; empty is treated as netstack.
	NetworkStack string `json:"networkStack,omitempty"`

	// EnableKVM exposes the configured character device as /dev/kvm. It is
	// intentionally opt-in and valid only for the host-kernel runc runtime.
	EnableKVM bool `json:"enableKVM,omitempty"`
}

type fsPrepareResult struct {
	fs  *preparedFS
	err error
}

type resourcePrepareResult struct {
	resources *preparedStartResources
	err       error
}

func (h *sandboxService) Start(ctx context.Context, request *runtime.StartRequest) (*runtime.StartResponse, error) {
	return h.createSandbox(ctx, request, createOptions{})
}

type createOptions struct {
	checkpointImage    string
	onReserved         func(*runtime.StartRequest, string) error
	restoreIdentity    *runtime.RestoreIdentity
	resourceGeneration string
	beforeSideEffects  func() error
}

func (h *sandboxService) createSandbox(
	ctx context.Context,
	request *runtime.StartRequest,
	options createOptions,
) (_ *runtime.StartResponse, retErr error) {
	if request == nil {
		err := fmt.Errorf("start request is nil")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	if !h.recoveryReady.Load() {
		err := errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	startReq := proto.Clone(request).(*runtime.StartRequest)
	checkpointDir := ""
	var err error
	if startReq.CheckpointInfo != nil {
		checkpointDir, err = validateCheckpointInputDirectory(
			startReq.CheckpointInfo.CheckpointDir,
		)
		if err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()}, errord.ToGRPC(err)
		}
	}
	// A caller cannot choose/reuse the physical resource incarnation.
	if startReq.Labels == nil {
		startReq.Labels = make(map[string]string)
	}
	startReq.Labels[resourceGenerationLabel] = uuid.NewString()
	if options.resourceGeneration != "" {
		startReq.Labels[resourceGenerationLabel] = options.resourceGeneration
	}
	// Birth-resource evidence is a fresh observation bound to the generation
	// above: drop any caller-supplied or checkpoint-source-carried record
	// before it can reach the metadata and annotations copies. A restored
	// generation always gets a newly observed record.
	delete(startReq.Labels, birthResourcesLabel)
	if err := validateElasticResources(startReq, h.config, options.checkpointImage != ""); err != nil {
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
	}
	if startReq.Runtime == "" {
		startReq.Runtime = config.RuntimeNameRunsc
	}
	networkPolicy, err := networkacl.NormalizePolicy(startReq.NetworkPolicy)
	if err != nil {
		wrapped := errord.ToGRPC(fmt.Errorf("invalid network policy: %v: %w", err, errord.ErrInvalidArgument))
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, wrapped
	}
	if startReq.Runtime == config.RuntimeNameRunc && !networkPolicy.Empty() {
		err := errors.New("network ACL is not supported by runtime runc")
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrFailedPrecondition))
	}
	if !networkPolicy.Empty() && h.aclMgr == nil {
		err := errors.New("network ACL is disabled")
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrFailedPrecondition))
	}
	aclEnabled := h.aclMgr != nil && startReq.Runtime != config.RuntimeNameRunc
	if aclEnabled {
		if err := validateManagedResolverMounts(startReq.Mounts); err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
		}
	}
	if startReq.Rootfs == nil {
		err := fmt.Errorf("rootfs is required")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	if startReq.InjectEntrypoint != "" && startReq.Rootfs.GetType() != runtime.RootfsSrcType_IMAGE {
		err := errors.New("inject_entrypoint requires an OCI or Nydus image rootfs")
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
	}
	if startReq.InjectEntrypoint != "" {
		if err := validateImageProcessTarget(startReq.InjectEntrypoint); err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
		}
		if err := validateImageProcessMounts(startReq.Mounts, startReq.InjectEntrypoint); err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
		}
	}
	if rootfsLimit := startReq.Rootfs.WritableLayerSizeBytes; rootfsLimit > 0 {
		if startReq.WritableLayerLimitBytes > 0 && startReq.WritableLayerLimitBytes != rootfsLimit {
			err := fmt.Errorf(
				"conflicting writable layer limits: start request has %d bytes, rootfs has %d bytes",
				startReq.WritableLayerLimitBytes,
				rootfsLimit,
			)
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrInvalidArgument)
		}
		startReq.WritableLayerLimitBytes = rootfsLimit
	}
	if startReq.Cwd == "" {
		startReq.Cwd = "/"
	}
	if startReq.Stdout == "" {
		logrus.Warnf("stdout path is empty for sandbox %q; discarding stdout to %s", startReq.SandboxID, os.DevNull)
		startReq.Stdout = os.DevNull
	}
	if startReq.Stderr == "" {
		logrus.Warnf("stderr path is empty for sandbox %q; discarding stderr to %s", startReq.SandboxID, os.DevNull)
		startReq.Stderr = os.DevNull
	}
	if startReq.Network == "" {
		startReq.Network = "sandbox"
	}
	for key := range startReq.Envs {
		if xpumanager.ReservedEnv(key) {
			err := fmt.Errorf("environment variable %q is managed by sandboxd", key)
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrInvalidArgument)
		}
	}
	for key := range startReq.Labels {
		if xpumanager.ReservedAnnotation(key) {
			err := fmt.Errorf("label %q is managed by sandboxd", key)
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrInvalidArgument)
		}
	}
	extraConfig := ExtraConfig{}
	if startReq.ExtraConfig != "" {
		if err := json.Unmarshal([]byte(startReq.ExtraConfig), &extraConfig); err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("invalid extra config: %v", err),
			}, errord.ToGRPC(errord.ErrInvalidArgument)
		}
		if extraConfig.NetworkStack != "" && extraConfig.NetworkStack != "netstack" {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("unsupported network stack %q", extraConfig.NetworkStack),
			}, errord.ToGRPC(errord.ErrInvalidArgument)
		}
	}
	if extraConfig.NetworkStack != "" && startReq.Runtime != config.RuntimeNameRunsc {
		err := fmt.Errorf("networkStack is supported only by runtime %q", config.RuntimeNameRunsc)
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if extraConfig.EnableKVM && startReq.Runtime != config.RuntimeNameRunc {
		err := fmt.Errorf("enableKVM is supported only by runtime %q", config.RuntimeNameRunc)
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if len(startReq.XpuAllocations) > 0 && startReq.Runtime != config.RuntimeNameRunsc {
		err := fmt.Errorf("XPU allocations require runtime %q", config.RuntimeNameRunsc)
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if startReq.WritableLayerLimitBytes > 0 {
		if startReq.Runtime != config.RuntimeNameRunsc &&
			startReq.Runtime != config.RuntimeNameFirecracker {
			err := fmt.Errorf(
				"writable layer limits require runtime %q or %q; runtime %q is unsupported",
				config.RuntimeNameRunsc,
				config.RuntimeNameFirecracker,
				startReq.Runtime,
			)
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrInvalidArgument)
		}
		if h.config.RuntimeConfig.FilestoreDir == "" {
			err := errors.New("writable layer limits require plugin.runtime.filestore_dir")
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrFailedPrecondition)
		}
		if h.volumeMgr == nil {
			err := errors.New("writable layer storage manager is unavailable")
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrFailedPrecondition)
		}
	}

	if err := h.checkRuntime(startReq.Runtime); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("runtime %q is not available: %v", startReq.Runtime, err),
		}, err
	}
	if handler, ok := h.serviceHandler.Get(startReq.Runtime); ok {
		if validator, ok := handler.(svc.StartRequestValidator); ok {
			if err := validator.ValidateStartRequest(startReq); err != nil {
				return &runtime.StartResponse{Code: -1, Message: err.Error()},
					errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrInvalidArgument))
			}
		}
	}
	if checkpointDir != "" {
		handler, ok := h.serviceHandler.Get(startReq.Runtime)
		if !ok {
			return &runtime.StartResponse{Code: -1, Message: "runtime is unavailable"},
				errord.ToGRPC(errord.ErrNotImplemented)
		}
		if !supportsCheckpointRestore(handler) {
			return &runtime.StartResponse{Code: -1, Message: "runtime does not support checkpoint restore"},
				errord.ToGRPC(errord.ErrNotImplemented)
		}
	}

	sandboxID, err := h.sandboxManager.ReserveID(startReq.SandboxID)
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to reserve sandbox id: %v", err),
		}, errord.ToGRPC(err)
	}
	startReq.SandboxID = sandboxID
	unlock, lockErr := h.resourceLocks.acquire(ctx, sandboxID)
	if lockErr != nil {
		h.sandboxManager.ReleaseID(sandboxID)
		return nil, errord.ToGRPC(lockErr)
	}
	defer unlock()
	startSucceeded := false
	var preparedFilesystem *preparedFS
	var preparedResources *preparedStartResources
	var sandboxFiles *preparedSandboxFiles
	var portsReserved bool
	var metadataPersistenceAttempted bool
	defer func() {
		if startSucceeded {
			return
		}
		// PersistMetadata can rename before its durability confirmation fails.
		// From the first attempted publication onward, every failure belongs to
		// this physical generation. Keep its ID, files and all prepared leases
		// for authoritative reconciliation; inline rollback cannot prove their
		// complete retirement and must not erase the durable ownership first.
		if metadataPersistenceAttempted {
			logrus.Warnf("retain original physical ownership for sandbox %s after creation failure", sandboxID)
			return
		}
		if portsReserved {
			h.networkMgr.releaseDnatPorts(sandboxID)
		}
		h.sandboxManager.ReleaseID(sandboxID)
	}()
	if options.beforeSideEffects != nil {
		if err := options.beforeSideEffects(); err != nil {
			return nil, err
		}
	}
	resolvedPorts, err := h.networkMgr.resolveDnatPorts(sandboxID, startReq.Ports)
	if err != nil {
		return &runtime.StartResponse{Code: -1, Message: err.Error()},
			errord.ToGRPC(fmt.Errorf("reserve sandbox ports: %v: %w", err, errord.ErrResourceExhausted))
	}
	startReq.Ports = resolvedPorts
	portsReserved = len(resolvedPorts) > 0
	metadata := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: startReq.Runtime,
		Labels:         copyStringMap(startReq.Labels),
		MetricLabels:   copyStringMap(startReq.MetricLabels),
		Stdout:         startReq.Stdout,
		Stderr:         startReq.Stderr,
		Ports:          clonePorts(startReq.Ports),
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
	}
	if options.restoreIdentity != nil {
		metadata.RestoreIdentity = proto.Clone(options.restoreIdentity).(*runtime.RestoreIdentity)
	}
	metadataPersistenceAttempted = true
	if err := h.sandboxManager.PersistMetadata(sandboxID, metadata); err != nil {
		return &runtime.StartResponse{
			Code: -1, Message: fmt.Sprintf("Failed to persist sandbox physical identity: %v", err),
		}, err
	}
	if options.onReserved != nil {
		if err := options.onReserved(startReq, sandboxID); err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
		}
	}

	fsCh := make(chan fsPrepareResult, 1)
	resourceCh := make(chan resourcePrepareResult, 1)
	go func() {
		preparedFS, err := h.fsMgr.Prepare(startReq)
		fsCh <- fsPrepareResult{fs: preparedFS, err: err}
	}()
	go func() {
		resources, err := h.prepareStartResources(startReq.Runtime, sandboxID, metadata.Labels[resourceGenerationLabel])
		resourceCh <- resourcePrepareResult{resources: resources, err: err}
	}()

	fsResult := <-fsCh
	resourceResult := <-resourceCh
	preparedFilesystem = fsResult.fs
	preparedResources = resourceResult.resources
	preparationErr := errors.Join(fsResult.err, resourceResult.err)
	// Persist every returned lease before reporting a preparation failure.
	// The allocation worker never releases a partial set on its own.
	if preparedResources != nil {
		if err := h.persistPhysicalResourceFacts(metadata, preparedResources.Resources); err != nil {
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errors.Join(preparationErr, err, errPhysicalPreparationIncomplete)
		}
	}
	if preparationErr != nil {
		// A partial filesystem preparation is owned too. Confirm its
		// original source so restart reconciliation can locate it even when
		// another resource failed. Its source intent was already written before
		// filesystem allocation, and commit errors retain that original owner.
		if preparedFilesystem != nil {
			if err := h.fsMgr.Commit(sandboxID, preparedFilesystem); err != nil {
				preparationErr = errors.Join(preparationErr, err)
			}
		}
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to prepare sandbox: %v", preparationErr),
			ID:      "",
		}, errors.Join(preparationErr, errPhysicalPreparationIncomplete)
	}
	if err := h.fsMgr.Commit(sandboxID, preparedFilesystem); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to commit filesystem state: %v", err),
		}, err
	}
	runtimeRootfs := preparedFilesystem.RootfsPath()
	var specUpdates *svc.SpecUpdates
	if len(startReq.XpuAllocations) > 0 {
		if h.xpuMgr == nil {
			err := errors.New("XPU manager is not configured")
			return &runtime.StartResponse{Code: -1, Message: err.Error()},
				errord.ToGRPC(errord.ErrFailedPrecondition)
		}
		specUpdates, err = h.xpuMgr.Acquire(sandboxID, startReq.XpuAllocations)
		if err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("failed to allocate XPU devices: %v", err),
			}, errord.ToGRPC(errord.ErrInvalidArgument)
		}
	}

	// Rootfs env (from image mount) goes first with lowest priority; request
	// envs follow and override on key conflict because combineEnvs uses a map
	// where later entries win.
	rootfsEnvs := preparedFilesystem.rootfs.RootFS.Env()
	env := make([]*runtime.KeyValue, 0, len(rootfsEnvs)+len(startReq.Envs))
	for _, e := range rootfsEnvs {
		if parts := strings.SplitN(e, "=", 2); len(parts) == 2 {
			if xpumanager.ReservedEnv(parts[0]) {
				continue
			}
			env = append(env, &runtime.KeyValue{
				Key:   parts[0],
				Value: parts[1],
			})
		}
	}
	for k, v := range startReq.Envs {
		env = append(env, &runtime.KeyValue{
			Key:   k,
			Value: v,
		})
	}
	var imageProcess *imageProcessSpec
	if startReq.InjectEntrypoint != "" {
		resolvedImageProcess, resolveErr := preparedFilesystem.rootfs.RootFS.ResolveImageProcess()
		if resolveErr != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("failed to resolve image process: %v", resolveErr),
			}, resolveErr
		}
		imageProcess, err = buildImageProcessSpec(resolvedImageProcess)
		if err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("failed to prepare image process: %v", err),
			}, err
		}
	}

	annotations := copyStringMap(startReq.Labels)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	for key, value := range preparedResources.ToLabels() {
		annotations[key] = value
	}

	sandboxResources := resourcesToLinux(startReq.Resources, h.config.CPULimitMode)
	if h.config.DisableCgroup {
		sandboxResources = nil
	}
	defaults := svc.SandboxDefaults{Hostname: svc.DefaultSandboxHostname}
	if handler, ok := h.serviceHandler.Get(startReq.Runtime); ok {
		if provider, ok := handler.(svc.SandboxDefaultsProvider); ok {
			defaults = provider.SandboxDefaults()
		}
	}
	if aclEnabled {
		if preparedResources.network == nil ||
			preparedResources.network.Interface == nil ||
			preparedResources.network.Interface.Name == "" {
			err = errors.New("allocated network policy endpoint is missing")
			return &runtime.StartResponse{
				Code: -1, Message: err.Error(),
			}, err
		}
		h.aclMu.Lock()
		err = h.aclMgr.Register(networkacl.Binding{
			SandboxID: sandboxID,
			IP:        preparedResources.network.Ip,
			HostVeth:  preparedResources.network.Interface.Name,
		}, networkPolicy)
		h.aclMu.Unlock()
		if err != nil {
			return &runtime.StartResponse{
				Code: -1, Message: fmt.Sprintf("failed to install network ACL: %v", err),
			}, err
		}
	}
	sandboxFiles, err = h.prepareSandboxFiles(
		sandboxID,
		defaults,
		preparedResources.network.Ip,
		aclEnabled,
		preparedFilesystem.Mounts(),
		imageProcess,
		startReq.InjectEntrypoint,
	)
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to prepare sandbox files: %v", err),
		}, err
	}
	runtimeConfig := svc.StartConfig{
		ID:                      sandboxID,
		Hostname:                defaults.Hostname,
		Command:                 startReq.Command,
		Rootfs:                  runtimeRootfs,
		RootfsReadonly:          startReq.Rootfs.GetReadonly(),
		Resources:               sandboxResources,
		Mounts:                  sandboxFiles.Mounts(),
		Envs:                    env,
		Stdout:                  startReq.Stdout,
		Stderr:                  startReq.Stderr,
		Cwd:                     startReq.Cwd,
		CgroupPath:              preparedResources.Resources[config.ResourceNameCgroup],
		Annotations:             annotations,
		Network:                 preparedResources.network,
		DisableCgroup:           h.config.DisableCgroup,
		SpecUpdates:             specUpdates,
		WritableLayerLimitBytes: startReq.WritableLayerLimitBytes,
		ExtraConfig:             startReq.ExtraConfig,
		EnableKVM:               extraConfig.EnableKVM,
		CheckpointDir:           checkpointDir,
	}
	if options.checkpointImage == "" {
		err = h.startSandboxRuntime(ctx, startReq.Runtime, runtimeConfig, metadata)
	} else {
		err = h.restoreSandboxRuntime(ctx, startReq.Runtime, runtimeConfig, options.checkpointImage, metadata)
	}
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to create sandbox runtime: %v", err),
			ID:      "",
		}, err
	}

	// If Ports are specified, set up DNAT rules using sandbox IP from startSandboxRuntime.
	if len(startReq.Ports) > 0 {
		if preparedResources.sandboxIP == "" {
			return &runtime.StartResponse{
				Code:    -1,
				Message: "Failed to get sandbox IP for DNAT",
			}, errors.New("sandbox IP not available")
		}
		if err := h.networkMgr.setupDnatRules(sandboxID, startReq.Ports, preparedResources.sandboxIP); err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("Failed to setup DNAT rules: %v", err),
			}, err
		}
	}

	metadata.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
	if preparedResources != nil && preparedResources.network != nil && preparedResources.network.Ip != nil {
		// W18: persist the bridge IP in metric labels so List exposes
		// sandbox_id <-> ip without reading OCI bundles off disk (bundles are
		// cleaned up while the sandbox runs).
		if metadata.MetricLabels == nil {
			metadata.MetricLabels = map[string]string{}
		}
		metadata.MetricLabels["bridge_ip"] = preparedResources.network.Ip.String()
	}
	if err := h.sandboxManager.PersistMetadata(sandboxID, metadata); err != nil {
		return &runtime.StartResponse{
			Code: -1, Message: fmt.Sprintf("Failed to commit sandbox physical identity: %v", err),
		}, err
	}
	if err := h.sandboxManager.ActivateMetadata(sandboxID); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to publish sandbox physical identity: %v", err),
		}, err
	}
	h.sandboxManager.ReceiveEvent(sandbox.Event{
		Type:      sandbox.EventTypeCreate,
		MetaData:  metadata,
		SandboxID: sandboxID,
	})
	startSucceeded = true
	return &runtime.StartResponse{
		Code:               0,
		Message:            "Succeed",
		ID:                 sandboxID,
		Ports:              clonePorts(startReq.Ports),
		ResourceGeneration: metadata.Labels[resourceGenerationLabel],
		SandboxIp:          preparedResources.sandboxIP,
	}, nil
}

func (h *sandboxService) Wait(ctx context.Context, request *runtime.WaitRequest) (*runtime.WaitResponse, error) {
	// Route Wait through the sandbox manager so the response observes the
	// terminal status that sandboxd has already persisted (set by the per-
	// sandbox monitor goroutine in sandbox.Manager.__startMonitor).
	// This avoids a second runc/runsc Wait and gives a consistent
	// happens-before edge for any state derived from the exit, e.g. the
	// OOM-kill reason embedded in WaitResponse.Message below.
	s, err := h.sandboxManager.WaitForExit(ctx, request.ID)
	if err != nil {
		return new(runtime.WaitResponse), errord.ToGRPC(err)
	}
	resp := &runtime.WaitResponse{ExitCode: s.ExitCode}
	if s.OOMKilled {
		resp.Message = "sandbox was oom-killed by the kernel (memory cgroup limit exceeded)"
	}
	return resp, nil
}
