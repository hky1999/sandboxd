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

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
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
	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/pkg/checkpointcatalog"
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

// aclManager is the network ACL surface the service depends on. Production
// binds *networkacl.Manager; recovery call-chain tests substitute a recording
// implementation, because the real manager cannot be constructed without
// kernel ACL state.
type aclManager interface {
	Register(binding networkacl.Binding, policy networkacl.Policy) error
	// Restore reconciles persisted ACL state with the ownership recovery
	// reconstructed: active bindings are re-applied, protected bindings
	// (pending start intents) are verified and retained without re-applying.
	Restore(active map[string]networkacl.Binding, protected map[string]networkacl.ProtectedBinding) error
	SetPolicy(sandboxID string, policy networkacl.Policy) error
	Remove(sandboxID string) error
	Close() error
}

var _ aclManager = (*networkacl.Manager)(nil)

// sandboxService implements SandboxService.
type sandboxService struct {
	// config is the sandbox service config
	config         config.Config
	serviceHandler cmap.ConcurrentMap[string, svc.Handler]

	sandboxManager *sandbox.Manager

	// Resource and infrastructure managers owned by the server. SandboxManager
	// receives only the cgroup manager reference it needs for OOM monitoring;
	// allocation, release, and shutdown stay in server-owned managers.
	cgroupMgr    *cgroupmanager.CgroupManager
	interfaceMgr *networkmanager.InterfaceManager
	networkMgr   *networkManager
	aclMgr       aclManager
	resourceMod  *resourcemanager.Module
	imageMod     *imagemanager.Module
	imageSvc     imageapi.Service
	volumeMgr    *volumemanager.Module
	xpuMgr       *xpumanager.Manager

	store store.DbStore

	runtime.UnimplementedSandboxServiceServer

	fsMgr *fsManager

	ready         atomic.Bool
	recoveryReady atomic.Bool
	deleteGroup   singleflight.Group
	resourceLocks physicalLocks
	// startIntents is the durable in-flight start journal. It is loaded before
	// sandbox/filesystem recovery and consulted by Start admission, Delete
	// (legacy and conditional), and Checkpoint so a retained failed start can
	// neither be restarted under the same ID nor be bypassed into cleanup.
	startIntents *startIntentStore
	// startOperations is the durable start-operation journal behind
	// StartWithOperation: per-operation idempotency records that survive reply
	// loss, daemon restart, and sandbox deletion. It loads before the intent
	// journal so committed-intent takeovers can promote operation facts.
	startOperations *startOperationStore
	// allocateStartResourceFn is an in-package test seam; production is nil.
	allocateStartResourceFn           allocateStartResourceFunc
	retirementMu                      sync.Mutex
	aclMu                             sync.Mutex
	checkpointMu                      sync.Mutex
	checkpointing                     map[string]struct{}
	firecrackerCheckpointMemorySlotMu sync.Mutex
	firecrackerCheckpointMemorySlot   chan struct{}
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

// startSandboxRuntime dispatches one runtime Start or Restore. The returned
// invoked flag reports whether the runtime call was reached at all: an error
// with invoked=false (capability or cgroup preparation) cannot have left a
// runtime process behind, while invoked=true failures carry whatever exit
// information the runtime's own contract provides. The error is returned raw
// — no sandbox-root cleanup and no gRPC conversion — because the management
// plane decides rollback versus retention from the error chain.
func (h *sandboxService) startSandboxRuntime(
	ctx context.Context,
	runtimeName string,
	startConfig svc.StartConfig,
) (invoked bool, err error) {
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("StartSandbox failed, traceID: %v, spanId: %v, err: %v", traceID, spanID, err)
		}
	}()

	if err = h.checkRuntime(runtimeName); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("check runtime failed: %v", err)
		return false, fmt.Errorf("runtime %q is not available: %w", runtimeName, err)
	}

	handler, ok := h.serviceHandler.Get(runtimeName)
	if !ok {
		return false, fmt.Errorf("runtime %q: %w", runtimeName, errord.ErrNotImplemented)
	}

	if startConfig.CgroupPath != "" {
		if h.cgroupMgr == nil {
			return false, errors.New("cgroup manager is not configured")
		}
		hostResources := startConfig.Resources
		if provider, ok := handler.(svc.HostResourcesProvider); ok {
			hostResources = provider.HostResources(startConfig.Resources)
		}
		if err = h.cgroupMgr.Prepare(startConfig.CgroupPath, hostResources); err != nil {
			return false, fmt.Errorf("prepare cgroup %s: %w", startConfig.CgroupPath, err)
		}
	}

	invoked = true
	if startConfig.CheckpointDir != "" {
		checkpointHandler, ok := handler.(svc.CheckpointHandler)
		if !ok {
			return false, fmt.Errorf(
				"runtime %q does not support checkpoint restore: %w",
				runtimeName, errord.ErrNotImplemented,
			)
		}
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
		err = handler.Start(ctx, startConfig)
	}
	if err != nil {
		// The error crosses no boundary here: the management plane must see
		// the raw runtime failure — including runtime.ErrStartCleanupPending —
		// to decide between rollback and retention, and the sandbox root it
		// allocated stays untouched until that decision is made.
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler create sandbox failed: %v", err)
		return true, err
	}

	logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("StartSandbox %s success, traceID: %v, spanId: %v, cost: %v", startConfig.ID, traceID, spanID, time.Since(start).String())
	return true, nil
}

// deleteSandboxRuntime retires the sandbox's physical resources under the
// per-ID physical lock shared with Start and Checkpoint. A non-empty expected
// generation switches the flow to conditional retirement: the generation is
// rechecked under the lock, a pending receipt is durably recorded before any
// runtime effect, only a strict runtime delete (which proves it retired state
// it found) may proceed, and a complete receipt is recorded only after the
// sandbox state directory is confirmed gone. Legacy deletion keeps the
// idempotent semantics: a missing sandbox is a successful no-op.
func (h *sandboxService) deleteSandboxRuntime(ctx context.Context, sandboxID string, expectedGeneration ...string) (err error) {
	expected := ""
	if len(expectedGeneration) > 0 {
		expected = expectedGeneration[0]
	}
	unlock, err := h.resourceLocks.acquire(ctx, sandboxID)
	if err != nil {
		return errord.ToGRPC(err)
	}
	defer unlock()

	// A pending start intent owns the ID with undetermined runtime state.
	// Neither legacy nor conditional deletion may bypass that protection:
	// legacy deletion would otherwise report success for an ID whose retained
	// incarnation still exists, and its DNAT cleanup would mutate the
	// retained sandbox's rules.
	if h.startIntents.Pending(sandboxID) {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s is protected by a pending start intent; reconcile the retained start before deletion",
			sandboxID,
		)
	}

	// Legacy deletion keeps its idempotent cleanup of stale DNAT rules —
	// including for an already-missing sandbox — but now under the same
	// physical lock as Start, so it cannot race a concurrent creation for
	// this ID. Conditional retirement cleans DNAT only after its generation
	// and strict-exit gates pass below.
	if expected == "" && h.networkMgr != nil {
		h.networkMgr.cleanupDnatRules(sandboxID)
	}

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
			// Durable proof from a prior attempt: replay it without touching
			// the current physical state.
			return nil
		}
	}

	c, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) && expected == "" {
			return nil
		}
		// Conditional retirement: missing sandbox state without a complete
		// receipt is an unknown outcome, never a retirement proof.
		return errord.ToGRPC(err)
	}

	if expected != "" && (c.Metadata == nil ||
		c.Metadata.Labels[resourceGenerationLabel] != expected) {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox resource generation changed before delete",
		)
	}

	if h.checkRuntime(c.Metadata.RuntimeHandler) != nil {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	handler, ok := h.serviceHandler.Get(c.Metadata.RuntimeHandler)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	var strictDelete svc.StrictDeleteHandler
	if expected != "" {
		strictDelete, ok = handler.(svc.StrictDeleteHandler)
		if !ok {
			return errord.ToGRPCf(
				errord.ErrNotImplemented,
				"runtime %q does not support strict conditional delete",
				c.Metadata.RuntimeHandler,
			)
		}
	}

	resource, err := h.sandboxManager.CollectResourceByID(sandboxID)
	if err != nil {
		return err
	}

	if expected != "" {
		// The pending receipt must be durable before the runtime can produce
		// any effect, so a crash mid-delete leaves an explicitly unfinished
		// record rather than silence.
		if err := h.writeRetirement(sandboxID, expected, false); err != nil {
			return err
		}
	}

	if expected != "" {
		// Strict delete: any error, including missing runtime state or an
		// unbound/mismatched runtime generation, fails conditional
		// retirement. Absence attests nothing.
		if err = strictDelete.DeleteStrict(ctx, sandboxID, expected); err != nil {
			metrics.RecordRuntimeCallResult("delete", "failed", c.Metadata.RuntimeHandler)
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler strict delete sandbox failed: %v", err)
			return errord.ToGRPC(err)
		}
	} else {
		err = handler.Delete(ctx, sandboxID)
		if err != nil && !errors.Is(err, errord.ErrNotFound) {
			metrics.RecordRuntimeCallResult("delete", "failed", c.Metadata.RuntimeHandler)
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler force delete sandbox failed: %v", err)
			return errord.ToGRPC(err)
		}
	}
	metrics.RecordRuntimeCallResult("delete", "success", c.Metadata.RuntimeHandler)
	if h.resourceMod != nil {
		h.resourceMod.ReleaseTransientMemory(
			firecrackerCheckpointReservationOwner(sandboxID),
		)
	}
	if h.xpuMgr != nil {
		h.xpuMgr.Release(sandboxID)
	}
	// Conditional retirement reaches network cleanup only now, after the
	// generation and strict-exit gates passed; legacy deletion cleaned DNAT
	// under the lock at the top of this function.
	if expected != "" && h.networkMgr != nil {
		h.networkMgr.cleanupDnatRules(sandboxID)
	}

	if err := h.deactivateStartNetwork(resource); err != nil {
		return err
	}

	if err := h.fsMgr.Release(sandboxID); err != nil {
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
	if err := h.releaseStartResources(resource); err != nil {
		return err
	}

	h.sandboxManager.Delete(sandboxID)
	if expected != "" {
		root, rootErr := util.JoinWithinRoot(
			filepath.Join(h.config.RootDir, "containers"),
			sandboxID,
		)
		if rootErr != nil {
			return rootErr
		}
		// Manager.Delete is void and its disk cleanup can fail silently; the
		// receipt attests a retired generation only when the state directory
		// is confirmed absent.
		if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf(
				"sandbox metadata retirement not confirmed for %s (lstat: %v)",
				sandboxID,
				statErr,
			)
		}
		if err := syncRetirementDirectory(filepath.Dir(root)); err != nil {
			return err
		}
		if err := h.writeRetirement(sandboxID, expected, true); err != nil {
			return err
		}
	}
	return nil
}

// deleteSandbox coalesces concurrent delete requests for the same sandbox.
// Cleanup runs independently from the initiating caller's cancellation so a
// timed-out RPC cannot leave a partially deleted sandbox for another caller to
// release again, and every network or resource effect happens under the
// per-ID physical lock inside deleteSandboxRuntime. Legacy and conditional
// deletes, and different expected generations, use distinct coalescing keys:
// a legacy request must never join or be joined by a conditional one.
func (h *sandboxService) deleteSandbox(ctx context.Context, sandboxID string, expectedGeneration ...string) error {
	expected := ""
	if len(expectedGeneration) > 0 {
		expected = expectedGeneration[0]
	}
	key, _ := json.Marshal([2]string{sandboxID, expected})
	resultCh := h.deleteGroup.DoChan(string(key), func() (interface{}, error) {
		cleanupCtx := context.WithoutCancel(ctx)
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
	var sandboxes []*sandbox.Sandbox
	response := new(runtime.ListSandboxesResponse)
	if request.ID != "" {
		sandboxes = h.sandboxManager.List(sandbox.ListFilterById(request.ID))
		if len(sandboxes) == 0 {
			return response, errord.ToGRPC(errord.ErrNotFound)
		}
	} else {
		sandboxes = h.sandboxManager.List(sandbox.ListFilterByLabels(request.Selector))
	}

	for idx := range sandboxes {
		c := sandboxes[idx]
		if c == nil || c.Status == nil || c.Metadata == nil {
			continue
		}
		response.Sandboxes = append(response.Sandboxes, &runtime.SandboxStatus{
			ID:           c.Metadata.ID,
			Runtime:      c.Metadata.RuntimeHandler,
			State:        c.Status.Get().State(),
			StartedAt:    util.MustInt64(c.Status.Get().StartedAt),
			FinishedAt:   util.MustInt64(c.Status.Get().FinishedAt),
			ExitCode:     c.Status.Get().ExitCode,
			Labels:       copyStringMap(c.Metadata.Labels),
			MetricLabels: copyStringMap(c.Metadata.MetricLabels),
			Stdout:       c.Metadata.Stdout,
			Stderr:       c.Metadata.Stderr,
		})
	}
	return response, nil
}

func (h *sandboxService) Stats(ctx context.Context, request *runtime.StatsRequest) (*runtime.StatsResponse, error) {
	if request.ID == "" {
		return nil, errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if h.config.DisableCgroup {
		return nil, errord.ToGRPC(fmt.Errorf(
			"sandbox stats require per-sandbox cgroups: %w",
			errord.ErrFailedPrecondition,
		))
	}

	// Look up the sandbox to verify it exists.
	_, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}

	// Get the cgroup path from the sandbox's OCI spec.
	resource, err := h.sandboxManager.CollectResourceByID(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	cgroupPath, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupPath == "" {
		return nil, errord.ToGRPC(fmt.Errorf("cgroup path not found for sandbox %s", request.ID))
	}

	if h.cgroupMgr == nil {
		return nil, errord.ToGRPC(errors.New("cgroup manager is not configured"))
	}
	cgroupStats, err := h.cgroupMgr.Stats(cgroupPath)
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("stat cgroup %s failed: %v", cgroupPath, err))
	}

	return &runtime.StatsResponse{
		CpuUsageNs:          cgroupStats.CPUUsageNanos,
		CpuKernelNs:         cgroupStats.CPUKernelNanos,
		CpuUserNs:           cgroupStats.CPUUserNanos,
		MemoryUsageBytes:    cgroupStats.MemoryUsageBytes,
		MemoryLimitBytes:    cgroupStats.MemoryLimitBytes,
		MemoryMaxUsageBytes: cgroupStats.MemoryMaxUsageBytes,
	}, nil
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
		if _, ok := handler.(svc.CheckpointHandler); ok {
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

	// 0. Drain admitted start operations first. Admission closes atomically,
	// every in-flight execution's context is cancelled to request
	// convergence, and Shutdown BLOCKS until each executor has actually
	// returned — a context deadline proves nothing about goroutine
	// convergence, and tearing down filesystem/network/runtime state an
	// executor may still be using would break the rollback and retention
	// invariants the Start flow enforces. An execution that ignores
	// cancellation therefore holds shutdown until it exits.
	h.startOperations.shutdown()

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

	// A retained start's filesystem ownership and network leases survive the
	// shutdown: the persisted fs state keeps them, and the interface manager
	// keeps their leased devices recorded as active so restart recovery
	// re-acquires instead of destroying them. ACL close, image-module drain,
	// and volume unmount below still tear their layers down for everything;
	// that boundary is documented in doc/checkpoint-restore.md.
	h.fsMgr.Shutdown(h.startIntents.Pending)

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
		if err := h.interfaceMgr.ShutDownPreserving(preservedInterfaceResources(h.startIntents)); err != nil {
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
		// Retained starts keep their OCI mounts: the image layer must not
		// unmount what the filesystem layer deliberately preserved.
		h.imageMod.StopPreserving(preservedOCIImages(h.startIntents))
	}
	if h.resourceMod != nil {
		h.resourceMod.Stop()
	}
	if h.volumeMgr != nil {
		// Retained starts keep the bounded filestore mounted and its backing
		// image intact; the next daemon start adopts the mount.
		if err := h.volumeMgr.StopPreserving(len(h.startIntents.List()) > 0); err != nil {
			logrus.Warnf("shutdown: failed to unmount filestore: %v", err)
		}
	}
	logrus.Info("sandbox service shutdown complete")
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
//
// A changed or missing stamp is not evidence that the previous pod's runtimes
// exited, so the wipe is refused outright while any start-intent record
// exists: those records protect undetermined runtime incarnations, and
// clearing them (or the state they reference) without a retirement proof
// would silently release retained objects. An empty journal keeps the
// historical behavior.
func resetStateIfPodChanged(storeDir, rootDir, imageManagerRoot string) error {
	current, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}
	stampPath := filepath.Join(storeDir, ".pod_host")
	if stored, err := os.ReadFile(stampPath); err == nil && string(stored) == current {
		return nil
	}

	intentEntries, err := os.ReadDir(filepath.Join(rootDir, startIntentsDirName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read start intent journal before pod reset: %w", err)
	}
	records := 0
	for _, entry := range intentEntries {
		if strings.HasPrefix(entry.Name(), ".intent-") {
			continue
		}
		if _, ok := startIntentFileID(entry.Name()); ok {
			records++
		}
	}
	if records > 0 {
		return fmt.Errorf(
			"pod identity changed (hostname=%q) but %d start-intent record(s) protect undetermined "+
				"runtime incarnations; reconcile the retained starts before the state reset",
			current, records,
		)
	}

	logrus.Infof("pod identity changed (hostname=%q): wiping persisted state in %s, %s, %s", current, storeDir, rootDir, imageManagerRoot)
	if err := os.RemoveAll(storeDir); err != nil {
		return fmt.Errorf("remove storeDir %s: %w", storeDir, err)
	}
	// "containers" is the established on-disk directory name used by the
	// sandbox manager and runsc handler for state recovery. The start-intent
	// journal describes state that this same wipe removes (sandbox metadata,
	// resource leases), so it is wiped with it rather than left protecting
	// IDs whose referenced state no longer exists. The start-operation
	// tombstones are deliberately KEPT: a historical start fact does not
	// require the sandbox to exist, and deleting it would let an old
	// operation ID be re-admitted after the reset — the replay protection
	// must outlive the instances it describes.
	for _, sub := range []string{"containers", startIntentsDirName} {
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

	// The start-operation journal loads first so committed-intent takeovers
	// during the intent load below can promote matching operation records
	// from the same committed evidence. A corrupt record fails startup.
	startOperations, err := loadStartOperations(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("load start operations: %w", err)
	}

	// The start-intent journal loads before any resource module or recovery
	// pass runs: a pending intent must be known before a manager could
	// destroy retained state, and a corrupt or contradictory record must fail
	// this startup before construction defers tear anything down. A prepared
	// intent is satisfied only by sandbox metadata carrying the same
	// daemon-assigned generation.
	var startIntents *startIntentStore
	startIntents, err = loadStartIntents(
		cfg.RootDir,
		readSandboxMetadataIdentity(cfg.RootDir),
		startOperations.promoteCommittedTakeover,
	)
	if err != nil {
		return nil, fmt.Errorf("load start intents: %w", err)
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
	if cfg.NodeResourceConfig.SockPath != "" {
		sockPath := cfg.NodeResourceConfig.SockPath
		mod, merr := resourcemanager.NewModule(sockPath, cfg.NodeResourceConfig.Provider)
		if merr != nil {
			return nil, fmt.Errorf("node-resource module init: %w", merr)
		}
		mod.SetXPUProvider(xpuMgr)
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

	// The optional checkpoint catalog exposes the node's Firecracker v2
	// checkpoint directories as a read-only inventory view for cross-node
	// consumers. Gated on [plugin.checkpoint_catalog]: nothing to serve
	// without configured roots.
	if catalogCfg := cfg.CheckpointCatalogConfig; catalogCfg.SockPath != "" {
		nodeRecord, nerr := buildCheckpointCatalogNode(cfg, catalogCfg)
		if nerr != nil {
			return nil, fmt.Errorf("checkpoint catalog node record: %w", nerr)
		}
		catalogMod, cerr := checkpointcatalog.NewModule(checkpointcatalog.Config{
			SockPath:      catalogCfg.SockPath,
			Listen:        catalogCfg.Listen,
			Dirs:          catalogCfg.Dirs,
			TemplateRoots: catalogCfg.TemplateRoots,
			Node:          nodeRecord,
		})
		if cerr != nil {
			return nil, fmt.Errorf("checkpoint catalog module init: %w", cerr)
		}
		logrus.Infof("checkpoint catalog module ready, sock=%s listen=%s dirs=%v node=%s",
			catalogCfg.SockPath, catalogCfg.Listen, catalogCfg.Dirs, nodeRecord.ID)
		defer func() {
			if retErr != nil {
				catalogMod.Close()
			}
		}()
	} else {
		logrus.Infof("checkpoint catalog module disabled (no [plugin.checkpoint_catalog] config)")
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
			imgMod.StopPreserving(preservedOCIImages(startIntents))
		}
	}()
	imgSvc := imgMod.Service()

	stateStore := store.NewStoreImp(storePath)
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
		startIntents:                      startIntents,
		startOperations:                   startOperations,
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
			if vErr := s.volumeMgr.StopPreserving(len(startIntents.List()) > 0); vErr != nil {
				logrus.Warnf("init rollback: volumemanager Stop failed: %v", vErr)
			}
		}
	}()
	s.loadRuntimeHandlers()
	if nodeResMod != nil && cfg.RuntimeConfig.FilestoreDir != "" {
		if _, ok := s.serviceHandler.Get(config.RuntimeNameRunsc); ok {
			nodeResMod.SetEphemeralStorageProvider(s.volumeMgr)
		}
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
		// The already-loaded start-intent journal protects pending IDs here:
		// recovery must not destroy an ephemeral lease whose sandbox metadata
		// is missing precisely because its start is retained.
		interfaceMgr, err = networkmanager.NewInterfaceManagerPreserving(
			s.store,
			cfg.IPRange,
			maxSandboxLimit,
			cfg.InterfaceCacheSize,
			cfg.NatBackend,
			startIntents.Pending,
			sandboxRoot,
		)
		if err != nil {
			return nil, err
		}
		s.interfaceMgr = interfaceMgr
		metrics.RecordResourceGauge("interface", float64(interfaceMgr.CacheSizeLimit()))
		defer func() {
			if retErr != nil {
				// Startup failed after the journal loaded: retained starts
				// keep their leased devices here too.
				_ = interfaceMgr.ShutDownPreserving(preservedInterfaceResources(startIntents))
			}
		}()
	}
	s.networkMgr = newNetworkManager(interfaceMgr, cfg.NatBackend, cfg.EnableLocalDNAT)
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

	// The start-intent journal is already loaded (before any module was
	// constructed). Here the recovery it gates runs before the sandbox
	// manager reads containers/, so a pending intent's directory without
	// metadata is preserved instead of being moved to the recycle bin that
	// housekeeping empties.
	pendingIntents := startIntents.List()

	if s.sandboxManager, err = sandbox.NewManager(
		cfg.RootDir,
		s.serviceHandler,
		healthChan,
		cgroupMgr,
		maxSandboxLimit,
		sandbox.WithPreservedSandboxRoots(startIntents.Pending),
	); err != nil {
		return nil, err
	}
	if nodeResMod != nil {
		nodeResMod.SetSandboxMetricsSource(s.sandboxManager)
		s.sandboxManager.OnSandboxStopped = nodeResMod.MarkSandboxStopped
	}
	// Pending intents block their IDs: the same ID must not start a second
	// incarnation while the retained one is unreconciled. They count against
	// the admission ceiling, and exhausting it is a hard startup failure. An
	// already-reserved ID means the recovered sandbox (the ambiguous
	// prepared-plus-metadata crash state) holds the reservation — that blocks
	// reuse exactly as well, so it is not an error.
	for _, record := range pendingIntents {
		if _, resErr := s.sandboxManager.ReserveID(record.SandboxID); resErr != nil &&
			!errors.Is(resErr, errord.ErrAlreadyExists) {
			return nil, fmt.Errorf("reserve pending start intent %s: %w", record.SandboxID, resErr)
		}
	}
	if err := s.fsMgr.Restore(func(sandboxID string) bool {
		if _, getErr := s.sandboxManager.Get(sandboxID); getErr == nil {
			return true
		}
		// A pending start still owns its committed filesystem references;
		// recovery must not reclaim them as an orphan's.
		return s.startIntents.Pending(sandboxID)
	}); err != nil {
		return nil, fmt.Errorf("restore sandbox filesystem state: %w", err)
	}
	if s.aclMgr != nil {
		if err := s.restoreNetworkACL(); err != nil {
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

// restoreNetworkACL reconciles persisted ACL state with everything recovery
// re-established as owning a network endpoint: running sandboxes and pending
// start intents. Failures are definite errors — no destructive reconciliation
// may run on contradictory or missing ownership evidence.
func (h *sandboxService) restoreNetworkACL() error {
	bindings, protected, err := h.aclRecoveryOwnership()
	if err != nil {
		return err
	}
	return h.aclMgr.Restore(bindings, protected)
}

// aclRecoveryOwnership reconstructs the complete network ACL ownership after
// recovery. Bindings holds every owner whose endpoint must survive the ACL
// restore: active sandboxes and pending start intents alike. Protected marks
// the pending subset — starts whose outcome is unknown — whose ACL entries
// must be verified against the durable network resource and retained, never
// re-applied as a normal active sandbox nor reconciled as orphans.
func (h *sandboxService) aclRecoveryOwnership() (
	bindings map[string]networkacl.Binding,
	protected map[string]networkacl.ProtectedBinding,
	err error,
) {
	bindings = make(map[string]networkacl.Binding)
	for _, current := range h.sandboxManager.List() {
		if current == nil || current.Metadata == nil {
			continue
		}
		if current.Metadata.RuntimeHandler == config.RuntimeNameRunc {
			continue
		}
		sandboxID := current.Metadata.ID
		resources, err := h.sandboxManager.CollectResourceByID(sandboxID)
		if err != nil {
			return nil, nil, fmt.Errorf("collect network resource for sandbox %s: %w", sandboxID, err)
		}
		encoded, ok := resources.Resources[config.ResourceNameInterface]
		if !ok {
			return nil, nil, fmt.Errorf("sandbox %s has no network resource", sandboxID)
		}
		network, err := networkmanager.NewNetResource(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("decode network resource for sandbox %s: %w", sandboxID, err)
		}
		if network.Interface == nil || network.Interface.Name == "" {
			return nil, nil, fmt.Errorf("sandbox %s network endpoint is missing", sandboxID)
		}
		bindings[sandboxID] = networkacl.Binding{
			SandboxID: sandboxID,
			IP:        network.Ip,
			HostVeth:  network.Interface.Name,
		}
	}
	protected, err = pendingACLOwnership(h.startIntents.List(), bindings)
	if err != nil {
		return nil, nil, err
	}
	for sandboxID, owner := range protected {
		bindings[sandboxID] = owner.Binding
	}
	return bindings, protected, nil
}

// activeACLBindings returns every network owner that must survive ACL
// recovery — running sandboxes and pending start intents alike. It is the
// union view of aclRecoveryOwnership; the ACL restore itself additionally
// receives the protected subset.
func (h *sandboxService) activeACLBindings() (map[string]networkacl.Binding, error) {
	bindings, _, err := h.aclRecoveryOwnership()
	return bindings, err
}

// pendingACLOwnership derives the protected ACL ownership of pending start
// intents from their durable network resource leases. A retained start owns
// its interface lease, so its ACL entry must survive recovery; the resource
// identity (IP, host endpoint, ifindex) is the only acceptable proof, and a
// record that is missing, undecodable, or contradictory is a definite error —
// never a guess by ID or a silently skipped protection. A pending intent
// whose ID also carries an active sandbox (the ambiguous crash state between
// metadata persistence and the committed handover) must describe the very
// same lease from both views; the pending protection then applies.
func pendingACLOwnership(
	records []startIntentRecord,
	active map[string]networkacl.Binding,
) (map[string]networkacl.ProtectedBinding, error) {
	protected := make(map[string]networkacl.ProtectedBinding)
	for _, record := range records {
		if record.Runtime == config.RuntimeNameRunc {
			// runc starts never register ACL state — Start refuses a policy
			// for them — so a retained runc start owns nothing to protect.
			continue
		}
		encoded := record.Resources[config.ResourceNameInterface]
		if encoded == "" {
			return nil, fmt.Errorf(
				"pending start intent %s (generation %s, phase %s) records no network resource lease",
				record.SandboxID, record.Generation, record.Phase,
			)
		}
		network, err := networkmanager.NewNetResource(encoded)
		if err != nil {
			return nil, fmt.Errorf(
				"decode network resource for pending start intent %s: %w", record.SandboxID, err,
			)
		}
		if network.Interface == nil || network.Interface.Name == "" ||
			network.Ip == nil || network.Ip.To4() == nil || network.Interface.Index == 0 {
			return nil, fmt.Errorf(
				"pending start intent %s network endpoint identity is incomplete", record.SandboxID,
			)
		}
		owner := networkacl.ProtectedBinding{
			Binding: networkacl.Binding{
				SandboxID: record.SandboxID,
				IP:        network.Ip,
				HostVeth:  network.Interface.Name,
			},
			IfIndex: network.Interface.Index,
		}
		if binding, alsoActive := active[record.SandboxID]; alsoActive {
			if binding.HostVeth != owner.HostVeth || !binding.IP.Equal(owner.IP) {
				return nil, fmt.Errorf(
					"active network resource for sandbox %s (ip %s, host endpoint %s) contradicts its pending start intent (ip %s, host endpoint %s)",
					record.SandboxID, binding.IP, binding.HostVeth, owner.IP, owner.HostVeth,
				)
			}
		}
		for otherID, other := range protected {
			if other.IP.Equal(owner.IP) || other.HostVeth == owner.HostVeth {
				return nil, fmt.Errorf(
					"pending start intents %s and %s both claim network endpoint %s/%s",
					otherID, record.SandboxID, owner.IP, owner.HostVeth,
				)
			}
		}
		protected[record.SandboxID] = owner
	}
	return protected, nil
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
	err = h.deleteSandbox(ctx, request.ID)
	return response, err
}

// DeleteIfGeneration requires a physical identity match under the same lock as
// Start/Checkpoint/Delete, or replays a completed durable receipt for that
// generation. Missing sandbox state without such a receipt remains unknown and
// is reported as an error, never as a retirement.
func (h *sandboxService) DeleteIfGeneration(ctx context.Context, request *runtime.DeleteIfGenerationRequest) (*runtime.DeleteIfGenerationResponse, error) {
	if request == nil || request.ID == "" ||
		request.ExpectedGeneration == "" || len(request.ExpectedGeneration) > 128 {
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
	return h.start(ctx, request, nil)
}

// start runs the complete legacy Start flow. op, when non-nil, is the trusted
// server-side operation binding StartWithOperation admitted: it fixes the
// daemon-assigned generation (a caller label can never choose it) and records
// the operation's terminal facts at the exact ordering points this flow
// reaches — success between the intent journal's committed write and its
// record removal, failure before the intent record is cleared, unknown when
// the outcome cannot be proven. Nothing else about the flow changes.
func (h *sandboxService) start(
	ctx context.Context,
	request *runtime.StartRequest,
	op *startOperationBinding,
) (*runtime.StartResponse, error) {
	if request == nil {
		err := fmt.Errorf("start request is nil")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	if !h.recoveryReady.Load() {
		err := errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	startReq := proto.Clone(request).(*runtime.StartRequest)
	// The physical incarnation identity is daemon-owned: a caller-supplied
	// label under the reserved key is replaced, never honored. An admitted
	// operation reuses the generation persisted at its admission, so a
	// replayed or recovered operation always names the same incarnation.
	var generation string
	if op != nil {
		generation = op.generation
		bindResourceGeneration(startReq, generation)
	} else {
		generation = assignResourceGeneration(startReq)
	}
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
		if _, ok := handler.(svc.CheckpointHandler); !ok {
			return &runtime.StartResponse{Code: -1, Message: "runtime does not support checkpoint restore"},
				errord.ToGRPC(errord.ErrNotImplemented)
		}
	}

	// A retained failed start still owns its ID; restarting under the same ID
	// could produce a second incarnation of an undetermined runtime state.
	if startReq.SandboxID != "" && h.startIntents.Pending(startReq.SandboxID) {
		err := fmt.Errorf(
			"sandbox %s is protected by a pending start intent; reconcile the retained start first: %w",
			startReq.SandboxID, errord.ErrFailedPrecondition,
		)
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, errord.ToGRPC(err)
	}
	sandboxID, err := h.sandboxManager.ReserveID(startReq.SandboxID)
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to reserve sandbox id: %v", err),
		}, errord.ToGRPC(err)
	}
	startReq.SandboxID = sandboxID
	// Serialize creation against checkpoint and (conditional or legacy) delete
	// for this ID. The lock is held through the full rollback below, so a
	// failed start cannot race a delete that reuses the reserved ID.
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
	var filesystemCommitted bool
	var runtimeCalled bool
	var runtimeStarted bool
	var runtimeStartErr error
	var startIntentRecord *startIntentRecord
	var dnatConfigured bool
	var aclAttempted bool
	var aclRegistered bool
	var xpuAcquired bool
	// retained keeps every start reference in place — runtime state, ID,
	// network/cgroup leases, filesystem ownership, DNAT, ACL, sandbox files —
	// when the runtime's exit or a release step could not be proven. The
	// durable intent record is moved to the retained phase so a restart and
	// the reconciliation tooling can see why the ID is blocked. Failures from
	// before the intent existed have no durable anchor and no unknown runtime
	// state; they keep the legacy best-effort rollback and return false.
	retained := false
	retain := func(reason error) bool {
		if startIntentRecord == nil {
			logrus.Warnf("rollback step failed for sandbox %s before the start intent existed: %v", sandboxID, reason)
			return false
		}
		retained = true
		logrus.Errorf(
			"retain sandbox %s after failed start (generation %s): %v; ID, resources, and filesystem stay reserved until reconciliation",
			sandboxID, generation, reason,
		)
		if err := h.startIntents.retain(sandboxID, startIntentRecord, reason.Error()); err != nil {
			logrus.Errorf("persist retained start intent for sandbox %s: %v", sandboxID, err)
		}
		if op != nil {
			// Retention means the outcome could not be proven either way; the
			// operation must never re-execute under this ID.
			h.startOperations.markUnknown(op.operationID, fmt.Sprintf(
				"start retained with undetermined outcome: %v", reason,
			))
		}
		return true
	}
	defer func() {
		if startSucceeded || retained {
			return
		}
		// Runtime disposition comes first: nothing else may be released until
		// the runtime side of this start is proven gone.
		if runtimeCalled {
			handler, _ := h.serviceHandler.Get(startReq.Runtime)
			if runtimeStartErr != nil && errors.Is(runtimeStartErr, svc.ErrStartCleanupPending) {
				// The runtime itself retained the instance and its artifacts;
				// signalling it again is forbidden. Everything stays.
				if retain(fmt.Errorf(
					"runtime retained sandbox after failed start: %v", runtimeStartErr,
				)) {
					return
				}
			}
			if handler != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				var proofErr error
				if runtimeStarted {
					// The runtime reported success and then a later step
					// failed; releasing references now would orphan a live
					// process, so retirement requires the generation-checked
					// strict delete proof.
					strict, ok := handler.(svc.StrictDeleteHandler)
					if !ok {
						cancel()
						if retain(fmt.Errorf(
							"runtime %q cannot prove exit by generation after start succeeded",
							startReq.Runtime,
						)) {
							return
						}
					} else {
						proofErr = strict.DeleteStrict(cleanupCtx, sandboxID, generation)
						if proofErr == nil {
							// The generation-checked proof retired exactly
							// this incarnation, so its sandbox directory may
							// go too.
							h.sandboxManager.CleanSandboxRoot(sandboxID)
						}
					}
				} else {
					// A failed start: only the runtime's own failure contract
					// can prove its side. A participating runtime's plain
					// error already confirmed the exit and cleaned its state;
					// any other runtime's failure — including its legacy
					// Delete's idempotent nil — proves nothing, so the start
					// is retained for reconciliation instead of unwound.
					// The prover's plain error covers only the artifacts THIS
					// call created; it is not authorization to wipe the whole
					// containers/<id> directory, which may still hold a
					// pre-existing same-ID incarnation's state. This start's
					// own artifacts (sandbox files, leases, filesystem
					// ownership) are released by the steps below.
					prover, ok := handler.(svc.StartFailureCleanupProver)
					if !ok || !prover.StartFailureCleanupProven() {
						cancel()
						if retain(fmt.Errorf(
							"runtime %q has no proven failed-start cleanup contract; outcome unknown",
							startReq.Runtime,
						)) {
							return
						}
					}
				}
				cancel()
				if proofErr != nil {
					if retain(fmt.Errorf(
						"runtime exit for sandbox %s not confirmed: %w", sandboxID, proofErr,
					)) {
						return
					}
				}
			}
		}
		if dnatConfigured {
			h.networkMgr.cleanupDnatRules(sandboxID)
		}
		if preparedResources != nil {
			if err := h.deactivateStartNetwork(preparedResources.OccupiedResource); err != nil {
				if retain(fmt.Errorf(
					"deactivate network endpoint while rolling back sandbox %s: %w", sandboxID, err,
				)) {
					return
				}
			}
		}
		aclCleanupFailed := aclAttempted && !aclRegistered
		if aclAttempted && h.aclMgr != nil {
			h.aclMu.Lock()
			aclErr := h.aclMgr.Remove(sandboxID)
			h.aclMu.Unlock()
			if aclErr != nil {
				if retain(fmt.Errorf("rollback network ACL for sandbox %s: %w", sandboxID, aclErr)) {
					return
				}
				aclCleanupFailed = true
			}
		}
		if aclCleanupFailed && preparedResources != nil {
			resource := preparedResources.Resources[config.ResourceNameInterface]
			// Never return an endpoint whose ACL registration or cleanup failed
			// to the idle pool. A successful discard destroys its TC
			// attachments; a failed discard leaves the lease quarantined in
			// the interface manager for restart recovery.
			if discardErr := h.networkMgr.Discard(resource); discardErr != nil {
				logrus.Warnf(
					"quarantine interface after ACL rollback failure for sandbox %s: %v",
					sandboxID,
					discardErr,
				)
			}
			delete(preparedResources.Resources, config.ResourceNameInterface)
		}
		if filesystemCommitted {
			if err := h.fsMgr.Release(sandboxID); err != nil {
				if retain(fmt.Errorf(
					"rollback filesystem state for sandbox %s: %w", sandboxID, err,
				)) {
					return
				}
			}
		} else if preparedFilesystem != nil {
			preparedFilesystem.Rollback()
		}
		if preparedResources != nil {
			if err := h.releaseStartResources(preparedResources.OccupiedResource); err != nil {
				if retain(fmt.Errorf(
					"rollback resources for sandbox %s: %w", sandboxID, err,
				)) {
					return
				}
			}
		}
		if xpuAcquired && h.xpuMgr != nil {
			h.xpuMgr.Release(sandboxID)
		}
		if sandboxFiles != nil {
			sandboxFiles.Rollback()
		}
		// The rollback is fully proven; the intent record may be dropped only
		// durably, and only then may the ID return to the pool. A record whose
		// removal fails keeps the ID blocked — after a restart it shows up as
		// a pending intent again. The operation's failed fact is recorded
		// first so a crash between the two writes leaves the operation
		// reporting failure rather than an unproven admission.
		if op != nil {
			if err := h.startOperations.markFailedConfirmed(op.operationID,
				"start was fully rolled back with a proven cleanup"); err != nil {
				logrus.Errorf("persist failed outcome for start operation %s: %v", op.operationID, err)
			}
		}
		if startIntentRecord != nil {
			if err := h.startIntents.clear(sandboxID); err != nil {
				logrus.Errorf(
					"clear start intent for sandbox %s after confirmed rollback: %v; ID stays reserved",
					sandboxID, err,
				)
				return
			}
		}
		h.sandboxManager.ReleaseID(sandboxID)
	}()

	fsCh := make(chan fsPrepareResult, 1)
	resourceCh := make(chan resourcePrepareResult, 1)
	go func() {
		preparedFS, err := h.fsMgr.Prepare(startReq)
		fsCh <- fsPrepareResult{fs: preparedFS, err: err}
	}()
	go func() {
		resources, err := h.prepareStartResources(startReq.Runtime, sandboxID)
		resourceCh <- resourcePrepareResult{resources: resources, err: err}
	}()

	fsResult := <-fsCh
	resourceResult := <-resourceCh
	preparedFilesystem = fsResult.fs
	preparedResources = resourceResult.resources
	if fsResult.err != nil || resourceResult.err != nil {
		err := errors.Join(fsResult.err, resourceResult.err)
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to prepare sandbox: %v", err),
			ID:      "",
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
		xpuAcquired = specUpdates != nil
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
		aclAttempted = true
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
		aclRegistered = true
	}
	sandboxFiles, err = h.prepareSandboxFiles(
		sandboxID,
		defaults,
		preparedResources.network.Ip,
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
		// The runtime binds the daemon-generated incarnation identity into
		// its own persisted state, so strict deletes can verify it there.
		ResourceGeneration: generation,
		// Only an admitted start operation sets the admission-bound content
		// root; the legacy Start leaves it empty and runtimes enforce
		// nothing for it.
		ExpectedCheckpointRoot: op.expectedCheckpointRoot(),
	}
	// Commit the prepared filesystem references and persist the start intent
	// before the runtime can spawn anything. From the intent's durable write
	// onward, an unknown outcome keeps the ID, resource leases, and
	// filesystem ownership reserved; recovery treats the ID as existing, so
	// its committed filesystem state is never reclaimed as an orphan's.
	if err := h.fsMgr.Commit(sandboxID, preparedFilesystem); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to commit filesystem state: %v", err),
		}, err
	}
	filesystemCommitted = true
	startIntentRecord = h.buildStartIntent(sandboxID, generation, startReq.Runtime, preparedResources, preparedFilesystem)
	if err := h.startIntents.begin(startIntentRecord); err != nil {
		// The write's outcome may be indeterminate; only a confirmed record
		// removal makes the pre-runtime rollback below safe to release.
		if clearErr := h.startIntents.clear(sandboxID); clearErr != nil {
			retain(fmt.Errorf(
				"persist start intent for sandbox %s failed (%v) and the record's removal also failed (%v)",
				sandboxID, err, clearErr,
			))
		}
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to persist start intent: %v", err),
		}, errord.ToGRPC(fmt.Errorf("persist start intent for sandbox %s: %w", sandboxID, err))
	}

	// Set before the dispatch so a panic inside it still runs the runtime
	// disposition; a normal return replaces the flag with the accurate value
	// reported by startSandboxRuntime.
	runtimeCalled = true
	var runtimeInvoked bool
	runtimeInvoked, runtimeStartErr = h.startSandboxRuntime(ctx, startReq.Runtime, runtimeConfig)
	runtimeCalled = runtimeInvoked
	if runtimeStartErr != nil {
		// The raw runtime error reaches the RPC boundary unchanged in content;
		// the retention decision above has already used its error chain.
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to start: %v", runtimeStartErr),
			ID:      "",
		}, errord.ToGRPC(runtimeStartErr)
	}
	runtimeStarted = true

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
		dnatConfigured = true
	}

	metadata := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: startReq.Runtime,
		Labels:         copyStringMap(startReq.Labels),
		MetricLabels:   copyStringMap(startReq.MetricLabels),
		Stdout:         startReq.Stdout,
		Stderr:         startReq.Stderr,
	}
	if err := h.sandboxManager.StoreMetadata(sandboxID, metadata); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to persist sandbox metadata: %v", err),
		}, err
	}
	// The sandbox exists and runs from the manager's perspective once its
	// metadata is durable, so the monitor event is published regardless of
	// how the journal handover below resolves.
	h.sandboxManager.ReceiveEvent(sandbox.Event{
		Type:      sandbox.EventTypeCreate,
		MetaData:  metadata,
		SandboxID: sandboxID,
	})
	// The start has now succeeded on every durable axis — runtime, filesystem
	// commit, sandbox metadata — so the intent records the committed phase,
	// the success linearization point only recovery may take over against
	// fully matching metadata identity. For an identified operation, the
	// durable success fact is written between the committed record and its
	// removal: while that write fails the committed record stays on disk, so
	// no crash window exists in which the original success fact is lost — it
	// is recoverable from the operation record or from the committed-intent
	// takeover, whichever the crash leaves behind. A committed write that
	// fails leaves the outcome unproven on disk: the running instance is
	// never rolled back or auto-revoked, everything the start owns stays
	// protected (the ID, the resources, the committed filesystem ownership,
	// and the original prepared record), and the RPC must report the unknown
	// completion instead of success. A failure here means the committed write
	// itself could not be made durable; a committed record whose later
	// removal failed is NOT an error — complete reports that handover as done
	// and recovery takes the leftover committed record over.
	var onCommitted func() error
	if op != nil {
		onCommitted = func() error {
			return h.startOperations.markSucceeded(op.operationID, fmt.Sprintf(
				"start succeeded; sandbox %s runs as generation %s (historical fact, not a liveness claim)",
				sandboxID, generation,
			))
		}
	}
	if err := h.startIntents.complete(sandboxID, startIntentRecord, onCommitted); err != nil {
		if op != nil && !op.terminal() {
			h.startOperations.markUnknown(op.operationID, fmt.Sprintf(
				"sandbox %s may be running, but recording its start completion failed (%v); "+
					"the ID stays protected until reconciliation",
				sandboxID, err,
			))
		}
		retained = true
		logrus.Errorf(
			"persist committed start intent for sandbox %s failed (%v): completion outcome unknown; "+
				"the sandbox stays running, and the ID, resources, and original prepared record stay "+
				"protected until reconciliation",
			sandboxID, err,
		)
		return &runtime.StartResponse{
				Code:               -1,
				Message:            fmt.Sprintf("sandbox %s is running, but recording its start completion failed (%v); the ID stays protected until reconciliation", sandboxID, err),
				ID:                 sandboxID,
				ResourceGeneration: generation,
			}, errord.ToGRPC(fmt.Errorf(
				"record committed start intent for sandbox %s: completion outcome unknown: %w",
				sandboxID, err,
			))
	}
	startSucceeded = true
	return &runtime.StartResponse{
		Code:               0,
		Message:            "Succeed",
		ID:                 sandboxID,
		ResourceGeneration: generation,
	}, nil
}

// assignResourceGeneration installs a fresh daemon-owned physical incarnation
// label on the start request and returns it. A caller-supplied value under the
// reserved key is discarded: the client must not choose or reuse a sandbox's
// physical identity.
func assignResourceGeneration(request *runtime.StartRequest) string {
	generation := newResourceGeneration()
	bindResourceGeneration(request, generation)
	return generation
}

// newResourceGeneration mints one daemon-owned incarnation identity.
func newResourceGeneration() string {
	return uuid.NewString()
}

// bindResourceGeneration installs an already-assigned daemon-owned generation
// on the start request. StartWithOperation uses it with the generation
// persisted at admission so a replayed or recovered operation always names
// the same incarnation; a caller-supplied value is replaced, never honored.
func bindResourceGeneration(request *runtime.StartRequest, generation string) {
	if request.Labels == nil {
		request.Labels = make(map[string]string)
	}
	request.Labels[resourceGenerationLabel] = generation
}

// buildStartIntent snapshots the durable ownership a start has secured for the
// runtime invocation: the daemon-generated identity, the allocated resource
// leases, and the committed filesystem references. The record deliberately
// lists only what was handed to this preparation — allocations that crashed
// before the intent write are bounded by the resource managers' own durable
// leases, not by this record.
func (h *sandboxService) buildStartIntent(
	sandboxID, generation, runtimeName string,
	resources *preparedStartResources,
	filesystem *preparedFS,
) *startIntentRecord {
	record := &startIntentRecord{
		SandboxID:  sandboxID,
		Generation: generation,
		Runtime:    runtimeName,
	}
	if resources != nil {
		record.Resources = make(map[string]string, len(resources.Resources))
		for name, value := range resources.Resources {
			if value == "" {
				// An empty value is not a lease identity; record only the
				// resources this start actually owns.
				continue
			}
			record.Resources[name] = value
		}
	}
	if filesystem != nil {
		if state, err := stateFromPrepared(filesystem); err == nil {
			record.Filesystem = &startIntentFilesystem{
				Rootfs: state.Rootfs,
				S3:     state.S3,
				OCI:    state.OCI,
			}
		} else {
			logrus.Warnf("encode filesystem ownership for start intent %s: %v", sandboxID, err)
		}
	}
	return record
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
