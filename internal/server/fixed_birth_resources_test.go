// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func fixedBirthFixture(t *testing.T) (*sandboxService, *resizeCgroups, svc.StartConfig, *runtime.SandboxMetadata, *observedStartHandler) {
	t.Helper()
	handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
	h := newTestService(t, map[string]svc.Handler{"runsc": handler})
	h.config.CPULimitMode = config.CPULimitModeQuota
	h.config.ResourceConfig.MemoryHighRatio = 0.75
	c := &resizeCgroups{
		highRatio: 0.75, requestKnown: true, eventsKnown: true,
		autoFreezeConfirm: true, shrinkSupported: true,
		stats: cgroupmanager.Stats{
			CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true,
			MemoryLimitBytes: 2048 << 20, MemoryLimitKnown: true,
			MemoryUsageBytes: 64 << 20, MemoryUsageKnown: true,
		},
	}
	c.applyMemoryHigh(c.stats.MemoryLimitBytes)
	h.cgroupMgr = c
	annotations := map[string]string{
		"adx.environment_id":    "fixed-environment",
		"adx.runtime_id":        "fixed-runtime",
		"adx.generation":        "17",
		resourceGenerationLabel: "fixed-physical-generation",
	}
	start := svc.StartConfig{
		ID: "fixed-sandbox", CgroupPath: t.TempDir(),
		Resources: &runtime.LinuxSandboxResources{
			CpuQuota: 50000, CpuPeriod: 100000, MemoryLimitInBytes: 2048 << 20,
		},
		Annotations: annotations,
	}
	metadata := &runtime.SandboxMetadata{
		ID: start.ID, RuntimeHandler: "runsc", Labels: maps.Clone(annotations),
		ResourceFacts: map[string]string{config.ResourceNameCgroup: start.CgroupPath},
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
	}
	require.NoError(t, h.sandboxManager.PersistMetadata(start.ID, metadata))
	return h, c, start, metadata, handler
}

func commitFixedBirth(t *testing.T, h *sandboxService, start svc.StartConfig, metadata *runtime.SandboxMetadata) {
	t.Helper()
	require.NoError(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
	metadata.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
	require.NoError(t, h.sandboxManager.StoreMetadata(start.ID, metadata))
}

func TestFixedBirthPersistsEvidenceAndRevisionBeforeRuntimeStart(t *testing.T) {
	h, c, start, metadata, handler := fixedBirthFixture(t)
	handler.beforeStart = func() {
		raw, err := os.ReadFile(filepath.Join(h.config.RootDir, "containers", start.ID, config.SandboxMetaFile))
		require.NoError(t, err)
		saved := &runtime.SandboxMetadata{}
		require.NoError(t, proto.Unmarshal(raw, saved))
		require.NotEmpty(t, saved.Labels[birthResourcesLabel], "真实固定出生资源必须在处理器启动前持久保存。")
		birth := decodeBirthEvidence(t, saved.Labels[birthResourcesLabel])
		require.Equal(t, "fixed-physical-generation", birth.ResourceGeneration)
		require.Equal(t, int64(50000), birth.CpuQuotaUsec)
		require.Equal(t, uint64(2048<<20), birth.MemoryLimitBytes)
		state, result, err := h.loadResourceOperationState(start.ID, "fixed-physical-generation")
		require.NoError(t, err)
		require.Equal(t, resourceStateLoaded, result)
		require.Equal(t, uint64(1), state.Revision)
		require.Equal(t, start.CgroupPath, state.CgroupPath)
		require.NotZero(t, state.CgroupInode)
		require.False(t, state.open())
		require.Empty(t, saved.Labels[elasticResourcesLabel])
	}
	commitFixedBirth(t, h, start, metadata)
	require.True(t, handler.started)
	stats, err := h.resourceStats(start.ID)
	require.NoError(t, err)
	require.True(t, stats.ResourceRevisionKnown)
	require.Equal(t, uint64(1), stats.ResourceRevision)
	require.Equal(t, start.CgroupPath, stats.MemoryCgroupPath)
	require.Empty(t, stats.ElasticPolicy)
	require.Zero(t, c.freezeWrites)
}

func TestFixedBirthRestoreRecordsFreshPhysicalGeneration(t *testing.T) {
	h, _, start, metadata, _ := fixedBirthFixture(t)
	handler := &observedRestoreHandler{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	start.Annotations[resourceGenerationLabel] = "fixed-restored-generation"
	metadata.Labels[resourceGenerationLabel] = "fixed-restored-generation"
	metadata.Labels[birthResourcesLabel] = "调用者携带的旧证据不得成为本代际证据。"
	require.NoError(t, h.restoreSandboxRuntime(context.Background(), "runsc", start, "checkpoint.img", metadata))
	require.True(t, handler.restored)
	birth := decodeBirthEvidence(t, metadata.Labels[birthResourcesLabel])
	require.Equal(t, "restore", birth.Phase)
	require.Equal(t, "fixed-restored-generation", birth.ResourceGeneration)
	state, result, err := h.loadResourceOperationState(start.ID, "fixed-restored-generation")
	require.NoError(t, err)
	require.Equal(t, resourceStateLoaded, result)
	require.Equal(t, uint64(1), state.Revision)
	_, result, err = h.loadResourceOperationState(start.ID, "fixed-physical-generation")
	require.NoError(t, err)
	require.Equal(t, resourceStateMissing, result)
}

func TestFixedBirthRejectsUnprovenOrMismatchingPreparedLimits(t *testing.T) {
	for _, failure := range []string{"unknown_memory", "unknown_cpu", "setter_noop", "backend_error"} {
		t.Run(failure, func(t *testing.T) {
			h, c, start, metadata, handler := fixedBirthFixture(t)
			switch failure {
			case "unknown_memory":
				c.stats.MemoryLimitKnown = false
			case "unknown_cpu":
				c.stats.CPULimitsKnown = false
			case "setter_noop":
				c.noWrite = true
				c.stats.MemoryLimitBytes = 4096 << 20
			case "backend_error":
				c.failReadback = true
			}
			err := h.startSandboxRuntime(context.Background(), "runsc", start, metadata)
			require.Error(t, err)
			require.False(t, handler.started)
			_, result, err := h.loadResourceOperationState(start.ID, "fixed-physical-generation")
			require.NoError(t, err)
			require.Equal(t, resourceStateMissing, result)
		})
	}
}

func TestFixedBirthRejectsForeignPreparedOwnership(t *testing.T) {
	for _, field := range []string{"nil", "sandbox", "generation", "phase", "adx.environment_id", "adx.runtime_id", "adx.generation"} {
		t.Run(field, func(t *testing.T) {
			h, _, start, metadata, handler := fixedBirthFixture(t)
			switch field {
			case "nil":
				metadata = nil
			case "sandbox":
				metadata.ID = "foreign-sandbox"
			case "generation":
				metadata.Labels[resourceGenerationLabel] = "foreign-generation"
			case "phase":
				metadata.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
			default:
				metadata.Labels[field] = "foreign"
			}
			require.Error(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
			require.False(t, handler.started)
		})
	}
}

func TestFixedBirthPersistenceFailureStopsRuntimeHandler(t *testing.T) {
	for _, failure := range []string{"birth_metadata", "revision_directory", "missing_cgroup"} {
		t.Run(failure, func(t *testing.T) {
			h, _, start, metadata, handler := fixedBirthFixture(t)
			switch failure {
			case "birth_metadata":
				target := filepath.Join(h.config.RootDir, "containers", start.ID)
				require.NoError(t, os.RemoveAll(target))
				require.NoError(t, os.WriteFile(target, []byte("不是元数据目录"), 0600))
			case "revision_directory":
				require.NoError(t, os.WriteFile(h.resourceStateDir(), []byte("不是修订目录"), 0600))
			case "missing_cgroup":
				require.NoError(t, os.Remove(start.CgroupPath))
			}
			require.Error(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
			require.False(t, handler.started)
		})
	}
}

func TestFixedBirthRevisionSurvivesJournalReopen(t *testing.T) {
	h, c, start, metadata, _ := fixedBirthFixture(t)
	commitFixedBirth(t, h, start, metadata)
	_, path := h.resourceStatePath(start.ID, "fixed-physical-generation")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	reopened := &sandboxService{config: h.config, sandboxManager: h.sandboxManager, cgroupMgr: c}
	open, failures := reopened.healOpenResourceStates(context.Background())
	require.Zero(t, open)
	require.Zero(t, failures)
	stats, err := reopened.resourceStats(start.ID)
	require.NoError(t, err)
	require.True(t, stats.ResourceRevisionKnown)
	require.Equal(t, uint64(1), stats.ResourceRevision)
	require.Equal(t, start.CgroupPath, stats.MemoryCgroupPath)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, c.freezeWrites)
}

func TestFixedBirthMissingOrCorruptJournalIsNotReinitialized(t *testing.T) {
	for _, failure := range []string{"missing", "corrupt"} {
		t.Run(failure, func(t *testing.T) {
			h, c, start, metadata, _ := fixedBirthFixture(t)
			commitFixedBirth(t, h, start, metadata)
			_, path := h.resourceStatePath(start.ID, "fixed-physical-generation")
			if failure == "missing" {
				require.NoError(t, os.Remove(path))
			} else {
				require.NoError(t, os.WriteFile(path, []byte("{损坏"), 0600))
			}
			reopened := &sandboxService{config: h.config, sandboxManager: h.sandboxManager, cgroupMgr: c}
			reopened.healOpenResourceStates(context.Background())
			stats, err := reopened.resourceStats(start.ID)
			require.NoError(t, err)
			require.False(t, stats.ResourceRevisionKnown)
			require.Empty(t, stats.MemoryCgroupPath)
			if failure == "missing" {
				_, err := os.Stat(path)
				require.True(t, os.IsNotExist(err))
			} else {
				raw, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, []byte("{损坏"), raw)
				require.True(t, stats.ResourceOperationPending)
			}
			require.Zero(t, c.freezeWrites)
		})
	}
}

func TestFixedBirthReplacedCgroupWithholdsTrustedLocator(t *testing.T) {
	h, _, start, metadata, _ := fixedBirthFixture(t)
	commitFixedBirth(t, h, start, metadata)
	require.NoError(t, os.Rename(start.CgroupPath, start.CgroupPath+"-original"))
	require.NoError(t, os.Mkdir(start.CgroupPath, 0700))
	stats, err := h.resourceStats(start.ID)
	require.NoError(t, err)
	require.True(t, stats.ResourceRevisionKnown)
	require.Equal(t, uint64(1), stats.ResourceRevision)
	require.Empty(t, stats.MemoryCgroupPath)
}

func TestFixedBirthRecordDoesNotEnableElasticMutations(t *testing.T) {
	h, c, start, metadata, _ := fixedBirthFixture(t)
	commitFixedBirth(t, h, start, metadata)
	_, path := h.resourceStatePath(start.ID, "fixed-physical-generation")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	writes, memoryWrites, freezeWrites := c.writes, c.memoryWrites, c.freezeWrites
	expected := &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 2048 << 20}
	_, err = h.ResizeResources(context.Background(), &runtime.ResizeResourcesRequest{
		SandboxID: start.ID, ResourceGeneration: "fixed-physical-generation",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(), OperationID: "fixed-grow-rejected",
		ExpectedRevision: 1, Expected: expected,
		Target: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 2560 << 20},
	})
	require.ErrorContains(t, err, "no elastic policy")
	_, err = h.ShrinkResources(context.Background(), &runtime.ShrinkResourcesRequest{
		SandboxID: start.ID, ResourceGeneration: "fixed-physical-generation",
		DeadlineUnixMs: time.Now().Add(30 * time.Second).UnixMilli(), OperationID: "fixed-shrink-rejected",
		ExpectedRevision: 1, Expected: expected,
		Target: &runtime.ResourceLimits{CpuQuotaUsec: 50000, CpuPeriodUsec: 100000, MemoryLimitBytes: 1024 << 20},
	})
	require.ErrorContains(t, err, "no elastic policy")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, writes, c.writes)
	require.Equal(t, memoryWrites, c.memoryWrites)
	require.Equal(t, freezeWrites, c.freezeWrites)
}

func TestFixedBirthDuplicateInitializationDoesNotResetRevision(t *testing.T) {
	h, _, start, metadata, _ := fixedBirthFixture(t)
	commitFixedBirth(t, h, start, metadata)
	metadata.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT
	_, path := h.resourceStatePath(start.ID, "fixed-physical-generation")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Error(t, h.initializeResourceRevision(start, metadata))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
