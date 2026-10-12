// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestCheckpointCreatePathPersistsFreshRestoreBirthBeforeDispatch(t *testing.T) {
	h, _, _ := newResizeService(t)
	handler := newCheckpointTestHandler()
	h.serviceHandler.Set("runsc", handler)
	metadata := birthMetadata("elastic", "generation-checkpoint-create")
	metadata.Labels[birthResourcesLabel] = `{"schema_version":1,"resource_generation":"old-source"}`
	require.NoError(t, h.sandboxManager.PersistMetadata(metadata.ID, metadata))
	start := birthStartConfig(t, metadata.ID, birthAnnotations(t, metadata.Labels[resourceGenerationLabel]), 50000, 512*1024*1024)
	start.CheckpointDir = filepath.Join(t.TempDir(), "paired")
	handler.restoreFn = func(_ context.Context, actual svc.StartConfig, image string) error {
		require.Equal(t, "generation-checkpoint-create", actual.ResourceGeneration)
		require.Equal(t, filepath.Join(start.CheckpointDir, "checkpoint.img"), image)
		data, err := os.ReadFile(filepath.Join(h.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
		require.NoError(t, err)
		var saved runtime.SandboxMetadata
		require.NoError(t, proto.Unmarshal(data, &saved))
		birth := decodeBirthEvidence(t, saved.Labels[birthResourcesLabel])
		require.Equal(t, "restore", birth.Phase)
		require.Equal(t, metadata.Labels[resourceGenerationLabel], birth.ResourceGeneration)
		require.Equal(t, int64(50000), birth.CpuQuotaUsec)
		require.Equal(t, uint64(512*1024*1024), birth.MemoryLimitBytes)
		state, _, err := h.loadResourceOperationState(metadata.ID, actual.ResourceGeneration)
		require.NoError(t, err)
		require.NotNil(t, state)
		require.Equal(t, uint64(1), state.Revision)
		require.Equal(t, start.CgroupPath, state.CgroupPath)
		return nil
	}
	require.NoError(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
	require.Len(t, handler.restores, 1)
	require.Empty(t, handler.starts)
}

func TestCheckpointCreatePathRefusesUnknownOrUnboundRestoreBirth(t *testing.T) {
	for _, kind := range []string{"unknown-memory", "unknown-cpu", "mismatched-limits", "missing-metadata", "committed-metadata", "stale-generation"} {
		t.Run(kind, func(t *testing.T) {
			h, c, _ := newResizeService(t)
			handler := newCheckpointTestHandler()
			h.serviceHandler.Set("runsc", handler)
			metadata := birthMetadata("elastic", "generation-checkpoint-create")
			start := birthStartConfig(t, metadata.ID, birthAnnotations(t, metadata.Labels[resourceGenerationLabel]), 50000, 512*1024*1024)
			start.CheckpointDir = "/checkpoint-create-source"
			switch kind {
			case "unknown-memory":
				c.stats.MemoryLimitKnown = false
			case "unknown-cpu":
				c.stats.CPULimitsKnown = false
			case "mismatched-limits":
				c.noWrite = true
				start.Resources.MemoryLimitInBytes *= 2
			case "missing-metadata":
				metadata = nil
			case "committed-metadata":
				metadata.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
			case "stale-generation":
				metadata.Labels[resourceGenerationLabel] = "old-source"
			}
			require.Error(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
			require.Empty(t, handler.restores)
			require.Empty(t, handler.starts)
		})
	}
}

func TestCheckpointCreatePathPersistenceFailurePreventsRestoreDispatch(t *testing.T) {
	for _, kind := range []string{"birth-metadata", "resource-revision"} {
		t.Run(kind, func(t *testing.T) {
			h, _, _ := newResizeService(t)
			handler := newCheckpointTestHandler()
			h.serviceHandler.Set("runsc", handler)
			metadata := birthMetadata("elastic", "generation-checkpoint-create")
			start := birthStartConfig(t, metadata.ID, birthAnnotations(t, metadata.Labels[resourceGenerationLabel]), 50000, 512*1024*1024)
			start.CheckpointDir = "/checkpoint-create-source"
			var obstacle string
			if kind == "birth-metadata" {
				metadata.ID, start.ID = "sbox-checkpoint-create-obstacle", "sbox-checkpoint-create-obstacle"
				obstacle = filepath.Join(h.config.RootDir, "containers", metadata.ID)
				require.NoError(t, os.MkdirAll(filepath.Dir(obstacle), 0700))
			} else {
				_, obstacle = h.resourceStatePath(metadata.ID, metadata.Labels[resourceGenerationLabel])
			}
			require.NoError(t, os.WriteFile(obstacle, []byte("original-damaged-record"), 0600))
			require.Error(t, h.startSandboxRuntime(context.Background(), "runsc", start, metadata))
			require.Empty(t, handler.restores)
			require.Empty(t, handler.starts)
			data, err := os.ReadFile(obstacle)
			require.NoError(t, err)
			require.Equal(t, "original-damaged-record", string(data))
		})
	}
}

func TestCheckpointCreatePathUnknownRestoreRetainsOriginalIntentAndRevision(t *testing.T) {
	h, _, _ := newResizeService(t)
	handler := newCheckpointTestHandler()
	h.serviceHandler.Set("runsc", handler)
	metadata := birthMetadata("elastic", "generation-checkpoint-create")
	require.NoError(t, h.sandboxManager.PersistMetadata(metadata.ID, metadata))
	start := birthStartConfig(t, metadata.ID, birthAnnotations(t, metadata.Labels[resourceGenerationLabel]), 50000, 512*1024*1024)
	start.CheckpointDir = "/checkpoint-create-source"
	handler.restoreFn = func(context.Context, svc.StartConfig, string) error {
		return errors.Join(context.DeadlineExceeded, svc.ErrRestoreCleanupIncomplete)
	}
	err := h.startSandboxRuntime(context.Background(), "runsc", start, metadata)
	require.ErrorIs(t, err, svc.ErrRuntimeCreationUnconfirmed)
	require.ErrorIs(t, err, svc.ErrRestoreCleanupIncomplete)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	require.Len(t, handler.restores, 1)
	intents := h.sandboxManager.ListPhysicalIntents()
	require.Len(t, intents, 1)
	require.Equal(t, metadata.Labels[resourceGenerationLabel], intents[0].Labels[resourceGenerationLabel])
	require.NotEmpty(t, intents[0].Labels[birthResourcesLabel])
	state, _, err := h.loadResourceOperationState(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, uint64(1), state.Revision)
	require.Equal(t, start.CgroupPath, state.CgroupPath)
}
