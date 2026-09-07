// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// birthAnnotations returns the labels a prepared elastic handler config would
// carry: the elastic policy plus the incarnation's resource generation.
func birthAnnotations(t *testing.T, generation string) map[string]string {
	t.Helper()
	labels := elasticTestRequest(t).Labels
	labels[resourceGenerationLabel] = generation
	return labels
}

// birthMetadata mirrors createSandbox's durable INTENT metadata for the same
// generation, as it exists by the time the runtime handler is invoked.
func birthMetadata(id, generation string) *runtime.SandboxMetadata {
	return &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc",
		Labels: map[string]string{
			resourceGenerationLabel: generation,
			"prepared":              "intent",
		},
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
	}
}

func birthStartConfig(id string, annotations map[string]string, quota, memoryBytes int64) svc.StartConfig {
	return svc.StartConfig{
		ID: id, CgroupPath: "/sandbox/lease",
		Resources:   &runtime.LinuxSandboxResources{CpuQuota: quota, CpuPeriod: 100000, MemoryLimitInBytes: memoryBytes},
		Annotations: annotations,
	}
}

func decodeBirthEvidence(t *testing.T, raw string) birthResourceEvidence {
	t.Helper()
	var evidence birthResourceEvidence
	require.NoError(t, json.Unmarshal([]byte(raw), &evidence))
	return evidence
}

// The evidence must record the limits actually read back from the leaf cgroup
// (50000/100000 usec and 512MiB here), not merely the requested policy, and it
// must be durable on the INTENT metadata by the time the handler has run.
func TestBirthEvidencePersistsObservedLeafLimitsBeforeRuntimeStart(t *testing.T) {
	h, _, _ := newResizeService(t)
	handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	metadata := birthMetadata("elastic", "generation-1")
	handler.beforeStart = func() {
		raw, err := os.ReadFile(filepath.Join(h.config.RootDir, "containers", "elastic", config.SandboxMetaFile))
		require.NoError(t, err)
		saved := &runtime.SandboxMetadata{}
		require.NoError(t, proto.Unmarshal(raw, saved))
		require.Equal(t, runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT, saved.PhysicalPhase)
		birth := decodeBirthEvidence(t, saved.Labels[birthResourcesLabel])
		require.Equal(t, "generation-1", birth.ResourceGeneration)
		require.Equal(t, int64(50000), birth.CpuQuotaUsec)
		require.Equal(t, uint64(512*1024*1024), birth.MemoryLimitBytes)
	}
	require.NoError(t, h.sandboxManager.PersistMetadata("elastic", metadata))
	require.NoError(t, h.startSandboxRuntime(context.Background(), "runsc",
		birthStartConfig("elastic", birthAnnotations(t, "generation-1"), 50000, 512*1024*1024), metadata))
	require.True(t, handler.started)

	raw := metadata.Labels[birthResourcesLabel]
	require.NotEmpty(t, raw)
	evidence := decodeBirthEvidence(t, raw)
	require.Equal(t, birthResourceEvidenceSchemaVersion, evidence.SchemaVersion)
	require.Equal(t, "elastic", evidence.SandboxID)
	require.Equal(t, "generation-1", evidence.ResourceGeneration)
	require.Equal(t, "start", evidence.Phase)
	require.Equal(t, int64(50000), evidence.CpuQuotaUsec)
	require.Equal(t, uint64(100000), evidence.CpuPeriodUsec)
	require.Equal(t, uint64(512*1024*1024), evidence.MemoryLimitBytes)
	require.Greater(t, evidence.ObservedAtUnixMs, int64(0))
	require.LessOrEqual(t, evidence.ObservedAtUnixMs, time.Now().UnixMilli())

	// The durable INTENT record carries the same evidence before the runtime
	// could report any state of its own.
	intents := h.sandboxManager.ListPhysicalIntents()
	require.Len(t, intents, 1)
	require.Equal(t, raw, intents[0].Labels[birthResourcesLabel])
}

// A failure to persist the evidence must stop the handler: a start that cannot
// prove its birth limits must not run. A non-directory at the metadata path
// makes the pre-handler PersistMetadata fail without a runtime stub.
func TestBirthEvidencePersistenceFailureBlocksRuntimeStart(t *testing.T) {
	h, _, _ := newResizeService(t)
	handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	const id = "sbox-birth-obstacle"
	require.NoError(t, os.MkdirAll(filepath.Join(h.config.RootDir, "containers"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(h.config.RootDir, "containers", id), []byte("not a directory"), 0600))
	err := h.startSandboxRuntime(context.Background(), "runsc",
		birthStartConfig(id, birthAnnotations(t, "generation-1"), 50000, 512*1024*1024),
		birthMetadata(id, "generation-1"))
	require.ErrorContains(t, err, "persist elastic start birth evidence")
	require.False(t, handler.started)
}

// Evidence is only valid bound to the prepared incarnation: metadata that is
// absent, foreign, stale, or already committed must be rejected before the
// handler runs.
func TestBirthEvidenceRejectsUnboundMetadata(t *testing.T) {
	for name, prepare := range map[string]func(*runtime.SandboxMetadata) *runtime.SandboxMetadata{
		"nil metadata": func(*runtime.SandboxMetadata) *runtime.SandboxMetadata { return nil },
		"stale generation": func(m *runtime.SandboxMetadata) *runtime.SandboxMetadata {
			m.Labels[resourceGenerationLabel] = "generation-old"
			return m
		},
		"other sandbox": func(m *runtime.SandboxMetadata) *runtime.SandboxMetadata {
			m.ID = "sbox-other"
			return m
		},
		"committed phase": func(m *runtime.SandboxMetadata) *runtime.SandboxMetadata {
			m.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
			return m
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, _ := newResizeService(t)
			handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
			h.serviceHandler.Set("runsc", handler)
			metadata := prepare(birthMetadata("elastic", "generation-1"))
			err := h.startSandboxRuntime(context.Background(), "runsc",
				birthStartConfig("elastic", birthAnnotations(t, "generation-1"), 50000, 512*1024*1024),
				metadata)
			require.ErrorContains(t, err, "birth evidence requires prepared INTENT metadata")
			require.False(t, handler.started)
		})
	}
}

type observedRestoreHandler struct {
	svc.Handler
	restored bool
}

func (*observedRestoreHandler) Checkpoint(context.Context, string, string, svc.CheckpointOptions) error {
	return nil
}

func (h *observedRestoreHandler) Restore(context.Context, svc.StartConfig, string) error {
	h.restored = true
	return nil
}

// A restored segment records the grown limits it actually restored under and
// the fresh generation of the new incarnation, replacing any record the source
// segment once carried.
func TestRestoreBirthEvidenceRecordsGrownLimitsAndFreshGeneration(t *testing.T) {
	h, _, _ := newResizeService(t)
	handler := &observedRestoreHandler{Handler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	metadata := birthMetadata("elastic", "generation-2")
	require.NoError(t, h.sandboxManager.PersistMetadata("elastic", metadata))
	require.NoError(t, h.restoreSandboxRuntime(context.Background(), "runsc",
		birthStartConfig("elastic", birthAnnotations(t, "generation-2"), 125000, 2048*1024*1024),
		"checkpoint.img", metadata))
	require.True(t, handler.restored)

	evidence := decodeBirthEvidence(t, metadata.Labels[birthResourcesLabel])
	require.Equal(t, "restore", evidence.Phase)
	require.Equal(t, "generation-2", evidence.ResourceGeneration)
	require.Equal(t, int64(125000), evidence.CpuQuotaUsec)
	require.Equal(t, uint64(100000), evidence.CpuPeriodUsec)
	require.Equal(t, uint64(2048*1024*1024), evidence.MemoryLimitBytes)
}

// A caller (or a checkpoint source replayed through one) cannot inject birth
// evidence: the label is dropped at the create boundary for both start and
// restore, before any metadata or annotations copy is made.
func TestCreateSandboxDropsCallerSuppliedBirthEvidence(t *testing.T) {
	for name, restoring := range map[string]bool{"start": false, "restore": true} {
		t.Run(name, func(t *testing.T) {
			h, _, _ := newResizeService(t)
			request := elasticTestRequest(t)
			request.SandboxID = "sbox-birth-inject"
			request.Rootfs = &runtime.RootfsConfig{}
			request.Labels[birthResourcesLabel] = `{"schema_version":1,"sandbox_id":"forged"}`
			options := createOptions{
				onReserved: func(reserved *runtime.StartRequest, _ string) error {
					require.NotContains(t, reserved.Labels, birthResourcesLabel)
					require.NotEmpty(t, reserved.Labels[resourceGenerationLabel])
					require.NotEmpty(t, reserved.Labels[elasticResourcesLabel])
					return errors.New("abort after boundary")
				},
			}
			if restoring {
				options.checkpointImage = "checkpoint.img"
			}
			_, err := h.createSandbox(context.Background(), request, options)
			require.ErrorContains(t, err, "abort after boundary")
		})
	}
}
