// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// A false MemoryLimitKnown can accompany a nonzero legacy fallback number, so
// numerics that merely equal the request must never pass as an observation of
// the enforced memory limit.

// Birth readback: an unknown memory limit must stop the runtime handler and
// leave birth evidence absent, for start and restore alike.
func TestUnknownMemoryLimitBlocksBirthEvidenceAndRuntime(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		h, c, _ := newResizeService(t)
		c.stats.MemoryLimitKnown = false // numbers still equal the request
		handler := &observedStartHandler{Handler: svc.NewFakeRuntimeHandler()}
		h.serviceHandler.Set("runsc", handler)
		metadata := birthMetadata("elastic", "generation-limit")
		require.NoError(t, h.sandboxManager.PersistMetadata("elastic", metadata))
		err := h.startSandboxRuntime(context.Background(), "runsc",
			birthStartConfig(t, "elastic", birthAnnotations(t, "generation-limit"), 50000, 512*1024*1024), metadata)
		require.ErrorContains(t, err, "cannot prove requested limits")
		require.False(t, handler.started)
		require.NotContains(t, metadata.Labels, birthResourcesLabel)
		for _, intent := range h.sandboxManager.ListPhysicalIntents() {
			require.NotContains(t, intent.Labels, birthResourcesLabel)
		}
	})
	t.Run("restore", func(t *testing.T) {
		h, c, _ := newResizeService(t)
		c.stats.MemoryLimitKnown = false
		handler := &observedRestoreHandler{Handler: svc.NewFakeRuntimeHandler()}
		h.serviceHandler.Set("runsc", handler)
		metadata := birthMetadata("elastic", "generation-limit-restore")
		require.NoError(t, h.sandboxManager.PersistMetadata("elastic", metadata))
		err := h.restoreSandboxRuntime(context.Background(), "runsc",
			birthStartConfig(t, "elastic", birthAnnotations(t, "generation-limit-restore"), 50000, 512*1024*1024),
			"checkpoint.img", metadata)
		require.ErrorContains(t, err, "cannot prove requested limits")
		require.False(t, handler.restored)
		require.NotContains(t, metadata.Labels, birthResourcesLabel)
	})
}

// Elastic checkpoint capture: an unproven memory number must not publish a
// sidecar; a proven one must persist the flag for the restore gate.
func TestElasticCheckpointRequiresKnownMemoryLimit(t *testing.T) {
	h, c, _ := newResizeService(t)
	c.stats.MemoryLimitKnown = false
	dir := t.TempDir()
	err := h.captureResourceLimits("elastic", dir)
	require.ErrorContains(t, err, "elastic checkpoint requires known finite resource limits")
	_, statErr := os.Stat(filepath.Join(dir, resourceLimitsFile))
	require.ErrorIs(t, statErr, os.ErrNotExist, "no sidecar may be published")
}

func TestElasticCheckpointPersistsMemoryLimitKnownFlag(t *testing.T) {
	h, _, _ := newResizeService(t)
	dir := t.TempDir()
	require.NoError(t, h.captureResourceLimits("elastic", dir))
	raw, err := os.ReadFile(filepath.Join(dir, resourceLimitsFile))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"memory_limit_known":true`)
	var snapshot resourceLimitsSnapshot
	require.NoError(t, json.Unmarshal(raw, &snapshot))
	require.True(t, snapshot.MemoryLimitKnown)
}

// Elastic restore accepts only a sidecar that saved the flag; explicit false,
// a legacy sidecar without the field, and non-elastic memory-only sidecars
// keep their respective fail-closed and legacy-compatible behaviors.
func TestElasticRestoreSidecarRequiresSavedMemoryLimitFlag(t *testing.T) {
	policy := elasticTestRequest(t).Labels[elasticResourcesLabel]
	savedKnown, err := json.Marshal(resourceLimitsSnapshot{
		ElasticPolicy: policy, CPUQuotaUsec: 125000, CPUPeriodUsec: 100000,
		CPULimitsKnown: true, MemoryLimitBytes: 2048 * 1024 * 1024, MemoryLimitKnown: true,
	})
	require.NoError(t, err)
	// MemoryLimitKnown false is omitted by omitempty: this is also exactly
	// the byte shape of a pre-flag legacy elastic sidecar.
	legacyAbsent, err := json.Marshal(resourceLimitsSnapshot{
		ElasticPolicy: policy, CPUQuotaUsec: 125000, CPUPeriodUsec: 100000,
		CPULimitsKnown: true, MemoryLimitBytes: 2048 * 1024 * 1024,
	})
	require.NoError(t, err)
	require.NotContains(t, string(legacyAbsent), "memory_limit_known")
	explicitFalse, err := json.Marshal(map[string]any{
		"elastic_policy": policy, "cpu_quota_usec": 125000, "cpu_period_usec": 100000,
		"cpu_limits_known": true, "memory_limit_bytes": 2147483648, "memory_limit_known": false,
	})
	require.NoError(t, err)

	t.Run("saved flag true applies limits", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile), savedKnown, 0o600))
		request := elasticTestRequest(t)
		require.NoError(t, applyCheckpointResourceLimits(request, dir))
		require.Equal(t, float64(2048), request.Resources["Memory"])
	})
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"explicit false", explicitFalse},
		{"flag absent legacy", legacyAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile), tc.raw, 0o600))
			request := elasticTestRequest(t)
			require.ErrorContains(t, applyCheckpointResourceLimits(request, dir),
				"elastic restore requires saved policy and finite CPU/memory limits")
		})
	}
	t.Run("non-elastic memory-only sidecar stays legacy-compatible", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
			[]byte(`{"memory_limit_bytes":6442450944}`), 0o600))
		request := &runtime.StartRequest{Resources: map[string]float64{"Memory": 32768}}
		require.NoError(t, applyCheckpointResourceLimits(request, dir))
		require.Equal(t, float64(6144), request.Resources["Memory"])
	})
}

// Resize must refuse to write while the effective memory limit is unproven,
// even though the fallback number equals the expected limits.
func TestResizeRequiresKnownMemoryLimitBeforeWrite(t *testing.T) {
	h, c, request := newResizeService(t)
	c.stats.MemoryLimitKnown = false
	_, err := h.ResizeResources(context.Background(), request)
	require.ErrorContains(t, err, "effective memory limit is unknown")
	require.Zero(t, c.writes)
}

// An unknown readback after the write is an uncertain outcome, not success
// and not a proven no-op: numerics may equal the target yet prove nothing.
func TestResizeUnknownReadbackAfterWriteStaysIncomplete(t *testing.T) {
	h, c, request := newResizeService(t)
	c.onPrepare = func() { c.stats.MemoryLimitKnown = false }
	response, err := h.ResizeResources(context.Background(), request)
	require.NoError(t, err)
	require.False(t, response.Complete)
	require.False(t, response.Actual.MemoryLimitKnown)
	require.True(t, response.Actual.CpuLimitsKnown, "proven CPU flags must survive")
	require.Equal(t, request.Target.MemoryLimitBytes, response.Actual.MemoryLimitBytes)
	require.Contains(t, response.UpdateError, "unknown after possible write")
	require.Equal(t, 1, c.writes)
}
