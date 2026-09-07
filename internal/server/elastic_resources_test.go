// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

func elasticTestRequest(t *testing.T) *runtime.StartRequest {
	t.Helper()
	policy := elasticResourcePolicy{Version: 1, CPU: elasticBounds{500, 8000}, Memory: elasticBounds{512, 8192}}
	raw, err := json.Marshal(policy)
	require.NoError(t, err)
	return &runtime.StartRequest{
		Runtime: "runsc", Resources: map[string]float64{"CPU": 500, "Memory": 512},
		Labels: map[string]string{elasticResourcesLabel: string(raw)},
	}
}

func TestElasticStartUsesInitialHardLimits(t *testing.T) {
	req := elasticTestRequest(t)
	cfg := config.DefaultConfig()
	require.NoError(t, validateElasticResources(req, cfg, false))
	linux := resourcesToLinux(req.Resources, cfg.CPULimitMode)
	require.Equal(t, int64(50000), linux.CpuQuota)
	require.Equal(t, uint64(100000), linux.CpuPeriod)
	require.Equal(t, int64(512*1024*1024), linux.MemoryLimitInBytes)
	req.Resources["CPU"], req.Resources["Memory"] = 1250, 2048
	require.Error(t, validateElasticResources(req, cfg, false))
	require.NoError(t, validateElasticResources(req, cfg, true))
	req.Resources["Memory"] = 8193
	require.Error(t, validateElasticResources(req, cfg, true))
}

func TestElasticPolicyRejectsMalformedOrUnsupportedContract(t *testing.T) {
	for _, raw := range []string{
		"", "null", "{}", "{} {}", `{"version":2}`,
		`{"version":1,"CPU":{"initial":500,"ceiling":499},"Memory":{"initial":512,"ceiling":8192}}`,
		`{"version":1,"CPU":{"initial":1,"ceiling":8000},"Memory":{"initial":512,"ceiling":8192}}`,
		`{"version":1,"CPU":{"initial":500,"ceiling":8000},"Memory":{"initial":512,"ceiling":1e30}}`,
		`{"version":1,"CPU":{"initial":500,"ceiling":8000},"Memory":{"initial":512,"ceiling":8192},"typo":true}`,
	} {
		t.Run(raw, func(t *testing.T) {
			req := elasticTestRequest(t)
			req.Labels[elasticResourcesLabel] = raw
			require.Error(t, validateElasticResources(req, config.DefaultConfig(), false))
		})
	}
	for _, value := range []float64{0, -1, math.NaN(), math.Inf(1), 9000} {
		req := elasticTestRequest(t)
		req.Resources["CPU"] = value
		require.Error(t, validateElasticResources(req, config.DefaultConfig(), true))
	}
}

func TestElasticStartRejectsUnenforceableNodeBeforeAllocation(t *testing.T) {
	for _, mode := range []string{"shares", "cgroup-disabled", "kata"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			h.config.CPULimitMode = config.CPULimitModeQuota
			req := elasticTestRequest(t)
			switch mode {
			case "shares":
				h.config.CPULimitMode = config.CPULimitModeShares
			case "cgroup-disabled":
				h.config.DisableCgroup = true
			case "kata":
				req.Runtime = "kata"
			}
			// No rootfs or allocators: this must reject on the policy itself.
			_, err := h.Start(context.Background(), req)
			require.ErrorContains(t, err, "elastic resources require")
		})
	}
}

func TestNonElasticStartContractIsUnchanged(t *testing.T) {
	require.NoError(t, validateElasticResources(&runtime.StartRequest{}, config.Config{}, false))
}

func TestElasticRestoreRequiresSavedLimitsAndRetainsSourceCeiling(t *testing.T) {
	request := elasticTestRequest(t)
	dir := t.TempDir()
	require.ErrorContains(t, applyCheckpointResourceLimits(request, dir), "requires resource limits sidecar")
	path := filepath.Join(dir, resourceLimitsFile)
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0o600))
	require.ErrorContains(t, applyCheckpointResourceLimits(request, dir), "invalid elastic restore")
	require.NoError(t, os.WriteFile(path, []byte(`{"memory_limit_bytes":2147483648}`), 0o600))
	require.ErrorContains(t, applyCheckpointResourceLimits(request, dir), "requires saved policy")
	policy := request.Labels[elasticResourcesLabel]
	snapshot := resourceLimitsSnapshot{
		ElasticPolicy: policy, CPUQuotaUsec: 125000, CPUPeriodUsec: 100000,
		CPULimitsKnown: true, MemoryLimitBytes: 2048 * 1024 * 1024, MemoryLimitKnown: true,
	}
	raw, err := json.Marshal(snapshot)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	request.Labels[elasticResourcesLabel] = `{"version":99}`
	require.NoError(t, applyCheckpointResourceLimits(request, dir))
	require.Equal(t, policy, request.Labels[elasticResourcesLabel])
	require.Equal(t, float64(1250), request.Resources["CPU"])
	require.Equal(t, float64(2048), request.Resources["Memory"])
	require.NoError(t, validateElasticResources(request, config.DefaultConfig(), true))
	// Omitting the request label must not remove the source's policy.
	request.Labels = nil
	require.NoError(t, applyCheckpointResourceLimits(request, dir))
	require.Equal(t, policy, request.Labels[elasticResourcesLabel])
}
