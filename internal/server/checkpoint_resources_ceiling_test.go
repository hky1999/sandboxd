// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0.

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

type testSidecar struct {
	ElasticPolicy     string `json:"elastic_policy,omitempty"`
	MemoryLimitBytes  uint64 `json:"memory_limit_bytes"`
	MemoryLimitKnown  bool   `json:"memory_limit_known"`
	CPUQuotaUsec      int64  `json:"cpu_quota_usec"`
	CPUPeriodUsec     int64  `json:"cpu_period_usec"`
	CPULimitsKnown    bool   `json:"cpu_limits_known"`
}

func writeElasticSidecar(t *testing.T, dir, policy string, memBytes uint64) {
	t.Helper()
	body, err := json.Marshal(testSidecar{ElasticPolicy: policy,
		MemoryLimitBytes: memBytes, MemoryLimitKnown: true,
		CPUQuotaUsec: 50000, CPUPeriodUsec: 100000, CPULimitsKnown: true})
	if err != nil {
		t.Fatal(err)
	}
	writeSidecar(t, dir, string(body))
}

const testPolicy = `{"CPU":{"ceiling":500.0,"initial":500.0},"Memory":{"ceiling":512.0,"initial":128.0},"version":1}`

func writeSidecar(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, resourceLimitsFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Trusted-restore ceiling admission: the caller's reserved ceiling (512)
// must win over the sidecar's checkpoint-time initial (128) for elastic
// restores — honoring the sidecar alone re-created the restore OOM.
func TestApplyCheckpointResourceLimits_ElasticRestoreKeepsCallerCeiling(t *testing.T) {
	dir := t.TempDir()
	writeElasticSidecar(t, dir, testPolicy, 134217728)
	req := &runtime.StartRequest{}
	req.Resources = map[string]float64{"CPU": 500, "Memory": 512}
	req.Labels = map[string]string{elasticResourcesLabel: testPolicy}
	if err := applyCheckpointResourceLimits(req, dir); err != nil {
		t.Fatal(err)
	}
	if got := req.Resources["Memory"]; got != 512 {
		t.Fatalf("elastic restore memory = %v, want caller ceiling 512", got)
	}
}

// A caller ABOVE the source ceiling is clamped to the ceiling, never above.
func TestApplyCheckpointResourceLimits_ElasticRestoreClampsAboveCeiling(t *testing.T) {
	dir := t.TempDir()
	writeElasticSidecar(t, dir, testPolicy, 134217728)
	req := &runtime.StartRequest{}
	req.Resources = map[string]float64{"CPU": 500, "Memory": 4096}
	req.Labels = map[string]string{elasticResourcesLabel: testPolicy}
	if err := applyCheckpointResourceLimits(req, dir); err != nil {
		t.Fatal(err)
	}
	if got := req.Resources["Memory"]; got != 512 {
		t.Fatalf("elastic restore memory = %v, want clamp to ceiling 512", got)
	}
}

// A caller BELOW the sidecar limit never lowers the restore (sidecar wins).
func TestApplyCheckpointResourceLimits_ElasticRestoreSidecarWinsWhenLarger(t *testing.T) {
	dir := t.TempDir()
	writeElasticSidecar(t, dir, testPolicy, 268435456)
	req := &runtime.StartRequest{}
	req.Resources = map[string]float64{"CPU": 500, "Memory": 128}
	req.Labels = map[string]string{elasticResourcesLabel: testPolicy}
	if err := applyCheckpointResourceLimits(req, dir); err != nil {
		t.Fatal(err)
	}
	if got := req.Resources["Memory"]; got != 256 {
		t.Fatalf("elastic restore memory = %v, want sidecar 256", got)
	}
}

// Non-elastic restores keep the exact legacy behavior: sidecar wins.
func TestApplyCheckpointResourceLimits_NonElasticSidecarWins(t *testing.T) {
	dir := t.TempDir()
	writeSidecar(t, dir, `{"memory_limit_bytes":268435456,"memory_limit_known":true,"cpu_quota_usec":50000,"cpu_period_usec":100000,"cpu_limits_known":true}`)
	req := &runtime.StartRequest{}
	req.Resources = map[string]float64{"CPU": 500, "Memory": 512}
	if err := applyCheckpointResourceLimits(req, dir); err != nil {
		t.Fatal(err)
	}
	if got := req.Resources["Memory"]; got != 256 {
		t.Fatalf("non-elastic restore memory = %v, want sidecar 256", got)
	}
}
