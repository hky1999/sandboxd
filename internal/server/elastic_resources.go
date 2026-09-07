// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

const elasticResourcesLabel = "akernel.scheduler/elastic-resources"

type elasticBounds struct {
	Initial float64 `json:"initial"`
	Ceiling float64 `json:"ceiling"`
}

// These units match StartRequest.Resources, not Linux cgroup file units.
type elasticResourcePolicy struct {
	Version int           `json:"version"`
	CPU     elasticBounds `json:"CPU"`    // millicores
	Memory  elasticBounds `json:"Memory"` // MiB
}

// This label is persisted by the existing metadata/checkpoint path. A new
// sandbox must start at initial; a restore may retain a later effective limit.
// Never accept a policy whose promised hard limits this node cannot enforce.
func validateElasticResources(req *runtime.StartRequest, cfg config.Config, restoring bool) error {
	raw, ok := req.Labels[elasticResourcesLabel]
	if !ok {
		return nil
	}
	if (req.Runtime != "" && req.Runtime != config.RuntimeNameRunsc) || cfg.DisableCgroup || cfg.CPULimitMode != config.CPULimitModeQuota {
		return fmt.Errorf("elastic resources require runsc with cgroup CPU quota enforcement")
	}
	if len(raw) > 4096 {
		return fmt.Errorf("elastic resource policy is too large")
	}
	var policy elasticResourcePolicy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return fmt.Errorf("invalid elastic resource policy: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("elastic resource policy must contain exactly one JSON object")
	}
	if policy.Version != 1 {
		return fmt.Errorf("unsupported elastic resource policy version %d", policy.Version)
	}
	for name, bounds := range map[string]elasticBounds{"CPU": policy.CPU, "Memory": policy.Memory} {
		// Avoid quota clamping and float-to-int64 overflow in resourcesToLinux.
		minimum, exclusiveMaximum := float64(1), float64(math.MaxInt64)/(1024*1024)
		if name == "CPU" {
			minimum = 1000 * 1000 / float64(config.DefaultCPUPeriodMicros)
			exclusiveMaximum = float64(math.MaxInt64) * 1000 / float64(config.DefaultCPUPeriodMicros)
		}
		if math.IsNaN(bounds.Initial) || math.IsNaN(bounds.Ceiling) || bounds.Initial < minimum ||
			bounds.Ceiling < bounds.Initial || bounds.Ceiling >= exclusiveMaximum ||
			math.Trunc(bounds.Initial) != bounds.Initial || math.Trunc(bounds.Ceiling) != bounds.Ceiling {
			return fmt.Errorf("invalid elastic %s initial/ceiling", name)
		}
		current, found := req.Resources[name]
		if !found || math.IsNaN(current) || math.IsInf(current, 0) || current < bounds.Initial || current > bounds.Ceiling ||
			(!restoring && current != bounds.Initial) {
			return fmt.Errorf("elastic %s effective limit does not match policy", name)
		}
	}
	return nil
}

// Read the effective leaf cgroup limits before any workload process is started.
// A setter returning nil alone is not proof that initial limits were applied.
func (h *sandboxService) verifyPreparedElasticLimits(start svc.StartConfig, phase string) error {
	if start.Annotations[elasticResourcesLabel] == "" {
		return nil
	}
	if start.CgroupPath == "" || h.cgroupMgr == nil || start.Resources == nil {
		return fmt.Errorf("elastic %s requires prepared cgroup limits", phase)
	}
	actual, err := h.cgroupMgr.Stats(start.CgroupPath)
	if err != nil {
		return fmt.Errorf("read elastic %s limits: %w", phase, err)
	}
	if !actual.CPULimitsKnown || actual.CPUQuotaUsec != start.Resources.CpuQuota ||
		actual.CPUPeriodUsec != start.Resources.CpuPeriod ||
		actual.MemoryLimitBytes != uint64(start.Resources.MemoryLimitInBytes) {
		return fmt.Errorf("elastic %s cgroup readback does not match requested limits", phase)
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": start.ID, "resource_generation": start.Annotations[resourceGenerationLabel],
		"phase": phase, "cpu_quota_usec": actual.CPUQuotaUsec,
		"cpu_period_usec": actual.CPUPeriodUsec, "memory_limit_bytes": actual.MemoryLimitBytes,
		"elastic_policy": start.Annotations[elasticResourcesLabel],
	}).Info("scheduler resource limits prepared")
	return nil
}
