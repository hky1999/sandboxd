// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

const elasticResourcesLabel = "akernel.scheduler/elastic-resources"

// Reserved label holding the birth evidence observed for this incarnation.
// Like the elastic policy, it is persisted through the metadata/checkpoint
// path; a caller or a checkpoint source must never supply it.
const birthResourcesLabel = "akernel.scheduler/birth-resources"

const birthResourceEvidenceSchemaVersion = 1

// birthResourceEvidence is a compact record of the leaf hard limits the node
// was actually enforcing when this incarnation was born. It is an observation
// of the prepared leaf cgroup before any workload process exists: it is not
// ancestor-effective capacity, and it is not proof that the runtime started.
type birthResourceEvidence struct {
	SchemaVersion      int    `json:"schema_version"`
	SandboxID          string `json:"sandbox_id"`
	ResourceGeneration string `json:"resource_generation"`
	Phase              string `json:"phase"`
	ObservedAtUnixMs   int64  `json:"observed_at_unix_ms"`
	CpuQuotaUsec       int64  `json:"cpu_quota_usec"`
	CpuPeriodUsec      uint64 `json:"cpu_period_usec"`
	MemoryLimitBytes   uint64 `json:"memory_limit_bytes"`
}

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
// The elastic path additionally persists the observed limits as birth evidence
// on the prepared metadata before the runtime handler runs; any failure there
// must stop the handler rather than start an unevidenced incarnation.
func (h *sandboxService) verifyPreparedElasticLimits(start svc.StartConfig, phase string, metadata *runtime.SandboxMetadata) error {
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
	// Numeric equality alone is not proof: with MemoryLimitKnown false the
	// number is a legacy fallback that must never become birth evidence.
	if !actual.CPULimitsKnown || !actual.MemoryLimitKnown {
		return fmt.Errorf("elastic %s cgroup readback cannot prove requested limits", phase)
	}
	if actual.CPUQuotaUsec != start.Resources.CpuQuota ||
		actual.CPUPeriodUsec != start.Resources.CpuPeriod ||
		actual.MemoryLimitBytes != uint64(start.Resources.MemoryLimitInBytes) {
		return fmt.Errorf("elastic %s cgroup readback does not match requested limits", phase)
	}
	// The evidence binds the observation to this incarnation's prepared
	// identity: a fresh nonempty generation, still in the INTENT phase. It is
	// an observation of the leaf cgroup only — not ancestor-effective capacity
	// and not proof that the runtime started.
	generation := start.Annotations[resourceGenerationLabel]
	if metadata == nil || h.sandboxManager == nil || metadata.ID != start.ID ||
		generation == "" || metadata.Labels[resourceGenerationLabel] != generation ||
		metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
		return fmt.Errorf("elastic %s birth evidence requires prepared INTENT metadata for this generation", phase)
	}
	evidence, err := json.Marshal(birthResourceEvidence{
		SchemaVersion:      birthResourceEvidenceSchemaVersion,
		SandboxID:          start.ID,
		ResourceGeneration: generation,
		Phase:              phase,
		ObservedAtUnixMs:   time.Now().UnixMilli(),
		CpuQuotaUsec:       actual.CPUQuotaUsec,
		CpuPeriodUsec:      actual.CPUPeriodUsec,
		MemoryLimitBytes:   actual.MemoryLimitBytes,
	})
	if err != nil {
		return fmt.Errorf("encode elastic %s birth evidence: %w", phase, err)
	}
	if metadata.Labels == nil {
		metadata.Labels = make(map[string]string)
	}
	metadata.Labels[birthResourcesLabel] = string(evidence)
	// Persist while still INTENT so the durable record names the observed
	// limits before the handler could claim any runtime fact.
	if err := h.sandboxManager.PersistMetadata(start.ID, metadata); err != nil {
		return fmt.Errorf("persist elastic %s birth evidence: %w", phase, err)
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": start.ID, "resource_generation": generation,
		"phase": phase, "cpu_quota_usec": actual.CPUQuotaUsec,
		"cpu_period_usec": actual.CPUPeriodUsec, "memory_limit_bytes": actual.MemoryLimitBytes,
		"elastic_policy": start.Annotations[elasticResourcesLabel],
	}).Info("scheduler resource limits prepared")
	return nil
}
