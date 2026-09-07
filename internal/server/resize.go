// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"math"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

const resourceGenerationLabel = "akernel.scheduler/resource-generation"

// limitsMatch requires proven observations: an unknown memory limit is a
// legacy fallback number that must not pass as the enforced hard limit.
func limitsMatch(stats *runtime.StatsResponse, limits *runtime.ResourceLimits) bool {
	return stats.CpuLimitsKnown && stats.MemoryLimitKnown && stats.CpuQuotaUsec == limits.CpuQuotaUsec &&
		stats.CpuPeriodUsec == limits.CpuPeriodUsec && stats.MemoryLimitBytes == limits.MemoryLimitBytes
}

// ResizeResources executes a node-budgeted increase. Global admission remains
// the scheduler's responsibility; this endpoint owns identity, ceilings and
// truthful readback, including partial writes. It never lowers a live limit.
func (h *sandboxService) ResizeResources(ctx context.Context, req *runtime.ResizeResourcesRequest) (*runtime.ResizeResourcesResponse, error) {
	if req == nil || req.SandboxID == "" || req.ResourceGeneration == "" || req.Expected == nil || req.Target == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox, generation, expected and target limits are required")
	}
	if req.DeadlineUnixMs <= 0 || req.DeadlineUnixMs > time.Now().Add(time.Minute).UnixMilli() {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resize requires a command deadline within one minute")
	}
	if time.Now().UnixMilli() >= req.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	// Preserve expiry through service/lock queues, independently of the gRPC
	// deadline which a delayed intermediary could otherwise start afresh.
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(req.DeadlineUnixMs))
	defer cancel()
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resource recovery is incomplete")
	}
	for _, limits := range []*runtime.ResourceLimits{req.Expected, req.Target} {
		if limits.CpuQuotaUsec <= 0 || limits.CpuPeriodUsec == 0 || limits.MemoryLimitBytes == 0 || limits.MemoryLimitBytes > math.MaxInt64 {
			return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "finite positive CPU/memory limits are required")
		}
	}
	release, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resource service is shutting down")
	}
	defer release()
	unlock, err := h.resourceLocks.acquire(ctx, req.SandboxID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	defer unlock()
	current, err := h.sandboxManager.Get(req.SandboxID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if current.Metadata == nil || current.Status == nil || current.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "resize requires a running sandbox")
	}
	labels := current.Metadata.Labels
	if labels[resourceGenerationLabel] != req.ResourceGeneration {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "stale resource generation")
	}
	if labels[elasticResourcesLabel] == "" {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox has no elastic policy")
	}
	targetConfig := &runtime.StartRequest{
		Runtime: current.Metadata.RuntimeHandler, Labels: labels,
		Resources: map[string]float64{
			"CPU":    1000 * float64(req.Target.CpuQuotaUsec) / float64(req.Target.CpuPeriodUsec),
			"Memory": float64(req.Target.MemoryLimitBytes) / (1024 * 1024),
		},
	}
	if err := validateElasticResources(targetConfig, h.config, true); err != nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resize target violates policy: %v", err)
	}
	before, err := h.resourceStats(req.SandboxID)
	if err != nil {
		return nil, err
	}
	if !before.CpuLimitsKnown || before.CpuQuotaUsec <= 0 || before.CpuPeriodUsec == 0 {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective CPU limits are unknown or unlimited")
	}
	if !before.MemoryLimitKnown {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective memory limit is unknown")
	}
	if req.Target.CpuPeriodUsec != before.CpuPeriodUsec || req.Target.CpuQuotaUsec < before.CpuQuotaUsec || req.Target.MemoryLimitBytes < before.MemoryLimitBytes {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resize cannot lower limits or change CPU period")
	}
	if !limitsMatch(before, req.Expected) && !limitsMatch(before, req.Target) {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "effective limits changed; refresh Stats and admission")
	}
	facts, err := h.physicalResources(current.Metadata)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	// resourceStats already validated the managed cgroup and manager.
	if err := ctx.Err(); err != nil {
		return nil, errord.ToGRPC(err)
	}
	if time.Now().UnixMilli() >= req.DeadlineUnixMs {
		return nil, errord.ToGRPC(context.DeadlineExceeded)
	}
	updateErr := h.cgroupMgr.Prepare(facts.Resources[config.ResourceNameCgroup], &runtime.LinuxSandboxResources{
		CpuQuota: req.Target.CpuQuotaUsec, CpuPeriod: req.Target.CpuPeriodUsec,
		MemoryLimitInBytes: int64(req.Target.MemoryLimitBytes),
	})
	after, readErr := h.resourceStats(req.SandboxID)
	if readErr != nil {
		// An RPC error after a write is explicitly an uncertain outcome. The
		// scheduler must retain its reservation and reconcile via Stats.
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "resize readback failed after possible write: %v (update: %v)", readErr, updateErr)
	}
	response := &runtime.ResizeResourcesResponse{Actual: after, Complete: updateErr == nil && limitsMatch(after, req.Target)}
	if updateErr != nil {
		response.UpdateError = updateErr.Error()
	}
	if !response.Complete && response.UpdateError == "" {
		if !after.CpuLimitsKnown || !after.MemoryLimitKnown {
			// An unproven readback cannot claim success or a no-op write; the
			// scheduler must reconcile via Stats while holding its reservation.
			response.UpdateError = "effective limits unknown after possible write"
		} else {
			response.UpdateError = "effective hard limits did not match target"
		}
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": req.SandboxID, "resource_generation": req.ResourceGeneration,
		"old_cpu_quota_usec": before.CpuQuotaUsec, "cpu_quota_usec": after.CpuQuotaUsec,
		"cpu_period_usec": after.CpuPeriodUsec, "old_memory_limit_bytes": before.MemoryLimitBytes,
		"memory_limit_bytes": after.MemoryLimitBytes, "complete": response.Complete,
		"update_error": response.UpdateError,
	}).Info("scheduler resource resize")
	return response, nil
}
