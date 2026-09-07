// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package identityresolver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

// Reserved label the elastic path persists with the leaf hard limits observed
// for this incarnation. Mirrored from the writer in internal/server so this
// read-only package stays decoupled from server internals.
const birthResourcesLabel = "akernel.scheduler/birth-resources"

const maxBirthResourceEvidenceBytes = 2048
const birthResourceEvidenceSchemaVersion = 1
const resourceReportSchemaVersion = 1

// birthResourceEvidence mirrors the writer's compact record (schema 1): the
// prepared leaf limits at incarnation birth. Like the writer, this proves only
// prepared leaf limits — not ancestor-effective capacity and not that the
// runtime ever started.
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

// resourceReport is the bounded read-only resource view of one incarnation:
// validated identity, the birth limits it was created under, and a single
// explicitly allowlisted live Stats sample. It never echoes raw sandbox
// status, labels, envs, commands, or the elastic policy.
type resourceReport struct {
	SchemaVersion        int                   `json:"schema_version"`
	Identity             Identity              `json:"identity"`
	Birth                birthResourceEvidence `json:"birth"`
	SampleStartedUnixMs  int64                 `json:"sample_started_unix_ms"`
	SampleFinishedUnixMs int64                 `json:"sample_finished_unix_ms"`
	Current              resourceSample        `json:"current"`
}

type resourceSample struct {
	CpuUsageNs          uint64 `json:"cpu_usage_ns"`
	CpuUsageKnown       bool   `json:"cpu_usage_known"`
	MemoryUsageBytes    uint64 `json:"memory_usage_bytes"`
	MemoryUsageKnown    bool   `json:"memory_usage_known"`
	MemoryLimitBytes    uint64 `json:"memory_limit_bytes"`
	MemoryLimitKnown    bool   `json:"memory_limit_known"`
	MemoryMaxUsageBytes uint64 `json:"memory_max_usage_bytes"`
	// True only when memory_max_usage_bytes is a measured memory.peak; when
	// false the daemon may have substituted current usage for legacy
	// consumers, which is not an observed peak.
	MemoryPeakKnown     bool   `json:"memory_peak_known"`
	CpuQuotaUsec        int64  `json:"cpu_quota_usec"`
	CpuPeriodUsec       uint64 `json:"cpu_period_usec"`
	CpuLimitsKnown      bool   `json:"cpu_limits_known"`
	CpuPressureKnown    bool   `json:"cpu_pressure_known"`
	CpuPeriods          uint64 `json:"cpu_periods"`
	CpuThrottledPeriods uint64 `json:"cpu_throttled_periods"`
	CpuThrottledNs      uint64 `json:"cpu_throttled_ns"`
	MemoryPressureKnown bool   `json:"memory_pressure_known"`
	MemoryHighEvents    uint64 `json:"memory_high_events"`
	MemoryOomEvents     uint64 `json:"memory_oom_events"`
	MemoryOomKillEvents uint64 `json:"memory_oom_kill_events"`
}

// decodeBirthResourceEvidence parses the persisted birth label under strict
// schema rules and binds it to the identity it must name. The label must be
// present, at most 2048 bytes, exactly one JSON object with no unknown
// fields, schema 1, a start or restore phase, a positive observation time not
// in the future, positive finite leaf limits, and the exact sandbox and
// resource generation of the resolved identity. The CPU quota must be a real
// enforced limit: an unlimited (-1) or zero reading is not birth evidence.
func decodeBirthResourceEvidence(raw string, identity Identity) (birthResourceEvidence, bool) {
	var birth birthResourceEvidence
	if raw == "" || len(raw) > maxBirthResourceEvidenceBytes {
		return birth, false
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&birth); err != nil {
		return birth, false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return birth, false
	}
	if birth.SchemaVersion != birthResourceEvidenceSchemaVersion {
		return birth, false
	}
	if birth.Phase != "start" && birth.Phase != "restore" {
		return birth, false
	}
	if birth.ObservedAtUnixMs <= 0 || birth.ObservedAtUnixMs > time.Now().UnixMilli() {
		return birth, false
	}
	if birth.CpuQuotaUsec <= 0 || birth.CpuPeriodUsec <= 0 || birth.MemoryLimitBytes <= 0 {
		return birth, false
	}
	if birth.SandboxID != identity.SandboxID || birth.ResourceGeneration != identity.ResourceGeneration {
		return birth, false
	}
	return birth, true
}

// serveResources renders the /resources report for an identity already
// confirmed by both List snapshots and the physical Stats readback. The birth
// label must carry byte-identical evidence on both snapshots: anything
// missing, malformed, or changed is answered with a single generic conflict
// carrying no private label data. The live sample is exactly what Stats
// returned for the RUNNING incarnation between the two Lists — it is not a
// final accounting for a dead sandbox, so peak readings only bound the sample
// window, never a whole lifetime.
func serveResources(w http.ResponseWriter, identity Identity, firstBirth, secondBirth string, stats *runtime.StatsResponse, sampleStartedUnixMs, sampleFinishedUnixMs int64) {
	birth, ok := decodeBirthResourceEvidence(firstBirth, identity)
	if !ok || firstBirth != secondBirth {
		http.Error(w, "birth resource evidence missing, malformed, or changed", 409)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resourceReport{
		SchemaVersion:        resourceReportSchemaVersion,
		Identity:             identity,
		Birth:                birth,
		SampleStartedUnixMs:  sampleStartedUnixMs,
		SampleFinishedUnixMs: sampleFinishedUnixMs,
		Current: resourceSample{
			CpuUsageNs:          stats.CpuUsageNs,
			CpuUsageKnown:       stats.CpuUsageKnown,
			MemoryUsageBytes:    stats.MemoryUsageBytes,
			MemoryUsageKnown:    stats.MemoryUsageKnown,
			MemoryLimitBytes:    stats.MemoryLimitBytes,
			MemoryLimitKnown:    stats.MemoryLimitKnown,
			MemoryMaxUsageBytes: stats.MemoryMaxUsageBytes,
			MemoryPeakKnown:     stats.MemoryPeakKnown,
			CpuQuotaUsec:        stats.CpuQuotaUsec,
			CpuPeriodUsec:       stats.CpuPeriodUsec,
			CpuLimitsKnown:      stats.CpuLimitsKnown,
			CpuPressureKnown:    stats.CpuPressureKnown,
			CpuPeriods:          stats.CpuPeriods,
			CpuThrottledPeriods: stats.CpuThrottledPeriods,
			CpuThrottledNs:      stats.CpuThrottledNs,
			MemoryPressureKnown: stats.MemoryPressureKnown,
			MemoryHighEvents:    stats.MemoryHighEvents,
			MemoryOomEvents:     stats.MemoryOomEvents,
			MemoryOomKillEvents: stats.MemoryOomKillEvents,
		},
	})
}
