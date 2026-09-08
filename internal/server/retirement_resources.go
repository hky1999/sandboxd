// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// Daemon-owned append-only evidence for scheduler-managed generations: an
// external poll can never observe an intermediate physical generation that
// park/eviction is about to retire, so the daemon preserves the observations
// itself. Unlike scheduler-retirements (mutable completion receipts), every
// capture here is a separate immutable file — a retry after a failed physical
// delete adds observations under a fresh delete attempt ID, it never replaces
// one. No GC, no endpoint, and no consumer is wired in this change.
const retirementResourceDirName = "scheduler-resource-retirements"

// Trusted scheduler identity labels, mirrored from the writer/resolver so the
// server stays the single owner of its label vocabulary.
const schedulerInstanceIDLabel = "akernel.scheduler/instance-id"
const schedulerRuntimeIDLabel = "akernel.scheduler/runtime-id"

const retirementResourceRecordSchema = 1
const retirementResourcePhaseBeforeDelete = "before_runtime_delete"
const retirementResourcePhaseAfterDelete = "after_runtime_delete"

const retirementResourceRecordLimit = 65536
const retirementResourceRecordLimitBytes = 32 * 1024
const retirementResourceIdentityMaxBytes = 256
const retirementResourceBirthMaxBytes = 4096

const retirementBirthStatusOk = "ok"
const retirementBirthStatusMissing = "missing"
const retirementBirthStatusInvalid = "invalid"
const retirementBirthStatusUncommitted = "uncommitted"
const retirementSampleStatusOk = "ok"
const retirementSampleStatusUnavailable = "unavailable"

// retirementResourceSample is the allowlisted numeric view of one physical
// Stats readback — exactly the /resources resolver's current-sample allowlist.
// It never carries the elastic policy, raw labels, the full StatsResponse,
// error strings, paths, auth, commands or env. Source-validity flags are
// copied verbatim: a false flag means the sibling number is only a legacy
// fallback, and knownness is never inferred from a nonzero value.
type retirementResourceSample struct {
	CpuUsageNs          uint64 `json:"cpu_usage_ns"`
	CpuUsageKnown       bool   `json:"cpu_usage_known"`
	MemoryUsageBytes    uint64 `json:"memory_usage_bytes"`
	MemoryUsageKnown    bool   `json:"memory_usage_known"`
	MemoryLimitBytes    uint64 `json:"memory_limit_bytes"`
	MemoryLimitKnown    bool   `json:"memory_limit_known"`
	MemoryMaxUsageBytes uint64 `json:"memory_max_usage_bytes"`
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

// retirementResourceRecord is the immutable schema-1 record of ONE capture
// observation. The before/after records of a single delete share their
// delete_attempt_id and the immutable metadata snapshot taken when the
// attempt began; record_id stays unique per observation. It is observation
// evidence only: the samples bracket the runtime handler, so neither is the
// exact last kernel sample nor a whole-lifetime CPU peak, and
// physical_deletion_confirmed stays false — proof of deletion remains the
// separate completion receipt's job.
type retirementResourceRecord struct {
	SchemaVersion             int                       `json:"schema_version"`
	RecordID                  string                    `json:"record_id"`
	SandboxID                 string                    `json:"sandbox_id"`
	ResourceGeneration        string                    `json:"resource_generation"`
	DeleteAttemptID           string                    `json:"delete_attempt_id"`
	InstanceID                string                    `json:"instance_id,omitempty"`
	RuntimeID                 string                    `json:"runtime_id,omitempty"`
	IdentityComplete          bool                      `json:"identity_complete"`
	MetadataCommitted         bool                      `json:"metadata_committed"`
	Phase                     string                    `json:"phase"`
	SampleStartedUnixMs       int64                     `json:"sample_started_unix_ms"`
	SampleFinishedUnixMs      int64                     `json:"sample_finished_unix_ms"`
	Birth                     *birthResourceEvidence    `json:"birth"`
	BirthStatus               string                    `json:"birth_status"`
	Sample                    *retirementResourceSample `json:"sample"`
	SampleStatus              string                    `json:"sample_status"`
	PhysicalDeletionConfirmed bool                      `json:"physical_deletion_confirmed"`
}

// schedulerIdentityValue accepts a trusted akernel.scheduler identity label
// only when it is bounded, valid UTF-8, and free of whitespace and control
// characters — the same shape the resolver demands of instance_id. Anything
// missing or invalid collapses to empty so no unvetted label text reaches
// durable daemon storage; identity_complete records that collapse.
func schedulerIdentityValue(raw string) string {
	if raw == "" || len(raw) > retirementResourceIdentityMaxBytes || !utf8.ValidString(raw) {
		return ""
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ""
		}
	}
	return raw
}

// decodeRetirementBirthEvidence validates the persisted birth label against
// the incarnation being retired: at most 4096 bytes, exactly one strict JSON
// object with no unknown or trailing fields, schema 1, a start/restore phase,
// positive observation time and leaf limits, and the exact sandbox and
// resource generation. Invalid or missing input is reported by category only;
// the raw label text is never persisted. Like the writer, this is observation
// evidence of prepared leaf limits, never proof of runtime success.
func decodeRetirementBirthEvidence(raw, sandboxID, generation string) (birthResourceEvidence, bool) {
	var birth birthResourceEvidence
	if raw == "" || len(raw) > retirementResourceBirthMaxBytes {
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
	if birth.ObservedAtUnixMs <= 0 || birth.CpuQuotaUsec <= 0 || birth.CpuPeriodUsec == 0 || birth.MemoryLimitBytes == 0 {
		return birth, false
	}
	if birth.SandboxID != sandboxID || birth.ResourceGeneration != generation {
		return birth, false
	}
	return birth, true
}

func retirementSampleFromStats(stats *runtime.StatsResponse) *retirementResourceSample {
	return &retirementResourceSample{
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
	}
}

// captureRetirementResources records one daemon-owned observation of a
// scheduler-managed generation around its physical delete. The caller holds
// the sandbox's physical resource lock and passes the delete attempt's ID, the
// observation phase, and the immutable metadata snapshot proto.Clone'd from
// the identity the attempt selected: the sample is read through resourceStats
// directly — the Stats RPC would try to reacquire the same lock — and the
// still-live metadata must remain proto.Equal to that snapshot before the
// record is archived, so an identity that moved mid-capture refuses the
// attempt instead of archiving a mixed observation. The after-phase capture
// reuses the same initial snapshot; the daemon never re-adopts changed
// metadata for an attempt already in flight. A failed sample is persisted
// honestly as null/unavailable and alone never blocks cleanup; a persistence
// failure returns an error — before the runtime handler it prevents the
// delete, after it the caller must stop resource release and the completion
// receipt, retaining recoverable unknown state.
func (h *sandboxService) captureRetirementResources(sandboxID, generation, attemptID, phase string, snapshot *runtime.SandboxMetadata) error {
	if snapshot == nil {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s has no metadata snapshot for retirement evidence", sandboxID)
	}
	if attemptID == "" {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"retirement evidence for sandbox %s requires a delete attempt ID", sandboxID)
	}
	if phase != retirementResourcePhaseBeforeDelete && phase != retirementResourcePhaseAfterDelete {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"unknown retirement evidence phase %q", phase)
	}
	labels := snapshot.GetLabels()
	instanceID := schedulerIdentityValue(labels[schedulerInstanceIDLabel])
	runtimeID := schedulerIdentityValue(labels[schedulerRuntimeIDLabel])

	record := &retirementResourceRecord{
		SchemaVersion:             retirementResourceRecordSchema,
		RecordID:                  uuid.NewString(),
		SandboxID:                 sandboxID,
		ResourceGeneration:        generation,
		DeleteAttemptID:           attemptID,
		InstanceID:                instanceID,
		RuntimeID:                 runtimeID,
		IdentityComplete:          instanceID != "" && runtimeID != "",
		MetadataCommitted:         snapshot.PhysicalPhase == runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		Phase:                     phase,
		PhysicalDeletionConfirmed: false,
	}
	if record.MetadataCommitted {
		raw := labels[birthResourcesLabel]
		if birth, ok := decodeRetirementBirthEvidence(raw, sandboxID, generation); ok {
			record.Birth = &birth
			record.BirthStatus = retirementBirthStatusOk
		} else if raw == "" {
			record.BirthStatus = retirementBirthStatusMissing
		} else {
			record.BirthStatus = retirementBirthStatusInvalid
		}
	} else {
		// Birth evidence is only ever associated with a committed incarnation:
		// an INTENT that never reached the runtime must not donate its label.
		record.BirthStatus = retirementBirthStatusUncommitted
	}

	record.SampleStartedUnixMs = time.Now().UnixMilli()
	stats, statsErr := h.resourceStats(sandboxID)
	record.SampleFinishedUnixMs = time.Now().UnixMilli()
	if statsErr != nil {
		// Honest absence, not fake zero values.
		record.Sample = nil
		record.SampleStatus = retirementSampleStatusUnavailable
	} else {
		if stats == nil || stats.ResourceGeneration != generation {
			return errord.ToGRPCf(errord.ErrFailedPrecondition,
				"sandbox %s resource generation changed during %s capture", sandboxID, phase)
		}
		record.Sample = retirementSampleFromStats(stats)
		record.SampleStatus = retirementSampleStatusOk
	}

	// Re-read the physical metadata under the still-held lock and require it
	// to still equal the attempt's immutable snapshot — never the possibly
	// mutated original pointer — before the record is accepted for archival.
	current, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s disappeared during %s capture: %v", sandboxID, phase, err)
	}
	if current == nil || current.Metadata == nil || !proto.Equal(current.Metadata, snapshot) {
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s identity changed during %s capture", sandboxID, phase)
	}

	return h.persistRetirementResourceRecord(record)
}

func (h *sandboxService) retirementResourceDir() string {
	return filepath.Join(h.config.RootDir, retirementResourceDirName)
}

// persistRetirementResourceRecord publishes one immutable attempt file. The
// name binds SHA256([sandboxID, generation]) with the fresh random record ID
// so a retry after a failed physical delete adds another observation instead
// of replacing the first — an unavailable retry can never overwrite the last
// good sample. Publication goes through link(2), which never replaces an
// existing destination, and the entry-count cap plus retirementMu bound
// journal growth. Only the bounded publication runs under retirementMu; the
// physical lock the caller still holds orders attempts per sandbox.
func (h *sandboxService) persistRetirementResourceRecord(record *retirementResourceRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode retirement resource record: %w", err)
	}
	if len(data) > retirementResourceRecordLimitBytes {
		return fmt.Errorf("retirement resource record for sandbox %s exceeds %d bytes",
			record.SandboxID, retirementResourceRecordLimitBytes)
	}
	// The same keying as completion receipts, so evidence and receipt for one
	// generation cluster without sharing a namespace.
	key, _ := json.Marshal([2]string{record.SandboxID, record.ResourceGeneration})
	digest := sha256.Sum256(key)
	dir := h.retirementResourceDir()
	destination := filepath.Join(dir, hex.EncodeToString(digest[:])+"."+record.RecordID+".json")

	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// Exact ownership regardless of the daemon's umask.
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if err := syncRetirementDirectory(h.config.RootDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) >= retirementResourceRecordLimit {
		return fmt.Errorf("retirement resource journal full; reconciliation required")
	}
	f, err := os.CreateTemp(dir, ".resource-retirement-*")
	if err != nil {
		return err
	}
	// Failure paths before publication must not leak the temp name.
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Ordering: the file fsync above precedes the link, and the directory
	// fsync follows it, so the exposed name never outruns durable bytes.
	if err := os.Link(f.Name(), destination); err != nil {
		return err
	}
	// Drop the owned temp name before the directory fsync so the durable
	// entry list never includes it. A published record may already exist —
	// the error still propagates so deletion must not proceed on uncertain
	// journal state. Published records themselves are never removed.
	if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncRetirementDirectory(dir)
}
