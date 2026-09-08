// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
)

// Daemon-owned, bounded, per-physical-incarnation state for the resource
// revision contract. One mutable record per (sandbox, resource generation)
// lives next to the scheduler journals under the daemon root — never inside a
// sandbox-writable directory. The record is the only authority for "which
// revision is this incarnation on" and "does this daemon own an open freeze";
// a missing record is unknown state, never an inferred initial revision.
const resourceStateDirName = "scheduler-resource-states"

const resourceStateSchemaVersion = 1

// Journal bounds mirror the sibling scheduler journals: hard entry cap with no
// automatic GC, and a per-record byte cap so one incarnation cannot grow an
// unbounded file.
const resourceStateRecordLimit = 65536
const resourceStateRecordLimitBytes = 32 * 1024

// Stages of the operation currently recorded in a state file. The empty stage
// means no operation is open: the last operation reached a terminal outcome
// and the daemon owns no freeze for the incarnation.
const (
	resourceStageIdle          = ""
	resourceStageIntent        = "intent"         // next revision persisted, no side effect yet
	resourceStageFreezeWritten = "freeze_written" // freeze=1 requested, confirmation pending
	resourceStageFrozen        = "frozen"         // kernel confirmed the freeze
	resourceStageApplied       = "applied"        // memory writes issued, verification pending
)

// Terminal outcomes. Complete is the only outcome a caller may book as a
// successful operation; everything else is a truthful partial or recovered
// fact with the revision already advanced.
const (
	resourceOutcomeComplete       = "complete"
	resourceOutcomePartial        = "partial"
	resourceOutcomeFreezeTimeout  = "freeze_timeout"
	resourceOutcomeUnsafeHeadroom = "unsafe_headroom"
	resourceOutcomeRecovered      = "recovered_after_restart"
	resourceOutcomeRetired        = "retired_with_incarnation"
)

const (
	resourceOperationGrow   = "grow"
	resourceOperationShrink = "shrink"
)

type resourceStateLimits struct {
	CpuQuotaUsec     int64  `json:"cpu_quota_usec"`
	CpuPeriodUsec    uint64 `json:"cpu_period_usec"`
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
}

// resourceReadbackSnapshot is the allowlisted observation that closed an
// operation. Knownness flags travel with the numbers: an unknown flag means
// the sibling number is a legacy fallback, not an observation.
type resourceReadbackSnapshot struct {
	CpuQuotaUsec        int64  `json:"cpu_quota_usec"`
	CpuPeriodUsec       uint64 `json:"cpu_period_usec"`
	CpuLimitsKnown      bool   `json:"cpu_limits_known"`
	MemoryLimitBytes    uint64 `json:"memory_limit_bytes"`
	MemoryLimitKnown    bool   `json:"memory_limit_known"`
	MemoryHighBytes     uint64 `json:"memory_high_bytes"`
	MemoryHighKnown     bool   `json:"memory_high_known"`
	MemoryHighUnlimited bool   `json:"memory_high_unlimited"`
	Frozen              bool   `json:"frozen"`
	FrozenKnown         bool   `json:"frozen_known"`
	ObservedAtUnixMs    int64  `json:"observed_at_unix_ms"`
}

// resourceOperationState is the durable, schema-1 record for one physical
// incarnation. Revision starts at 1 when the incarnation is created and
// advances by exactly one per accepted operation, including partially applied
// ones — a partial outcome never rolls the revision back. An open stage
// (anything but resourceStageIdle) means reconciliation is required before
// the incarnation accepts another resource operation.
type resourceOperationState struct {
	SchemaVersion      int    `json:"schema_version"`
	SandboxID          string `json:"sandbox_id"`
	ResourceGeneration string `json:"resource_generation"`
	CgroupPath         string `json:"cgroup_path"`
	CgroupInode        uint64 `json:"cgroup_inode"`
	CgroupDevice       uint64 `json:"cgroup_device"`
	Revision           uint64 `json:"revision"`
	CreatedAtUnixMs    int64  `json:"created_at_unix_ms"`
	UpdatedAtUnixMs    int64  `json:"updated_at_unix_ms"`

	LastOperationID      string `json:"last_operation_id,omitempty"`
	LastFingerprint      string `json:"last_fingerprint,omitempty"`
	LastOperationType    string `json:"last_operation_type,omitempty"`
	LastOutcome          string `json:"last_outcome,omitempty"`
	LastOutcomeMessage   string `json:"last_outcome_message,omitempty"`
	LastCompletionUnixMs int64  `json:"last_completion_unix_ms,omitempty"`

	Stage                   string                    `json:"stage,omitempty"`
	FreezeOwned             bool                      `json:"freeze_owned"`
	OperationKind           string                    `json:"operation_kind,omitempty"`
	OperationDeadlineUnixMs int64                     `json:"operation_deadline_unix_ms,omitempty"`
	Expected                *resourceStateLimits      `json:"expected,omitempty"`
	Target                  *resourceStateLimits      `json:"target,omitempty"`
	OldMemoryHighBytes      uint64                    `json:"old_memory_high_bytes"`
	OldMemoryMaxBytes       uint64                    `json:"old_memory_max_bytes"`
	Actual                  *resourceReadbackSnapshot `json:"actual_readback,omitempty"`
}

// open reports whether an operation is unclosed: the durable record claims an
// in-flight mutation, so its outcome is UNKNOWN until reconciliation.
func (s *resourceOperationState) open() bool {
	return s.Stage != resourceStageIdle
}

// resourceStateLoadResult classifies why no usable record exists.
type resourceStateLoadResult int

const (
	resourceStateLoaded resourceStateLoadResult = iota
	resourceStateMissing
	resourceStateCorrupt
)

func (h *sandboxService) resourceStateDir() string {
	return filepath.Join(h.config.RootDir, resourceStateDirName)
}

func (h *sandboxService) resourceStatePath(id, generation string) (string, string) {
	key, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(key)
	dir := h.resourceStateDir()
	return dir, filepath.Join(dir, hex.EncodeToString(digest[:])+".json")
}

// loadResourceOperationState reads one incarnation's record. Corrupt input is
// reported as corrupt, not missing: a damaged record can hide an owned freeze
// and must keep the incarnation fail-closed instead of reverting to legacy
// no-state behavior.
func (h *sandboxService) loadResourceOperationState(id, generation string) (*resourceOperationState, resourceStateLoadResult, error) {
	_, path := h.resourceStatePath(id, generation)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, resourceStateMissing, nil
		}
		return nil, resourceStateCorrupt, err
	}
	state, result := decodeResourceOperationState(data)
	if result != resourceStateLoaded {
		return nil, result, fmt.Errorf("resource state record for sandbox %s generation %s is damaged", id, generation)
	}
	if state.SandboxID != id || state.ResourceGeneration != generation {
		return nil, resourceStateCorrupt, fmt.Errorf("resource state record for sandbox %s generation %s holds foreign identity", id, generation)
	}
	return state, resourceStateLoaded, nil
}

// saveResourceOperationState publishes one incarnation's mutable record with
// the same discipline as the scheduler journals: temp file, fsync, rename,
// directory fsync, 0600 file in a 0700 daemon-owned directory, hard entry
// cap. Callers hold the incarnation's physical resource lock; resourceStateMu
// only serializes publication across sandboxes.
func (h *sandboxService) saveResourceOperationState(state *resourceOperationState) error {
	if state == nil || state.SandboxID == "" || state.ResourceGeneration == "" {
		return fmt.Errorf("resource state identity is required")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode resource state for sandbox %s: %w", state.SandboxID, err)
	}
	if len(data) > resourceStateRecordLimitBytes {
		return fmt.Errorf("resource state record for sandbox %s exceeds %d bytes", state.SandboxID, resourceStateRecordLimitBytes)
	}
	dir, path := h.resourceStatePath(state.SandboxID, state.ResourceGeneration)

	h.resourceStateMu.Lock()
	defer h.resourceStateMu.Unlock()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
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
	occupied := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".resource-state-") {
			continue
		}
		occupied++
	}
	if occupied >= resourceStateRecordLimit {
		return fmt.Errorf("resource state journal full; reconciliation required")
	}
	f, err := os.CreateTemp(dir, ".resource-state-*")
	if err != nil {
		return err
	}
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
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncRetirementDirectory(dir)
}

// initResourceOperationState initializes revision 1 for a freshly prepared
// elastic incarnation, after its birth evidence and before the runtime
// handler is allowed to claim any physical fact. The cgroup identity is
// proven by stat: a path that cannot be resolved leaves the incarnation
// without revision state and creation fails rather than recording an
// unprovable identity.
func (h *sandboxService) initResourceOperationState(id, generation, cgroupPath string) error {
	if id == "" || generation == "" || cgroupPath == "" {
		return fmt.Errorf("resource revision initialization requires sandbox, generation and cgroup identity")
	}
	if existing, result, err := h.loadResourceOperationState(id, generation); err != nil || result != resourceStateMissing {
		if err != nil {
			return fmt.Errorf("resource revision initialization for sandbox %s read failed: %w", id, err)
		}
		if result == resourceStateCorrupt {
			return fmt.Errorf("resource revision initialization for sandbox %s found a damaged record", id)
		}
		return fmt.Errorf("resource revision state for sandbox %s generation %s already exists at revision %d",
			id, generation, existing.Revision)
	}
	if h.cgroupMgr == nil {
		return fmt.Errorf("resource revision initialization requires the cgroup manager")
	}
	identity, err := h.cgroupMgr.CgroupIdentity(cgroupPath)
	if err != nil {
		return fmt.Errorf("prove cgroup identity for sandbox %s: %w", id, err)
	}
	now := time.Now().UnixMilli()
	state := &resourceOperationState{
		SchemaVersion:      resourceStateSchemaVersion,
		SandboxID:          id,
		ResourceGeneration: generation,
		CgroupPath:         cgroupPath,
		CgroupInode:        identity.Inode,
		CgroupDevice:       identity.Device,
		Revision:           1,
		CreatedAtUnixMs:    now,
		UpdatedAtUnixMs:    now,
		Stage:              resourceStageIdle,
	}
	if err := h.saveResourceOperationState(state); err != nil {
		return fmt.Errorf("persist initial resource revision for sandbox %s: %w", id, err)
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": id, "resource_generation": generation,
		"cgroup_path": cgroupPath, "revision": 1,
	}).Info("scheduler resource revision initialized")
	return nil
}

// initializeResourceRevision creates revision 1 for a freshly prepared
// elastic incarnation, after its birth evidence and before the runtime
// handler runs — so the incarnation can never be published without proven
// revision state. Restore shares this hook: it owns a new physical
// generation and starts a new revision, never the checkpoint's old identity.
func (h *sandboxService) initializeResourceRevision(start svc.StartConfig, metadata *runtime.SandboxMetadata) error {
	if start.Annotations[elasticResourcesLabel] == "" {
		return nil
	}
	generation := start.Annotations[resourceGenerationLabel]
	if metadata == nil || metadata.ID != start.ID ||
		generation == "" || metadata.Labels[resourceGenerationLabel] != generation {
		return fmt.Errorf("resource revision initialization requires prepared INTENT metadata for this generation")
	}
	return h.initResourceOperationState(start.ID, generation, start.CgroupPath)
}

// snapshotResourceReadback captures the observation that ends an operation.
func snapshotResourceReadback(stats *runtime.StatsResponse) *resourceReadbackSnapshot {
	if stats == nil {
		return nil
	}
	return &resourceReadbackSnapshot{
		CpuQuotaUsec:        stats.CpuQuotaUsec,
		CpuPeriodUsec:       stats.CpuPeriodUsec,
		CpuLimitsKnown:      stats.CpuLimitsKnown,
		MemoryLimitBytes:    stats.MemoryLimitBytes,
		MemoryLimitKnown:    stats.MemoryLimitKnown,
		MemoryHighBytes:     stats.MemoryHighBytes,
		MemoryHighKnown:     stats.MemoryHighKnown,
		MemoryHighUnlimited: stats.MemoryHighUnlimited,
		Frozen:              stats.Frozen,
		FrozenKnown:         stats.FrozenKnown,
		ObservedAtUnixMs:    time.Now().UnixMilli(),
	}
}

// closeResourceOperation durably records the terminal outcome of the last
// operation. The revision stays at its post-intent value whatever the outcome;
// closing never rolls it back.
func (h *sandboxService) closeResourceOperation(state *resourceOperationState, outcome, message string, actual *resourceReadbackSnapshot) error {
	state.Stage = resourceStageIdle
	state.FreezeOwned = false
	state.LastOutcome = outcome
	state.LastOutcomeMessage = message
	state.LastCompletionUnixMs = time.Now().UnixMilli()
	state.Actual = actual
	state.UpdatedAtUnixMs = state.LastCompletionUnixMs
	return h.saveResourceOperationState(state)
}

// retireResourceOperationState closes and removes an incarnation's record
// after that generation was fully retired by a successful physical delete.
// Only the deletion itself is authority here: discovering a missing record
// never proves anything, and an unpersistable close leaves the file behind
// for restart reconciliation.
func (h *sandboxService) retireResourceOperationState(id, generation string) {
	state, result, err := h.loadResourceOperationState(id, generation)
	if err != nil || result == resourceStateMissing {
		if err != nil {
			logrus.WithError(err).Warnf("read resource state for retired sandbox %s generation %s failed", id, generation)
		}
		return
	}
	if result == resourceStateCorrupt {
		logrus.Warnf("retain damaged resource state for retired sandbox %s generation %s", id, generation)
		return
	}
	if state.open() {
		state.Stage = resourceStageIdle
		state.FreezeOwned = false
		state.LastOutcome = resourceOutcomeRetired
		state.LastOutcomeMessage = "incarnation retired by a completed physical delete"
		state.LastCompletionUnixMs = time.Now().UnixMilli()
		state.UpdatedAtUnixMs = state.LastCompletionUnixMs
		if err := h.saveResourceOperationState(state); err != nil {
			logrus.WithError(err).Warnf("close resource state of retired sandbox %s generation %s failed; retaining record", id, generation)
			return
		}
	}
	_, path := h.resourceStatePath(id, generation)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		logrus.WithError(err).Warnf("remove resource state of retired sandbox %s generation %s failed", id, generation)
		return
	}
	if err := syncRetirementDirectory(h.resourceStateDir()); err != nil {
		logrus.WithError(err).Warnf("sync resource state directory after retirement failed")
	}
}

// resourceStateObservation is the Stats-facing projection of the journal.
type resourceStateObservation struct {
	Revision      uint64
	RevisionKnown bool
	OperationID   string
	OperationOpen bool
	// CgroupPath is the backend-proven absolute cgroup directory, populated
	// only when the journal record's identity (path plus inode/device)
	// verifies against the live cgroup. Empty otherwise.
	CgroupPath string
}

// observeResourceOperationState reads the incarnation's journal for Stats.
// A missing record is a legacy or never-initialized incarnation (known false);
// a damaged record is conservative: it can hide an owned freeze, so the
// incarnation reports an open operation until it is reconciled. The absolute
// cgroup locator from the just-completed backend read is exposed only after
// the record's physical identity verifies; it is read-only and never
// replaces the journal's binding.
func (h *sandboxService) observeResourceOperationState(id, generation, cgroupPath, backendCgroupPath string) resourceStateObservation {
	if generation == "" {
		return resourceStateObservation{}
	}
	state, result, err := h.loadResourceOperationState(id, generation)
	switch {
	case err != nil:
		logrus.WithError(err).Warnf("read resource state for sandbox %s generation %s failed", id, generation)
		return resourceStateObservation{OperationOpen: true}
	case result == resourceStateMissing:
		return resourceStateObservation{}
	case result == resourceStateCorrupt:
		logrus.Warnf("resource state for sandbox %s generation %s is damaged; operations stay rejected", id, generation)
		return resourceStateObservation{OperationOpen: true}
	}
	observation := resourceStateObservation{
		Revision:      state.Revision,
		RevisionKnown: true,
		OperationID:   state.LastOperationID,
		OperationOpen: state.open(),
	}
	if backendCgroupPath != "" && cgroupPath != "" && state.CgroupPath == cgroupPath && h.cgroupMgr != nil {
		if identity, identityErr := h.cgroupMgr.CgroupIdentity(cgroupPath); identityErr == nil &&
			identity.Inode == state.CgroupInode && identity.Device == state.CgroupDevice {
			observation.CgroupPath = backendCgroupPath
		}
	}
	return observation
}

// rejectUnclosedResourceOperation refuses Sentry-dependent control operations
// (Pause/Resume/Checkpoint) while this daemon owns an open or unparsable
// resource operation for the incarnation: the sandbox may still be frozen by
// our own shrink, and a Sentry round-trip that hangs while holding the
// physical lock would wedge the self-heal recovery that must unfreeze it.
// The check never releases anyone's freeze and never adopts a foreign one.
func (h *sandboxService) rejectUnclosedResourceOperation(id string) error {
	current, err := h.sandboxManager.Get(id)
	if err != nil || current == nil || current.Metadata == nil {
		// The caller's own resolution reports missing sandboxes.
		return nil
	}
	generation := current.Metadata.GetLabels()[resourceGenerationLabel]
	if generation == "" {
		return nil
	}
	state, result, err := h.loadResourceOperationState(id, generation)
	if err != nil {
		return errord.ToGRPCf(errord.ErrUnavailable,
			"resource state for sandbox %s is unreadable; reconcile before pausing or checkpointing: %v", id, err)
	}
	switch result {
	case resourceStateCorrupt:
		return errord.ToGRPCf(errord.ErrFailedPrecondition,
			"resource state for sandbox %s is damaged; reconciliation required before pausing or checkpointing", id)
	case resourceStateLoaded:
		if state.open() {
			return errord.ToGRPCf(errord.ErrFailedPrecondition,
				"sandbox %s has resource operation %s pending; reconcile it before pausing or checkpointing",
				id, state.LastOperationID)
		}
	}
	return nil
}
