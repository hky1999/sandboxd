// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

// firecrackerCheckpointOperationRecordVersion is the version-1 schema of
// firecrackerCheckpointOperationRecord: the sealed-operation witness every
// production path writes today (prepared/completed/acked phases, a bound
// sealed root, no directory identity). Version-1 validation keeps its exact
// historical shape; see firecrackerCheckpointOperationRecordVersion2 for the
// early-intent extension.
const firecrackerCheckpointOperationRecordVersion = 1

// firecrackerCheckpointOperationRecordVersion2 is the early-intent schema of
// firecrackerCheckpointOperationRecord: it adds the unsealed
// intent/aborting/aborted/abort-acked phases and the directory birth identity,
// and also admits the version-1 phases under their existing sealed root
// validation, so a later step can promote a durable intent into a prepared
// witness in place — same record, same directory identity — instead of
// rewriting the evidence. Records at this version predate the persistent
// directory claim: they carry no sandbox identity, and every recovery, abort,
// and acknowledgment path keeps verifying them exactly as it did before the
// claim protocol existed — no claim file is required or consulted for them.
// Validation is strict: every version-2 phase requires the complete common
// operation and source identity plus a complete directory identity, and the
// root shape must match the phase exactly.
const firecrackerCheckpointOperationRecordVersion2 = 2

// firecrackerCheckpointOperationRecordVersion3 is the claim-bound schema of
// firecrackerCheckpointOperationRecord: every version-2 promise plus the
// sandbox identity whose operation claimed the output directory. Admission of
// this version establishes the persistent exclusive directory claim (see
// claimFirecrackerCheckpointDirectory) BEFORE the durable intent is written,
// and every hot or cold recovery and abort path that needs the directory
// identity verifies the exact claim alongside it. The sandbox identity makes
// the witness self-contained — the claim binds the source sandbox, and the
// record now restates it so a cold reconciliation can cross-check the
// incarnation state. Version-1/2 records never carry the field; a mixed shape
// is corruption.
const firecrackerCheckpointOperationRecordVersion3 = 3

// Identified checkpoint operation witness phases. The witness lives inside the
// single persisted instance state so the evidence and the constraints it
// imposes can never be split across two durable writes.
const (
	// firecrackerCheckpointOperationPhasePrepared marks a sealed snapshot
	// bound to the operation with the source's stop still unconfirmed. The
	// source must never be resumed again.
	firecrackerCheckpointOperationPhasePrepared = "prepared"
	// firecrackerCheckpointOperationPhaseCompleted marks the confirmed exit
	// of the exact recorded source processes, durable in the state.
	firecrackerCheckpointOperationPhaseCompleted = "completed"
	// firecrackerCheckpointOperationPhaseAcked marks the service's durable
	// SUCCEEDED receipt having released the evidence-retention gate.
	firecrackerCheckpointOperationPhaseAcked = "acked"
	// firecrackerCheckpointOperationPhaseIntent (versions 2 and 3) marks a
	// durably recorded early intent captured before layout, quiesce, pause,
	// or snapshot: the operation owns the source, the source and directory
	// identity are already bound, and no sealed root exists — an intent is
	// operation ownership, never a success witness. An identified Checkpoint
	// writes it after establishing the directory claim; a version-3 record is
	// the claim-bound shape.
	firecrackerCheckpointOperationPhaseIntent = "intent"
	// firecrackerCheckpointOperationPhaseAborting (versions 2 and 3) marks the
	// durably recorded decision to abort an intent that never sealed: the
	// abort's source handback is in progress and its evidence must be
	// retained until the abort is confirmed. AbortCheckpointOperation writes
	// it before every resume attempt.
	firecrackerCheckpointOperationPhaseAborting = "aborting"
	// firecrackerCheckpointOperationPhaseAborted (versions 2 and 3) marks a
	// confirmed abort fact durable in the state; the explicit abort
	// acknowledgment that releases its evidence is the separate abort-side
	// step — the success Ack refuses it.
	firecrackerCheckpointOperationPhaseAborted = "aborted"
	// firecrackerCheckpointOperationPhaseAbortAcked (versions 2 and 3) marks
	// the abort-side acknowledgment having released the abort evidence
	// retention gate. AckAbortedCheckpointOperation writes it.
	firecrackerCheckpointOperationPhaseAbortAcked = "abort-acked"
)

// firecrackerCheckpointOperationPhaseRequiresSealedRoot reports whether a
// phase's witness must carry the bound sealed content root. The version-1
// phases always do; the early-intent phases of every later version never do —
// an intent or abort record proves operation ownership and an abort fact,
// never a sealed artifact, and a root on such a record would misread it as a
// success witness.
func firecrackerCheckpointOperationPhaseRequiresSealedRoot(phase string) bool {
	switch phase {
	case firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked:
		return true
	default:
		return false
	}
}

// firecrackerCheckpointOperationRecord is the durable witness of an identified
// stop-and-copy checkpoint operation. It is a comparable value type held
// directly in firecrackerPersistedState (never a separate credential file) so
// the witness, the no-new-checkpoint constraint, and the evidence-retaining
// Delete gate are one atomic state write with no double-write window, and the
// existing state comparisons in persistCheckpointChanges keep working.
//
// The zero record means no operation evidence is retained: a legacy
// checkpoint, or a state written before this record existed. Such states keep
// the legacy lifecycle behavior unchanged.
//
// Version 2 (the early-intent schema) extends the same value type with the
// unsealed intent/aborting/aborted/abort-acked phases and the directory birth
// identity; version 3 (the claim-bound schema) adds the sandbox identity whose
// operation claimed the directory. See the version constants and the schema
// subsections in doc/checkpoint-restore.md.
type firecrackerCheckpointOperationRecord struct {
	// Version is the record schema version.
	Version int `json:"version,omitempty"`
	// Phase is prepared until the source stop is confirmed, completed once
	// the durable completion fact exists, and acked once the service's
	// durable SUCCEEDED receipt released the evidence-retention gate.
	Phase string `json:"phase,omitempty"`
	// OperationID, RequestDigest and SourceGeneration restate the exact
	// binding the operation was admitted under; recovery accepts only a
	// complete, exact match. SandboxID (version 3 only) additionally restates
	// the source sandbox the operation claimed the output directory for, so
	// the claim-bound witness is self-contained; version-1/2 records never
	// carry it.
	OperationID      string `json:"operation_id,omitempty"`
	RequestDigest    string `json:"request_digest,omitempty"`
	SourceGeneration string `json:"source_generation,omitempty"`
	SandboxID        string `json:"sandbox_id,omitempty"`
	// RootDigest and RootScheme bind the sealed checkpoint content root the
	// operation produced — small metadata derived through the shared
	// pkg/checkpointroot algorithm, never a payload re-hash. Directory is
	// the caller-owned output directory that root was derived from.
	RootDigest string `json:"root_digest,omitempty"`
	RootScheme string `json:"root_scheme,omitempty"`
	Directory  string `json:"directory,omitempty"`
	// DirectoryDev and DirectoryInode are the birth identity of the canonical
	// output directory itself: the containing filesystem's device number and
	// the directory's inode number as Linux reports them through
	// statx/stat — DirectoryDev is stx_dev (the ID of the filesystem holding
	// the directory, never stx_rdev, which only character and block special
	// files carry), DirectoryInode is stx_ino. A same-path directory removed
	// and recreated underneath an operation gets a new inode, so a later
	// reconciliation can refuse a binding whose directory identity drifted
	// even when the path string still matches. They are version-2 fields,
	// kept by version 3: required complete in every version-2-or-later
	// record, absent from every valid version-1 record, and captured from the
	// descriptor the directory claim anchors to.
	DirectoryDev   uint64 `json:"directory_dev,omitempty"`
	DirectoryInode uint64 `json:"directory_inode,omitempty"`
	// VMMPID, VMMStartTime, VMMBootID and VMMAPIPath are the immutable birth
	// identity of the source VMM, captured while it was still alive and
	// BEFORE any stop step, so a later reconciliation stops the exact
	// recorded process and never a PID-reused or next-generation one.
	VMMPID       int    `json:"vmm_pid,omitempty"`
	VMMStartTime uint64 `json:"vmm_start_time,omitempty"`
	VMMBootID    string `json:"vmm_boot_id,omitempty"`
	VMMAPIPath   string `json:"vmm_api_path,omitempty"`
	// Uffd freezes the tracked uffd handler ownership record as it was at
	// prepare time. A reconciliation compares it against the incarnation's
	// current record before any recovery side effect, so an operation whose
	// handler identity was rewritten underneath it is refused rather than
	// completed against a different process's handler. The zero value means
	// no handler was tracked, exactly like the incarnation state's own field.
	Uffd firecrackerUffdRecord `json:"uffd"`
}

func (record firecrackerCheckpointOperationRecord) isZero() bool {
	return record == firecrackerCheckpointOperationRecord{}
}

// retainsEvidence reports whether the record still holds unacknowledged
// operation evidence: a prepared, completed, intent, aborting, or aborted
// witness blocks every new checkpoint and the delete that would clear the
// only runtime evidence of the operation, including legacy calls. Only an
// acked or abort-acked record — and the zero record — may retain nothing,
// and even then only when the record fully validates: a malformed
// acknowledgment (an unknown version, an incomplete binding, a half root or
// directory identity) proves no release, so it keeps the gate like every
// other unreadable witness. Any other phase value, including one a future
// schema adds, keeps the gate for the same reason.
func (record firecrackerCheckpointOperationRecord) retainsEvidence() bool {
	if record.isZero() {
		return false
	}
	switch record.Phase {
	case firecrackerCheckpointOperationPhaseAcked,
		firecrackerCheckpointOperationPhaseAbortAcked:
		return validateFirecrackerCheckpointOperationRecord(record) != nil
	default:
		return true
	}
}

// validateFirecrackerCheckpointOperationRecord accepts only complete,
// self-consistent witnesses; anything partial can prove nothing and is never
// recovered as a claim about an operation or a process. Each schema version
// validates strictly within its own field set — a version-1 record never
// borrows version-2 fields and vice versa — and an unknown version is
// rejected, never reinterpreted.
func validateFirecrackerCheckpointOperationRecord(
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Version {
	case firecrackerCheckpointOperationRecordVersion:
		return validateFirecrackerCheckpointOperationRecordV1(record)
	case firecrackerCheckpointOperationRecordVersion2:
		return validateFirecrackerCheckpointOperationRecordV2(record)
	case firecrackerCheckpointOperationRecordVersion3:
		return validateFirecrackerCheckpointOperationRecordV3(record)
	default:
		return fmt.Errorf(
			"unsupported checkpoint operation record version %d", record.Version,
		)
	}
}

// validateFirecrackerCheckpointOperationRecordV1 enforces the exact
// version-1 sealed-operation shape every existing record and writer uses: a
// prepared/completed/acked phase with a bound sealed root and the complete
// operation and source identity. The later-version phases, directory identity,
// and sandbox identity fields are mixed-schema corruption here — a version-1
// record with any of them is rejected rather than reinterpreted as a richer
// schema.
func validateFirecrackerCheckpointOperationRecordV1(
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked:
	default:
		return fmt.Errorf("invalid checkpoint operation record phase %q", record.Phase)
	}
	if record.DirectoryDev != 0 || record.DirectoryInode != 0 {
		return fmt.Errorf(
			"version %d checkpoint operation record must not carry directory identity (dev=%d inode=%d)",
			firecrackerCheckpointOperationRecordVersion,
			record.DirectoryDev, record.DirectoryInode,
		)
	}
	if record.SandboxID != "" {
		return fmt.Errorf(
			"version %d checkpoint operation record must not carry a sandbox identity (%q)",
			firecrackerCheckpointOperationRecordVersion, record.SandboxID,
		)
	}
	for _, field := range []struct{ name, value string }{
		{"operation id", record.OperationID},
		{"request digest", record.RequestDigest},
		{"source generation", record.SourceGeneration},
		{"root scheme", record.RootScheme},
		{"directory", record.Directory},
		{"vmm api path", record.VMMAPIPath},
	} {
		if field.value == "" {
			return fmt.Errorf(
				"checkpoint operation record carries no %s", field.name,
			)
		}
	}
	if err := validateFirecrackerCheckpointOperationRoot(record); err != nil {
		return err
	}
	return validateFirecrackerCheckpointOperationSourceIdentity(record)
}

// validateFirecrackerCheckpointOperationRecordV2 enforces the version-2
// early-intent schema. Every phase — sealed or unsealed — requires the
// complete common binding (operation ID, request digest, source generation),
// the canonical directory, and the complete source birth identity under the
// same constraints version 1 already imposed, plus the complete directory
// birth identity. The root shape must match the phase exactly: the sealed
// phases keep the version-1 root validation, and the unsealed early-intent
// phases carry no root at all, because a root on an intent or abort record
// would misread ownership or an abort fact as a success witness. The
// version-3 sandbox identity is mixed-schema corruption here.
func validateFirecrackerCheckpointOperationRecordV2(
	record firecrackerCheckpointOperationRecord,
) error {
	if record.SandboxID != "" {
		return fmt.Errorf(
			"version %d checkpoint operation record must not carry a sandbox identity (%q)",
			firecrackerCheckpointOperationRecordVersion2, record.SandboxID,
		)
	}
	return validateFirecrackerCheckpointOperationRecordEarlyIntent(record)
}

// validateFirecrackerCheckpointOperationRecordV3 enforces the version-3
// claim-bound schema: every version-2 constraint plus the source sandbox
// identity the directory claim binds. A version-3 record without it is
// corruption — the claim protocol's whole distinction is that the witness
// restates which sandbox's operation claimed the directory.
func validateFirecrackerCheckpointOperationRecordV3(
	record firecrackerCheckpointOperationRecord,
) error {
	if record.SandboxID == "" {
		return fmt.Errorf(
			"version %d checkpoint operation record carries no sandbox identity",
			firecrackerCheckpointOperationRecordVersion3,
		)
	}
	return validateFirecrackerCheckpointOperationRecordEarlyIntent(record)
}

// validateFirecrackerCheckpointOperationRecordEarlyIntent is the shared
// version-2/3 core: the complete phases, binding, directory identity, root
// shape, and source birth identity, all independent of the sandbox-identity
// field that only version 3 carries.
func validateFirecrackerCheckpointOperationRecordEarlyIntent(
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked,
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked:
	default:
		return fmt.Errorf("invalid checkpoint operation record phase %q", record.Phase)
	}
	for _, field := range []struct{ name, value string }{
		{"operation id", record.OperationID},
		{"request digest", record.RequestDigest},
		{"source generation", record.SourceGeneration},
		{"directory", record.Directory},
		{"vmm api path", record.VMMAPIPath},
	} {
		if field.value == "" {
			return fmt.Errorf(
				"checkpoint operation record carries no %s", field.name,
			)
		}
	}
	if record.DirectoryDev == 0 || record.DirectoryInode == 0 {
		return fmt.Errorf(
			"checkpoint operation record carries no complete directory identity (dev=%d inode=%d)",
			record.DirectoryDev, record.DirectoryInode,
		)
	}
	if firecrackerCheckpointOperationPhaseRequiresSealedRoot(record.Phase) {
		if err := validateFirecrackerCheckpointOperationRoot(record); err != nil {
			return err
		}
	} else if record.RootDigest != "" || record.RootScheme != "" {
		return fmt.Errorf(
			"unsealed checkpoint operation record phase %q must carry no root (digest %q scheme %q)",
			record.Phase, record.RootDigest, record.RootScheme,
		)
	}
	return validateFirecrackerCheckpointOperationSourceIdentity(record)
}

// validateFirecrackerCheckpointOperationRoot enforces the sealed-root shape
// shared by every phase that carries one: a nonempty scheme and a digest that
// is exactly the shared root algorithm's hex length and valid hex.
func validateFirecrackerCheckpointOperationRoot(
	record firecrackerCheckpointOperationRecord,
) error {
	if record.RootScheme == "" {
		return errors.New("checkpoint operation record carries no root scheme")
	}
	if len(record.RootDigest) != checkpointroot.DigestHexLen {
		return fmt.Errorf(
			"checkpoint operation record root digest is not %d hex characters",
			checkpointroot.DigestHexLen,
		)
	}
	if _, err := hex.DecodeString(record.RootDigest); err != nil {
		return errors.New("checkpoint operation record root digest is not hex")
	}
	return nil
}

// validateFirecrackerCheckpointOperationSourceIdentity enforces the immutable
// source birth identity every phase of every schema version must carry
// completely: the VMM's PID and /proc start time, a canonical nonzero boot
// UUID, and — when a uffd handler was tracked — a usable frozen uffd record.
func validateFirecrackerCheckpointOperationSourceIdentity(
	record firecrackerCheckpointOperationRecord,
) error {
	if record.VMMPID <= 1 || record.VMMStartTime == 0 {
		return fmt.Errorf(
			"checkpoint operation record carries no complete vmm identity (pid=%d start_time=%d)",
			record.VMMPID, record.VMMStartTime,
		)
	}
	if parsed, err := uuid.Parse(record.VMMBootID); err != nil ||
		parsed == uuid.Nil || parsed.String() != record.VMMBootID {
		return errors.New(
			"checkpoint operation record boot id must be a canonical nonzero UUID",
		)
	}
	if !record.Uffd.isZero() {
		if err := validateFirecrackerUffdRecord(record.Uffd); err != nil {
			return fmt.Errorf(
				"checkpoint operation record carries an unusable uffd identity: %w", err,
			)
		}
	}
	return nil
}

// refuseCheckpointOperationEvidence rejects any checkpoint — legacy, conditional,
// or identified — against an instance whose state still retains unacknowledged
// operation evidence. The source of a prepared or completed operation is being
// (or has been) stopped for that operation; a new snapshot could neither
// resume it nor replace the retained evidence, and redoing the operation as a
// Full snapshot is not a way around the block. Callers run this under the
// instance operation lock before any checkpoint side effect.
func refuseCheckpointOperationEvidence(
	sandboxID string,
	state firecrackerPersistedState,
) error {
	record := state.CheckpointOperation
	if !record.retainsEvidence() {
		return nil
	}
	rootDigest := record.RootDigest
	if rootDigest == "" {
		// The unsealed early-intent phases carry no root by schema; report
		// that instead of an empty binding.
		rootDigest = "none"
	}
	return fmt.Errorf(
		"Firecracker sandbox %s retains %s checkpoint operation %s evidence (root %s); new checkpoints are blocked until the operation is recovered or acknowledged: %w",
		sandboxID, record.Phase, record.OperationID, rootDigest,
		errord.ErrFailedPrecondition,
	)
}

// verifyCheckpointOperationRequest validates the operation binding of an
// identified checkpoint against the runtime's own persisted identity before
// any checkpoint side effect. The binding must be complete and its source
// generation must match exactly — an identified operation is admitted against
// one physical incarnation, and the runtime never takes the management
// plane's word for which one.
func verifyCheckpointOperationRequest(
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
	state firecrackerPersistedState,
) error {
	if binding.OperationID == "" || binding.RequestDigest == "" ||
		binding.SourceGeneration == "" {
		return fmt.Errorf(
			"identified checkpoint for Firecracker sandbox %s carries an incomplete operation binding: %w",
			sandboxID, errord.ErrInvalidArgument,
		)
	}
	return verifyCheckpointExpectedGeneration(
		sandboxID, binding.SourceGeneration, state.Generation,
	)
}

// matchCheckpointOperationWitness resolves the durable witness for a recovery
// or acknowledgment request. A missing record is NotFound and proves nothing;
// a corrupted record, an incomplete request binding, or any field that does
// not exactly match the recorded binding or the runtime's own incarnation
// identity is refused without side effects.
func matchCheckpointOperationWitness(
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
	state firecrackerPersistedState,
) (firecrackerCheckpointOperationRecord, error) {
	record := state.CheckpointOperation
	if record.isZero() {
		return record, fmt.Errorf(
			"Firecracker sandbox %s retains no checkpoint operation witness: %w",
			sandboxID, errord.ErrNotFound,
		)
	}
	if err := validateFirecrackerCheckpointOperationRecord(record); err != nil {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness is unusable: %w",
			sandboxID, err,
		)
	}
	if binding.OperationID == "" || binding.RequestDigest == "" ||
		binding.SourceGeneration == "" {
		return record, fmt.Errorf(
			"checkpoint operation recovery for Firecracker sandbox %s carries an incomplete binding: %w",
			sandboxID, errord.ErrInvalidArgument,
		)
	}
	if record.OperationID != binding.OperationID ||
		record.RequestDigest != binding.RequestDigest {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness binds operation %s (request %s), not operation %s (request %s): %w",
			sandboxID, record.OperationID, record.RequestDigest,
			binding.OperationID, binding.RequestDigest,
			errord.ErrFailedPrecondition,
		)
	}
	if record.SandboxID != "" && record.SandboxID != state.ID {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness binds sandbox %s, not this incarnation: %w",
			sandboxID, record.SandboxID, errord.ErrFailedPrecondition,
		)
	}
	if record.SourceGeneration != state.Generation {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness binds source generation %q but the runtime state carries %q: %w",
			sandboxID, record.SourceGeneration, state.Generation,
			errord.ErrFailedPrecondition,
		)
	}
	if record.VMMPID != state.PID {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness records source pid %d but the incarnation state records %d: %w",
			sandboxID, record.VMMPID, state.PID,
			errord.ErrFailedPrecondition,
		)
	}
	if filepath.Clean(record.VMMAPIPath) != filepath.Clean(state.APIPath) {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness records API path %q but the incarnation state carries %q: %w",
			sandboxID, record.VMMAPIPath, state.APIPath,
			errord.ErrFailedPrecondition,
		)
	}
	if record.Uffd != state.Uffd {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness froze a uffd handler identity that differs from the incarnation state's current record: %w",
			sandboxID, errord.ErrFailedPrecondition,
		)
	}
	if binding.SourceGeneration != record.SourceGeneration {
		return record, fmt.Errorf(
			"Firecracker sandbox %s checkpoint operation witness binds source generation %q, not the requested %q: %w",
			sandboxID, record.SourceGeneration, binding.SourceGeneration,
			errord.ErrFailedPrecondition,
		)
	}
	return record, nil
}

// firecrackerVMMBirthIdentity is the immutable kernel identity of a source
// VMM: PID plus /proc starttime (which survives execve and disambiguates PID
// reuse), the host boot id, and the incarnation's API socket path.
type firecrackerVMMBirthIdentity struct {
	pid       int
	startTime uint64
	bootID    string
}

// captureFirecrackerVMMBirthIdentity records the birth identity of the live
// source VMM. It must run BEFORE any stop step of the operation: once the
// process is gone the identity can no longer be captured, and a reconciliation
// after a daemon crash must be able to prove it stops the exact recorded
// process rather than a PID-reused or next-generation one.
func captureFirecrackerVMMBirthIdentity(
	state firecrackerPersistedState,
) (firecrackerVMMBirthIdentity, error) {
	if state.PID <= 1 {
		return firecrackerVMMBirthIdentity{}, fmt.Errorf(
			"recorded Firecracker pid %d is not a valid source identity", state.PID,
		)
	}
	startTime, err := readFirecrackerProcessStartTime(state.PID)
	if err != nil {
		return firecrackerVMMBirthIdentity{}, fmt.Errorf(
			"read Firecracker source %d start time: %w", state.PID, err,
		)
	}
	bootID, err := readFirecrackerBootID()
	if err != nil {
		return firecrackerVMMBirthIdentity{}, fmt.Errorf("read boot id: %w", err)
	}
	return firecrackerVMMBirthIdentity{
		pid:       state.PID,
		startTime: startTime,
		bootID:    bootID,
	}, nil
}

// buildFirecrackerCheckpointOperationIntent assembles the durable early intent
// of an identified operation from the exact admission binding, the runtime's
// own incarnation state, and the source birth identity captured while the
// source is still alive and unpaused. The intent carries no root by schema: it
// proves operation ownership, never a sealed artifact. It is a version-3
// claim-bound record: the caller has already established the persistent
// directory claim this witness's reconciliation will verify.
func buildFirecrackerCheckpointOperationIntent(
	binding runtimecore.CheckpointOperationBinding,
	state firecrackerPersistedState,
	identity firecrackerVMMBirthIdentity,
	directory string,
	directoryDev, directoryInode uint64,
) firecrackerCheckpointOperationRecord {
	return firecrackerCheckpointOperationRecord{
		Version:          firecrackerCheckpointOperationRecordVersion3,
		Phase:            firecrackerCheckpointOperationPhaseIntent,
		OperationID:      binding.OperationID,
		RequestDigest:    binding.RequestDigest,
		SourceGeneration: state.Generation,
		SandboxID:        state.ID,
		Directory:        directory,
		DirectoryDev:     directoryDev,
		DirectoryInode:   directoryInode,
		VMMPID:           identity.pid,
		VMMStartTime:     identity.startTime,
		VMMBootID:        identity.bootID,
		VMMAPIPath:       state.APIPath,
		Uffd:             state.Uffd,
	}
}

// verifyCheckpointOperationDirectoryIdentity proves the recorded canonical
// directory is still the exact directory the intent reserved, through its
// birth identity rather than the path string alone: a same-path replacement
// gets a new inode and is refused.
func verifyCheckpointOperationDirectoryIdentity(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	info, err := os.Lstat(record.Directory)
	if err != nil {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s that can no longer be inspected: %w; refusing to reconcile: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s that is now a symbolic link; a link is never reconciled through its target: %w",
			record.OperationID, sandboxID, record.Directory, errord.ErrFailedPrecondition,
		)
	}
	if !info.IsDir() {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s that is no longer a directory: %w",
			record.OperationID, sandboxID, record.Directory, errord.ErrFailedPrecondition,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	var gotDev, gotInode uint64
	if ok {
		gotDev, gotInode = uint64(stat.Dev), stat.Ino
	}
	if !ok || gotDev != record.DirectoryDev || gotInode != record.DirectoryInode {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory identity (dev=%d inode=%d) but %s now carries (dev=%d inode=%d); a replaced output directory is never reconciled: %w",
			record.OperationID, sandboxID, record.DirectoryDev, record.DirectoryInode,
			record.Directory, gotDev, gotInode, errord.ErrFailedPrecondition,
		)
	}
	return nil
}

// verifyCheckpointOperationDirectoryOwnership proves the recorded directory is
// still the exact directory the operation claimed: the birth identity (every
// schema from version 2 on carries one), and — for a version-3 claim-bound
// record — the persistent exclusive claim binding the same sandbox,
// operation, request digest, source generation, canonical directory, and
// directory birth identity. Every hot and cold recovery and abort path that
// needs the directory identity runs this check before any side effect.
// Version-1 records carry no directory identity and predate the claim
// protocol: neither is required or consulted for them, so their recovery,
// abort, and acknowledgment paths keep their original semantics.
func verifyCheckpointOperationDirectoryOwnership(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	if record.Version >= firecrackerCheckpointOperationRecordVersion2 {
		if err := verifyCheckpointOperationDirectoryIdentity(sandboxID, record); err != nil {
			return err
		}
	}
	return verifyFirecrackerCheckpointDirectoryClaim(sandboxID, record)
}

// verifyCheckpointOperationIntentSeal proves the recorded directory of a
// durable intent now holds the complete sealed artifact of THE SAME
// operation: the exact directory identity, a fully openable seal, and a
// manifest operation binding equal to the intent's own binding — a shared root
// whose manifest bytes were overwritten, or a legacy manifest with no binding,
// proves nothing. It returns the content root the promotion records, derived
// through the shared root algorithm from the manifest view it just opened
// (metadata-only, never a payload re-hash).
func verifyCheckpointOperationIntentSeal(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) (*checkpointroot.Binding, error) {
	if err := verifyCheckpointOperationDirectoryOwnership(sandboxID, record); err != nil {
		return nil, err
	}
	artifact, err := openFirecrackerCheckpoint(record.Directory)
	if err != nil {
		return nil, fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s whose seal is not a complete verifiable artifact: %w; an intent is promoted only from its own operation's complete seal: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
	if artifact.Layout != firecrackerCheckpointLayoutV2Directory || artifact.Manifest == nil {
		return nil, fmt.Errorf("checkpoint operation %s of Firecracker sandbox %s requires a v2 directory seal, not a legacy archive: %w", record.OperationID, sandboxID, errord.ErrFailedPrecondition)
	}
	if artifact.Manifest.Operation == nil {
		return nil, fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s found a sealed manifest in %s carrying no operation binding; a legacy or foreign seal never proves this intent sealed: %w",
			record.OperationID, sandboxID, record.Directory, errord.ErrFailedPrecondition,
		)
	}
	if artifact.Manifest.Operation.OperationID != record.OperationID ||
		artifact.Manifest.Operation.RequestDigest != record.RequestDigest ||
		artifact.Manifest.Operation.SourceGeneration != record.SourceGeneration {
		return nil, fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s found a sealed manifest in %s binding operation %s (request %s, generation %s), not the intent's own operation: %w",
			record.OperationID, sandboxID, record.Directory,
			artifact.Manifest.Operation.OperationID,
			artifact.Manifest.Operation.RequestDigest,
			artifact.Manifest.Operation.SourceGeneration,
			errord.ErrFailedPrecondition,
		)
	}
	root, err := checkpointroot.RootFromView(record.Directory, artifact.ManifestRaw)
	if err != nil {
		return nil, fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s whose content root is no longer verifiable: %w; refusing to promote the intent: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
	return root, nil
}

// refuseAbortCheckpointOperationSealedIntent enforces the new-abort decision
// boundary: a durable intent whose recorded directory holds the verifiable
// complete seal of the SAME operation must be recovered, not aborted — the
// artifact is exactly the success the operation owes. A directory holding a
// sealed manifest that cannot be attributed to the intent fails closed: the
// abort never destroys or ignores evidence it cannot classify. Only a
// directory with no sealed manifest (an unsealed or partially laid-out
// reservation) may proceed to the abort.
func refuseAbortCheckpointOperationSealedIntent(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	if _, err := os.Lstat(filepath.Join(
		record.Directory, firecrackerCheckpointManifestName,
	)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf(
			"inspect Firecracker checkpoint output %s of operation %s: %w; refusing to abort fail-closed: %w",
			record.Directory, record.OperationID, err, errord.ErrFailedPrecondition,
		)
	}
	if _, err := verifyCheckpointOperationIntentSeal(sandboxID, record); err == nil {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s already holds its own complete sealed artifact in %s; recover the operation instead of aborting it: %w",
			record.OperationID, sandboxID, record.Directory, errord.ErrFailedPrecondition,
		)
	} else {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s holding a sealed manifest that is not this operation's verifiable seal: %w; refusing to abort fail-closed: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
}

// finishIdentifiedCheckpointOperation runs the post-seal tail of an identified
// stop-and-copy checkpoint: bind the sealed root and promote the durable
// intent into the prepared witness of the SAME record — the birth and
// directory identity captured before any side effect are the operation's
// identity, and nothing is recaptured or replaced after the seal. From the
// caller's seal onward the source may never be resumed again; a failure in
// this tail — including an ambiguous prepared-write result — keeps the source
// paused and the sealed artifact in place, because a returned error does not
// prove the witness write did not land.
func (handler *Handler) finishIdentifiedCheckpointOperation(
	instance *firecrackerInstance,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
	files firecrackerCheckpointFiles,
) error {
	state := instance.snapshot()
	record := state.CheckpointOperation
	if record.Phase != firecrackerCheckpointOperationPhaseIntent ||
		record.OperationID != binding.OperationID ||
		record.RequestDigest != binding.RequestDigest ||
		record.SourceGeneration != state.Generation {
		return fmt.Errorf(
			"Firecracker sandbox %s carries no durable intent of operation %s to promote after the seal; refusing to fabricate a prepared witness: %w",
			sandboxID, binding.OperationID, errord.ErrFailedPrecondition,
		)
	}
	// Bind the sealed content root through the shared root algorithm: small
	// metadata reads over the manifest and sidecars the seal just wrote,
	// never a payload re-hash or fsync. Publication durability stays with the
	// publish gates.
	root, err := checkpointroot.Bind(record.Directory)
	if err != nil {
		return fmt.Errorf(
			"bind Firecracker checkpoint root for operation %s of sandbox %s: %w; the source stays paused and the sealed artifact is retained",
			binding.OperationID, sandboxID, err,
		)
	}
	prepared := record
	prepared.Phase = firecrackerCheckpointOperationPhasePrepared
	prepared.RootDigest = root.RootDigest
	prepared.RootScheme = root.Scheme
	// The in-memory record is set before the write so the constraint binds
	// this daemon even when the write's result is ambiguous.
	instance.setCheckpointOperation(prepared)
	if err := handler.persistInstance(instance); err != nil {
		return fmt.Errorf(
			"persist prepared checkpoint operation witness for operation %s of Firecracker sandbox %s: %w; the write may have committed, the source stays paused, the sealed artifact is retained, and the operation must be recovered or retired explicitly",
			binding.OperationID, sandboxID, err,
		)
	}
	// The artifact is sealed and its retention is now guaranteed by the
	// witness: queue the memory writeback best effort, completion outcome
	// notwithstanding.
	defer handler.scheduleCheckpointMemoryWriteback(files.Memory)
	return handler.completeIdentifiedCheckpointOperation(instance, prepared)
}

// completeIdentifiedCheckpointOperation finishes the original operation's
// stop-source flow: stop the exact process the prepared witness recorded,
// confirm the tracked uffd handler left, then make the completion fact
// durable. Nothing else may happen here — no artifact allocation, no
// snapshot, no resume. Every failure retains the witness and the sealed
// artifact so the same operation can retry through recovery.
func (handler *Handler) completeIdentifiedCheckpointOperation(
	instance *firecrackerInstance,
	record firecrackerCheckpointOperationRecord,
) error {
	state := instance.snapshot()
	if err := stopFirecrackerProcessConfirmedBirth(
		state, handler.binary, record.VMMPID, record.VMMStartTime,
	); err != nil {
		return fmt.Errorf(
			"stop Firecracker sandbox %s for checkpoint operation %s: %w; the prepared witness and sealed artifact are retained and the operation can be recovered",
			state.ID, record.OperationID, err,
		)
	}
	if err := confirmFirecrackerUffdExit(state.Uffd); err != nil {
		return fmt.Errorf(
			"confirm uffd handler exit for Firecracker sandbox %s after checkpoint operation %s: %w; the prepared witness and sealed artifact are retained and the operation can be recovered",
			state.ID, record.OperationID, err,
		)
	}
	if err := handler.publishCheckpointOperationCompletion(instance, record); err != nil {
		return fmt.Errorf(
			"persist completed checkpoint operation witness for operation %s of Firecracker sandbox %s: %w; the stop is confirmed and the evidence is retained, and the operation must be recovered before its success is reported",
			record.OperationID, state.ID, err,
		)
	}
	return nil
}

// publishCheckpointOperationCompletion makes the completed fact durable under
// persistMu and publishes it only afterwards. The next record and the
// terminal exit state are constructed from a snapshot taken under the same
// lock that every other state writer serializes on, written through the
// atomic rename and directory fsync, and only a durable write updates the
// instance — so a failed or ambiguous write leaves the previous prepared
// record in memory. A post-rename sync failure may already have changed
// the disk record; callers still require a successful durable retry. Neither
// a caller nor a concurrent
// persistInstance can observe or carry an unpersisted completion, and a
// recovery retried after the storage is repaired re-persists rather than
// replaying success from memory. There is deliberately no shouldPersist
// shortcut here: the completion is a releasing fact and may be claimed only
// from durable state.
func (handler *Handler) publishCheckpointOperationCompletion(
	instance *firecrackerInstance,
	record firecrackerCheckpointOperationRecord,
) error {
	instance.persistMu.Lock()
	defer instance.persistMu.Unlock()
	state := instance.snapshot()
	if state.CheckpointOperation != record {
		return fmt.Errorf(
			"checkpoint operation witness for Firecracker sandbox %s changed under the completion (records %s, not the matched %s): %w",
			state.ID, state.CheckpointOperation.OperationID, record.OperationID,
			errord.ErrFailedPrecondition,
		)
	}
	completed := record
	completed.Phase = firecrackerCheckpointOperationPhaseCompleted
	persisted := state
	persisted.CheckpointOperation = completed
	exit := runtimecore.Exit{ExitCode: 0, ExitedAt: time.Now()}
	if !persisted.Exited {
		persisted.Exited = true
		persisted.ExitedAt = exit.ExitedAt.Format(time.RFC3339Nano)
		persisted.ExitCode = 0
	} else if parsed, err := time.Parse(time.RFC3339Nano, persisted.ExitedAt); err == nil {
		exit = runtimecore.Exit{ExitCode: persisted.ExitCode, ExitedAt: parsed}
	}
	if err := writeFirecrackerState(persisted); err != nil {
		return err
	}
	// Durable: publish the record and the terminal exit together, then the
	// done notification. An already-finished instance keeps its own exit.
	instance.setCheckpointOperation(completed)
	instance.finish(exit)
	return nil
}

// readValidatedColdState reads and validates the durable incarnation record of
// a sandbox without mapping or recovering it, for callers that must verify a
// binding before any recovery side effect runs.
func (handler *Handler) readValidatedColdState(
	sandboxID string,
) (firecrackerPersistedState, error) {
	bundlePath, err := util.JoinWithinRoot(handler.sandboxRoot, sandboxID)
	if err != nil {
		return firecrackerPersistedState{}, err
	}
	state, err := readFirecrackerState(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return firecrackerPersistedState{}, fmt.Errorf(
				"Firecracker sandbox %s has no runtime state: %w",
				sandboxID, errord.ErrNotFound,
			)
		}
		return firecrackerPersistedState{}, err
	}
	if err := handler.validatePersistedState(sandboxID, bundlePath, state); err != nil {
		return firecrackerPersistedState{}, err
	}
	return state, nil
}

// verifyCheckpointOperationColdState performs the binding and scope checks a
// recovery or acknowledgment must pass while the sandbox is still absent from
// the in-memory map, so a refusal observes the durable record without
// triggering recoverState's side effects (lineage reset persistence, recovery
// monitors, recorded-process stops). It deliberately verifies no artifact
// root: the acknowledgment releases retention for a service that already
// recorded SUCCEEDED, and a caller-owned artifact directory legitimately
// removed after that must not wedge the retirement; the recovery adds its own
// root proof on top (see RecoverCheckpointOperation).
func (handler *Handler) verifyCheckpointOperationColdState(
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) (firecrackerCheckpointOperationRecord, error) {
	state, err := handler.readValidatedColdState(sandboxID)
	if err != nil {
		return firecrackerCheckpointOperationRecord{}, err
	}
	record, err := matchCheckpointOperationWitness(sandboxID, binding, state)
	if err != nil {
		return firecrackerCheckpointOperationRecord{}, err
	}
	if err := verifyCheckpointOperationWitnessScope(sandboxID, record); err != nil {
		return firecrackerCheckpointOperationRecord{}, err
	}
	return record, nil
}

// verifyCheckpointOperationWitnessRoot proves the recorded artifact root still
// describes the recorded directory, through the same shared root algorithm the
// seal and the service admission use — small metadata reads over the manifest
// and sidecars, never a payload re-hash. A directory whose root drifted or can
// no longer be verified fails the reconciliation closed: the recovery must not
// complete an operation whose sealed evidence no longer matches what was
// prepared, and the failure touches nothing.
func verifyCheckpointOperationWitnessRoot(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	root, err := checkpointroot.Bind(record.Directory)
	if err != nil {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s whose content root is no longer verifiable: %w; refusing to reconcile: %w",
			record.OperationID, sandboxID, record.Directory, err,
			errord.ErrFailedPrecondition,
		)
	}
	if root.RootDigest != record.RootDigest || root.Scheme != record.RootScheme {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records root %s (%s) but directory %s now binds %s (%s): %w",
			record.OperationID, sandboxID, record.RootDigest, record.RootScheme,
			record.Directory, root.RootDigest, root.Scheme,
			errord.ErrFailedPrecondition,
		)
	}
	return nil
}

// verifyCheckpointOperationRecoveryRoot is the sealed-record recovery's
// directory proof: the artifact root must still bind the recorded directory,
// and the directory itself must still be the one the operation owns — the
// birth identity plus, for a version-3 claim-bound record, the exact
// persistent claim. Version-1/2 records keep their root-only contract.
func verifyCheckpointOperationRecoveryRoot(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	if err := verifyCheckpointOperationWitnessRoot(sandboxID, record); err != nil {
		return err
	}
	return verifyCheckpointOperationDirectoryOwnership(sandboxID, record)
}

// verifyCheckpointOperationWitnessScope enforces the daemon-crash scope of the
// reconciliation path: the record's host boot must still be the current one,
// and the recorded API binding must still belong to this incarnation's state.
// A host reboot invalidates every recorded process identity and the metadata
// itself may have been lost mid-write, so the recovery refuses fail-closed
// instead of reconciling from metadata whose durability a power loss may have
// compromised; artifact damage after a host power loss is the publication
// gates' problem to refuse, never this record's to mask.
func verifyCheckpointOperationWitnessScope(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	bootID, err := readFirecrackerBootID()
	if err != nil {
		return fmt.Errorf(
			"read boot id to reconcile checkpoint operation %s of Firecracker sandbox %s: %w",
			record.OperationID, sandboxID, err,
		)
	}
	if record.VMMBootID != bootID {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s was prepared under boot %s, not the current %s; this daemon-crash recovery path refuses to reconcile across a host reboot: %w",
			record.OperationID, sandboxID, record.VMMBootID, bootID,
			errord.ErrFailedPrecondition,
		)
	}
	return nil
}

// refuseUnrecoverableAbortPhase keeps the success-recovery path away from the
// abort protocol's phases. A record being aborted, durably aborted, or
// abort-acked proves no sealed artifact and no success: it is retired only
// through AbortCheckpointOperation and its own abort acknowledgment, never
// guessed into a completion. The durable intent phase is the one early-intent
// phase this recovery reconciles — by promoting a verified same-operation
// seal, never by taking a new snapshot.
func refuseUnrecoverableAbortPhase(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked:
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is %s, a phase of the explicit abort protocol; this recovery reconciles sealed operations and a never-sealed intent only, and an aborted operation is retired through AbortCheckpointOperation and its own acknowledgment: %w",
			record.OperationID, sandboxID, record.Phase, errord.ErrFailedPrecondition,
		)
	}
	return nil
}

// RecoverCheckpointOperation reconciles one existing identified checkpoint
// operation. It is the runtime capability method (see
// runtimecore.CheckpointOperationWitness) used by the public service recovery
// RPC after durable service-side admission.
//
// The binding is verified against the durable record before any recovery side
// effect (cold path) and again under the instance operation lock; the request
// must match the recorded operation ID, request digest, and source
// generation exactly, the record's source generation must still equal the
// runtime's own persisted incarnation identity, and the recorded artifact
// root must still bind the recorded directory. Within the lock the recovery
// only completes the original stop-source flow: a prepared witness is first
// made durable again — the in-memory record alone does not prove the original
// write landed — and then it never allocates artifacts, takes a snapshot,
// resumes the source, or modifies the artifact root. A durable intent whose
// recorded directory holds the complete same-operation seal is promoted to
// that prepared witness in place — same binding, birth identity, and
// directory identity — and follows the same stop-source tail; an intent
// without its own verifiable seal is refused, never re-snapshotted. A
// durable completion is returned as the original binding's recorded result
// with zero further work. The returned completion is a fact about the sealed
// root and the confirmed stop, not a payload-durability claim.
func (handler *Handler) RecoverCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) (runtimecore.CheckpointOperationCompletion, error) {
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		record, err := handler.verifyCheckpointOperationColdState(sandboxID, binding)
		if err != nil {
			return runtimecore.CheckpointOperationCompletion{}, err
		}
		// The already-acknowledged refusal also holds before any cold
		// recovery side effect: a released operation must not run recovery
		// only to be refused under the lock.
		if record.Phase == firecrackerCheckpointOperationPhaseAcked {
			return runtimecore.CheckpointOperationCompletion{}, ackedRefusal(sandboxID, record)
		}
		if err := refuseUnrecoverableAbortPhase(sandboxID, record); err != nil {
			return runtimecore.CheckpointOperationCompletion{}, err
		}
		if record.Phase == firecrackerCheckpointOperationPhaseIntent {
			if _, err := verifyCheckpointOperationIntentSeal(sandboxID, record); err != nil {
				return runtimecore.CheckpointOperationCompletion{}, err
			}
		} else if err := verifyCheckpointOperationRecoveryRoot(sandboxID, record); err != nil {
			return runtimecore.CheckpointOperationCompletion{}, err
		}
	}
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	record, err := matchCheckpointOperationWitness(sandboxID, binding, state)
	if err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if err := refuseUnrecoverableAbortPhase(sandboxID, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if record.Phase == firecrackerCheckpointOperationPhaseIntent {
		// The seal proof is the intent's only recoverable evidence: check it
		// before the boot scope so the refusal names the missing seal.
		if _, err := verifyCheckpointOperationIntentSeal(sandboxID, record); err != nil {
			return runtimecore.CheckpointOperationCompletion{}, err
		}
	} else if err := verifyCheckpointOperationRecoveryRoot(sandboxID, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if err := verifyCheckpointOperationWitnessScope(sandboxID, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if record.Phase == firecrackerCheckpointOperationPhaseAcked {
		return runtimecore.CheckpointOperationCompletion{}, ackedRefusal(sandboxID, record)
	}
	if record.Phase == firecrackerCheckpointOperationPhaseCompleted {
		// The durable completion already carries the original binding's
		// result; return it without further writes or process interaction.
		return runtimecore.CheckpointOperationCompletion{
			RootDigest: record.RootDigest,
			RootScheme: record.RootScheme,
		}, nil
	}
	if record.Phase == firecrackerCheckpointOperationPhaseIntent {
		// A daemon crash after the seal but before the promotion left the
		// durable intent plus the sealed artifact: promote the SAME record —
		// the binding, birth identity, and directory identity captured before
		// any side effect — never a recaptured or replaced identity, and
		// never a new snapshot or resume. The promotion write is the durable
		// prepared boundary: it must land before any stop-source work, and a
		// failure keeps the intent, the source, and the sealed artifact
		// exactly as they were.
		root, sealErr := verifyCheckpointOperationIntentSeal(sandboxID, record)
		if sealErr != nil {
			return runtimecore.CheckpointOperationCompletion{}, sealErr
		}
		prepared := record
		prepared.Phase = firecrackerCheckpointOperationPhasePrepared
		prepared.RootDigest = root.RootDigest
		prepared.RootScheme = root.Scheme
		instance.setCheckpointOperation(prepared)
		if err := handler.persistInstance(instance); err != nil {
			return runtimecore.CheckpointOperationCompletion{}, fmt.Errorf(
				"persist prepared checkpoint operation witness promoted from the intent of operation %s of Firecracker sandbox %s: %w; the write may have committed, no stop was attempted, the source and the sealed artifact are retained, and the recovery must be retried once the state storage is writable",
				record.OperationID, sandboxID, err,
			)
		}
		return handler.completeIntentPromotion(instance, prepared)
	}
	// The prepared witness held in daemon memory is not proof of its own
	// durability: the original write may have failed with an unknown result,
	// leaving only the in-memory record that binds this daemon fail-closed.
	// Re-establish the durable prepared boundary before any stop-source or
	// uffd exit processing. persistInstance serializes on the same persistMu
	// as every other state writer and writes through the atomic rename and
	// directory fsync with no unchanged-state shortcut, so a nil result here
	// has re-proven the matching prepared state on disk. A failure stops
	// nothing: the source, the in-memory record, and the sealed artifact are
	// retained exactly as they were, and the recovery can be retried once
	// the state storage is writable.
	if err := handler.persistInstance(instance); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, fmt.Errorf(
			"persist prepared checkpoint operation witness before recovering operation %s of Firecracker sandbox %s: %w; no stop was attempted, the source and the sealed artifact are retained, and the recovery must be retried once the state storage is writable",
			record.OperationID, sandboxID, err,
		)
	}
	if err := handler.completeIdentifiedCheckpointOperation(instance, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	return runtimecore.CheckpointOperationCompletion{
		RootDigest: record.RootDigest,
		RootScheme: record.RootScheme,
	}, nil
}

// ackedRefusal is the shared already-acknowledged refusal of the recovery
// path.
func ackedRefusal(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	return fmt.Errorf(
		"checkpoint operation %s of Firecracker sandbox %s is already acknowledged; its evidence retention is released and recovery is not this path's to redo: %w",
		record.OperationID, sandboxID, errord.ErrFailedPrecondition,
	)
}

// completeIntentPromotion finishes a promoted prepared witness through the
// ordinary stop-source tail and answers with the root the promotion recorded.
func (handler *Handler) completeIntentPromotion(
	instance *firecrackerInstance,
	prepared firecrackerCheckpointOperationRecord,
) (runtimecore.CheckpointOperationCompletion, error) {
	if err := handler.completeIdentifiedCheckpointOperation(instance, prepared); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	return runtimecore.CheckpointOperationCompletion{
		RootDigest: prepared.RootDigest,
		RootScheme: prepared.RootScheme,
	}, nil
}

// refuseUnacknowledgablePhase enforces the success acknowledgment's phase
// policy: only a durable completion may be acknowledged. A prepared witness
// still owes the source's stop — its evidence constraint is not the service's
// to release, and no internal caller may turn an unfinished operation into an
// acked one. The version-2 early-intent phases are refused here too: this is
// the SUCCESS acknowledgment, and an intent that never sealed, an abort in
// flight, an aborted fact, or an abort already acknowledged is never released
// through it — the explicit abort acknowledgment that retires those records
// is a later protocol step. An already-acknowledged record stays idempotently
// acknowledgeable so a lost reply can be retried after a durable success
// receipt.
func refuseUnacknowledgablePhase(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked:
		return nil
	default:
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is %s, not completed; recover the operation's stop before acknowledging it, and retire an aborted operation only through its own explicit abort acknowledgment, which this success acknowledgment never is: %w",
			record.OperationID, sandboxID, record.Phase,
			errord.ErrFailedPrecondition,
		)
	}
}

// AckCheckpointOperation releases the evidence-retention gate of the matching
// operation. The service calls it only after its SUCCEEDED receipt is durable;
// the acknowledgment never resumes or revives the source — it only permits
// the delete that would otherwise clear the operation's only runtime
// evidence. Only a completed (or already-acknowledged, idempotently)
// operation is acknowledgeable. The release becomes claimable exclusively
// from a durable write: the acked record is persisted before it is published,
// so a failed or ambiguous write leaves the evidence gate in force in memory
// as well, exactly as the error reports. After the evidence was released and
// the sandbox state retired, a further acknowledgment observes absence
// (NotFound) — the service's durable receipt is the authority by then.
func (handler *Handler) AckCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) error {
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		record, err := handler.verifyCheckpointOperationColdState(sandboxID, binding)
		if err != nil {
			return err
		}
		// The phase policy also holds before any cold recovery side effect:
		// an unfinished operation must not run recovery only to be refused.
		if err := refuseUnacknowledgablePhase(sandboxID, record); err != nil {
			return err
		}
	}
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	record, err := matchCheckpointOperationWitness(sandboxID, binding, state)
	if err != nil {
		return err
	}
	if err := refuseUnacknowledgablePhase(sandboxID, record); err != nil {
		return err
	}
	if err := handler.publishCheckpointOperationAcknowledgment(instance); err != nil {
		return fmt.Errorf(
			"persist acknowledgment of checkpoint operation %s for Firecracker sandbox %s: %w; the evidence-retaining Delete gate stays in force until the acknowledgment is durable",
			record.OperationID, sandboxID, err,
		)
	}
	return nil
}

// publishCheckpointOperationAcknowledgment makes the acked fact durable under
// persistMu and publishes it only afterwards — the same construct, write,
// fsync, then publish ordering as the completion, so an unpersisted release
// is never visible to callers or carried to disk by a concurrent state
// writer. The idempotent retry persists again deliberately: a first
// acknowledgment whose write failed left the durable record completed, and
// the release of the Delete gate must not rest on daemon memory.
func (handler *Handler) publishCheckpointOperationAcknowledgment(
	instance *firecrackerInstance,
) error {
	instance.persistMu.Lock()
	defer instance.persistMu.Unlock()
	state := instance.snapshot()
	if err := refuseUnacknowledgablePhase(state.ID, state.CheckpointOperation); err != nil {
		return err
	}
	acknowledged := state.CheckpointOperation
	acknowledged.Phase = firecrackerCheckpointOperationPhaseAcked
	persisted := state
	persisted.CheckpointOperation = acknowledged
	if err := writeFirecrackerState(persisted); err != nil {
		return err
	}
	instance.setCheckpointOperation(acknowledged)
	return nil
}

// refuseAbortablePhase enforces which witness phases an explicit abort may
// act on. Only a never-sealed intent may be newly aborted, an abort already
// in flight is retried, and a durable abort fact is idempotently confirmed.
// Everything else — a sealed prepared or completed witness, a
// success-acknowledged record, and a released abort-acked record — is
// refused: those operations owe (or owed) their outcome through the recovery
// protocol instead.
func refuseAbortablePhase(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted:
		return nil
	case firecrackerCheckpointOperationPhaseAbortAcked:
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is already abort-acknowledged; its evidence retention is released and the abort is not this path's to redo: %w",
			record.OperationID, sandboxID, errord.ErrFailedPrecondition,
		)
	default:
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is %s; a sealed or success-acknowledged operation cannot be aborted — recover or acknowledge it instead: %w",
			record.OperationID, sandboxID, record.Phase, errord.ErrFailedPrecondition,
		)
	}
}

// verifyCheckpointOperationAbortScope proves, before any abort decision,
// resume, or lookup side effect, that the record still describes THIS
// runtime's incarnation and canonical output directory — the binding match
// alone proves none of it. The recorded host boot must still be current, the
// recorded source process must still be the executable this handler owns
// under its recorded API socket, and the version-2 directory identity — plus,
// for a version-3 claim-bound record, the exact directory claim — must still
// describe the recorded directory; the no-seal case checks the directory
// ownership exactly like the sealed one. Both the hot and the cold
// abort path run it, so an in-memory witness whose recorded identity drifted
// (a foreign boot id, a replaced source, a recreated output directory, a
// deleted or rewritten claim) is refused without touching the source.
func (handler *Handler) verifyCheckpointOperationAbortScope(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	if err := verifyCheckpointOperationWitnessScope(sandboxID, record); err != nil {
		return err
	}
	if !firecrackerProcessMatches(
		record.VMMPID, handler.binary, record.VMMAPIPath, sandboxID,
	) {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records source pid %d that is not the Firecracker executable this handler owns at %s; the abort cannot prove it resumes the recorded source and the evidence is retained: %w",
			record.OperationID, sandboxID, record.VMMPID, record.VMMAPIPath,
			errord.ErrFailedPrecondition,
		)
	}
	return verifyCheckpointOperationDirectoryOwnership(sandboxID, record)
}

// AbortCheckpointOperation deterministically retires an identified checkpoint
// operation that never sealed. It is the runtime capability method (see
// runtimecore.CheckpointOperationAborter) used by the public service abort RPC,
// and it is deliberately separate from the success recovery — an abort is
// never mixed into RecoverCheckpointOperation's completion semantics.
//
// Only a durable intent may be newly aborted, and not while its recorded
// directory holds the verifiable complete seal of the same operation — that
// artifact is exactly the success the operation owes and must be recovered
// instead; a seal that cannot be attributed fails closed. Before any decision
// or resume, on both the hot and the cold path, the record's boot, source
// executable, and directory identity are verified against the current
// runtime. The abort decision is made durable (`aborting`) BEFORE EVERY
// resume attempt — including the retry after an ambiguous first write, whose
// in-memory `aborting` witness is not proof its write landed — so a crash or
// timeout retries the same decision instead of silently re-owning the source.
// The handback then proves the exact recorded birth identity is live before
// and after the resume and the guest error release; a missing, replaced, or
// dead source is never claimed resumed. Only after that proof is the source's
// incremental lineage invalidated — a failed snapshot may have reset the VMM's
// dirty accounting — and the `aborted` fact made durable. Every failure
// retains the evidence and reports honestly what did and did not happen; an
// ambiguous aborted write is re-persisted by the retry before success is
// reported.
func (handler *Handler) AbortCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) error {
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		record, err := handler.verifyCheckpointOperationColdState(sandboxID, binding)
		if err != nil {
			return err
		}
		if err := refuseAbortablePhase(sandboxID, record); err != nil {
			return err
		}
		// The identity and new-abort seal boundaries also hold before any
		// cold recovery side effect: a drifted or sealed intent must not run
		// recovery only to be refused under the lock.
		if err := handler.verifyCheckpointOperationAbortScope(sandboxID, record); err != nil {
			return err
		}
		if record.Phase == firecrackerCheckpointOperationPhaseIntent {
			if err := refuseAbortCheckpointOperationSealedIntent(sandboxID, record); err != nil {
				return err
			}
		}
	}
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	record, err := matchCheckpointOperationWitness(sandboxID, binding, state)
	if err != nil {
		return err
	}
	if err := refuseAbortablePhase(sandboxID, record); err != nil {
		return err
	}
	if record.Phase != firecrackerCheckpointOperationPhaseAborted {
		// The same identity gate the cold path runs, against the hot record
		// too: an in-memory witness whose recorded boot, source executable,
		// or directory identity drifted is refused before any abort decision
		// or resume.
		if err := handler.verifyCheckpointOperationAbortScope(sandboxID, record); err != nil {
			return err
		}
	}
	if record.Phase == firecrackerCheckpointOperationPhaseAborted {
		// The abort fact may not have been durable when it was first claimed:
		// re-persist before reporting success, exactly like the idempotent
		// success acknowledgment.
		if err := handler.persistInstance(instance); err != nil {
			return fmt.Errorf(
				"persist aborted checkpoint operation %s of Firecracker sandbox %s: %w; the durable abort fact is unproven and the evidence gate stays in force",
				record.OperationID, sandboxID, err,
			)
		}
		return nil
	}
	if record.Phase == firecrackerCheckpointOperationPhaseIntent {
		if err := refuseAbortCheckpointOperationSealedIntent(sandboxID, record); err != nil {
			return err
		}
		aborting := record
		aborting.Phase = firecrackerCheckpointOperationPhaseAborting
		// The in-memory record is set before the write so the abort decision
		// binds this daemon even when the write's result is ambiguous.
		instance.setCheckpointOperation(aborting)
		record = aborting
	}
	// record.Phase is now aborting — a fresh decision or a retry. Re-establish
	// the durable aborting boundary before EVERY resume attempt: a hot witness
	// that already says aborting is not proof its write landed, and the source
	// is never resumed against a decision that may only exist in memory.
	// persistInstance serializes on the same persistMu as every other state
	// writer and has no unchanged-state shortcut, so a nil result has re-proven
	// the aborting record on disk.
	if err := handler.persistInstance(instance); err != nil {
		return fmt.Errorf(
			"persist aborting checkpoint operation witness for operation %s of Firecracker sandbox %s: %w; the source was not resumed and the evidence is retained",
			record.OperationID, sandboxID, err,
		)
	}
	return handler.resumeCheckpointOperationForAbort(ctx, instance, record)
}

// resumeCheckpointOperationForAbort performs the abort's source handback for
// an `aborting` witness: prove the exact recorded birth identity live, resume
// the source, release the guest checkpoint error handoff, re-prove the same
// birth still live, invalidate the incremental lineage, and only then make
// the `aborted` fact durable. Every failure returns an explicit error with
// the `aborting` evidence retained and never claims the source was resumed
// when that is unproven.
func (handler *Handler) resumeCheckpointOperationForAbort(
	ctx context.Context,
	instance *firecrackerInstance,
	record firecrackerCheckpointOperationRecord,
) error {
	sandboxID := instance.snapshot().ID
	fd, err := pinAliveFirecrackerProcessBirth(record.VMMPID, record.VMMStartTime)
	if err != nil {
		return fmt.Errorf(
			"confirm the recorded source of aborting checkpoint operation %s of Firecracker sandbox %s before resuming: %w; the source's resumption is unproven, the evidence is retained, and the abort must be retried or reconciled explicitly",
			record.OperationID, sandboxID, err,
		)
	}
	defer unix.Close(fd)
	api := newFirecrackerAPI(instance.snapshot().APIPath)
	if err := api.resume(ctx); err != nil {
		return fmt.Errorf(
			"resume Firecracker sandbox %s for the abort of checkpoint operation %s: %w; the resumption is unconfirmed, the evidence is retained, and the abort must be retried",
			sandboxID, record.OperationID, err,
		)
	}
	// Guest release through the retryable abort message: the full record
	// binding lets the guest agent deduplicate a retry after a lost reply,
	// which the legacy one-shot error outcome cannot. An agent that predates
	// the message rejects it, and this path has no legacy fallback — the
	// abort simply stays retryable with its evidence retained.
	if err := requestFirecrackerAgent(
		ctx,
		instance.snapshot().VsockPath,
		firecrackerproto.MessageCheckpointAbort,
		firecrackerproto.CheckpointAbortRequest{OperationID: record.OperationID, RequestDigest: record.RequestDigest, SourceGeneration: record.SourceGeneration},
	); err != nil {
		return fmt.Errorf(
			"release Firecracker sandbox %s after the abort of checkpoint operation %s: %w; the source was resumed but the guest error handoff is unconfirmed, the evidence is retained, and the abort must be retried",
			sandboxID, record.OperationID, err,
		)
	}
	if err := confirmPinnedFirecrackerProcessBirth(record.VMMPID, record.VMMStartTime, fd); err != nil {
		return fmt.Errorf(
			"re-confirm the resumed source of aborting checkpoint operation %s of Firecracker sandbox %s: %w; the source's continued resumption is unproven and the evidence is retained",
			record.OperationID, sandboxID, err,
		)
	}
	// The failed operation may have disturbed the VMM's dirty-page ledger
	// against a base it never sealed: force the next checkpoint to Full.
	instance.markBaseMemoryLineageLost()
	aborted := record
	aborted.Phase = firecrackerCheckpointOperationPhaseAborted
	// The in-memory record is set before the write so the abort fact binds
	// this daemon even when the write's result is ambiguous; the retry
	// re-persists before reporting success.
	instance.setCheckpointOperation(aborted)
	if err := handler.persistInstance(instance); err != nil {
		return fmt.Errorf(
			"persist aborted checkpoint operation witness for operation %s of Firecracker sandbox %s: %w; the source was resumed and released but the abort fact is not durable, the evidence is retained, and the retry must not claim a fresh resume",
			record.OperationID, sandboxID, err,
		)
	}
	return nil
}

// refuseUnacknowledgableAbortPhase enforces the abort acknowledgment's phase
// policy: only a durable abort fact may be abort-acknowledged, and an already
// abort-acknowledged record stays idempotently acknowledgeable so a lost
// reply can be retried.
func refuseUnacknowledgableAbortPhase(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	switch record.Phase {
	case firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked:
		return nil
	default:
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is %s, not aborted; the abort acknowledgment releases only a durable abort fact, and the success acknowledgment never releases an abort: %w",
			record.OperationID, sandboxID, record.Phase, errord.ErrFailedPrecondition,
		)
	}
}

// AckAbortedCheckpointOperation releases the evidence-retention gate of a
// durably aborted operation after the service has persisted its failure fact.
// It is the runtime capability tail (see
// runtimecore.CheckpointOperationAborter) used by the public service abort RPC.
// It reads no artifact and touches no source — an aborted operation retains no
// success claim, so a legitimately removed artifact directory must not wedge
// the retirement — and the release becomes claimable exclusively from a
// durable write, exactly like the success acknowledgment.
func (handler *Handler) AckAbortedCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) error {
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		record, err := handler.verifyCheckpointOperationColdState(sandboxID, binding)
		if err != nil {
			return err
		}
		if err := refuseUnacknowledgableAbortPhase(sandboxID, record); err != nil {
			return err
		}
	}
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	record, err := matchCheckpointOperationWitness(sandboxID, binding, state)
	if err != nil {
		return err
	}
	if err := refuseUnacknowledgableAbortPhase(sandboxID, record); err != nil {
		return err
	}
	if err := handler.publishCheckpointOperationAbortAcknowledgment(instance); err != nil {
		return fmt.Errorf(
			"persist abort acknowledgment of checkpoint operation %s for Firecracker sandbox %s: %w; the evidence-retaining Delete gate stays in force until the abort acknowledgment is durable",
			record.OperationID, sandboxID, err,
		)
	}
	return nil
}

// publishCheckpointOperationAbortAcknowledgment makes the abort-acked fact
// durable under persistMu and publishes it only afterwards — the same
// construct, write, fsync, then publish ordering as the success
// acknowledgment, so an unpersisted release is never visible to callers or
// carried to disk by a concurrent state writer. The idempotent retry persists
// again deliberately.
func (handler *Handler) publishCheckpointOperationAbortAcknowledgment(
	instance *firecrackerInstance,
) error {
	instance.persistMu.Lock()
	defer instance.persistMu.Unlock()
	state := instance.snapshot()
	if err := refuseUnacknowledgableAbortPhase(state.ID, state.CheckpointOperation); err != nil {
		return err
	}
	acknowledged := state.CheckpointOperation
	acknowledged.Phase = firecrackerCheckpointOperationPhaseAbortAcked
	persisted := state
	persisted.CheckpointOperation = acknowledged
	if err := writeFirecrackerState(persisted); err != nil {
		return err
	}
	instance.setCheckpointOperation(acknowledged)
	return nil
}
