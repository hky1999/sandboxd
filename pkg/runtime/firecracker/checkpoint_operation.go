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
	"time"

	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// firecrackerCheckpointOperationRecordVersion is the schema of
// firecrackerCheckpointOperationRecord. Records carrying any other version
// are rejected, never reinterpreted.
const firecrackerCheckpointOperationRecordVersion = 1

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
)

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
type firecrackerCheckpointOperationRecord struct {
	// Version is the record schema version.
	Version int `json:"version,omitempty"`
	// Phase is prepared until the source stop is confirmed, completed once
	// the durable completion fact exists, and acked once the service's
	// durable SUCCEEDED receipt released the evidence-retention gate.
	Phase string `json:"phase,omitempty"`
	// OperationID, RequestDigest and SourceGeneration restate the exact
	// binding the operation was admitted under; recovery accepts only a
	// complete, exact match.
	OperationID      string `json:"operation_id,omitempty"`
	RequestDigest    string `json:"request_digest,omitempty"`
	SourceGeneration string `json:"source_generation,omitempty"`
	// RootDigest and RootScheme bind the sealed checkpoint content root the
	// operation produced — small metadata derived through the shared
	// pkg/checkpointroot algorithm, never a payload re-hash. Directory is
	// the caller-owned output directory that root was derived from.
	RootDigest string `json:"root_digest,omitempty"`
	RootScheme string `json:"root_scheme,omitempty"`
	Directory  string `json:"directory,omitempty"`
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
// operation evidence: a prepared or completed witness blocks every new
// checkpoint and the delete that would clear the only runtime evidence of the
// operation, including legacy calls. An acked record keeps its fields for
// audit but retains nothing the service still owes an answer for.
func (record firecrackerCheckpointOperationRecord) retainsEvidence() bool {
	switch record.Phase {
	case firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted:
		return true
	default:
		return false
	}
}

// validateFirecrackerCheckpointOperationRecord accepts only complete,
// self-consistent witnesses; anything partial can prove nothing and is never
// recovered as a claim about an operation or a process.
func validateFirecrackerCheckpointOperationRecord(
	record firecrackerCheckpointOperationRecord,
) error {
	if record.Version != firecrackerCheckpointOperationRecordVersion {
		return fmt.Errorf(
			"unsupported checkpoint operation record version %d", record.Version,
		)
	}
	switch record.Phase {
	case firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked:
	default:
		return fmt.Errorf("invalid checkpoint operation record phase %q", record.Phase)
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
	if len(record.RootDigest) != checkpointroot.DigestHexLen {
		return fmt.Errorf(
			"checkpoint operation record root digest is not %d hex characters",
			checkpointroot.DigestHexLen,
		)
	}
	if _, err := hex.DecodeString(record.RootDigest); err != nil {
		return errors.New("checkpoint operation record root digest is not hex")
	}
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
	return fmt.Errorf(
		"Firecracker sandbox %s retains %s checkpoint operation %s evidence (root %s); new checkpoints are blocked until the operation is recovered or acknowledged: %w",
		sandboxID, record.Phase, record.OperationID, record.RootDigest,
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

// finishIdentifiedCheckpointOperation runs the post-seal tail of an identified
// stop-and-copy checkpoint: bind the sealed root, capture the source VMM's
// birth identity while it is still alive, and make the prepared witness
// durable. From the caller's seal onward the source may never be resumed
// again; a failure in this tail — including an ambiguous prepared-write
// result — keeps the source paused and the sealed artifact in place, because a
// returned error does not prove the witness write did not land.
func (handler *Handler) finishIdentifiedCheckpointOperation(
	instance *firecrackerInstance,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
	directory string,
	files firecrackerCheckpointFiles,
) error {
	// Bind the sealed content root through the shared root algorithm: small
	// metadata reads over the manifest and sidecars the seal just wrote,
	// never a payload re-hash or fsync. Publication durability stays with the
	// publish gates.
	root, err := checkpointroot.Bind(directory)
	if err != nil {
		return fmt.Errorf(
			"bind Firecracker checkpoint root for operation %s of sandbox %s: %w; the source stays paused and the sealed artifact is retained",
			binding.OperationID, sandboxID, err,
		)
	}
	state := instance.snapshot()
	identity, err := captureFirecrackerVMMBirthIdentity(state)
	if err != nil {
		return fmt.Errorf(
			"capture Firecracker sandbox %s source identity for operation %s: %w; the source stays paused and the sealed artifact is retained",
			sandboxID, binding.OperationID, err,
		)
	}
	record := firecrackerCheckpointOperationRecord{
		Version:          firecrackerCheckpointOperationRecordVersion,
		Phase:            firecrackerCheckpointOperationPhasePrepared,
		OperationID:      binding.OperationID,
		RequestDigest:    binding.RequestDigest,
		SourceGeneration: state.Generation,
		RootDigest:       root.RootDigest,
		RootScheme:       root.Scheme,
		Directory:        directory,
		VMMPID:           identity.pid,
		VMMStartTime:     identity.startTime,
		VMMBootID:        identity.bootID,
		VMMAPIPath:       state.APIPath,
		Uffd:             state.Uffd,
	}
	// The in-memory record is set before the write so the constraint binds
	// this daemon even when the write's result is ambiguous.
	instance.setCheckpointOperation(record)
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
	return handler.completeIdentifiedCheckpointOperation(instance, record)
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

// RecoverCheckpointOperation reconciles one existing identified checkpoint
// operation. It is an internal capability method (see
// runtimecore.CheckpointOperationWitness): nothing public invokes it yet.
//
// The binding is verified against the durable record before any recovery side
// effect (cold path) and again under the instance operation lock; the request
// must match the recorded operation ID, request digest, and source
// generation exactly, the record's source generation must still equal the
// runtime's own persisted incarnation identity, and the recorded artifact
// root must still bind the recorded directory. Within the lock the recovery
// only completes the original stop-source flow: it never allocates artifacts,
// takes a snapshot, resumes the source, or modifies the artifact root. A
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
			return runtimecore.CheckpointOperationCompletion{}, fmt.Errorf(
				"checkpoint operation %s of Firecracker sandbox %s is already acknowledged; its evidence retention is released and recovery is not this path's to redo: %w",
				record.OperationID, sandboxID, errord.ErrFailedPrecondition,
			)
		}
		if err := verifyCheckpointOperationWitnessRoot(sandboxID, record); err != nil {
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
	if err := verifyCheckpointOperationWitnessRoot(sandboxID, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if err := verifyCheckpointOperationWitnessScope(sandboxID, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	if record.Phase == firecrackerCheckpointOperationPhaseAcked {
		return runtimecore.CheckpointOperationCompletion{}, fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s is already acknowledged; its evidence retention is released and recovery is not this path's to redo: %w",
			record.OperationID, sandboxID, errord.ErrFailedPrecondition,
		)
	}
	if record.Phase == firecrackerCheckpointOperationPhaseCompleted {
		// The durable completion already carries the original binding's
		// result; return it without further writes or process interaction.
		return runtimecore.CheckpointOperationCompletion{
			RootDigest: record.RootDigest,
			RootScheme: record.RootScheme,
		}, nil
	}
	if err := handler.completeIdentifiedCheckpointOperation(instance, record); err != nil {
		return runtimecore.CheckpointOperationCompletion{}, err
	}
	return runtimecore.CheckpointOperationCompletion{
		RootDigest: record.RootDigest,
		RootScheme: record.RootScheme,
	}, nil
}

// refuseUnacknowledgablePhase enforces the acknowledgment's phase policy: only
// a durable completion may be acknowledged. A prepared witness still owes the
// source's stop — its evidence constraint is not the service's to release,
// and no internal caller may turn an unfinished operation into an acked one.
// An already-acknowledged record stays idempotently acknowledgeable so a lost
// reply can be retried after a durable success receipt.
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
			"checkpoint operation %s of Firecracker sandbox %s is %s, not completed; recover the operation's stop before acknowledging it: %w",
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
