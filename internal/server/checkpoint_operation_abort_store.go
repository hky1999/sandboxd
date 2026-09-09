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

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// --- explicit abort of recorded operations (internal store stage) ---

// admitAbortable durably records the operation as a version-3 (abortable)
// record before any side effect. It is the entry CheckpointWithOperation
// calls after it verified the runtime holds the CheckpointOperationAborter
// capability beside writer and witness; a caller that did not verify that
// capability must keep using admit. An operation that is already recorded is
// replayed from history unchanged — its recorded version is a fact, so an
// abortable admission never upgrades an older record and a plain admission
// never downgrades a newer one.
func (s *checkpointOperationStore) admitAbortable(draft *checkpointOperationRecord) (
	execution *checkpointOperationExecution,
	joined <-chan struct{},
	err error,
) {
	return s.admitVersioned(draft, checkpointOperationRecordVersionAbortable)
}

// checkpointOperationAbort is the handle of the single executor that won an
// abort slot for one already-recorded version-3 operation. It wraps the very
// same in-flight execution slot the original admission and the recovery
// primitives use — so shutdown, joining replayers, and cancellation converge
// on one lifecycle — plus the published record the abort was admitted under,
// which markAborted re-verifies before claiming anything. It is a store
// primitive for the later abort service stage: it carries no runtime
// evidence, performs no runtime call, and holding it proves an execution
// slot, never that the runtime retired the operation.
type checkpointOperationAbort struct {
	store *checkpointOperationStore
	exec  *checkpointOperationExecution

	// bound is the record as published when the abort was admitted. Its
	// binding fields are immutable for the record's lifetime; keeping the
	// snapshot lets the failure transition refuse a record that was replaced
	// or drifted rather than aborted. Only read after admission, never
	// mutated.
	bound *checkpointOperationRecord

	// ackOnly marks a slot admitted for a FAILED+AbortConfirmed record. Its
	// sole purpose is the side-effecting AckAborted retry of an
	// already-durable confirmed abort: it owns a fully lifecycle-managed
	// executor slot, but it may never create the failure fact — the recorded
	// abort stays the authority. Set once at admission, only read afterwards.
	ackOnly bool
}

// acknowledgmentOnly reports whether the slot was admitted for an
// already-confirmed abort, so the abort service stage delivers its
// AckAborted retry instead of retiring an undetermined outcome.
func (a *checkpointOperationAbort) acknowledgmentOnly() bool {
	return a != nil && a.ackOnly
}

// boundRecord returns a copy of the record the abort was admitted under, so
// the abort service stage can rebuild the runtime binding — operation ID,
// request digest, source generation, directory — without re-deriving anything
// from a source sandbox that may no longer exist. The copy is independent all
// the way down: the artifact receipt is duplicated too, so a caller cannot
// mutate the published record through the handle it was handed.
func (a *checkpointOperationAbort) boundRecord() *checkpointOperationRecord {
	if a == nil {
		return nil
	}
	copyRecord := *a.bound
	if a.bound.Artifact != nil {
		artifact := *a.bound.Artifact
		copyRecord.Artifact = &artifact
	}
	return &copyRecord
}

// registerCancel attaches the abort executor's cancellation under the same
// admission lock shutdown uses, with the same compensation for a shutdown
// that snapshotted before the cancel was attached, as the original execution
// and recovery paths.
func (a *checkpointOperationAbort) registerCancel(cancel context.CancelFunc) {
	if a == nil {
		return
	}
	a.store.registerExecutionCancel(a.bound.OperationID, a.exec, cancel)
}

// finish releases the abort slot and wakes every joined replayer and a
// draining shutdown. Like the other executors' last action, an abort must
// call it only after it has fully returned from its work.
func (a *checkpointOperationAbort) finish() {
	if a == nil {
		return
	}
	a.store.finishExecution(a.bound.OperationID, a.exec)
}

// abortExistingContext admits the abort of one already-recorded version-3
// checkpoint operation. It never creates a record, never executes a
// checkpoint, and never calls the runtime: a missing record is NotFound, a
// mismatched binding is refused, and only an abortable record may be aborted.
// The undetermined outcomes — admitted without a live executor (a restart, or
// a terminal write that never landed) and unknown — are the records an abort
// may retire; a FAILED record with the confirmation already durable admits
// only the side-effecting half that may still be owed, the AckAborted retry,
// through an acknowledgment-only slot. An ordinary FAILED record (no runtime
// ever confirmed an abort), a SUCCEEDED record, and every version-1/2 record
// are refused: rewriting any of them into a confirmed abort would invent a
// fact the record never carried.
//
// Waiting for the store's admission lock is part of the caller's abort
// budget, exactly as for the context-aware recovery admission: a durable
// write (or any other writer) holding writeMu past the budget ends this
// attempt with the context's error — DeadlineExceeded or Canceled — having
// granted no slot and mutated nothing, and an already-expired context never
// wins a slot even when the lock is free. Abort shares the operation's one
// lifecycle rather than adding a parallel execution: while any executor — the
// original one, an earlier recovery, or an earlier abort — holds the slot,
// the caller is handed its done channel to join, and joining never revokes
// the running work. Winning a slot registers it under lifeMu atomically with
// the shutdown flag, so a store that began draining never starts an abort,
// and admission performs no durable write at all: the record already exists,
// and its history must not change.
func (s *checkpointOperationStore) abortExistingContext(
	ctx context.Context,
	draft *checkpointOperationRecord,
) (
	abort *checkpointOperationAbort,
	joined <-chan struct{},
	err error,
) {
	if s == nil {
		return nil, nil, fmt.Errorf("abort checkpoint operation requires a store")
	}
	if err := s.writeMu.Acquire(ctx); err != nil {
		return nil, nil, errord.ToGRPCf(
			err,
			"admit the abort of checkpoint operation %s: the store admission lock wait exceeded the caller's budget; "+
				"no execution slot was granted and nothing was aborted",
			draft.OperationID,
		)
	}
	defer s.writeMu.Unlock()
	return s.abortExistingAdmitted(draft)
}

// abortExistingAdmitted is the eligibility decision under a held writeMu,
// shared by the context-aware admission and any internal caller that already
// owns the serialization: writeMu serializes it with admissions and competing
// recoveries and aborts, so exactly one applicant can register the slot.
// Nothing here performs durable I/O, so the writeMu discipline (durable write
// before publication) is preserved trivially.
func (s *checkpointOperationStore) abortExistingAdmitted(draft *checkpointOperationRecord) (
	abort *checkpointOperationAbort,
	joined <-chan struct{},
	err error,
) {
	existing, ok := s.published(draft.OperationID)
	if !ok {
		return nil, nil, errord.ToGRPCf(
			errord.ErrNotFound, "checkpoint operation %s is unknown", draft.OperationID)
	}
	if err := sameCheckpointOperationRequest(existing, draft); err != nil {
		return nil, nil, err
	}
	// The abort protocol is defined for abortable records only: their
	// admission verified the runtime can actually retire the operation. A
	// legacy or witness record never made that promise, so aborting it would
	// claim a runtime confirmation that cannot exist.
	if existing.Version != checkpointOperationRecordVersionAbortable {
		return nil, nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a version-%d record without the abortable protocol; explicit abort is refused",
			existing.OperationID, existing.Version,
		)
	}
	switch existing.Phase {
	case checkpointOperationPhaseAdmitted, checkpointOperationPhaseUnknown:
		// The undetermined outcomes are the records an abort may retire.
	case checkpointOperationPhaseFailed:
		if !existing.AbortConfirmed {
			return nil, nil, errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"checkpoint operation %s is recorded failed without a confirmed abort; an ordinary failure cannot be reinterpreted as one",
				existing.OperationID,
			)
		}
		// A confirmed abort is already durable history; only the
		// AckAborted retry may still be owed.
	case checkpointOperationPhaseSucceeded:
		return nil, nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is recorded succeeded; a successful operation cannot be aborted",
			existing.OperationID,
		)
	default:
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnknown,
			"checkpoint operation %s has invalid phase %q",
			existing.OperationID, existing.Phase,
		)
	}
	if done, running := s.executionDone(draft.OperationID); running {
		// The original executor, an earlier recovery, or an earlier abort
		// still owns the operation; join it instead of creating a second
		// executor.
		return nil, done, nil
	}
	exec := &checkpointOperationExecution{done: make(chan struct{})}
	s.lifeMu.Lock()
	if s.shuttingDown {
		s.lifeMu.Unlock()
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"daemon is shutting down; checkpoint operation %s cannot be aborted",
			existing.OperationID,
		)
	}
	s.inflight[draft.OperationID] = exec
	s.lifeMu.Unlock()
	bound := *existing
	return &checkpointOperationAbort{
		store:   s,
		exec:    exec,
		bound:   &bound,
		ackOnly: existing.Phase == checkpointOperationPhaseFailed,
	}, nil, nil
}

// markAborted is the dedicated failure transition of an abort slot: the only
// path that may move an undetermined version-3 record (admitted without an
// executor, or unknown) to FAILED with the abort confirmation, and only while
// this slot still owns the operation's execution slot and the record still
// carries the binding the abort was admitted under. It is called by the
// service stage only AFTER the runtime has confirmed the abort — the store
// itself never calls the runtime — and claims exactly that fact.
//
// Durable-first and serialized under writeMu: the confirmed failure is
// constructed, persisted, and only then published, so a slow, blocked,
// failed, or ambiguous write keeps every query at the undetermined outcome —
// the record keeps its old phase, the same slot (or, after its release, a
// re-admitted abort) may retry, and nothing about a confirmed abort is
// observable before it is durable. markTerminal is deliberately not used: it
// treats unknown as terminal, which would no-op exactly the transition an
// abort exists to make. An already-confirmed record is answered idempotently
// — the durable fact, not a later retry, is the authority, and a retry
// rewrites nothing, not even the message. A SUCCEEDED record, an ordinary
// FAILED record, a record that drifted off this slot's binding, and a stale
// owner are all refused; an acknowledgment-only slot can never create the
// failure fact in the first place.
func (a *checkpointOperationAbort) markAborted(message string) error {
	if a == nil {
		return fmt.Errorf("checkpoint operation abort is nil")
	}
	if len(message) > checkpointOperationMaxMsg {
		message = message[:checkpointOperationMaxMsg]
	}
	s := a.store
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.assertExecutionOwnership(a.bound.OperationID, a.exec); err != nil {
		return err
	}
	record, ok := s.published(a.bound.OperationID)
	if !ok {
		return fmt.Errorf("abort checkpoint operation %s without a record", a.bound.OperationID)
	}
	if err := sameCheckpointOperationRequest(record, a.bound); err != nil {
		// The record's binding drifted from the one this abort was admitted
		// under, so the confirmed failure would land on a different operation.
		return err
	}
	if record.Version != checkpointOperationRecordVersionAbortable {
		// Defense in depth beside the binding check: the version is static for
		// a record's lifetime, and only an abortable record may carry the
		// confirmation this transition writes.
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a version-%d record; only an abortable record can carry a confirmed abort",
			record.OperationID, record.Version,
		)
	}
	switch record.Phase {
	case checkpointOperationPhaseFailed:
		if !record.AbortConfirmed {
			return errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"checkpoint operation %s is recorded failed without a confirmed abort; an ordinary failure cannot be reinterpreted as one",
				record.OperationID,
			)
		}
		// Idempotent replay of the already-durable fact: a retry after an
		// ambiguous reply claims nothing new and rewrites nothing.
		return nil
	case checkpointOperationPhaseAdmitted, checkpointOperationPhaseUnknown:
		if a.ackOnly {
			// The slot was admitted against a confirmed abort; an
			// acknowledgment-only executor may not create the failure fact of
			// a record that is undetermined again. Unreachable while phases
			// only move forward, and structural rather than incidental for
			// exactly that reason.
			return errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"the abort slot for checkpoint operation %s was admitted for acknowledgment only; it may not create a confirmed abort",
				record.OperationID,
			)
		}
	case checkpointOperationPhaseSucceeded:
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is recorded succeeded; its outcome cannot be reinterpreted as a confirmed abort",
			record.OperationID,
		)
	default:
		return errord.ToGRPCf(
			errord.ErrUnknown,
			"checkpoint operation %s has invalid phase %q",
			record.OperationID, record.Phase,
		)
	}
	updated := *record
	updated.Phase = checkpointOperationPhaseFailed
	updated.AbortConfirmed = true
	// A confirmed abort never carries a sealed root: artifact is bound to
	// SUCCEEDED alone, and an undetermined record never had one. Dropped
	// explicitly so the written fact cannot smuggle completion evidence.
	updated.Artifact = nil
	updated.Message = message
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.persist(&updated); err != nil {
		// Durable-first: the published view keeps the undetermined phase, so
		// queries keep reporting an unproven outcome — including the case
		// where the write may have landed but its outcome is unknown — and
		// the same abort may be retried.
		return fmt.Errorf(
			"persist the confirmed abort of checkpoint operation %s: %w; the outcome stays undetermined and the same abort may be retried",
			a.bound.OperationID, err,
		)
	}
	s.publish(&updated)
	return nil
}
