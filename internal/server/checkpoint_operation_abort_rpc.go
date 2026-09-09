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

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc/status"
)

// AbortCheckpointOperation explicitly aborts one already-recorded checkpoint
// operation admitted under the witness-abortable protocol. The request must
// repeat the COMPLETE original payload unchanged: the service recomputes the
// request digest from that payload — never from a caller-echoed digest — and
// refuses the operation ID unless it matches the recorded binding exactly.
// The abort timeout is separate (1..600): it bounds this one attempt and never
// participates in the digest or rewrites the recorded operation.
//
// Abort never admits a record, never takes a snapshot, never binds an
// artifact, never resumes or deletes anything itself, and never falls back to
// Checkpoint, CheckpointIfGeneration, CheckpointWithOperation, or
// RecoverCheckpointOperation. A missing record is NotFound; a legacy
// version-1 record, a witness-only version-2 record, a SUCCEEDED record, an
// ordinary FAILED record, and any binding mismatch are refused before any
// side effect.
//
// Lifecycle mirrors RecoverCheckpointOperation: one absolute deadline taken
// at request admission bounds the whole call — the admission-lock queue, the
// join of a live executor, the per-sandbox physical-lock queue, the runtime
// abort, and the acknowledgment all share it and none of them resets it. The
// abort shares the operation's single execution slot with the original
// execution and recoveries: a live executor is joined, never run beside, and
// joining does not revoke it. After a slot is won its work context detaches
// from the caller's cancellation but carries the SAME deadline, its
// cancellation is registered with the shutdown drain, and the slot is held
// until the work has really returned.
//
// The identities come from the durable record alone — the recorded runtime
// and the recorded source sandbox ID (never the operation ID), never
// re-derived from live metadata that may have been replaced: the runtime's
// own abort protocol proves the source's recorded birth identity before and
// after it resumes the guest.
//
// The normal slot orders strictly: runtime Abort (the source is resumed and
// the operation durably retired on the runtime side) → markAborted (the
// FAILED+abort_confirmed fact made durable before it is published) → runtime
// AckAborted (the evidence-retention gate released for a durable fact). A
// slot admitted for an already-confirmed record is acknowledgment-only: it
// calls AckAborted alone — no second abort, no artifact access, no rewrite of
// the recorded outcome. Every failure is honest: a runtime abort failure, a
// persist failure (including an ambiguous write), or an acknowledgment
// failure — a NotFound target included — returns an error without a false
// release claim; the record keeps its exact durable fact (undetermined while
// the confirmed write never landed, confirmed FAILED once it did) and the
// same abort may be retried.
func (h *sandboxService) AbortCheckpointOperation(
	ctx context.Context,
	request *runtime.AbortCheckpointOperationRequest,
) (*runtime.CheckpointOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "abort checkpoint operation request is nil")
	}
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
	}
	if request.GetAbortTimeoutSeconds() == 0 ||
		request.GetAbortTimeoutSeconds() > checkpointOperationMaxTimeoutSeconds {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"abort timeout_seconds must be between 1 and %d", checkpointOperationMaxTimeoutSeconds,
		)
	}
	operation := request.GetOperation()
	if operation == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "operation request is required")
	}
	_, canonicalDir, digest, err := validatedCheckpointOperation(operation)
	if err != nil {
		return nil, err
	}
	draft := &checkpointOperationRecord{
		OperationID:   operation.GetOperationID(),
		SandboxID:     operation.GetCheckpoint().ID,
		Generation:    operation.ExpectedGeneration,
		CheckpointDir: canonicalDir,
		RequestDigest: digest,
	}
	// Abort is defined for abortable (version-3) records only, and the record
	// version is static for its lifetime, so every other version is refused
	// before any slot is taken: a legacy record has no runtime evidence at
	// all, and a witness-only record's admission never verified the runtime
	// can retire the operation. Queries and same-request replays keep
	// answering from the record.
	if existing := h.checkpointOperations.snapshot(operation.GetOperationID()); existing != nil &&
		existing.Version != checkpointOperationRecordVersionAbortable {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a version-%d record without the abortable protocol; "+
				"explicit abort is refused (queries and same-request replays keep answering from the record)",
			operation.GetOperationID(), existing.Version,
		)
	}

	// One absolute abort deadline governs the whole call, taken at request
	// admission: the store's admission-lock queue, the join below, the
	// physical-lock queue, the runtime abort, and the acknowledgment all
	// share it and none of them ever resets it. admitCtx carries BOTH the
	// caller's cancellation and this deadline into the context-aware abort
	// admission; the join below listens to the same two ends so even an
	// uncancellable Background caller cannot wait unbounded on an executor
	// that never returns.
	deadline := time.Now().Add(time.Duration(request.GetAbortTimeoutSeconds()) * time.Second)
	admitCtx, admitCancel := context.WithDeadline(ctx, deadline)
	defer admitCancel()
	var abortSlot *checkpointOperationAbort
	for {
		candidate, joined, err := h.checkpointOperations.abortExistingContext(admitCtx, draft)
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			abortSlot = candidate
			break
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-joined:
			timer.Stop()
		case <-timer.C:
			return nil, errord.ToGRPCf(
				context.DeadlineExceeded,
				"the existing execution of checkpoint operation %s did not finish within the abort deadline; "+
					"nothing was aborted and the operation ID is unchanged",
				operation.GetOperationID(),
			)
		case <-ctx.Done():
			timer.Stop()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		// The joined executor finished, but the budget it consumed counts
		// here: a re-admission with no remaining budget answers the deadline
		// instead of starting fresh work.
		if !time.Now().Before(deadline) {
			return nil, errord.ToGRPCf(
				context.DeadlineExceeded,
				"the abort deadline of checkpoint operation %s expired while joining its existing execution; "+
					"nothing was aborted and the operation ID is unchanged",
				operation.GetOperationID(),
			)
		}
	}
	defer abortSlot.finish()
	bound := abortSlot.boundRecord()
	// Defense in depth beside the pre-admission check: the slot's binding is
	// the authority for everything below.
	if bound.Version != checkpointOperationRecordVersionAbortable {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a version-%d record without the abortable protocol; abort is refused",
			bound.OperationID, bound.Version,
		)
	}
	// The abort work detaches from the caller's cancellation but carries the
	// SAME absolute deadline — the join's leftover budget is the work's
	// budget; it is never refreshed. Registering the cancellation immediately
	// after the slot is won keeps a draining shutdown able to request
	// convergence of every step below, while the slot itself is retained
	// until this executor has really returned.
	execCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	abortSlot.registerCancel(cancel)
	// The runtime is selected by the RECORDED handler name and the abort is
	// addressed to the RECORDED source sandbox ID — never the operation ID,
	// never a runtime re-derived from a source that may since have been
	// replaced or deleted. The explicit aborter capability is required: a
	// witness that cannot abort is a hard refusal with no fallback, because
	// the record is bound to an operation only this runtime can retire.
	handler, ok := h.serviceHandler.Get(bound.Runtime)
	if !ok {
		return nil, errord.ToGRPC(errord.ErrNotImplemented)
	}
	aborter, ok := handler.(svc.CheckpointOperationAborter)
	if !ok {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support explicit checkpoint operation aborts; "+
				"no recovery or checkpoint fallback exists for aborting operation %s",
			bound.Runtime, bound.OperationID,
		)
	}
	// Serialize the abort against checkpoint, start, delete, and recovery for
	// this sandbox. The queue wait shares the absolute deadline: an abort that
	// cannot acquire the physical lock in its remaining budget fails with that
	// deadline having aborted nothing.
	unlock, lockErr := h.resourceLocks.acquire(execCtx, bound.SandboxID)
	if lockErr != nil {
		return nil, errord.ToGRPC(lockErr)
	}
	defer unlock()
	binding := svc.CheckpointOperationBinding{
		OperationID:      bound.OperationID,
		RequestDigest:    bound.RequestDigest,
		SourceGeneration: bound.Generation,
		// The canonical directory from the durable record: the runtime's
		// zero-witness retirement locates the operation's caller-owned
		// directory evidence through it, and an empty value simply disables
		// that retirement (the abort keeps its historical NotFound answer
		// for a missing witness).
		CheckpointDir: bound.CheckpointDir,
	}
	if !abortSlot.acknowledgmentOnly() {
		// The runtime retires the never-sealed operation — handing back an
		// intent-bound source, or recording a zero-witness abort without a
		// source effect — and its nil return proves the durable aborted fact
		// on the runtime side. Only then may the service persist its own
		// confirmed failure.
		if abortErr := aborter.AbortCheckpointOperation(execCtx, bound.SandboxID, binding); abortErr != nil {
			return nil, errord.ToGRPCf(abortErr,
				"abort checkpoint operation %s at runtime %q failed; the service outcome is unchanged and the runtime evidence is retained for retry",
				bound.OperationID, bound.Runtime,
			)
		}
		// Durable-first: the FAILED+abort_confirmed fact is persisted before
		// it is published and before the evidence gate is released. A failure
		// here — including an ambiguous write whose outcome is unknown — keeps
		// every query at the undetermined outcome and the same abort may be
		// retried; the runtime treats a retried abort as the same recorded
		// decision.
		if markErr := abortSlot.markAborted(fmt.Sprintf(
			"abort of operation %s confirmed by runtime %q; the runtime operation is durably retired and no successful checkpoint artifact is claimed",
			bound.OperationID, bound.Runtime,
		)); markErr != nil {
			return nil, errord.ToGRPC(fmt.Errorf(
				"persist the confirmed abort of checkpoint operation %s: %w; "+
					"the outcome stays undetermined and the same abort may be retried",
				bound.OperationID, markErr,
			))
		}
	}
	// The abort acknowledgment releases the runtime's evidence-retention gate
	// for the durable confirmed failure — in both branches, strictly after any
	// persist above. Fail closed: a NotFound target is NOT a release (the
	// source may have been replaced), so the RPC fails while preserving the
	// durable record for another explicit attempt; a retry re-enters through
	// the acknowledgment-only slot and rewrites nothing.
	if ackErr := aborter.AckAbortedCheckpointOperation(execCtx, bound.SandboxID, binding); ackErr != nil {
		return nil, errord.ToGRPC(fmt.Errorf(
			"acknowledge the aborted checkpoint operation %s: %w; "+
				"the durable confirmed abort is retained and the evidence release is unproven",
			bound.OperationID, ackErr,
		))
	}
	aborted, err := h.checkpointOperationStatus(bound.OperationID)
	if err != nil {
		return nil, err
	}
	// evidence_released is per-invocation: true only because THIS call
	// completed the abort acknowledgment after the durable confirmed failure.
	aborted.EvidenceReleased = true
	return aborted, nil
}
