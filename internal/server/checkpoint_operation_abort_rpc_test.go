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
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests cover the public service stage of the explicit abort protocol:
// the AbortCheckpointOperation RPC and the version-3 admission of
// CheckpointWithOperation. The fake aborter below models the runtime half;
// nothing here is a real Firecracker acceptance.

// abortableRuntimeHandler wraps the witness fake with the explicit abort
// capability. ONLY the wrapper has it: the older fakes keep refusing aborts,
// so no existing version-2 test silently becomes version 3.
type abortableRuntimeHandler struct {
	*checkpointOperationRuntimeHandler

	mu           sync.Mutex
	aborts       []abortCall
	ackAborteds  []abortCall
	abortFn      func(context.Context, string, svc.CheckpointOperationBinding) error
	ackAbortedFn func(context.Context, string, svc.CheckpointOperationBinding) error
}

// abortCall records one runtime abort-protocol interaction with the exact
// sandbox it was addressed to and the exact binding it carried.
type abortCall struct {
	sandboxID string
	binding   svc.CheckpointOperationBinding
}

var _ svc.CheckpointOperationAborter = (*abortableRuntimeHandler)(nil)

func newAbortableRuntimeHandler() *abortableRuntimeHandler {
	return &abortableRuntimeHandler{checkpointOperationRuntimeHandler: newCheckpointOperationRuntimeHandler()}
}

func (h *abortableRuntimeHandler) AbortCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding svc.CheckpointOperationBinding,
) error {
	h.mu.Lock()
	h.aborts = append(h.aborts, abortCall{sandboxID: sandboxID, binding: binding})
	fn := h.abortFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, sandboxID, binding)
	}
	return nil
}

func (h *abortableRuntimeHandler) AckAbortedCheckpointOperation(
	ctx context.Context,
	sandboxID string,
	binding svc.CheckpointOperationBinding,
) error {
	h.mu.Lock()
	h.ackAborteds = append(h.ackAborteds, abortCall{sandboxID: sandboxID, binding: binding})
	fn := h.ackAbortedFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, sandboxID, binding)
	}
	return nil
}

func (h *abortableRuntimeHandler) recordedAborts() []abortCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]abortCall(nil), h.aborts...)
}

func (h *abortableRuntimeHandler) recordedAckAborteds() []abortCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]abortCall(nil), h.ackAborteds...)
}

// abortRequest wraps the complete, unchanged original request with a separate
// abort timeout, exactly as the public RPC expects it.
func abortRequest(
	request *runtime.CheckpointWithOperationRequest,
	abortTimeout uint32,
) *runtime.AbortCheckpointOperationRequest {
	return &runtime.AbortCheckpointOperationRequest{
		Operation:           request,
		AbortTimeoutSeconds: abortTimeout,
	}
}

// seedUndeterminedAbortable seeds one version-3 unknown record with its
// service, the state an abortable admission leaves after a restart.
func seedUndeterminedAbortable(t *testing.T, operationID, sandboxID string) (
	*sandboxService,
	*abortableRuntimeHandler,
	*runtime.CheckpointWithOperationRequest,
) {
	t.Helper()
	root := t.TempDir()
	request := checkpointOperationRequest(
		operationID, sandboxID, filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
	handler := newAbortableRuntimeHandler()
	return newCheckpointOperationService(t, handler, root), handler, request
}

// --- the normal abort slot ---

// TestAbortCheckpointOperationNormalAbort pins the ordered protocol of the
// normal slot: the runtime abort with the exact recorded source and binding
// comes first, the durable confirmed FAILED second, the abort acknowledgment
// last — and only a successful reply claims the release.
func TestAbortCheckpointOperationNormalAbort(t *testing.T) {
	s, handler, request := seedUndeterminedAbortable(t, "op-abort-rpc", "sbox-abort-rpc")
	binding := svc.CheckpointOperationBinding{
		OperationID:      "op-abort-rpc",
		RequestDigest:    requestDigestOf(t, request),
		SourceGeneration: "gen-1",
		// The abort binding carries the canonical directory of the durable
		// record — the runtime's zero-witness retirement locates the output
		// directory evidence through it.
		CheckpointDir: request.GetCheckpoint().GetCheckpointDir(),
	}

	var seqMu sync.Mutex
	var sequence []string
	record := func(step string) { seqMu.Lock(); sequence = append(sequence, step); seqMu.Unlock() }
	handler.abortFn = func(_ context.Context, _ string, _ svc.CheckpointOperationBinding) error {
		record("runtime-abort")
		return nil
	}
	handler.ackAbortedFn = func(_ context.Context, _ string, _ svc.CheckpointOperationBinding) error {
		record("runtime-ack-aborted")
		return nil
	}
	s.checkpointOperations.persistHook = func(r *checkpointOperationRecord) error {
		if r.AbortConfirmed {
			record("persist-confirmed")
		}
		return s.checkpointOperations.durablyWrite(r)
	}

	aborted, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 45))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, aborted.GetState())
	assert.True(t, aborted.GetAbortConfirmed())
	assert.True(t, aborted.GetEvidenceReleased(), "only a successful abort reply claims the release")
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE,
		aborted.GetRecoveryProtocol())
	assert.Equal(t, "sbox-abort-rpc", aborted.GetSandboxID())
	assert.Equal(t, binding.RequestDigest, aborted.GetRequestDigest())
	assert.Contains(t, aborted.GetMessage(), "runtime operation is durably retired")
	assert.Contains(t, aborted.GetMessage(), "no successful checkpoint artifact is claimed")
	assert.NotContains(t, aborted.GetMessage(), "no artifact exists",
		"an abort may leave unsealed component files, so the receipt must not claim physical absence")

	// The runtime abort is addressed to the RECORDED source sandbox ID — never
	// the operation ID — with the exact admitted binding, exactly once; the
	// acknowledgment answers the same identity.
	require.Len(t, handler.recordedAborts(), 1)
	assert.Equal(t, abortCall{sandboxID: "sbox-abort-rpc", binding: binding}, handler.recordedAborts()[0])
	require.Len(t, handler.recordedAckAborteds(), 1)
	assert.Equal(t, abortCall{sandboxID: "sbox-abort-rpc", binding: binding}, handler.recordedAckAborteds()[0])

	// Runtime abort → durable confirmed failure → acknowledgment, in order.
	seqMu.Lock()
	assert.Equal(t, []string{"runtime-abort", "persist-confirmed", "runtime-ack-aborted"}, sequence)
	seqMu.Unlock()

	// The durable record carries the confirmed failure and nothing else: no
	// artifact, no version rewrite, no new checkpoint or recovery.
	record3 := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-rpc")
	assert.Equal(t, checkpointOperationRecordVersionAbortable, record3.Version)
	assert.Equal(t, checkpointOperationPhaseFailed, record3.Phase)
	assert.True(t, record3.AbortConfirmed)
	assert.Nil(t, record3.Artifact)
	assert.Zero(t, handler.checkpointCount())
	recovers, witnessAcks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Zero(t, witnessAcks, "the abort protocol never uses the success acknowledgment")

	// Queries and replays restate the durable abort fact without the
	// per-invocation release.
	queried, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-abort-rpc"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, queried.GetState())
	assert.True(t, queried.GetAbortConfirmed())
	assert.False(t, queried.GetEvidenceReleased())
	replayed, rerr := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, replayed.GetState())
	assert.True(t, replayed.GetAbortConfirmed())
	assert.False(t, replayed.GetEvidenceReleased())
	assert.Zero(t, handler.checkpointCount())

	// After a restart the durable fact answers from history and a later abort
	// is the acknowledgment-only half.
	restartedHandler := newAbortableRuntimeHandler()
	restarted := newCheckpointOperationService(t, restartedHandler, s.config.RootDir)
	afterRestart, aerr := restarted.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-abort-rpc"})
	require.NoError(t, aerr)
	assert.True(t, afterRestart.GetAbortConfirmed())
	assert.False(t, afterRestart.GetEvidenceReleased())
	_, err = restarted.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
	require.NoError(t, err)
	assert.Zero(t, restartedHandler.recordedAborts(), "a confirmed abort is never re-driven at the runtime")
	require.Len(t, restartedHandler.recordedAckAborteds(), 1)
}

// --- authorization and refusals ---

// TestAbortCheckpointOperationRefusals pins the precondition set: the abort
// authorizes with the complete original request alone, the abort timeout is
// separate from it, and every ineligible record is refused before any effect.
func TestAbortCheckpointOperationRefusals(t *testing.T) {
	t.Run("timeout bounds are validated first", func(t *testing.T) {
		s, _, request := seedUndeterminedAbortable(t, "op-abort-bounds", "sbox-abort-refuse")
		for _, timeout := range []uint32{0, 601} {
			_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, timeout))
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "timeout %d", timeout)
		}
		_, err := s.AbortCheckpointOperation(context.Background(),
			&runtime.AbortCheckpointOperationRequest{AbortTimeoutSeconds: 30})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		aborts, acks := abortCounts(t, s)
		assert.Zero(t, aborts)
		assert.Zero(t, acks)
	})

	t.Run("a rewritten original payload is refused", func(t *testing.T) {
		s, _, request := seedUndeterminedAbortable(t, "op-abort-mismatch", "sbox-abort-refuse")
		rewritten := checkpointOperationRequest(
			"op-abort-mismatch", "sbox-abort-refuse", request.GetCheckpoint().GetCheckpointDir(), "gen-1", 31)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(rewritten, 30))
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "bound to a different request")
		aborts, acks := abortCounts(t, s)
		assert.Zero(t, aborts)
		assert.Zero(t, acks)
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-mismatch").Phase)

		// The abort timeout itself never participates in the digest: the same
		// original payload aborts under a different one than its own checkpoint
		// timeout.
		aborted, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 7))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
	})

	t.Run("a missing record is NotFound with zero writes", func(t *testing.T) {
		root := t.TempDir()
		s := newCheckpointOperationService(t, newAbortableRuntimeHandler(), root)
		request := checkpointOperationRequest(
			"op-abort-missing", "sbox-abort-refuse", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Zero(t, journalRecordCount(t, root))
	})

	t.Run("older versions and ineligible phases are refused before effects", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "checkpoint")
		cases := map[string]func(t *testing.T) (*sandboxService, string){
			"legacy version 1": func(t *testing.T) (*sandboxService, string) {
				root := t.TempDir()
				request := checkpointOperationRequest("op-abort-v1", "sbox-abort-refuse", directory, "gen-1", 30)
				seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
					request, config.RuntimeNameRunsc, requestDigestOf(t, request),
					checkpointOperationPhaseUnknown, "outcome unproven, re-execution forbidden"))
				return newCheckpointOperationService(t, newAbortableRuntimeHandler(), root), "op-abort-v1"
			},
			"witness version 2": func(t *testing.T) (*sandboxService, string) {
				root := t.TempDir()
				request := checkpointOperationRequest("op-abort-v2", "sbox-abort-refuse", directory, "gen-1", 30)
				seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
				return newCheckpointOperationService(t, newAbortableRuntimeHandler(), root), "op-abort-v2"
			},
			"succeeded version 3": func(t *testing.T) (*sandboxService, string) {
				root := t.TempDir()
				request := checkpointOperationRequest("op-abort-succeeded", "sbox-abort-refuse", directory, "gen-1", 30)
				seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseSucceeded, false,
					&checkpointOperationArtifact{RootDigest: repeatHex(64), Scheme: checkpointroot.Scheme})
				return newCheckpointOperationService(t, newAbortableRuntimeHandler(), root), "op-abort-succeeded"
			},
			"ordinary failed version 3": func(t *testing.T) (*sandboxService, string) {
				root := t.TempDir()
				request := checkpointOperationRequest("op-abort-ordinary", "sbox-abort-refuse", directory, "gen-1", 30)
				seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseFailed, false, nil)
				return newCheckpointOperationService(t, newAbortableRuntimeHandler(), root), "op-abort-ordinary"
			},
		}
		for name, setup := range cases {
			s, operationID := setup(t)
			request := checkpointOperationRequest(operationID, "sbox-abort-refuse", directory, "gen-1", 30)
			_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
			aborts, acks := abortCounts(t, s)
			assert.Zero(t, aborts, name)
			assert.Zero(t, acks, name)
		}

		// A FAILED version-3 record is refused by recovery too — an ordinary
		// failure is terminal for both directions.
		root := t.TempDir()
		failedRequest := checkpointOperationRequest("op-abort-ordinary", "sbox-abort-refuse", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, root, failedRequest, checkpointOperationPhaseFailed, false, nil)
		failed := newCheckpointOperationService(t, newAbortableRuntimeHandler(), root)
		_, err := failed.RecoverCheckpointOperation(
			context.Background(), witnessRecoveryRequest(failedRequest, 30))
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "cannot be recovered")
	})

	t.Run("a runtime without the aborter capability is a hard refusal", func(t *testing.T) {
		root := t.TempDir()
		request := checkpointOperationRequest(
			"op-abort-no-aborter", "sbox-abort-refuse", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		// The witness-only fake: no AbortCheckpointOperation method.
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		assert.Equal(t, codes.Unimplemented, status.Code(err))
		assert.ErrorContains(t, err, "does not support explicit checkpoint operation aborts")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-abort-no-aborter").Phase)
	})
}

// abortCounts reads a service's recorded abort interactions through the
// handler map, when the registered handler is the abortable fake.
func abortCounts(t *testing.T, s *sandboxService) (aborts, acks int) {
	t.Helper()
	handler, ok := s.serviceHandler.Get(config.RuntimeNameRunsc)
	if !ok {
		return 0, 0
	}
	abortable, ok := handler.(*abortableRuntimeHandler)
	if !ok {
		return 0, 0
	}
	return len(abortable.recordedAborts()), len(abortable.recordedAckAborteds())
}

// --- honest failures and retries ---

// TestAbortCheckpointOperationFailuresAndRetry pins that every failure keeps
// the exact durable fact and answers with an error — never a false release —
// and that the same abort retries to completion.
func TestAbortCheckpointOperationFailuresAndRetry(t *testing.T) {
	t.Run("runtime abort failure aborts nothing", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-rt-fail", "sbox-abort-retry")
		var failAborts atomic.Bool
		handler.abortFn = func(context.Context, string, svc.CheckpointOperationBinding) error {
			if failAborts.Load() {
				return errors.New("source sandbox is gone")
			}
			return nil
		}
		failAborts.Store(true)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.Error(t, err)
		assert.ErrorContains(t, err, "abort checkpoint operation")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-rt-fail").Phase)
		assert.Empty(t, handler.recordedAckAborteds(), "no acknowledgment without a confirmed failure")

		failAborts.Store(false)
		aborted, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
		assert.True(t, aborted.GetEvidenceReleased())
		assert.Len(t, handler.recordedAborts(), 2, "the retried abort re-drives the runtime's same decision")
	})

	t.Run("persist failure keeps the outcome undetermined and retryable", func(t *testing.T) {
		s, _, request := seedUndeterminedAbortable(t, "op-abort-persist", "sbox-abort-retry")
		var failConfirmed atomic.Bool
		s.checkpointOperations.persistHook = func(r *checkpointOperationRecord) error {
			if r.AbortConfirmed && failConfirmed.Load() {
				return errors.New("journal fsync failed")
			}
			return s.checkpointOperations.durablyWrite(r)
		}
		failConfirmed.Store(true)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.Error(t, err)
		assert.ErrorContains(t, err, "persist the confirmed abort")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-persist").Phase)

		failConfirmed.Store(false)
		aborted, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
		assert.True(t, aborted.GetEvidenceReleased())
		assert.Equal(t, checkpointOperationPhaseFailed,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-persist").Phase)
	})

	t.Run("an ambiguous persist stays honest across a restart", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-ambiguous", "sbox-abort-retry")
		var ambiguous atomic.Bool
		s.checkpointOperations.persistHook = func(r *checkpointOperationRecord) error {
			if !r.AbortConfirmed || !ambiguous.Load() {
				return s.checkpointOperations.durablyWrite(r)
			}
			if err := s.checkpointOperations.durablyWrite(r); err != nil {
				return err
			}
			return errors.New("directory fsync failed after the rename")
		}
		ambiguous.Store(true)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.Error(t, err, "an ambiguous write must not be reported as a release")
		require.Len(t, handler.recordedAborts(), 1)
		require.Empty(t, handler.recordedAckAborteds(), "the gate is never released for an unproven fact")

		// The write landed: after a restart the durable confirmed failure
		// answers, and the retry is acknowledgment-only — the runtime abort is
		// never re-driven and the recorded fact is not rewritten.
		restartedHandler := newAbortableRuntimeHandler()
		restarted := newCheckpointOperationService(t, restartedHandler, s.config.RootDir)
		durable := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-ambiguous")
		require.Equal(t, checkpointOperationPhaseFailed, durable.Phase)
		require.True(t, durable.AbortConfirmed)
		aborted, aerr := restarted.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
		assert.True(t, aborted.GetEvidenceReleased())
		assert.Empty(t, restartedHandler.recordedAborts())
		require.Len(t, restartedHandler.recordedAckAborteds(), 1)
		assert.Equal(t, durable, readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-ambiguous"),
			"an acknowledgment-only retry rewrites nothing")
	})

	t.Run("acknowledgment failure keeps the confirmed fact, NotFound included", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-ack-fail", "sbox-abort-retry")
		var failAcks atomic.Bool
		var notFound atomic.Bool
		handler.ackAbortedFn = func(context.Context, string, svc.CheckpointOperationBinding) error {
			if notFound.Load() {
				return errord.ErrNotFound
			}
			if failAcks.Load() {
				return errors.New("witness storage unwritable")
			}
			return nil
		}
		// A missing Ack target is NOT a release.
		notFound.Store(true)
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.Error(t, err)
		assert.ErrorContains(t, err, "acknowledge the aborted checkpoint operation")
		record := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-ack-fail")
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase,
			"the confirmed failure stays durable even when the acknowledgment fails")

		// The retry re-enters through the acknowledgment-only slot and
		// completes the release; the runtime abort is not repeated.
		notFound.Store(false)
		failAcks.Store(true)
		_, err = s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.Error(t, err)
		failAcks.Store(false)
		aborted, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
		assert.True(t, aborted.GetEvidenceReleased())
		assert.Len(t, handler.recordedAborts(), 1, "the abort itself ran exactly once")
		assert.Len(t, handler.recordedAckAborteds(), 3)
	})
}

// --- the acknowledgment-only slot ---

// TestAbortCheckpointOperationAckOnlySlot pins the retry shape of a confirmed
// record: AckAborted alone — no runtime abort, no artifact access, no rewrite
// of the recorded outcome — and only the successful call claims the release.
func TestAbortCheckpointOperationAckOnlySlot(t *testing.T) {
	root := t.TempDir()
	request := checkpointOperationRequest(
		"op-abort-ackonly", "sbox-abort-ackonly", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	seeded := seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseFailed, true, nil)
	handler := newAbortableRuntimeHandler()
	s := newCheckpointOperationService(t, handler, root)

	aborted, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, aborted.GetState())
	assert.True(t, aborted.GetAbortConfirmed())
	assert.True(t, aborted.GetEvidenceReleased())
	assert.Empty(t, handler.recordedAborts(), "an acknowledgment-only slot never re-drives the abort")
	require.Len(t, handler.recordedAckAborteds(), 1)
	assert.Equal(t, "sbox-abort-ackonly", handler.recordedAckAborteds()[0].sandboxID)
	// No artifact was touched: neither a checkpoint nor a witness recovery ran.
	assert.Zero(t, handler.checkpointCount())
	recovers, _ := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Equal(t, seeded, readJournalCheckpointOperation(t, root, "op-abort-ackonly"),
		"the acknowledgment-only retry rewrites nothing, not even updated_at")
}

// --- shared execution and joins ---

// TestAbortCheckpointOperationSharedExecution pins the single-executor
// contract from the RPC side: an abort joins a live original execution and a
// live recovery instead of acting beside them, and concurrent aborts converge
// on one abort with idempotent acknowledgments.
func TestAbortCheckpointOperationSharedExecution(t *testing.T) {
	t.Run("an abort joins the original execution and then refuses the success", func(t *testing.T) {
		handler := newAbortableRuntimeHandler()
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
			if err := writeSealedCheckpointDirectory(config.Directory); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		}
		root := t.TempDir()
		s := newCheckpointOperationService(t, handler, root)
		storeCheckpointOperationSandbox(t, s, "sbox-abort-join", "gen-1")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-join", "sbox-abort-join", directory, "gen-1", 30)

		executorDone := make(chan error, 1)
		go func() {
			_, err := s.CheckpointWithOperation(context.Background(), request)
			executorDone <- err
		}()
		awaitCheckpointOperationSignal(t, entered)

		abortDone := make(chan error, 1)
		go func() {
			_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
			abortDone <- err
		}()
		select {
		case err := <-abortDone:
			t.Fatalf("the abort answered while the original execution still ran: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		// The join never revokes the running work: the original completes and
		// the abort then refuses the recorded success honestly.
		releaseOnce.Do(func() { close(release) })
		require.NoError(t, <-executorDone)
		err := <-abortDone
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "recorded succeeded")
		assert.Empty(t, handler.recordedAborts(), "no abort ran beside the original execution")
		assert.Equal(t, 1, handler.checkpointCount())
		assert.Equal(t, checkpointOperationPhaseSucceeded,
			readJournalCheckpointOperation(t, root, "op-abort-join").Phase)
	})

	t.Run("an abort joins a recovery executor and aborts after it releases nothing", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-join-rec", "sbox-abort-join")
		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)

		abortDone := make(chan error, 1)
		go func() {
			_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
			abortDone <- err
		}()
		select {
		case err := <-abortDone:
			t.Fatalf("the abort answered while a recovery held the slot: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		// The recovery releases its slot without proving anything; the joined
		// abort then wins the slot and runs the protocol.
		recovery.finish()
		require.NoError(t, <-abortDone)
		assert.Len(t, handler.recordedAborts(), 1)
		assert.True(t, readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-join-rec").AbortConfirmed)
	})

	t.Run("concurrent aborts share one execution", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-join-race", "sbox-abort-join")
		const callers = 3
		replies := make(chan *runtime.CheckpointOperationStatus, callers)
		errs := make(chan error, callers)
		started := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-started
				aborted, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
				if err != nil {
					errs <- err
					return
				}
				replies <- aborted
			}()
		}
		close(started)
		wg.Wait()
		close(replies)
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		require.Len(t, replies, callers)
		for aborted := range replies {
			assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, aborted.GetState())
			assert.True(t, aborted.GetAbortConfirmed())
			assert.True(t, aborted.GetEvidenceReleased(),
				"every caller that completed an acknowledgment itself reports the release")
		}
		// The runtime abort ran exactly once; the joiners re-admitted into
		// acknowledgment-only slots and acknowledged idempotently.
		assert.Len(t, handler.recordedAborts(), 1)
		assert.Len(t, handler.recordedAckAborteds(), callers)
		assert.True(t, readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-join-race").AbortConfirmed)
	})
}

// --- deadlines and shutdown ---

// TestAbortCheckpointOperationDeadlines pins the one shared budget: an expired
// context never wins a slot, the admission-lock queue and the physical
// source-lock queue both answer the deadline, and a refused abort mutates
// nothing.
func TestAbortCheckpointOperationDeadlines(t *testing.T) {
	t.Run("an expired context never wins a slot", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-expired", "sbox-abort-budget")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := s.AbortCheckpointOperation(ctx, abortRequest(request, 30))
		assert.Equal(t, codes.Canceled, status.Code(err))
		assert.Empty(t, handler.recordedAborts())
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-expired").Phase)
	})

	t.Run("a held admission lock is answered by the budget", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-admlock", "sbox-abort-budget")
		s.checkpointOperations.writeMu.Lock()
		started := time.Now()
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 1))
		elapsed := time.Since(started)
		s.checkpointOperations.writeMu.Unlock()
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Less(t, elapsed, 1800*time.Millisecond,
			"the abort must answer its requested budget (took %s)", elapsed)
		assert.Empty(t, handler.recordedAborts())
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-admlock").Phase)

		aborted, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, aerr)
		assert.True(t, aborted.GetAbortConfirmed())
	})

	t.Run("a held physical source lock is answered by the budget", func(t *testing.T) {
		s, handler, request := seedUndeterminedAbortable(t, "op-abort-physlock", "sbox-abort-budget")
		unlock, err := s.resourceLocks.acquire(context.Background(), "sbox-abort-budget")
		require.NoError(t, err)
		started := time.Now()
		_, aerr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 1))
		elapsed := time.Since(started)
		unlock()
		assert.Equal(t, codes.DeadlineExceeded, status.Code(aerr))
		assert.Less(t, elapsed, 1800*time.Millisecond,
			"the abort must answer its requested budget (took %s)", elapsed)
		assert.Empty(t, handler.recordedAborts(), "the runtime is never entered without the physical lock")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-physlock").Phase)

		aborted, retryErr := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 30))
		require.NoError(t, retryErr)
		assert.True(t, aborted.GetAbortConfirmed())
	})
}

// TestAbortCheckpointOperationShutdownConvergence pins the drain: shutdown
// cancels the abort executor to request convergence and waits for its REAL
// exit — a callee that ignores the cancellation keeps shutdown blocked until
// the work actually returns, and the slot is never revoked early.
func TestAbortCheckpointOperationShutdownConvergence(t *testing.T) {
	s, handler, request := seedUndeterminedAbortable(t, "op-abort-drain", "sbox-abort-drain")
	abortEntered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var observedCancel atomic.Bool
	handler.abortFn = func(ctx context.Context, _ string, _ svc.CheckpointOperationBinding) error {
		close(abortEntered)
		<-release
		observedCancel.Store(ctx.Err() != nil)
		return nil
	}

	abortDone := make(chan error, 1)
	go func() {
		_, err := s.AbortCheckpointOperation(context.Background(), abortRequest(request, 60))
		abortDone <- err
	}()
	awaitCheckpointOperationSignal(t, abortEntered)

	shutdownDone := make(chan struct{})
	go func() {
		s.checkpointOperations.shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while the abort executor was still running")
	case <-time.After(200 * time.Millisecond):
	}
	// The convergence request does not revoke the slot: the executor finishes
	// the protocol — durable confirmed failure and acknowledgment — before it
	// returns, and only then does the drain complete.
	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-abortDone)
	assert.True(t, observedCancel.Load(), "shutdown did not cancel the abort executor")
	select {
	case <-shutdownDone:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not return after the abort executor exited")
	}
	record := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-drain")
	assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
	assert.True(t, record.AbortConfirmed)
}

// --- the abortable admission of the original RPC ---

// TestCheckpointWithOperationAbortableAdmission pins the version-3 admission
// through the public checkpoint RPC: the capability decides the version, the
// normal success path keeps its exact witness ordering and acknowledgment,
// and the abort flag stays false until an explicit abort confirms it.
func TestCheckpointWithOperationAbortableAdmission(t *testing.T) {
	handler := newAbortableRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-abort-admit", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-abort-admit", "sbox-abort-admit", directory, "gen-1", 30)

	reply, err := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, reply.GetState())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE,
		reply.GetRecoveryProtocol())
	assert.False(t, reply.GetAbortConfirmed(), "a success never carries an abort confirmation")
	assert.True(t, reply.GetEvidenceReleased(), "the first execution acknowledged in its own call")

	record := readJournalCheckpointOperation(t, root, "op-abort-admit")
	assert.Equal(t, checkpointOperationRecordVersionAbortable, record.Version)
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	require.NotNil(t, record.Artifact)
	assert.False(t, record.AbortConfirmed)
	// The success path uses the success acknowledgment, never the abort one,
	// and never drives an abort.
	assert.Equal(t, 1, handler.checkpointCount())
	recovers, witnessAcks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Equal(t, 1, witnessAcks)
	assert.Empty(t, handler.recordedAborts())
	assert.Empty(t, handler.recordedAckAborteds())

	// A replay reports the durable facts without the per-call release.
	replayed, rerr := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
	assert.False(t, replayed.GetAbortConfirmed())
	assert.False(t, replayed.GetEvidenceReleased())
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestAbortCheckpointOperationWireServesThePublicRPC drives the new RPC
// through a real gRPC client, proving the service registration and the wire
// shape beside the in-process calls above.
func TestAbortCheckpointOperationWireServesThePublicRPC(t *testing.T) {
	s, handler, request := seedUndeterminedAbortable(t, "op-abort-wire", "sbox-abort-wire")
	client := sourceReviewWireClient(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	aborted, err := client.AbortCheckpointOperation(ctx, abortRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, aborted.GetState())
	assert.True(t, aborted.GetAbortConfirmed())
	assert.True(t, aborted.GetEvidenceReleased())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE,
		aborted.GetRecoveryProtocol())
	assert.Len(t, handler.recordedAborts(), 1)
}
