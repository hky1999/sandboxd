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
	"fmt"
	"os"
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

// These tests cover the public service stage of the checkpoint operation
// recovery protocol: the RecoverCheckpointOperation RPC, the version-2
// admission contract of CheckpointWithOperation (writer+witness capability,
// exact runtime binding, acknowledge-after-durable-success), and the
// compatibility boundary against legacy version-1 records. The fake witness
// handler models the runtime half; nothing here is a real Firecracker
// acceptance.

// seedWitnessOperationRecord writes one durable version-2 journal record —
// the state a daemon restart or a spent witness-protocol operation leaves
// behind.
func seedWitnessOperationRecord(
	t *testing.T,
	root string,
	request *runtime.CheckpointWithOperationRequest,
	phase string,
	artifact *checkpointOperationArtifact,
) *checkpointOperationRecord {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := &checkpointOperationRecord{
		Version:       checkpointOperationRecordVersionWitness,
		OperationID:   request.GetOperationID(),
		SandboxID:     request.GetCheckpoint().GetID(),
		Generation:    request.GetExpectedGeneration(),
		Runtime:       config.RuntimeNameRunsc,
		CheckpointDir: filepath.Clean(request.GetCheckpoint().GetCheckpointDir()),
		RequestDigest: requestDigestOf(t, request),
		Phase:         phase,
		Artifact:      artifact,
		CreatedAt:     now,
		UpdatedAt:     now,
		Message:       "seeded witness-protocol record",
	}
	seedCheckpointOperationRecord(t, root, record)
	return record
}

// witnessRecoveryRequest wraps the complete, unchanged original request with
// a separate recovery timeout, exactly as the public RPC expects it.
func witnessRecoveryRequest(
	request *runtime.CheckpointWithOperationRequest,
	recoveryTimeout uint32,
) *runtime.RecoverCheckpointOperationRequest {
	return &runtime.RecoverCheckpointOperationRequest{
		Operation:              request,
		RecoveryTimeoutSeconds: recoveryTimeout,
	}
}

// sealedRootArtifact binds the directory through the shared algorithm and
// returns the completion artifact a recovery must land on.
func sealedRootArtifact(t *testing.T, directory string) *checkpointOperationArtifact {
	t.Helper()
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, writeSealedCheckpointDirectory(directory))
	root, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	return &checkpointOperationArtifact{RootDigest: root.RootDigest, Scheme: root.Scheme}
}

// --- the undetermined (admitted/unknown) version-2 record ---

// TestRecoverCheckpointOperationUndeterminedRecord: one explicit recovery of
// a version-2 UNKNOWN record drives the runtime witness exactly once with the
// exact admitted binding, verifies the returned root against the canonical
// directory, lands SUCCEEDED through the dedicated durable transition, then
// acknowledges — and only a successful reply reports evidence_released. The
// runtime checkpoint itself never re-executes, and the durable fact survives
// a restart.
func TestRecoverCheckpointOperationUndeterminedRecord(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	artifact := sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-unknown", "sbox-rec-rpc", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.witnessDirectory = directory
	s := newCheckpointOperationService(t, handler, root)

	recovered, err := s.RecoverCheckpointOperation(
		context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS, recovered.GetRecoveryProtocol())
	assert.True(t, recovered.GetEvidenceReleased(), "a successful recovery completed the acknowledgment itself")
	assert.Equal(t, artifact.RootDigest, recovered.GetArtifactRootDigest())

	// The witness saw exactly one recovery and one acknowledgment, both with
	// the exact admitted identity, and no checkpoint re-execution happened.
	recovers, acks := handler.witnessCounts()
	assert.Equal(t, 1, recovers)
	assert.Equal(t, 1, acks)
	assert.Zero(t, handler.checkpointCount())
	digest := requestDigestOf(t, request)
	binding := svc.CheckpointOperationBinding{
		OperationID:      "op-rec-rpc-unknown",
		RequestDigest:    digest,
		SourceGeneration: "gen-1",
		// The binding carries the canonical directory of the durable record.
		CheckpointDir: directory,
	}
	assert.Equal(t, []svc.CheckpointOperationBinding{binding}, handler.recordedRecovers())
	assert.Equal(t, []svc.CheckpointOperationBinding{binding}, handler.recordedAcks())

	record := readJournalCheckpointOperation(t, root, "op-rec-rpc-unknown")
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	assert.Equal(t, checkpointOperationRecordVersionWitness, record.Version)
	require.NotNil(t, record.Artifact)
	assert.Equal(t, artifact.RootDigest, record.Artifact.RootDigest)

	// The durable fact answers a later query from history, with no
	// evidence_released claim of its own.
	queried, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-rpc-unknown"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
	assert.False(t, queried.GetEvidenceReleased(), "a read-only query never claims a release")
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS, queried.GetRecoveryProtocol())

	// After a restart the same recovery is acknowledgment-only history.
	restartedHandler := newCheckpointOperationRuntimeHandler()
	restartedHandler.witnessDirectory = directory
	restarted := newCheckpointOperationService(t, restartedHandler, root)
	again, err := restarted.RecoverCheckpointOperation(
		context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, again.GetState())
	assert.True(t, again.GetEvidenceReleased())
	recovers, acks = restartedHandler.witnessCounts()
	assert.Zero(t, recovers, "a SUCCEEDED record is never recovered at the runtime again")
	assert.Equal(t, 1, acks)
	assert.Zero(t, restartedHandler.checkpointCount())
	assert.Equal(t, artifact.RootDigest,
		readJournalCheckpointOperation(t, root, "op-rec-rpc-unknown").Artifact.RootDigest)
}

// TestRecoverCheckpointOperationRootMustBindCanonicalDirectory: the runtime's
// recorded root is only accepted when it equals the shared algorithm's root of
// the service's canonical directory; anything else is a conflict that leaves
// the record undetermined and never acknowledges.
func TestRecoverCheckpointOperationRootMustBindCanonicalDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-rootconflict", "sbox-rec-rpc", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.recoverFn = func(context.Context, string, svc.CheckpointOperationBinding) (svc.CheckpointOperationCompletion, error) {
		return svc.CheckpointOperationCompletion{
			RootDigest: conflictingDigest(t, mustBindRoot(t, directory)),
			RootScheme: checkpointroot.Scheme,
		}, nil
	}
	s := newCheckpointOperationService(t, handler, root)

	_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "refusing to record a success")
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-rec-rpc-rootconflict").Phase)
	recovers, acks := handler.witnessCounts()
	assert.Equal(t, 1, recovers)
	assert.Zero(t, acks, "a conflicting root is never acknowledged")
}

// mustBindRoot is the test-side shorthand for the shared root algorithm.
func mustBindRoot(t *testing.T, directory string) string {
	t.Helper()
	root, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	return root.RootDigest
}

// --- the SUCCEEDED version-2 record: acknowledgment only ---

// TestRecoverCheckpointOperationSucceededIsAckOnly: a durable success owes
// only its acknowledgment. The recorded artifact stays the authority — the
// directory may already be gone — so the runtime Recover is never called and
// nothing about the receipt is rewritten.
func TestRecoverCheckpointOperationSucceededIsAckOnly(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	artifact := sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-ackonly", "sbox-rec-rpc", directory, "gen-1", 30)
	seeded := seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseSucceeded, artifact)
	// The artifact directory was garbage-collected after the success became
	// durable: an acknowledgment-only recovery must not re-read it.
	require.NoError(t, os.RemoveAll(directory))
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, root)

	recovered, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
	assert.True(t, recovered.GetEvidenceReleased())
	assert.Equal(t, artifact.RootDigest, recovered.GetArtifactRootDigest())
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers, "a SUCCEEDED record never runs the runtime recovery")
	assert.Equal(t, 1, acks)
	assert.Zero(t, handler.checkpointCount())

	record := readJournalCheckpointOperation(t, root, "op-rec-rpc-ackonly")
	assert.Equal(t, seeded.UpdatedAt, record.UpdatedAt, "an acknowledgment must not rewrite the receipt")
	assert.Equal(t, artifact.RootDigest, record.Artifact.RootDigest)
}

// TestRecoverCheckpointOperationAckFailuresKeepsSuccess: a failed (or
// NotFound) acknowledgment never downgrades the durable success and never
// fabricates evidence_released; the RPC fails with the record retained, and a
// later recovery of the same operation completes the release.
func TestRecoverCheckpointOperationAckFailuresKeepsSuccess(t *testing.T) {
	t.Run("ack fails after a recovered success", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		artifact := sealedRootArtifact(t, directory)
		request := checkpointOperationRequest("op-rec-rpc-ackfail", "sbox-rec-rpc", directory, "gen-1", 30)
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		handler := newCheckpointOperationRuntimeHandler()
		handler.witnessDirectory = directory
		handler.ackFn = func(context.Context, string, svc.CheckpointOperationBinding) error {
			return errors.New("acknowledge: evidence store unavailable")
		}
		s := newCheckpointOperationService(t, handler, root)

		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.Error(t, err)
		assert.ErrorContains(t, err, "acknowledge the recovered checkpoint operation")
		assert.ErrorContains(t, err, "is not downgraded")
		// The success landed durably; only the release is unproven.
		record := readJournalCheckpointOperation(t, root, "op-rec-rpc-ackfail")
		assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
		require.NotNil(t, record.Artifact)
		assert.Equal(t, artifact.RootDigest, record.Artifact.RootDigest)
		queried, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-rpc-ackfail"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
		assert.False(t, queried.GetEvidenceReleased())

		// A retry of the same recovery is acknowledgment-only and finishes the
		// release through the retained success.
		handler.ackFn = nil
		recovered, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.NoError(t, err)
		assert.True(t, recovered.GetEvidenceReleased())
		recovers, acks := handler.witnessCounts()
		assert.Equal(t, 1, recovers)
		assert.Equal(t, 2, acks)
		assert.Zero(t, handler.checkpointCount())
	})

	t.Run("ack target missing is not a release", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		artifact := sealedRootArtifact(t, directory)
		request := checkpointOperationRequest("op-rec-rpc-ackmissing", "sbox-rec-rpc", directory, "gen-1", 30)
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseSucceeded, artifact)
		handler := newCheckpointOperationRuntimeHandler()
		handler.ackFn = func(context.Context, string, svc.CheckpointOperationBinding) error {
			return fmt.Errorf("checkpoint operation has no runtime state: %w", errord.ErrNotFound)
		}
		s := newCheckpointOperationService(t, handler, root)

		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.Error(t, err)
		assert.ErrorContains(t, err, "evidence release is unproven")
		record := readJournalCheckpointOperation(t, root, "op-rec-rpc-ackmissing")
		assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
		assert.Equal(t, artifact.RootDigest, record.Artifact.RootDigest)
		_, acks := handler.witnessCounts()
		assert.Equal(t, 1, acks)
	})
}

// --- refusals ---

// TestRecoverCheckpointOperationRefusals pins the fail-closed admission set of
// the public recovery: a missing record, a FAILED record, a rewritten payload
// (the digest is recomputed from the presented request — a caller-echoed
// digest is never consulted), and malformed input are all refused with zero
// side effects.
func TestRecoverCheckpointOperationRefusals(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-refuse", "sbox-rec-rpc", directory, "gen-1", 30)

	t.Run("missing record is NotFound", func(t *testing.T) {
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), t.TempDir())
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("failed record is refused forever", func(t *testing.T) {
		root := t.TempDir()
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseFailed, nil)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "cannot be recovered")
	})

	t.Run("rewritten payload refuses the operation ID", func(t *testing.T) {
		root := t.TempDir()
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		handler := newCheckpointOperationRuntimeHandler()
		handler.witnessDirectory = directory
		s := newCheckpointOperationService(t, handler, root)
		// The recovery timeout replaces the original checkpoint timeout in
		// the caller's flags — the wrapped request must still repeat the
		// ORIGINAL timeout or the digest changes and the recovery is refused.
		rewritten := checkpointOperationRequest("op-rec-rpc-refuse", "sbox-rec-rpc", directory, "gen-1", 31)
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(rewritten, 300))
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "bound to a different request")
		// A different recovery timeout over the SAME original payload is fine.
		recovered, rerr := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 7))
		if assert.NoError(t, rerr) {
			assert.True(t, recovered.GetEvidenceReleased())
		}
	})

	invalid := map[string]func() *runtime.RecoverCheckpointOperationRequest{
		"zero recovery timeout": func() *runtime.RecoverCheckpointOperationRequest {
			return witnessRecoveryRequest(request, 0)
		},
		"excessive recovery timeout": func() *runtime.RecoverCheckpointOperationRequest {
			return witnessRecoveryRequest(request, checkpointOperationMaxTimeoutSeconds+1)
		},
		"missing original request": func() *runtime.RecoverCheckpointOperationRequest {
			return &runtime.RecoverCheckpointOperationRequest{RecoveryTimeoutSeconds: 30}
		},
		"leave-running original": func() *runtime.RecoverCheckpointOperationRequest {
			leaveRunning := checkpointOperationRequest("op-rec-rpc-refuse", "sbox-rec-rpc", directory, "gen-1", 30)
			leaveRunning.Checkpoint.LeaveRunning = true
			return witnessRecoveryRequest(leaveRunning, 30)
		},
	}
	for name, build := range invalid {
		t.Run(name, func(t *testing.T) {
			s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), t.TempDir())
			_, err := s.RecoverCheckpointOperation(context.Background(), build())
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestRecoverCheckpointOperationLegacyRecordRefused: a legacy version-1 record
// has no runtime witness, so explicit recovery refuses it — for UNKNOWN (the
// outcome cannot be proven) and for SUCCEEDED (no acknowledgment target
// exists) alike — while the historical query and the same-request replay keep
// answering exactly as before, without touching the runtime.
func TestRecoverCheckpointOperationLegacyRecordRefused(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	artifact := sealedRootArtifact(t, directory)
	handler := newCheckpointOperationRuntimeHandler()
	unknownRequest := checkpointOperationRequest("op-rec-rpc-legacy-unknown", "sbox-rec-rpc", directory, "gen-1", 30)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		unknownRequest, config.RuntimeNameRunsc, requestDigestOf(t, unknownRequest),
		checkpointOperationPhaseUnknown, "outcome unproven; re-execution forbidden"))
	succeededRequest := checkpointOperationRequest("op-rec-rpc-legacy-done", "sbox-rec-rpc", directory, "gen-1", 30)
	seeded := seededCheckpointOperationRecord(
		succeededRequest, config.RuntimeNameRunsc, requestDigestOf(t, succeededRequest),
		checkpointOperationPhaseSucceeded, "checkpoint completed; sealed content root is a completion-time fact")
	seeded.Artifact = artifact
	seedCheckpointOperationRecord(t, root, seeded)
	s := newCheckpointOperationService(t, handler, root)

	for name, request := range map[string]*runtime.CheckpointWithOperationRequest{
		"unknown":   unknownRequest,
		"succeeded": succeededRequest,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.ErrorContains(t, err, "legacy version-1 record")
			assert.ErrorContains(t, err, "cannot be proven recoverable")
		})
	}
	// History stays pure: the query answers from the record, the replay
	// repeats it, and the runtime witness is never contacted.
	queried, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: unknownRequest.GetOperationID()})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED, queried.GetRecoveryProtocol())
	assert.False(t, queried.GetEvidenceReleased())
	replayed, rerr := s.CheckpointWithOperation(context.Background(), succeededRequest)
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED, replayed.GetRecoveryProtocol())
	assert.False(t, replayed.GetEvidenceReleased())
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Zero(t, acks)
	assert.Zero(t, handler.checkpointCount())
}

// TestRecoverCheckpointOperationSourceMetadataConflict: when the source
// sandbox is still managed on this node, its live metadata must still answer
// for the recorded runtime and generation; a replaced incarnation is refused
// before the runtime is touched. An absent source is legitimate and proceeds.
func TestRecoverCheckpointOperationSourceMetadataConflict(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "checkpoint")
	artifact := sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-source", "sbox-rec-rpc-src", directory, "gen-1", 30)

	t.Run("replaced generation is refused", func(t *testing.T) {
		root := t.TempDir()
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		handler := newCheckpointOperationRuntimeHandler()
		s := newCheckpointOperationService(t, handler, root)
		storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-src", "gen-2")
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "replaced source")
		recovers, acks := handler.witnessCounts()
		assert.Zero(t, recovers)
		assert.Zero(t, acks)
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-rpc-source").Phase)
	})

	t.Run("re-created sandbox under another runtime is refused", func(t *testing.T) {
		root := t.TempDir()
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		handler := newCheckpointOperationRuntimeHandler()
		s := newCheckpointOperationService(t, handler, root)
		require.NoError(t, s.sandboxManager.StoreMetadata("sbox-rec-rpc-src", &runtime.SandboxMetadata{
			ID:             "sbox-rec-rpc-src",
			RuntimeHandler: config.RuntimeNameFirecracker,
			Labels:         map[string]string{resourceGenerationLabel: "gen-1"},
		}))
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "replaced source")
		recovers, _ := handler.witnessCounts()
		assert.Zero(t, recovers)
	})

	t.Run("absent source proceeds and matches the record", func(t *testing.T) {
		root := t.TempDir()
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseSucceeded, artifact)
		require.NoError(t, os.RemoveAll(directory))
		handler := newCheckpointOperationRuntimeHandler()
		s := newCheckpointOperationService(t, handler, root)
		recovered, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.NoError(t, err)
		assert.True(t, recovered.GetEvidenceReleased())
		_, acks := handler.witnessCounts()
		assert.Equal(t, 1, acks)
	})
}

// TestRecoverCheckpointOperationRequiresWitnessRuntime: a handler without the
// witness capability is a hard refusal — never a legacy checkpoint fallback —
// and a runtime name absent from the handler map is refused too.
func TestRecoverCheckpointOperationRequiresWitnessRuntime(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)

	t.Run("writer-only runtime is refused without fallback", func(t *testing.T) {
		root := t.TempDir()
		request := checkpointOperationRequest("op-rec-rpc-nowitness", "sbox-rec-rpc", directory, "gen-1", 30)
		seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		// A writer-only handler: it implements CheckpointHandler and
		// CheckpointOperationWriter but not CheckpointOperationWitness.
		writerOnly := &writerOnlyCheckpointHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		s := newCheckpointOperationService(t, writerOnly, root)
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		require.Equal(t, codes.Unimplemented, status.Code(err))
		assert.ErrorContains(t, err, "witness")
		assert.ErrorContains(t, err, "no checkpoint fallback")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-rpc-nowitness").Phase)
		assert.Zero(t, writerOnly.checkpointCount(), "a refusal never executes a checkpoint")
	})

	t.Run("unknown runtime is refused", func(t *testing.T) {
		root := t.TempDir()
		request := checkpointOperationRequest("op-rec-rpc-noruntime", "sbox-rec-rpc", directory, "gen-1", 30)
		record := seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
		record.Runtime = config.RuntimeNameFirecracker
		resignRecord(t, root, record)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		assert.Equal(t, codes.Unimplemented, status.Code(err))
	})
}

// writerOnlyCheckpointHandler models a runtime that writes sealed,
// root-bindable checkpoints but records no operation witnesses: it implements
// CheckpointHandler and CheckpointOperationWriter only.
type writerOnlyCheckpointHandler struct {
	*svc.FakeRuntimeHandler

	mu          sync.Mutex
	checkpoints []svc.CheckpointConfig
}

func (h *writerOnlyCheckpointHandler) Restore(context.Context, svc.StartConfig) error {
	return errors.New("restore is not exercised by checkpoint operation tests")
}

func (h *writerOnlyCheckpointHandler) Checkpoint(_ context.Context, config svc.CheckpointConfig) error {
	h.mu.Lock()
	h.checkpoints = append(h.checkpoints, config)
	h.mu.Unlock()
	return writeSealedCheckpointDirectory(config.Directory)
}

func (h *writerOnlyCheckpointHandler) SupportsCheckpointOperations() bool { return true }

func (h *writerOnlyCheckpointHandler) checkpointCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.checkpoints)
}

// resignRecord rewrites one durable record after an in-place mutation.
func resignRecord(t *testing.T, root string, record *checkpointOperationRecord) {
	t.Helper()
	seedCheckpointOperationRecord(t, root, record)
}

// --- joining the original execution ---

// TestRecoverCheckpointOperationJoinsOriginalExecution: while the original
// admitted execution runs, the recovery joins it — no second executor, no
// runtime recovery beside the real one — and once the original lands its
// durable success (and its own acknowledgment), the re-admitted recovery
// settles for the idempotent acknowledgment-only half.
func TestRecoverCheckpointOperationJoinsOriginalExecution(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
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
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-join", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-rpc-join", "sbox-rec-rpc-join", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	recoveryDone := make(chan *runtime.CheckpointOperationStatus, 1)
	recoveryErr := make(chan error, 1)
	go func() {
		recovered, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
		if err != nil {
			recoveryErr <- err
			return
		}
		recoveryDone <- recovered
	}()
	// The recovery is inside the join: the original executor still owns the
	// operation, and no second runtime interaction has happened.
	time.Sleep(150 * time.Millisecond)
	_, running := s.checkpointOperations.executionDone("op-rec-rpc-join")
	require.True(t, running)
	recovers, _ := handler.witnessCounts()
	assert.Zero(t, recovers)

	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-executorDone)
	select {
	case err := <-recoveryErr:
		t.Fatalf("the joined recovery failed: %v", err)
	case recovered := <-recoveryDone:
		require.NotNil(t, recovered)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
		assert.True(t, recovered.GetEvidenceReleased())
	case <-time.After(10 * time.Second):
		t.Fatal("the recovery did not settle after the original execution")
	}
	// One checkpoint execution; the original acknowledged its own success and
	// the recovery repeated that release idempotently; the runtime recovery
	// was never needed.
	assert.Equal(t, 1, handler.checkpointCount())
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Equal(t, 2, acks)
}

// TestRecoverCheckpointOperationCallerCancelEndsOnlyTheWait: cancelling the
// recovery caller while it joins the original execution ends only that wait;
// the original keeps its slot, finishes its work and its own acknowledgment,
// and nothing is left running behind the cancelled call.
func TestRecoverCheckpointOperationCallerCancelEndsOnlyTheWait(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
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
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-cancel", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-rpc-cancel", "sbox-rec-rpc-cancel", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	ctx, cancel := context.WithCancel(context.Background())
	cancelDone := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(ctx, witnessRecoveryRequest(request, 30))
		cancelDone <- err
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case err := <-cancelDone:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled recovery did not return")
	}
	// The original execution is untouched and still owns the operation.
	_, running := s.checkpointOperations.executionDone("op-rec-rpc-cancel")
	require.True(t, running)
	runningStatus, err := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-rpc-cancel"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING, runningStatus.GetState())

	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-executorDone)
	final, err := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-rpc-cancel"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, final.GetState())
	assert.Equal(t, 1, handler.checkpointCount())
	_, acks := handler.witnessCounts()
	assert.Equal(t, 1, acks, "only the original execution acknowledged")
}

// TestRecoverCheckpointOperationJoinDeadlineIsBounded: when the joined
// original execution outlives the recovery deadline, the recovery fails with
// DeadlineExceeded having reconciled nothing and left the operation unchanged.
func TestRecoverCheckpointOperationJoinDeadlineIsBounded(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
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
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-deadline", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-rpc-deadline", "sbox-rec-rpc-deadline", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	recoveryErr := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 1))
		recoveryErr <- err
	}()
	// Outlive the one-second recovery deadline, then let the original finish.
	time.Sleep(1300 * time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-executorDone)
	select {
	case err := <-recoveryErr:
		require.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.ErrorContains(t, err, "recovery deadline")
	case <-time.After(5 * time.Second):
		t.Fatal("the recovery did not observe its deadline")
	}
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Equal(t, 1, acks, "only the original execution's acknowledgment ran")
}

// TestRecoverCheckpointOperationJoinConsumesSharedBudget: the budget the
// joined original execution consumed is the recovery's budget too. The slot
// won after the join carries the SAME absolute deadline — never a fresh
// timeout — so the post-join acknowledgment that outlives the deadline is cut
// off at the requested time and the durable receipt is rewritten nothing.
func TestRecoverCheckpointOperationJoinConsumesSharedBudget(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
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
	// The original execution's own acknowledgment succeeds; only the
	// recovery's second call blocks on its context, proving the deadline
	// reached the work context after the slot was won.
	var acks atomic.Int64
	handler.ackFn = func(ctx context.Context, _ string, _ svc.CheckpointOperationBinding) error {
		if acks.Add(1) == 1 {
			return nil
		}
		<-ctx.Done()
		return ctx.Err()
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-budget", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-rpc-budget", "sbox-rec-rpc-budget", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)
	time.Sleep(100 * time.Millisecond)

	started := time.Now()
	recoveryErr := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 1))
		recoveryErr <- err
	}()
	// The original finishes at ~600ms of the one-second recovery budget.
	time.Sleep(500 * time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-executorDone)
	select {
	case err := <-recoveryErr:
		require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("the recovery did not observe its shared deadline")
	}
	elapsed := time.Since(started)
	assert.GreaterOrEqual(t, elapsed, time.Second, "the deadline must be honored, not cut short")
	assert.Less(t, elapsed, 1800*time.Millisecond,
		"a fresh timeout after the join would have pushed the acknowledgment past the requested deadline (took %s)", elapsed)
	// The durable receipt of the original execution is untouched, and no
	// runtime recovery ever ran.
	recovers, ackCalls := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Equal(t, 2, ackCalls)
	record := readJournalCheckpointOperation(t, s.config.RootDir, "op-rec-rpc-budget")
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestRecoverCheckpointOperationVerifiesSourceAfterLockQueue: the source
// metadata binding is read under the physical lock, after the queue wait — a
// sandbox replaced while the recovery sat in the lock queue is refused before
// any witness call, never validated against a stale pre-lock read.
func TestRecoverCheckpointOperationVerifiesSourceAfterLockQueue(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-rpc-queue", "sbox-rec-rpc-queue", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.witnessDirectory = directory
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-queue", "gen-1")

	// Hold the physical lock so the recovery queues behind it.
	lockCtx, lockCancel := context.WithCancel(context.Background())
	unlock, err := s.resourceLocks.acquire(lockCtx, "sbox-rec-rpc-queue")
	require.NoError(t, err)

	recoveryDone := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 10))
		recoveryDone <- err
	}()
	// The recovery is queued on the physical lock; replace the source
	// generation underneath it.
	time.Sleep(200 * time.Millisecond)
	recovers, _ := handler.witnessCounts()
	require.Zero(t, recovers, "the queued recovery must not have reached the runtime")
	storeCheckpointOperationSandbox(t, s, "sbox-rec-rpc-queue", "gen-2")
	unlock()
	lockCancel()

	select {
	case err := <-recoveryDone:
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "replaced source")
	case <-time.After(10 * time.Second):
		t.Fatal("the queued recovery did not settle")
	}
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers, "a replaced source must be refused before any witness call")
	assert.Zero(t, acks)
	assert.Zero(t, handler.checkpointCount(), "no snapshot may be taken by a refused recovery")
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-rec-rpc-queue").Phase)
	// The refused recovery released its slot.
	require.Eventually(t, func() bool {
		_, running := s.checkpointOperations.executionDone("op-rec-rpc-queue")
		return !running
	}, 5*time.Second, 10*time.Millisecond)
}

// --- the admission-time acknowledgment of CheckpointWithOperation ---

// TestCheckpointWithOperationAcknowledgesAfterDurableSuccess pins the normal
// protocol order on the initial execution: the runtime returns, the sealed
// root is bound, SUCCEEDED is durable on disk, and only THEN is the runtime
// acknowledgment issued with the exact admitted binding. The initial reply
// reports evidence_released; a later replay of the same record is pure and
// reports false without a second acknowledgment.
func TestCheckpointWithOperationAcknowledgesAfterDurableSuccess(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-ack", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-cop-ack", "sbox-cop-ack", directory, "gen-1", 5)
	digest := requestDigestOf(t, request)

	handler.ackFn = func(_ context.Context, sandboxID string, binding svc.CheckpointOperationBinding) error {
		if sandboxID != request.GetCheckpoint().GetID() {
			return fmt.Errorf("Ack received sandbox ID %q; want source %q (operation ID %q)", sandboxID, request.GetCheckpoint().GetID(), binding.OperationID)
		}
		// The acknowledgment may run only after the success fact is durable:
		// the in-memory view and the on-disk record must both be SUCCEEDED.
		persisted, err := readCheckpointOperationRecord(
			filepath.Join(root, checkpointOperationsDirName), binding.OperationID)
		if err != nil {
			return fmt.Errorf("acknowledgment ran before the receipt was readable: %w", err)
		}
		if persisted.Phase != checkpointOperationPhaseSucceeded {
			return fmt.Errorf("acknowledgment ran before the durable success (phase %q)", persisted.Phase)
		}
		if persisted.Artifact == nil {
			return fmt.Errorf("acknowledgment ran before the sealed root was recorded")
		}
		return nil
	}

	opStatus, err := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, opStatus.GetState())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS, opStatus.GetRecoveryProtocol())
	assert.True(t, opStatus.GetEvidenceReleased(), "the initial execution completed its own acknowledgment")
	// A new admission is durably a version-2 (witness protocol) record.
	admitted := readJournalCheckpointOperation(t, root, "op-cop-ack")
	assert.Equal(t, checkpointOperationRecordVersionWitness, admitted.Version)
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	require.Len(t, handler.recordedAcks(), 1)
	assert.Equal(t, svc.CheckpointOperationBinding{
		OperationID:      "op-cop-ack",
		RequestDigest:    digest,
		SourceGeneration: "gen-1",
		// The initial execution's acknowledgment carries the admitted
		// canonical directory like every other runtime binding.
		CheckpointDir: directory,
	}, handler.recordedAcks()[0])
	assert.Equal(t, 1, acks)

	// The historical replay stays pure: same durable answer, no runtime call,
	// no new acknowledgment, and no evidence_released claim of its own.
	replayed, err := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
	assert.False(t, replayed.GetEvidenceReleased())
	_, acks = handler.witnessCounts()
	assert.Equal(t, 1, acks)
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestCheckpointWithOperationAckFailureKeepsSuccess: an acknowledgment that
// fails after the durable success never downgrades the record. The RPC
// reports an explicit failure, the SUCCEEDED receipt stays on disk, and the
// outcome is reconciled by one explicit recovery of the same operation.
func TestCheckpointWithOperationAckFailureKeepsSuccess(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-ackfail", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-cop-ackfail", "sbox-cop-ackfail", directory, "gen-1", 5)
	handler.ackFn = func(context.Context, string, svc.CheckpointOperationBinding) error {
		return errors.New("evidence store offline")
	}

	opStatus, err := s.CheckpointWithOperation(context.Background(), request)
	require.Error(t, err)
	assert.Nil(t, opStatus, "gRPC must not expose an error response payload")
	assert.ErrorContains(t, err, "acknowledgment failed")
	assert.ErrorContains(t, err, "reconciled by an explicit recovery")
	record := readJournalCheckpointOperation(t, root, "op-cop-ackfail")
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	require.NotNil(t, record.Artifact)
	assert.Equal(t, mustBindRoot(t, directory), record.Artifact.RootDigest)

	queried, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-cop-ackfail"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
	assert.False(t, queried.GetEvidenceReleased())

	// The reconciliation is one explicit recovery, which here is
	// acknowledgment-only and finishes the release.
	handler.ackFn = nil
	recovered, rerr := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
	assert.True(t, recovered.GetEvidenceReleased())
	assert.Equal(t, mustBindRoot(t, directory), recovered.GetArtifactRootDigest())
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers, "the retained success never runs the runtime recovery")
	assert.Equal(t, 2, acks)
	assert.Equal(t, 1, handler.checkpointCount(), "no second snapshot was taken")
}

// TestCheckpointWithOperationRefusesRuntimeWithoutWitness: a runtime that
// writes sealed roots but records no operation witnesses cannot be admitted —
// its UNKNOWN outcomes could never be reconciled — and the refusal spends no
// operation ID and never reaches the runtime.
func TestCheckpointWithOperationRefusesRuntimeWithoutWitness(t *testing.T) {
	writerOnly := &writerOnlyCheckpointHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	root := t.TempDir()
	s := newCheckpointOperationService(t, writerOnly, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-nowitness", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	_, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-cop-nowitness", "sbox-cop-nowitness", directory, "gen-1", 5))
	require.Equal(t, codes.Unimplemented, status.Code(err))
	assert.ErrorContains(t, err, "witness")
	assert.Zero(t, writerOnly.checkpointCount(), "an unsupported runtime is never entered")
	assert.Zero(t, journalRecordCount(t, root), "the refused admission must not spend the operation ID")
}

// TestReviewRecoveryWireServesThePublicRPC drives the new RPC through a real
// gRPC client, proving the service registration and the wire shape beside the
// in-process calls above.
func TestReviewRecoveryWireServesThePublicRPC(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	artifact := sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-wire", "sbox-rec-wire", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.witnessDirectory = directory
	s := newCheckpointOperationService(t, handler, root)
	client := sourceReviewWireClient(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recovered, err := client.RecoverCheckpointOperation(ctx, witnessRecoveryRequest(request, 30))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
	assert.True(t, recovered.GetEvidenceReleased())
	assert.Equal(t, artifact.RootDigest, recovered.GetArtifactRootDigest())
	assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS, recovered.GetRecoveryProtocol())
}

// --- the bounded store-admission lock (20260909T1315 counterexample) ---

// holdStoreAdmissionLock holds the store's writeMu for the test's lifetime and
// returns its release.
func holdStoreAdmissionLock(t *testing.T, s *sandboxService) func() {
	t.Helper()
	s.checkpointOperations.writeMu.Lock()
	released := false
	return func() {
		if !released {
			released = true
			s.checkpointOperations.writeMu.Unlock()
		}
	}
}

// TestReviewRecoveryAdmissionLockDeadlineGrantsNothing: while another writer
// holds the store's admission lock, the one-second recovery budget bounds the
// queue wait — the RPC answers DeadlineExceeded, no execution slot was
// granted, the durable record is untouched, and the runtime witness was never
// called. Releasing the owner lets a retry of the same recovery succeed.
func TestReviewRecoveryAdmissionLockDeadlineGrantsNothing(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-admission-lock", "sbox-rec-adm", directory, "gen-1", 30)
	seeded := seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.witnessDirectory = directory
	s := newCheckpointOperationService(t, handler, root)

	release := holdStoreAdmissionLock(t, s)
	started := time.Now()
	_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 1))
	release()
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.ErrorContains(t, err, "admission lock wait exceeded the caller's budget")
	assert.Less(t, time.Since(started), 1800*time.Millisecond,
		"the recovery must answer its requested budget while the admission lock is held (took %s)", time.Since(started))
	// No slot was granted, nothing was written, no runtime call was made.
	_, running := s.checkpointOperations.executionDone("op-rec-admission-lock")
	assert.False(t, running, "a recovery that never won admission must not hold an execution slot")
	unchanged := readJournalCheckpointOperation(t, root, "op-rec-admission-lock")
	assert.Equal(t, seeded, unchanged, "the durable record must be byte-identical after the refused admission")
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Zero(t, acks)
	assert.Zero(t, handler.checkpointCount())

	// Once the owning writer exited, the same retry is admitted and completes.
	recovered, rerr := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
	assert.True(t, recovered.GetEvidenceReleased())
	recovers, acks = handler.witnessCounts()
	assert.Equal(t, 1, recovers)
	assert.Equal(t, 1, acks)
	assert.Zero(t, handler.checkpointCount(), "the retry reconciled without any new snapshot")
}

// TestReviewRecoveryAdmissionLockCallerCancelEndsQueue: a cancelled caller
// ends only its own admission wait; no slot, no mutation, and the same
// recovery still succeeds afterwards.
func TestReviewRecoveryAdmissionLockCallerCancelEndsQueue(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	sealedRootArtifact(t, directory)
	request := checkpointOperationRequest("op-rec-admission-cancel", "sbox-rec-adm", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	handler := newCheckpointOperationRuntimeHandler()
	handler.witnessDirectory = directory
	s := newCheckpointOperationService(t, handler, root)

	release := holdStoreAdmissionLock(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(ctx, witnessRecoveryRequest(request, 30))
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled recovery did not leave the admission queue")
	}
	release()
	_, running := s.checkpointOperations.executionDone("op-rec-admission-cancel")
	assert.False(t, running)
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-rec-admission-cancel").Phase)
	recovers, _ := handler.witnessCounts()
	assert.Zero(t, recovers)

	recovered, rerr := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.NoError(t, rerr)
	assert.True(t, recovered.GetEvidenceReleased())
}

// TestReviewRecoveryAdmissionExpiredContextNeverWins: an already-expired (or
// already-cancelled) context is refused even when the admission lock is free
// — no slot is granted and nothing is written.
func TestReviewRecoveryAdmissionExpiredContextNeverWins(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-admission-expired", "sbox-rec-adm", directory, "gen-1", 30)
	seeded := seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	digest := requestDigestOf(t, request)

	for name, build := range map[string]func() context.Context{
		"already cancelled": func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
		"already expired": func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			draft := &checkpointOperationRecord{
				OperationID:   request.GetOperationID(),
				SandboxID:     request.GetCheckpoint().GetID(),
				Generation:    request.GetExpectedGeneration(),
				CheckpointDir: filepath.Clean(request.GetCheckpoint().GetCheckpointDir()),
				RequestDigest: digest,
			}
			recovery, joined, err := s.checkpointOperations.recoverExistingContext(build(), draft)
			assert.Nil(t, recovery)
			assert.Nil(t, joined)
			assert.Error(t, err)
			_, running := s.checkpointOperations.executionDone(request.GetOperationID())
			assert.False(t, running, "an expired context must not win an execution slot")
			assert.Equal(t, seeded, readJournalCheckpointOperation(t, root, request.GetOperationID()))
			// The refusal left the lock usable for the next writer.
			s.checkpointOperations.writeMu.Lock()
			s.checkpointOperations.writeMu.Unlock()
		})
	}
}

// TestReviewRecoveryAdmissionLockKeepsQueriesAndWriters: the admission lock
// bounds only the recovery admission — read-only queries keep answering while
// it is held (publication reads never wait for writeMu), and the ordinary
// serialized writers still queue and run in order after it is released.
func TestReviewRecoveryAdmissionLockKeepsQueriesAndWriters(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-admission-query", "sbox-rec-adm", directory, "gen-1", 30)
	seeded := seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseUnknown, nil)
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	release := holdStoreAdmissionLock(t, s)
	// A query answers from the published view while the admission lock is held.
	queried := make(chan error, 1)
	go func() {
		_, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-admission-query"})
		queried <- qerr
	}()
	select {
	case qerr := <-queried:
		require.NoError(t, qerr)
	case <-time.After(2 * time.Second):
		t.Fatal("GetCheckpointOperation blocked on the store admission lock")
	}
	// A plain serialized writer queues behind the held lock and completes in
	// order once it is released — the Lock/Unlock discipline is unchanged.
	written := make(chan error, 1)
	go func() {
		written <- s.checkpointOperations.markFailedConfirmed(
			"op-rec-admission-query", "writer queued behind the held admission lock")
	}()
	select {
	case <-written:
		t.Fatal("a plain writer bypassed the held admission lock")
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case werr := <-written:
		// The writer ran under the lock once released: markTerminal keeps its
		// no-op contract over the terminal (unknown) phase, so it reports
		// success having rewritten nothing.
		require.NoError(t, werr)
	case <-time.After(5 * time.Second):
		t.Fatal("the queued writer did not run after the lock was released")
	}
	assert.Equal(t, seeded, readJournalCheckpointOperation(t, root, "op-rec-admission-query"),
		"the queued writer respected the no-op contract over the unknown phase")
}

// TestReviewRecoveryAdmissionAfterDrainRefuses: a recovery that was queueing
// for the admission lock while the store began draining is refused once the
// lock opens — draining closes recovery admission, an acknowledgment-only one
// included — and no slot is granted.
func TestReviewRecoveryAdmissionAfterDrainRefuses(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-admission-drain", "sbox-rec-adm", directory, "gen-1", 30)
	seedWitnessOperationRecord(t, root, request, checkpointOperationPhaseSucceeded, sealedRootArtifact(t, directory))
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	digest := requestDigestOf(t, request)

	release := holdStoreAdmissionLock(t, s)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		s.checkpointOperations.shutdown()
	}()
	// Draining never queues on the admission lock: it flips the lifecycle
	// flag under lifeMu and waits only for live executors (there are none),
	// so it returns while the test still holds writeMu.
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on the held admission lock")
	}
	release()

	_, err := s.RecoverCheckpointOperation(context.Background(), witnessRecoveryRequest(request, 30))
	require.Equal(t, codes.Unavailable, status.Code(err))
	assert.ErrorContains(t, err, "shutting down")
	_, running := s.checkpointOperations.executionDone("op-rec-admission-drain")
	assert.False(t, running, "a draining store must not grant a recovery slot")
	assert.Equal(t, digest, readJournalCheckpointOperation(t, root, "op-rec-admission-drain").RequestDigest)
}
