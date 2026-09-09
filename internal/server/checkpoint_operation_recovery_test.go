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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests cover the internal recovery primitives of the checkpoint
// operation store — recoverExisting and the recovery slot's dedicated
// completion transition — which no public RPC reaches yet. They are store
// semantics only: nothing here proves a runtime outcome, and the sealed roots
// they complete with stand for a root the later recovery service stage has
// verified through the runtime witness, never for evidence the store accepted
// on its own.

// seedCheckpointOperationRecord writes one durable journal record by hand, the
// state a daemon restart or a spent operation leaves behind.
func seedCheckpointOperationRecord(t *testing.T, root string, record *checkpointOperationRecord) {
	t.Helper()
	require.NoError(t, validateCheckpointOperationRecord(record))
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, checkpointOperationsDirName), 0700))
	require.NoError(t, os.WriteFile(
		checkpointOperationPath(filepath.Join(root, checkpointOperationsDirName), record.OperationID),
		data, 0600))
}

// seededCheckpointOperationRecord builds a record for an operation that was
// admitted under exactly this request and landed in the given phase.
func seededCheckpointOperationRecord(
	request *runtime.CheckpointWithOperationRequest,
	runtimeName, digest, phase, message string,
) *checkpointOperationRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &checkpointOperationRecord{
		Version:       1,
		OperationID:   request.GetOperationID(),
		SandboxID:     request.GetCheckpoint().GetID(),
		Generation:    request.GetExpectedGeneration(),
		Runtime:       runtimeName,
		CheckpointDir: filepath.Clean(request.GetCheckpoint().GetCheckpointDir()),
		RequestDigest: digest,
		Phase:         phase,
		CreatedAt:     now,
		UpdatedAt:     now,
		Message:       message,
	}
}

// recoveryDraftForRequest rebuilds the identity a recovery caller submits: the
// operation ID, sandbox, generation, canonical directory, and the digest of
// the complete original request. A recovery never re-derives the runtime, so
// the draft leaves it empty exactly as the service stage will.
func recoveryDraftForRequest(
	t *testing.T,
	request *runtime.CheckpointWithOperationRequest,
) *checkpointOperationRecord {
	t.Helper()
	digest, err := checkpointOperationRequestDigest(request)
	require.NoError(t, err)
	return &checkpointOperationRecord{
		OperationID:   request.GetOperationID(),
		SandboxID:     request.GetCheckpoint().GetID(),
		Generation:    request.GetExpectedGeneration(),
		CheckpointDir: filepath.Clean(request.GetCheckpoint().GetCheckpointDir()),
		RequestDigest: digest,
	}
}

// requestDigestOf fingerprints the request the same way admission did.
func requestDigestOf(t *testing.T, request *runtime.CheckpointWithOperationRequest) string {
	t.Helper()
	digest, err := checkpointOperationRequestDigest(request)
	require.NoError(t, err)
	return digest
}

// journalRecordCount counts the durable records of a journal, so a test can
// prove a refusal performed zero admission writes.
func journalRecordCount(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, checkpointOperationsDirName))
	require.NoError(t, err)
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	return count
}

// conflictingDigest flips the last hex character of a digest, so a test can
// name a well-formed but different sealed root.
func conflictingDigest(t *testing.T, digest string) string {
	t.Helper()
	require.Len(t, digest, checkpointroot.DigestHexLen)
	last := digest[len(digest)-1]
	if last == '0' {
		return digest[:len(digest)-1] + "1"
	}
	return digest[:len(digest)-1] + "0"
}

// readJournalCheckpointOperation reads one durable record for equality checks.
func readJournalCheckpointOperation(t *testing.T, root, id string) *checkpointOperationRecord {
	t.Helper()
	record, err := readCheckpointOperationRecord(filepath.Join(root, checkpointOperationsDirName), id)
	require.NoError(t, err)
	return record
}

// admitRecovery is the direct store admission the later service stage will
// call after its own request validation.
func admitRecovery(
	t *testing.T,
	s *sandboxService,
	request *runtime.CheckpointWithOperationRequest,
) (*checkpointOperationRecovery, <-chan struct{}) {
	t.Helper()
	recovery, joined, err := s.checkpointOperations.recoverExisting(recoveryDraftForRequest(t, request))
	require.NoError(t, err)
	return recovery, joined
}

// --- admission ---

// TestCheckpointOperationRecoveryAdmissionRequiresExistingExactRecord pins the
// recovery precondition set: a missing record is NotFound and writes nothing, a
// binding mismatch is refused, and a FAILED record can never be recovered.
func TestCheckpointOperationRecoveryAdmissionRequiresExistingExactRecord(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-exact", "sbox-rec-exact", directory, "gen-1", 30)
	digest := requestDigestOf(t, request)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		request, config.RuntimeNameRunsc, digest, checkpointOperationPhaseUnknown,
		"operation was admitted but the daemon restarted before its outcome was recorded; outcome unproven, re-execution forbidden"))

	t.Run("missing record is NotFound with zero writes", func(t *testing.T) {
		fresh := t.TempDir()
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), fresh)
		missing := checkpointOperationRequest("op-rec-missing", "sbox-rec-exact", directory, "gen-1", 30)
		recovery, joined, err := s.checkpointOperations.recoverExisting(recoveryDraftForRequest(t, missing))
		assert.Nil(t, recovery)
		assert.Nil(t, joined)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.ErrorContains(t, err, "op-rec-missing")
		assert.Zero(t, journalRecordCount(t, fresh), "a missing operation must not be created by recovery")
	})

	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	conflicts := map[string]*runtime.CheckpointWithOperationRequest{
		"different sandbox": checkpointOperationRequest(
			"op-rec-exact", "sbox-rec-other", directory, "gen-1", 30),
		"different generation": checkpointOperationRequest(
			"op-rec-exact", "sbox-rec-exact", directory, "gen-2", 30),
		"different directory": checkpointOperationRequest(
			"op-rec-exact", "sbox-rec-exact", filepath.Join(t.TempDir(), "other"), "gen-1", 30),
		"different timeout digest": checkpointOperationRequest(
			"op-rec-exact", "sbox-rec-exact", directory, "gen-1", 31),
	}
	for name, conflicting := range conflicts {
		t.Run(name, func(t *testing.T) {
			recovery, joined, err := s.checkpointOperations.recoverExisting(recoveryDraftForRequest(t, conflicting))
			assert.Nil(t, recovery)
			assert.Nil(t, joined)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.ErrorContains(t, err, "op-rec-exact")
		})
	}
	assert.Equal(t, 1, journalRecordCount(t, root), "a refused recovery must not write the journal")
	unchanged := readJournalCheckpointOperation(t, root, "op-rec-exact")
	assert.Equal(t, checkpointOperationPhaseUnknown, unchanged.Phase)

	t.Run("failed record is refused forever", func(t *testing.T) {
		failedRoot := t.TempDir()
		failedDir := filepath.Join(t.TempDir(), "checkpoint")
		failedRequest := checkpointOperationRequest("op-rec-failed", "sbox-rec-failed", failedDir, "gen-1", 30)
		seedCheckpointOperationRecord(t, failedRoot, seededCheckpointOperationRecord(
			failedRequest, config.RuntimeNameRunsc, requestDigestOf(t, failedRequest),
			checkpointOperationPhaseFailed, "checkpoint was refused before any side effect"))
		failed := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), failedRoot)

		recovery, joined, err := failed.checkpointOperations.recoverExisting(recoveryDraftForRequest(t, failedRequest))
		assert.Nil(t, recovery)
		assert.Nil(t, joined)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "cannot be recovered")
		assert.Equal(t, checkpointOperationPhaseFailed,
			readJournalCheckpointOperation(t, failedRoot, "op-rec-failed").Phase)
		assert.Equal(t, 1, journalRecordCount(t, failedRoot))
	})
}

// TestCheckpointOperationRecoveryAdmissionPhases pins which recorded phases a
// recovery may take over: the undetermined ones (admitted without an executor,
// and unknown) yield the single recovery slot, a SUCCEEDED record resolves from
// history for the later Ack retry, and an original executor keeps its slot.
func TestCheckpointOperationRecoveryAdmissionPhases(t *testing.T) {
	t.Run("admitted without executor is recoverable", func(t *testing.T) {
		handler := newCheckpointOperationRuntimeHandler()
		s := newCheckpointOperationService(t, handler, t.TempDir())
		storeCheckpointOperationSandbox(t, s, "sbox-rec-admitted", "gen-live")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-rec-admitted", "sbox-rec-admitted", directory, "gen-1", 30)
		// A real path into "admitted in memory without an executor": the
		// pre-entry refusal is proven failed, but its terminal write fails, so
		// the record stays admitted and the spent executor is gone.
		var persistFailures atomic.Int64
		s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
			if record.Phase == checkpointOperationPhaseFailed {
				persistFailures.Add(1)
				return errors.New("journal fsync failed")
			}
			return s.checkpointOperations.durablyWrite(record)
		}
		_, err := s.CheckpointWithOperation(context.Background(), request)
		require.Error(t, err)
		require.Equal(t, int64(1), persistFailures.Load())
		require.Equal(t, checkpointOperationPhaseAdmitted,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-rec-admitted").Phase)

		recovery, joined := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		assert.Nil(t, joined)
		// The record is admitted with a live executor again, so a query reports
		// the existing RUNNING shape — no new visible state was invented.
		running, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-admitted"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING, running.GetState())
		assert.Zero(t, handler.checkpointCount(), "recovery admission never executes the runtime")

		// Releasing the slot without proving anything returns the record to the
		// undetermined view instead of inventing an outcome.
		recovery.finish()
		unresolved, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-admitted"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, unresolved.GetState())
		assert.Equal(t, checkpointOperationPhaseAdmitted,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-rec-admitted").Phase)
	})

	t.Run("unknown after restart is recoverable", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-rec-unknown", "sbox-rec-unknown", directory, "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"operation was admitted but the daemon restarted before its outcome was recorded; outcome unproven, re-execution forbidden"))
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

		recovery, joined := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		assert.Nil(t, joined)
		// The phase claims nothing, so a query stays undetermined while the
		// recovery runs.
		unresolved, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-unknown"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, unresolved.GetState())
		assert.Empty(t, unresolved.GetArtifactRootDigest())
		recovery.finish()
	})

	t.Run("succeeded yields an acknowledgment-only slot", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, os.MkdirAll(directory, 0700))
		require.NoError(t, writeSealedCheckpointDirectory(directory))
		rootBinding, err := checkpointroot.Bind(directory)
		require.NoError(t, err)
		request := checkpointOperationRequest("op-rec-done", "sbox-rec-done", directory, "gen-1", 30)
		record := seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseSucceeded,
			"checkpoint completed; sealed content root is a completion-time fact")
		record.Artifact = &checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme}
		seedCheckpointOperationRecord(t, root, record)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

		// A SUCCEEDED record is not a query shortcut for an explicit recovery:
		// the Ack retry is a side effect, so it owns a fully lifecycle-managed
		// slot — marked acknowledgment-only — rather than acting untracked.
		recovery, joined := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		assert.Nil(t, joined)
		assert.True(t, recovery.acknowledgmentOnly())
		_, running := s.checkpointOperations.executionDone("op-rec-done")
		assert.True(t, running, "an acknowledgment-only slot must be a tracked executor")

		// The slot confirms the recorded receipt idempotently, rewrites nothing
		// — not even updated_at — and refuses any other root.
		require.NoError(t, recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme},
			"acknowledgment retry"))
		err = recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: conflictingDigest(t, rootBinding.RootDigest), Scheme: rootBinding.Scheme},
			"a different recovered root")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "conflict")
		recorded := readJournalCheckpointOperation(t, root, "op-rec-done")
		assert.Equal(t, record.UpdatedAt, recorded.UpdatedAt, "an acknowledgment must not rewrite history")
		assert.Equal(t, rootBinding.RootDigest, recorded.Artifact.RootDigest)

		// Queries stay pure: the recorded fact reads the same with the slot
		// held and after it is released.
		assertGetState := func() runtime.CheckpointOperationState {
			queried, qerr := s.GetCheckpointOperation(context.Background(),
				&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-done"})
			require.NoError(t, qerr)
			return queried.GetState()
		}
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, assertGetState())
		recovery.finish()
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, assertGetState())
	})
}

// TestCheckpointOperationRecoveryConcurrentApplicantsSingleSlot: concurrent
// recoveries of one undetermined record share a single execution slot — one
// applicant wins, every other applicant joins that exact executor — and a slot
// released without a completion may be re-admitted by a later recovery.
func TestCheckpointOperationRecoveryConcurrentApplicantsSingleSlot(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-race", "sbox-rec-race", directory, "gen-1", 30)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
		"outcome unproven, re-execution forbidden"))
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	const applicants = 8
	draft := recoveryDraftForRequest(t, request)
	var mu sync.Mutex
	var winner *checkpointOperationRecovery
	var joined <-chan struct{}
	applicantErrors := make([]error, applicants)
	started := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < applicants; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-started
			recovery, done, err := s.checkpointOperations.recoverExisting(draft)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				applicantErrors[i] = err
				return
			}
			if recovery != nil {
				if winner != nil {
					applicantErrors[i] = fmt.Errorf("a second recovery slot was granted")
					return
				}
				winner = recovery
				return
			}
			if done == nil {
				applicantErrors[i] = fmt.Errorf("a losing applicant was given no executor to join")
				return
			}
			joined = done
		}(i)
	}
	close(started)
	wg.Wait()
	for i, err := range applicantErrors {
		require.NoErrorf(t, err, "applicant %d", i)
	}
	require.NotNil(t, winner, "no applicant won the recovery slot")
	require.NotNil(t, joined, "no applicant joined the recovery slot")
	// The joiners' channel is exactly the winner's executor: releasing the
	// winner's slot closes it, so a joiner never outlives the executor.
	winner.finish()
	select {
	case <-joined:
	default:
		t.Fatal("the joined channel did not close with the winner's executor")
	}

	// A slot released without a completion returns the record to the pool: the
	// next recovery of the same operation wins a fresh, distinct executor.
	first := winner
	next, joinedNext := admitRecovery(t, s, request)
	require.NotNil(t, next)
	assert.Nil(t, joinedNext)
	assert.NotSame(t, first.exec, next.exec, "a re-admitted recovery must be a new executor")
	next.finish()
}

// TestCheckpointOperationRecoveryJoinsRunningOriginalExecution: while the
// original admitted execution runs, a recovery is handed its done channel
// instead of a second executor, and observes the recorded original outcome.
func TestCheckpointOperationRecoveryJoinsRunningOriginalExecution(t *testing.T) {
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
	storeCheckpointOperationSandbox(t, s, "sbox-rec-join", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-rec-join", "sbox-rec-join", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	// The recovery joins the original executor rather than creating a second
	// executor over an already-running operation.
	recovery, joined := admitRecovery(t, s, request)
	assert.Nil(t, recovery)
	require.NotNil(t, joined)
	originalDone, running := s.checkpointOperations.executionDone("op-rec-join")
	require.True(t, running)
	assert.Equal(t, originalDone, joined)

	releaseOnce.Do(func() { close(release) })
	select {
	case <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("the recovery did not observe the original executor's exit")
	}
	select {
	case err := <-executorDone:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the original executor did not finish")
	}
	assert.Equal(t, 1, handler.checkpointCount())

	// The completed operation now admits the Ack-retry half only, as a tracked
	// acknowledgment-only slot: no second reconciliation executor, and no
	// untracked side effect.
	ackSlot, joinedAfter := admitRecovery(t, s, request)
	require.NotNil(t, ackSlot)
	assert.Nil(t, joinedAfter)
	assert.True(t, ackSlot.acknowledgmentOnly())
	ackSlot.finish()
	final, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-join"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, final.GetState())
}

// TestCheckpointOperationReplayJoinsRecoveryExecution pins the shared lifecycle
// from the other side: an identical CheckpointWithOperation replay arriving
// while a recovery holds the slot joins it — it is never answered as finished,
// never executes the runtime, and resolves once the recovery completes.
func TestCheckpointOperationReplayJoinsRecoveryExecution(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, writeSealedCheckpointDirectory(directory))
	rootBinding, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	request := checkpointOperationRequest("op-rec-replay", "sbox-rec-replay", directory, "gen-1", 30)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
		"outcome unproven, re-execution forbidden"))
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, root)

	recovery, _ := admitRecovery(t, s, request)
	require.NotNil(t, recovery)
	replayDone := make(chan *runtime.CheckpointOperationStatus, 1)
	go func() {
		replayed, rerr := s.CheckpointWithOperation(context.Background(), request)
		require.NoError(t, rerr)
		replayDone <- replayed
	}()
	select {
	case replayed := <-replayDone:
		t.Fatalf("the replay answered before the recovery recorded its outcome: %+v", replayed)
	case <-time.After(200 * time.Millisecond):
	}
	require.NoError(t, recovery.markRecoveredSucceeded(
		&checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme},
		"recovery verified the sealed root through the runtime witness"))
	recovery.finish()

	select {
	case replayed := <-replayDone:
		require.NotNil(t, replayed)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
		assert.Equal(t, rootBinding.RootDigest, replayed.GetArtifactRootDigest())
	case <-time.After(10 * time.Second):
		t.Fatal("the replay did not resolve after the recovery completed")
	}
	assert.Zero(t, handler.checkpointCount(), "a replay joining a recovery must not execute the runtime")
}

// --- the dedicated completion transition ---

// TestCheckpointOperationRecoveryCompletesUndeterminedToSucceeded pins the
// durable-first completion: an undetermined record moves to SUCCEEDED only
// through its own slot, its history stays untouched, and the fact survives a
// restart and answers later recoveries from history.
func TestCheckpointOperationRecoveryCompletesUndeterminedToSucceeded(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, writeSealedCheckpointDirectory(directory))
	rootBinding, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	request := checkpointOperationRequest("op-rec-complete", "sbox-rec-complete", directory, "gen-1", 30)
	digest := requestDigestOf(t, request)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		request, config.RuntimeNameRunsc, digest, checkpointOperationPhaseUnknown,
		"operation was admitted but the daemon restarted before its outcome was recorded; outcome unproven, re-execution forbidden"))
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, root)

	recovery, joined := admitRecovery(t, s, request)
	require.NotNil(t, recovery)
	assert.Nil(t, joined)
	bound := recovery.boundRecord()
	require.NotNil(t, bound)
	assert.Equal(t, checkpointOperationPhaseUnknown, bound.Phase)

	require.NoError(t, recovery.markRecoveredSucceeded(
		&checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme},
		"recovery verified the sealed root through the runtime witness"))
	recovery.finish()

	record := readJournalCheckpointOperation(t, root, "op-rec-complete")
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	require.NotNil(t, record.Artifact)
	assert.Equal(t, rootBinding.RootDigest, record.Artifact.RootDigest)
	assert.Equal(t, checkpointroot.Scheme, record.Artifact.Scheme)
	// The completion transition changes the phase, the artifact, the message,
	// and updated_at only: the history a recovery must never rewrite stays.
	assert.Equal(t, "sbox-rec-complete", record.SandboxID)
	assert.Equal(t, "gen-1", record.Generation)
	assert.Equal(t, config.RuntimeNameRunsc, record.Runtime)
	assert.Equal(t, filepath.Clean(directory), record.CheckpointDir)
	assert.Equal(t, digest, record.RequestDigest)
	assert.Equal(t, bound.CreatedAt, record.CreatedAt)

	succeeded, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-complete"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, succeeded.GetState())
	assert.Equal(t, rootBinding.RootDigest, succeeded.GetArtifactRootDigest())

	// A daemon restart reads the same durable fact and never re-executes.
	restartedHandler := newCheckpointOperationRuntimeHandler()
	restarted := newCheckpointOperationService(t, restartedHandler, root)
	afterRestart, qerr := restarted.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-complete"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, afterRestart.GetState())
	assert.Equal(t, rootBinding.RootDigest, afterRestart.GetArtifactRootDigest())
	assert.Zero(t, restartedHandler.checkpointCount())

	// The recovered operation now admits only the Ack-retry half, through a
	// tracked acknowledgment-only slot that cannot create a success fact; an
	// exact replay of the completion stays idempotent.
	ackSlot, joinedAfter := admitRecovery(t, restarted, request)
	require.NotNil(t, ackSlot)
	assert.Nil(t, joinedAfter)
	assert.True(t, ackSlot.acknowledgmentOnly())
	require.NoError(t, ackSlot.markRecoveredSucceeded(
		&checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme},
		"acknowledgment retry after restart"))
	assert.Equal(t, rootBinding.RootDigest,
		readJournalCheckpointOperation(t, root, "op-rec-complete").Artifact.RootDigest)
	ackSlot.finish()
}

// TestCheckpointOperationRecoveryCompletionDurabilityFailures: a blocked or
// failed success write never exposes success — every query stays at the
// undetermined outcome — and the same slot may retry the completion after the
// journal is repaired, then replay idempotently while refusing any other root.
func TestCheckpointOperationRecoveryCompletionDurabilityFailures(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, writeSealedCheckpointDirectory(directory))
	rootBinding, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	request := checkpointOperationRequest("op-rec-durable", "sbox-rec-durable", directory, "gen-1", 30)
	seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
		request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
		"outcome unproven, re-execution forbidden"))
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	gate := make(chan struct{})
	var failSuccessWrites atomic.Bool
	s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
		if record.Phase != checkpointOperationPhaseSucceeded {
			return s.checkpointOperations.durablyWrite(record)
		}
		<-gate
		if failSuccessWrites.Load() {
			return errors.New("journal fsync failed")
		}
		return s.checkpointOperations.durablyWrite(record)
	}

	recovery, _ := admitRecovery(t, s, request)
	require.NotNil(t, recovery)
	artifact := &checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme}
	completeDone := make(chan error, 1)
	go func() {
		completeDone <- recovery.markRecoveredSucceeded(
			artifact, "recovery verified the sealed root through the runtime witness")
	}()

	// While the durable write is blocked the operation stays undetermined, in
	// memory and on disk; success is never observable before it is durable.
	undetermined := func() *runtime.CheckpointOperationStatus {
		queried, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-durable"})
		require.NoError(t, qerr)
		return queried
	}
	time.Sleep(100 * time.Millisecond)
	queried := undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
	assert.Empty(t, queried.GetArtifactRootDigest())
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-rec-durable").Phase)
	select {
	case err := <-completeDone:
		t.Fatalf("the completion reported before its write resolved: %v", err)
	default:
	}

	// The write fails: the completion returns an error, nothing is published,
	// and the durable record still claims nothing.
	failSuccessWrites.Store(true)
	close(gate)
	require.ErrorContains(t, <-completeDone, "persist recovered success")
	queried = undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-rec-durable").Phase)

	// After the journal is repaired the same slot retries the same operation
	// and the fact becomes durable.
	failSuccessWrites.Store(false)
	require.NoError(t, recovery.markRecoveredSucceeded(
		artifact, "recovery verified the sealed root through the runtime witness after the journal was repaired"))
	queried = undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
	assert.Equal(t, rootBinding.RootDigest, queried.GetArtifactRootDigest())
	assert.Equal(t, checkpointOperationPhaseSucceeded,
		readJournalCheckpointOperation(t, root, "op-rec-durable").Phase)

	// The already-durable fact replays idempotently for the exact root and
	// scheme only: the replay claims nothing new, so it rewrites nothing — not
	// even the message — while a different recovered root is a conflict rather
	// than an overwrite.
	require.NoError(t, recovery.markRecoveredSucceeded(
		artifact, "retried completion after an ambiguous reply"))
	err = recovery.markRecoveredSucceeded(
		&checkpointOperationArtifact{RootDigest: conflictingDigest(t, rootBinding.RootDigest), Scheme: rootBinding.Scheme},
		"a different recovered root")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "conflict")
	record := readJournalCheckpointOperation(t, root, "op-rec-durable")
	assert.Equal(t, rootBinding.RootDigest, record.Artifact.RootDigest)
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	assert.Equal(t,
		"recovery verified the sealed root through the runtime witness after the journal was repaired",
		record.Message, "an idempotent replay must not rewrite the recorded fact")
	recovery.finish()
}

// TestCheckpointOperationRecoveryCompletionRejectsStaleOwnerAndInvalidEvidence
// pins the completion transition's own preconditions: unverified input shapes
// and slots that no longer own the operation are refused without any durable
// write, a later recovery's slot cannot be used by an earlier one, and the
// ordinary markTerminal path stays closed to undetermined records.
func TestCheckpointOperationRecoveryCompletionRejectsStaleOwnerAndInvalidEvidence(t *testing.T) {
	seedUndetermined := func(t *testing.T, root, operationID string) *runtime.CheckpointWithOperationRequest {
		t.Helper()
		request := checkpointOperationRequest(
			operationID, "sbox-rec-stale", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"outcome unproven, re-execution forbidden"))
		return request
	}
	rootBinding := func(t *testing.T) checkpointOperationArtifact {
		t.Helper()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, os.MkdirAll(directory, 0700))
		require.NoError(t, writeSealedCheckpointDirectory(directory))
		binding, err := checkpointroot.Bind(directory)
		require.NoError(t, err)
		return checkpointOperationArtifact{RootDigest: binding.RootDigest, Scheme: binding.Scheme}
	}

	t.Run("invalid evidence is refused without a write", func(t *testing.T) {
		root := t.TempDir()
		request := seedUndetermined(t, root, "op-rec-evidence")
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		var writes atomic.Int64
		s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
			writes.Add(1)
			return s.checkpointOperations.durablyWrite(record)
		}
		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		valid := rootBinding(t)
		for name, artifact := range map[string]*checkpointOperationArtifact{
			"nil artifact":       nil,
			"missing digest":     {Scheme: valid.Scheme},
			"non-hex digest":     {RootDigest: strings.Repeat("z", checkpointroot.DigestHexLen), Scheme: valid.Scheme},
			"short digest":       {RootDigest: "abcd", Scheme: valid.Scheme},
			"unsupported scheme": {RootDigest: valid.RootDigest, Scheme: "unknown-root"},
		} {
			t.Run(name, func(t *testing.T) {
				err := recovery.markRecoveredSucceeded(artifact, "evidence")
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assert.ErrorContains(t, err, "sealed root")
			})
		}
		assert.Zero(t, writes.Load(), "an unverified completion must not reach the journal")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-evidence").Phase)
		recovery.finish()
	})

	t.Run("a released slot is a stale owner", func(t *testing.T) {
		root := t.TempDir()
		request := seedUndetermined(t, root, "op-rec-stale")
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		valid := rootBinding(t)
		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		recovery.finish()
		err := recovery.markRecoveredSucceeded(&valid, "late completion")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "no longer owns the operation")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-stale").Phase)
	})

	t.Run("an earlier recovery cannot complete through a later slot", func(t *testing.T) {
		root := t.TempDir()
		request := seedUndetermined(t, root, "op-rec-owner")
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		valid := rootBinding(t)
		earlier, _ := admitRecovery(t, s, request)
		require.NotNil(t, earlier)
		earlier.finish()
		later, joined := admitRecovery(t, s, request)
		require.NotNil(t, later)
		assert.Nil(t, joined)

		err := earlier.markRecoveredSucceeded(&valid, "completion through a stale slot")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "no longer owns the operation")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-owner").Phase)

		require.NoError(t, later.markRecoveredSucceeded(&valid, "completion by the owning recovery"))
		assert.Equal(t, checkpointOperationPhaseSucceeded,
			readJournalCheckpointOperation(t, root, "op-rec-owner").Phase)
		later.finish()
	})

	t.Run("the ordinary terminal path stays closed to undetermined records", func(t *testing.T) {
		root := t.TempDir()
		seedUndetermined(t, root, "op-rec-closed")
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		valid := rootBinding(t)
		// markTerminal treats unknown as terminal, so the ordinary success path
		// must keep refusing to rewrite it — which is exactly why the recovery
		// needs its own dedicated, slot-owned transition.
		assert.NoError(t, s.checkpointOperations.markSucceeded(
			"op-rec-closed", &valid, "an ordinary executor fallback"))
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-closed").Phase)
		resolved, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-rec-closed"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, resolved.GetState())
	})
}

// --- acknowledgment-only slots for SUCCEEDED records ---

// succeededOperationWithLiveExecutor builds the state the original execution
// leaves between its durable success fact and its slot release: the record is
// SUCCEEDED on disk and in memory while the original executor still holds the
// in-flight slot. That window is the acknowledgment tail an explicit recovery
// of an already-succeeded operation must join rather than act beside.
func succeededOperationWithLiveExecutor(t *testing.T, operationID string) (
	*checkpointOperationStore,
	*checkpointOperationRecord,
	*checkpointOperationExecution,
	checkpointOperationArtifact,
) {
	t.Helper()
	store, err := loadCheckpointOperations(t.TempDir())
	require.NoError(t, err)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, writeSealedCheckpointDirectory(directory))
	rootBinding, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	artifact := checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	draft := &checkpointOperationRecord{
		Version:       1,
		OperationID:   operationID,
		SandboxID:     "sbox-rec-ack",
		Generation:    "gen-1",
		Runtime:       config.RuntimeNameRunsc,
		CheckpointDir: directory,
		RequestDigest: strings.Repeat("a", checkpointroot.DigestHexLen),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	exec, joined, err := store.admit(draft)
	require.NoError(t, err)
	require.NotNil(t, exec)
	require.Nil(t, joined)
	require.NoError(t, store.markSucceeded(
		operationID, &artifact, "checkpoint completed; acknowledgment pending"))
	persisted, err := readCheckpointOperationRecord(store.dir, operationID)
	require.NoError(t, err)
	require.Equal(t, checkpointOperationPhaseSucceeded, persisted.Phase)
	return store, draft, exec, artifact
}

// TestCheckpointOperationRecoveryAckSlotSharesLifecycle pins the SUCCEEDED
// admission contract for the side-effecting Ack retry: it joins any executor
// still live — the original execution's acknowledgment tail included — and
// otherwise owns a tracked, cancellable, shutdown-drained acknowledgment-only
// slot that can neither create a success fact nor rewrite the recorded root.
func TestCheckpointOperationRecoveryAckSlotSharesLifecycle(t *testing.T) {
	const operationID = "op-ack-lifecycle"

	t.Run("joins the original executor's acknowledgment tail", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, operationID)
		defer store.finishExecution(operationID, exec)

		recovery, joined, err := store.recoverExisting(draft)
		require.NoError(t, err)
		assert.Nil(t, recovery, "a live executor must not gain a second slot")
		require.NotNil(t, joined, "the recovery must join the acknowledgment tail")
		liveDone, running := store.executionDone(operationID)
		require.True(t, running)
		assert.Equal(t, liveDone, joined)
		var executorDone <-chan struct{} = exec.done
		assert.Equal(t, executorDone, joined)

		store.finishExecution(operationID, exec)
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Fatal("the joining recovery did not observe the tail's exit")
		}
		persisted, perr := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, perr)
		assert.Equal(t, artifact.RootDigest, persisted.Artifact.RootDigest,
			"joining a tail must not rewrite the recorded root")
	})

	t.Run("owns a tracked acknowledgment-only slot after the original exited", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, operationID)
		store.finishExecution(operationID, exec)

		recovery, joined, err := store.recoverExisting(draft)
		require.NoError(t, err)
		require.NotNil(t, recovery, "an Ack retry needs a tracked executor")
		assert.Nil(t, joined)
		assert.True(t, recovery.acknowledgmentOnly())
		_, running := store.executionDone(operationID)
		assert.True(t, running, "the acknowledgment-only slot is a registered executor")

		// Cancellation registers under the same admission lock shutdown uses,
		// and stays idle while no shutdown asks for convergence.
		ackCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		recovery.registerCancel(cancel)
		select {
		case <-ackCtx.Done():
			t.Fatal("the acknowledgment executor was cancelled without a shutdown")
		default:
		}
		// The slot confirms the recorded receipt and refuses any other root.
		require.NoError(t, recovery.markRecoveredSucceeded(&artifact, "acknowledgment retry"))
		err = recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: conflictingDigest(t, artifact.RootDigest), Scheme: artifact.Scheme},
			"a different recovered root")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "conflict")

		recovery.finish()
		_, running = store.executionDone(operationID)
		assert.False(t, running)
		persisted, perr := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, perr)
		assert.Equal(t, artifact.RootDigest, persisted.Artifact.RootDigest)
	})

	t.Run("an acknowledgment-only slot cannot create a success fact", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, operationID)
		store.finishExecution(operationID, exec)
		recovery, _, err := store.recoverExisting(draft)
		require.NoError(t, err)
		require.NotNil(t, recovery)
		defer recovery.finish()

		// No legitimate flow moves a SUCCEEDED record back to an undetermined
		// phase, so this defense-in-depth branch is exercised by forcing the
		// impossible state directly; the guard must hold regardless.
		store.viewsMu.Lock()
		store.records[operationID].Phase = checkpointOperationPhaseUnknown
		store.viewsMu.Unlock()
		err = recovery.markRecoveredSucceeded(&artifact, "an acknowledgment slot completing a record")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "acknowledgment only")
		persisted, perr := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, perr)
		assert.Equal(t, checkpointOperationPhaseSucceeded, persisted.Phase,
			"the durable fact stays succeeded")
	})

	t.Run("refuses to start once the store is draining", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, operationID)
		store.finishExecution(operationID, exec)
		store.shutdown()

		recovery, joined, err := store.recoverExisting(draft)
		assert.Nil(t, recovery)
		assert.Nil(t, joined)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.ErrorContains(t, err, "shutting down")
		_, running := store.executionDone(operationID)
		assert.False(t, running)
		persisted, perr := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, perr)
		assert.Equal(t, artifact.RootDigest, persisted.Artifact.RootDigest)
		assert.Equal(t, 1, journalRecordCount(t, store.rootDir))
	})

	t.Run("concurrent acknowledgment retries share one slot", func(t *testing.T) {
		store, draft, exec, _ := succeededOperationWithLiveExecutor(t, operationID)
		store.finishExecution(operationID, exec)

		const retries = 6
		var mu sync.Mutex
		var winner *checkpointOperationRecovery
		joins := make([]<-chan struct{}, 0, retries)
		errors := make([]error, retries)
		started := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < retries; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-started
				recovery, joined, err := store.recoverExisting(draft)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errors[i] = err
					return
				}
				if recovery != nil {
					if winner != nil {
						errors[i] = fmt.Errorf("a second acknowledgment slot was granted")
						return
					}
					winner = recovery
					return
				}
				joins = append(joins, joined)
			}(i)
		}
		close(started)
		wg.Wait()
		for i, err := range errors {
			require.NoErrorf(t, err, "acknowledgment retry %d", i)
		}
		require.NotNil(t, winner)
		require.Len(t, joins, retries-1)
		var winnerDone <-chan struct{} = winner.exec.done
		winner.finish()
		for _, joined := range joins {
			assert.Equal(t, winnerDone, joined, "every retry joined the winner's executor")
			select {
			case <-joined:
			default:
				t.Fatal("a joined acknowledgment retry outlived the winning executor")
			}
		}
	})

	t.Run("shutdown cancels and drains an acknowledgment slot", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, operationID)
		store.finishExecution(operationID, exec)
		before, err := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, err)

		recovery, _, err := store.recoverExisting(draft)
		require.NoError(t, err)
		require.NotNil(t, recovery)
		require.True(t, recovery.acknowledgmentOnly())
		ackCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		recovery.registerCancel(cancel)

		shutdownDone := make(chan struct{})
		go func() {
			store.shutdown()
			close(shutdownDone)
		}()
		select {
		case <-ackCtx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown did not cancel the acknowledgment-only executor")
		}
		select {
		case <-shutdownDone:
			t.Fatal("shutdown returned while the acknowledgment executor was still running")
		case <-time.After(200 * time.Millisecond):
		}
		// The drained slot may still finish its acknowledgment work — an
		// idempotent confirmation that rewrites nothing — before it returns.
		require.NoError(t, recovery.markRecoveredSucceeded(&artifact, "acknowledged during drain"))
		recovery.finish()
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown did not return after the acknowledgment executor exited")
		}
		after, err := readCheckpointOperationRecord(store.dir, operationID)
		require.NoError(t, err)
		assert.Equal(t, before.Artifact.RootDigest, after.Artifact.RootDigest)
		assert.Equal(t, before.UpdatedAt, after.UpdatedAt,
			"an acknowledgment must not rewrite the recorded receipt")
	})
}

// TestCheckpointOperationRecoveryBoundRecordIsIndependent pins that the handle
// hands out an independent copy: a caller cannot reach the published record —
// least of all a sealed root already recorded as SUCCEEDED — through the
// artifact pointer of the record it was admitted under.
func TestCheckpointOperationRecoveryBoundRecordIsIndependent(t *testing.T) {
	t.Run("succeeded receipt is duplicated", func(t *testing.T) {
		store, draft, exec, artifact := succeededOperationWithLiveExecutor(t, "op-ack-bound")
		store.finishExecution("op-ack-bound", exec)
		recovery, _, err := store.recoverExisting(draft)
		require.NoError(t, err)
		require.NotNil(t, recovery)
		defer recovery.finish()

		bound := recovery.boundRecord()
		require.NotNil(t, bound)
		require.NotNil(t, bound.Artifact)
		assert.NotSame(t, recovery.bound.Artifact, bound.Artifact)
		// Scribbling on the handed-out copy changes neither the published view
		// nor the durable receipt, and cannot smuggle a different root past
		// the idempotency check of the slot's own completion.
		bound.Artifact.RootDigest = conflictingDigest(t, artifact.RootDigest)
		bound.Artifact.Scheme = "unknown-root"
		bound.Phase = checkpointOperationPhaseUnknown
		bound.SandboxID = "sbox-forged"

		published, ok := store.published("op-ack-bound")
		require.True(t, ok)
		assert.Equal(t, checkpointOperationPhaseSucceeded, published.Phase)
		assert.Equal(t, "sbox-rec-ack", published.SandboxID)
		require.NotNil(t, published.Artifact)
		assert.Equal(t, artifact.RootDigest, published.Artifact.RootDigest)
		assert.Equal(t, artifact.Scheme, published.Artifact.Scheme)
		persisted, perr := readCheckpointOperationRecord(store.dir, "op-ack-bound")
		require.NoError(t, perr)
		assert.Equal(t, artifact.RootDigest, persisted.Artifact.RootDigest)

		require.NoError(t, recovery.markRecoveredSucceeded(&artifact, "acknowledgment retry"))
		err = recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: bound.Artifact.RootDigest, Scheme: artifact.Scheme},
			"the mutated copy as evidence")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "conflict")
	})

	t.Run("undetermined record has no artifact to alias", func(t *testing.T) {
		root := t.TempDir()
		request := checkpointOperationRequest(
			"op-ack-bound-unknown", "sbox-rec-bound", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"outcome unproven, re-execution forbidden"))
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		defer recovery.finish()

		bound := recovery.boundRecord()
		require.NotNil(t, bound)
		assert.Nil(t, bound.Artifact)
		bound.Phase = checkpointOperationPhaseSucceeded
		bound.RequestDigest = strings.Repeat("c", checkpointroot.DigestHexLen)
		published, ok := s.checkpointOperations.published("op-ack-bound-unknown")
		require.True(t, ok)
		assert.Equal(t, checkpointOperationPhaseUnknown, published.Phase)
		assert.Equal(t, requestDigestOf(t, request), published.RequestDigest)
	})
}

// --- shutdown ---

// TestCheckpointOperationRecoveryShutdownClosesAdmissionAndWaits: a draining
// store never starts a recovery, and shutdown cancels a recovery executor to
// request convergence, waits for its real exit, and does not revoke a durable
// completion the executor lands before returning.
func TestCheckpointOperationRecoveryShutdownClosesAdmissionAndWaits(t *testing.T) {
	t.Run("admission is closed once draining", func(t *testing.T) {
		root := t.TempDir()
		request := checkpointOperationRequest(
			"op-rec-drain", "sbox-rec-drain", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"outcome unproven, re-execution forbidden"))
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		s.checkpointOperations.shutdown()

		recovery, joined, err := s.checkpointOperations.recoverExisting(recoveryDraftForRequest(t, request))
		assert.Nil(t, recovery)
		assert.Nil(t, joined)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.ErrorContains(t, err, "shutting down")
		_, running := s.checkpointOperations.executionDone("op-rec-drain")
		assert.False(t, running)
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-rec-drain").Phase)
		assert.Equal(t, 1, journalRecordCount(t, root))
	})

	t.Run("shutdown requests convergence and waits for the real exit", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, os.MkdirAll(directory, 0700))
		require.NoError(t, writeSealedCheckpointDirectory(directory))
		rootBinding, err := checkpointroot.Bind(directory)
		require.NoError(t, err)
		request := checkpointOperationRequest("op-rec-conv", "sbox-rec-conv", directory, "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"outcome unproven, re-execution forbidden"))
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		recoveryCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		recovery.registerCancel(cancel)

		shutdownDone := make(chan struct{})
		go func() {
			s.checkpointOperations.shutdown()
			close(shutdownDone)
		}()
		// Shutdown cancels the recovery executor's context to request
		// convergence...
		select {
		case <-recoveryCtx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown did not cancel the recovery executor")
		}
		// ...and then blocks until that executor has actually returned, even
		// though it ignores the cancellation.
		select {
		case <-shutdownDone:
			t.Fatal("shutdown returned while the recovery executor was still running")
		case <-time.After(200 * time.Millisecond):
		}
		// The convergence request does not revoke the slot: the executor may
		// still land the original operation's durable fact before it returns.
		require.NoError(t, recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: rootBinding.RootDigest, Scheme: rootBinding.Scheme},
			"recovery completed before returning during shutdown"))
		recovery.finish()
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown did not return after the recovery executor exited")
		}
		assert.Equal(t, checkpointOperationPhaseSucceeded,
			readJournalCheckpointOperation(t, root, "op-rec-conv").Phase)
	})
}

// TestCheckpointOperationRecoveryAdmissionShutdownRace races recovery
// admissions against a concurrent shutdown: every applicant gets a definitive
// answer, a joiner always waits on an executor some applicant won, no second
// slot is granted beside a live one, and shutdown returns once every granted
// slot has really been released.
func TestCheckpointOperationRecoveryAdmissionShutdownRace(t *testing.T) {
	const iterations = 25
	for i := 0; i < iterations; i++ {
		root := t.TempDir()
		request := checkpointOperationRequest(
			fmt.Sprintf("op-rec-race-%d", i), "sbox-rec-shutdown",
			filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedCheckpointOperationRecord(t, root, seededCheckpointOperationRecord(
			request, config.RuntimeNameRunsc, requestDigestOf(t, request), checkpointOperationPhaseUnknown,
			"outcome unproven, re-execution forbidden"))
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		draft := recoveryDraftForRequest(t, request)

		var mu sync.Mutex
		granted := []*checkpointOperationRecovery{}
		joins := []<-chan struct{}{}
		refusals := []error{}
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				recovery, joined, err := s.checkpointOperations.recoverExisting(draft)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err != nil:
					refusals = append(refusals, err)
				case recovery != nil:
					granted = append(granted, recovery)
				case joined != nil:
					joins = append(joins, joined)
				}
			}()
		}
		shutdownDone := make(chan struct{})
		go func() {
			s.checkpointOperations.shutdown()
			close(shutdownDone)
		}()
		wg.Wait()
		for _, refusal := range refusals {
			assert.Equal(t, codes.Unavailable, status.Code(refusal))
		}

		// Every joiner waited on an executor one of the applicants won, and no
		// live executor ever coexisted with a second granted slot.
		for _, joined := range joins {
			matched := false
			for _, recovery := range granted {
				if joined == recovery.exec.done {
					matched = true
					break
				}
			}
			assert.True(t, matched, "a joiner waited on an executor no applicant was granted")
		}
		// Releasing every granted slot is what lets shutdown return: it waits
		// for the real exit of each executor it discovered.
		for _, recovery := range granted {
			recovery.finish()
		}
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: shutdown did not return after %d slots were released", i, len(granted))
		}
		assert.Equal(t, 4, len(granted)+len(joins)+len(refusals))
		if len(granted) > 0 {
			_, running := s.checkpointOperations.executionDone(request.GetOperationID())
			assert.False(t, running, "a released slot must leave the registry")
		}
	}
}
