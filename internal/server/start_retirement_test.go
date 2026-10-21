package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/require"
)

func retirementRequest(op, sandbox string) *runtime.RetireStartOperationRequest {
	return &runtime.RetireStartOperationRequest{OperationID: op, SandboxID: sandbox}
}

func TestRetirementBeforeAdmissionSurvivesRestartAndRejectsLateStart(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const op, id = "retire-before-arrival", "sbox-retire-before-arrival"
	first, err := s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.NoError(t, err)
	require.NotEmpty(t, first.GetRetirementReceipt())
	operations, err := loadStartOperations(s.config.RootDir)
	require.NoError(t, err)
	s.startOperations = operations
	_, err = s.StartWithOperation(context.Background(), operationWrapper(op, intentTestStartRequest(t, id)))
	require.Error(t, err)
	starts, _, _ := handler.counts()
	require.Zero(t, starts, "late RPC must not invoke the runtime after restart")
	again, err := s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.NoError(t, err)
	require.Equal(t, first.GetRetirementReceipt(), again.GetRetirementReceipt())
	_, err = s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err, "legacy Start must not bypass the tombstone by omitting operation ID")
}

func TestRetirementFencePersistenceFailureReturnsNoProofAndStillDenies(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	s.startOperations.persistHook = func(*startOperationRecord) error { return errors.New("injected fsync failure") }
	req := retirementRequest("retire-fsync", "sbox-retire-fsync")
	proof, err := s.RetireStartOperation(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, proof)
	require.False(t, s.startOperations.snapshot(req.OperationID).RetirementComplete)
	_, err = s.StartWithOperation(context.Background(), operationWrapper(req.OperationID, intentTestStartRequest(t, req.SandboxID)))
	require.Error(t, err)
	s.startOperations.persistHook = nil
	proof, err = s.RetireStartOperation(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, proof.GetRetirementReceipt())
}

func TestRetirementWaitsForActualExecutorAndTimeoutKeepsProtection(t *testing.T) {
	s := newIntentTestService(t, newOperationRuntimeHandler())
	draft := newStartOperationDraft(t, "retire-active", "sbox-retire-active")
	execution, _, err := s.startOperations.admit(draft)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	proof, err := s.RetireStartOperation(ctx, retirementRequest(draft.OperationID, draft.SandboxID))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, proof)
	require.True(t, s.startOperations.snapshot(draft.OperationID).RetirementRequested)
	require.False(t, s.startOperations.snapshot(draft.OperationID).RetirementComplete)
	// A durable failed fact is not enough while the executor still runs.
	require.NoError(t, s.startOperations.markFailedConfirmed(draft.OperationID, "fully rolled back"))
	result := make(chan error, 1)
	go func() {
		_, err := s.RetireStartOperation(context.Background(), retirementRequest(draft.OperationID, draft.SandboxID))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("retirement returned before executor exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	s.startOperations.finishExecution(draft.OperationID, execution)
	require.NoError(t, <-result)
	require.True(t, s.startOperations.snapshot(draft.OperationID).RetirementComplete)
}

func TestRetirementUnknownOutcomeNeverBecomesAbsenceProof(t *testing.T) {
	s := newIntentTestService(t, newOperationRuntimeHandler())
	draft := newStartOperationDraft(t, "retire-unknown", "sbox-retire-unknown")
	execution, _, err := s.startOperations.admit(draft)
	require.NoError(t, err)
	s.startOperations.markUnknown(draft.OperationID, "daemon lost completion")
	s.startOperations.finishExecution(draft.OperationID, execution)
	proof, err := s.RetireStartOperation(context.Background(), retirementRequest(draft.OperationID, draft.SandboxID))
	require.Error(t, err)
	require.Nil(t, proof)
	require.True(t, s.startOperations.snapshot(draft.OperationID).RetirementRequested)
	require.False(t, s.startOperations.snapshot(draft.OperationID).RetirementComplete)
}

func TestRetirementConcurrentReplayHasOneDurableIdentity(t *testing.T) {
	s := newIntentTestService(t, newOperationRuntimeHandler())
	req := retirementRequest("retire-replay", "sbox-retire-replay")
	const n = 8
	results := make(chan *runtime.RetireStartOperationResponse, n)
	failures := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.RetireStartOperation(context.Background(), req)
			results <- got
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	var receipt string
	for got := range results {
		require.NotNil(t, got)
		if receipt == "" {
			receipt = got.GetRetirementReceipt()
		}
		require.Equal(t, receipt, got.GetRetirementReceipt())
	}
	_, err := s.RetireStartOperation(context.Background(), retirementRequest(req.OperationID, "sbox-another-owner"))
	require.Error(t, err, "an operation cannot retire a different sandbox")
}

func TestRetirementCompletedReplayCannotDeleteLaterIncarnation(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	old := retirementRequest("retire-old-operation", "sbox-reused-id")
	proof, err := s.RetireStartOperation(context.Background(), old)
	require.NoError(t, err)
	_, err = s.StartWithOperation(context.Background(), operationWrapper("new-incarnation-operation", intentTestStartRequest(t, old.SandboxID)))
	require.NoError(t, err, "a distinct identified incarnation may reuse a physical ID")
	replay, err := s.RetireStartOperation(context.Background(), old)
	require.NoError(t, err)
	require.Equal(t, proof.GetRetirementReceipt(), replay.GetRetirementReceipt())
	_, deletes, strict := handler.counts()
	require.Zero(t, deletes)
	require.Zero(t, strict, "an old completed receipt must never retire the new generation")
}

func TestRetirementSuccessfulStartUsesStrictProofAndReplaySparesNewGeneration(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const op, id = "retire-successful-operation", "sbox-retire-successful"
	started, err := s.StartWithOperation(context.Background(), operationWrapper(op, intentTestStartRequest(t, id)))
	require.NoError(t, err)
	require.NotEmpty(t, started.GetResourceGeneration())
	require.Equal(t, "10.0.0.2", started.GetSandboxIp(), "additive operation status preserves routing IP")
	seedRetirementRuntimeSpec(t, s, id)
	proof, err := s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.NoError(t, err)
	require.Equal(t, started.GetResourceGeneration(), proof.GetResourceGeneration())
	require.NotEmpty(t, proof.GetRetirementReceipt())
	_, legacyDeletes, strictDeletes := handler.counts()
	require.Zero(t, legacyDeletes, "legacy idempotent Delete is not retirement proof")
	require.Equal(t, 1, strictDeletes)
	next, err := s.StartWithOperation(context.Background(), operationWrapper("next-operation-after-retirement", intentTestStartRequest(t, id)))
	require.NoError(t, err)
	require.NotEqual(t, started.GetResourceGeneration(), next.GetResourceGeneration())
	replay, err := s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.NoError(t, err)
	require.Equal(t, proof.GetRetirementReceipt(), replay.GetRetirementReceipt())
	_, legacyDeletes, strictDeletes = handler.counts()
	require.Zero(t, legacyDeletes)
	require.Equal(t, 1, strictDeletes, "completed old operation replay cannot delete current generation")
}

func TestRetirementStrictExitFailureKeepsFenceWithoutReceipt(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const op, id = "retire-exit-unconfirmed", "sbox-retire-exit-unconfirmed"
	_, err := s.StartWithOperation(context.Background(), operationWrapper(op, intentTestStartRequest(t, id)))
	require.NoError(t, err)
	seedRetirementRuntimeSpec(t, s, id)
	handler.setStrictErr(errors.New("exit unconfirmed"))
	proof, err := s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.Error(t, err)
	require.Nil(t, proof)
	record := s.startOperations.snapshot(op)
	require.True(t, record.RetirementRequested)
	require.False(t, record.RetirementComplete)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err, "unproven exit retains sandbox metadata and resources")
	handler.setStrictErr(nil)
	proof, err = s.RetireStartOperation(context.Background(), retirementRequest(op, id))
	require.NoError(t, err)
	require.NotEmpty(t, proof.GetRetirementReceipt())
}

// The fake runtime does not generate OCI bundles; mirror the already-existing
// start-operation deletion fixture rather than weakening production spec reads.
func seedRetirementRuntimeSpec(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(s.config.RootDir, "containers", id, "config.json"),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`), 0600))
}
