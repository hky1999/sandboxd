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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// strictDeleteHandler records strict deletions and can inject failures,
// mimicking a runtime whose DeleteStrict proves retirement of one bound
// generation of found state.
type strictDeleteHandler struct {
	*svc.FakeRuntimeHandler

	mu            sync.Mutex
	strictCalls   int
	legacyCalls   int
	lastStrictID  string
	lastStrictGen string
	strictFn      func(context.Context, string, string) error
}

func (h *strictDeleteHandler) DeleteStrict(
	ctx context.Context,
	sandboxID, expectedGeneration string,
) error {
	h.mu.Lock()
	h.strictCalls++
	h.lastStrictID = sandboxID
	h.lastStrictGen = expectedGeneration
	fn := h.strictFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, sandboxID, expectedGeneration)
	}
	return nil
}

func (h *strictDeleteHandler) Delete(ctx context.Context, sandboxID string) error {
	h.mu.Lock()
	h.legacyCalls++
	h.mu.Unlock()
	return h.FakeRuntimeHandler.Delete(ctx, sandboxID)
}

func (h *strictDeleteHandler) strictCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.strictCalls
}

func (h *strictDeleteHandler) legacyCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.legacyCalls
}

// checkpointStrictHandler combines the checkpoint capability with a recording
// strict delete on one runtime handler.
type checkpointStrictHandler struct {
	*checkpointTestHandler
	strictMu      sync.Mutex
	strictCalls   int
	lastStrictGen string
}

func (h *checkpointStrictHandler) DeleteStrict(
	_ context.Context,
	_, expectedGeneration string,
) error {
	h.strictMu.Lock()
	defer h.strictMu.Unlock()
	h.strictCalls++
	h.lastStrictGen = expectedGeneration
	return nil
}

func (h *checkpointStrictHandler) strictCount() int {
	h.strictMu.Lock()
	defer h.strictMu.Unlock()
	return h.strictCalls
}

func storeGenerationSandbox(t *testing.T, s *sandboxService, id, generation string) {
	t.Helper()
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{resourceGenerationLabel: generation},
	}))
}

func TestDeleteIfGenerationRejectsStaleAndReturnsPhysicalReceipt(t *testing.T) {
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "generation-delete"
	storeGenerationSandbox(t, s, id, "physical-one")

	for _, request := range []*runtime.DeleteIfGenerationRequest{
		nil,
		{ID: id},
		{ExpectedGeneration: "physical-one"},
	} {
		_, err := s.DeleteIfGeneration(context.Background(), request)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	// A stale generation must produce zero side effects: no runtime call, no
	// receipt, and the sandbox keeps its physical identity.
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "wrong",
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.strictCount())
	receipt, err := s.readRetirement(id, "wrong")
	require.NoError(t, err)
	require.Nil(t, receipt)

	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "physical-one",
	})
	require.NoError(t, err)
	require.Equal(t, "physical-one", response.RetiredGeneration)
	require.Equal(t, 1, handler.strictCount())
	// The service passed the caller's expected generation — the stored
	// metadata identity — through to the runtime's strict delete.
	handler.mu.Lock()
	require.Equal(t, id, handler.lastStrictID)
	require.Equal(t, "physical-one", handler.lastStrictGen)
	handler.mu.Unlock()

	// Replay reuses the durable receipt without another runtime retirement.
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "physical-one",
	})
	require.NoError(t, err)
	require.Equal(t, 1, handler.strictCount())

	// A replacement incarnation under the same ID is not touched by the old
	// generation's receipt.
	storeGenerationSandbox(t, s, id, "physical-two")
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "physical-one",
	})
	require.NoError(t, err)
	require.Equal(t, 1, handler.strictCount())
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "physical-two", current.Metadata.Labels[resourceGenerationLabel])
}

func TestRetirementReceiptSurvivesServiceReopen(t *testing.T) {
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "receipt-reopen"
	storeGenerationSandbox(t, s, id, "generation")
	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)

	// A fresh service instance has no in-memory sandbox state but reads the
	// same durable journal under the shared root.
	reopenedHandler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	reopened := newTestService(t, map[string]svc.Handler{"runsc": reopenedHandler})
	reopened.config.RootDir = s.config.RootDir
	receipt, err := reopened.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "generation", receipt.RetiredGeneration)
	require.Zero(t, reopenedHandler.strictCount())
}

func TestPendingOrCorruptRetirementCannotProveDeletion(t *testing.T) {
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	request := &runtime.DeleteIfGenerationRequest{ID: "missing", ExpectedGeneration: "generation"}

	// No record at all: a missing sandbox without a receipt stays unknown.
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Zero(t, handler.strictCount())

	// A pending record alone proves nothing.
	require.NoError(t, s.writeRetirement(request.ID, request.ExpectedGeneration, false))
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Zero(t, handler.strictCount())

	// A corrupt record proves nothing either.
	_, path := s.retirementPath(request.ID, request.ExpectedGeneration)
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.Zero(t, handler.strictCount())
}

func TestRetirementJournalFailurePreventsPhysicalDelete(t *testing.T) {
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeGenerationSandbox(t, s, "blocked", "generation")
	// A journal path that cannot be created must fail the delete before the
	// runtime is allowed to produce any effect.
	require.NoError(t, os.WriteFile(
		filepath.Join(s.config.RootDir, "scheduler-retirements"),
		[]byte("not a directory"),
		0600,
	))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: "blocked", ExpectedGeneration: "generation",
	})
	require.Error(t, err)
	require.Zero(t, handler.strictCount())
	_, getErr := s.sandboxManager.Get("blocked")
	require.NoError(t, getErr)
}

func TestPendingRetirementRetriesOnlyMatchingLiveGeneration(t *testing.T) {
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "pending-live"
	storeGenerationSandbox(t, s, id, "new")

	// A pending receipt for a superseded generation cannot retire the live one.
	require.NoError(t, s.writeRetirement(id, "old", false))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "old",
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.strictCount())

	require.NoError(t, s.writeRetirement(id, "new", false))
	receipt, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "new",
	})
	require.NoError(t, err)
	require.Equal(t, "new", receipt.RetiredGeneration)
	require.Equal(t, 1, handler.strictCount())
	saved, err := s.readRetirement(id, "new")
	require.NoError(t, err)
	require.True(t, saved.Complete)
}

func TestDeleteIfGenerationRequiresStrictRuntime(t *testing.T) {
	// The plain fake handler implements only the legacy idempotent Delete, so
	// conditional deletion must be rejected before any effect or receipt.
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "not-strict"
	storeGenerationSandbox(t, s, id, "generation")
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "generation",
	})
	require.Equal(t, codes.Unimplemented, status.Code(err))
	_, getErr := s.sandboxManager.Get(id)
	require.NoError(t, getErr)
	receipt, readErr := s.readRetirement(id, "generation")
	require.NoError(t, readErr)
	require.Nil(t, receipt)
}

func TestDeleteIfGenerationRejectsRuntimeMissingState(t *testing.T) {
	// Runtime absence is not a retirement proof: DeleteStrict reporting a
	// missing state must fail the conditional delete and leave the receipt
	// pending rather than complete.
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	handler.strictFn = func(_ context.Context, _, _ string) error {
		return errord.ErrNotFound
	}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "runtime-missing"
	storeGenerationSandbox(t, s, id, "generation")
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "generation",
	})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Equal(t, 1, handler.strictCount())
	receipt, readErr := s.readRetirement(id, "generation")
	require.NoError(t, readErr)
	require.NotNil(t, receipt)
	require.False(t, receipt.Complete)
	// Metadata survived: nothing after the strict gate ran.
	_, getErr := s.sandboxManager.Get(id)
	require.NoError(t, getErr)
}

func TestDeleteIfGenerationWaitsForInFlightCheckpoint(t *testing.T) {
	combined := &checkpointStrictHandler{
		checkpointTestHandler: newCheckpointTestHandler(),
	}
	checkpointStarted := make(chan struct{})
	checkpointRelease := make(chan struct{})
	combined.checkpointFn = func(_ context.Context, _ svc.CheckpointConfig) error {
		close(checkpointStarted)
		<-checkpointRelease
		return nil
	}
	s := newTestService(t, map[string]svc.Handler{"runsc": combined})
	const id = "checkpoint-delete"
	storeGenerationSandbox(t, s, id, "generation")

	checkpointDone := make(chan error, 1)
	go func() {
		_, err := s.Checkpoint(context.Background(), &runtime.CheckpointRequest{
			ID:             id,
			CheckpointDir:  filepath.Join(t.TempDir(), "checkpoint"),
			TimeoutSeconds: 30,
			LeaveRunning:   true,
		})
		checkpointDone <- err
	}()
	<-checkpointStarted

	// The conditional delete must queue on the shared physical lock while the
	// checkpoint holds it, not retire the sandbox underneath the operation.
	deleteDone := make(chan error, 1)
	go func() {
		_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
			ID: id, ExpectedGeneration: "generation",
		})
		deleteDone <- err
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("conditional delete finished while checkpoint held the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.Zero(t, combined.strictCount())

	close(checkpointRelease)
	require.NoError(t, <-checkpointDone)
	require.NoError(t, <-deleteDone)
	combined.strictMu.Lock()
	require.Equal(t, 1, combined.strictCalls)
	require.Equal(t, "generation", combined.lastStrictGen)
	combined.strictMu.Unlock()
	receipt, err := s.readRetirement(id, "generation")
	require.NoError(t, err)
	require.True(t, receipt.Complete)
}

func TestDeleteIfGenerationDoesNotJoinLegacySingleflight(t *testing.T) {
	// A legacy force-delete in flight must not satisfy a conditional request:
	// the conditional path either observes its own strict proof or reports an
	// unknown outcome, never a fabricated receipt.
	legacyHandler := &blockingDeleteHandler{
		FakeRuntimeHandler: svc.NewFakeRuntimeHandler(),
		started:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	s := newTestService(t, map[string]svc.Handler{"runsc": legacyHandler})
	const id = "legacy-then-conditional"
	storeGenerationSandbox(t, s, id, "generation")

	legacyDone := make(chan error, 1)
	go func() {
		_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
		legacyDone <- err
	}()
	<-legacyHandler.started

	conditionalDone := make(chan error, 1)
	go func() {
		_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
			ID: id, ExpectedGeneration: "generation",
		})
		conditionalDone <- err
	}()
	// The conditional delete queues on the physical lock held by the legacy
	// delete; it cannot complete first.
	select {
	case err := <-conditionalDone:
		t.Fatalf("conditional delete finished while legacy delete held the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(legacyHandler.release)
	require.NoError(t, <-legacyDone)
	// The legacy flight retired the sandbox without a receipt, so the
	// conditional outcome is unknown — reported as an error, not success.
	err := <-conditionalDone
	require.Equal(t, codes.NotFound, status.Code(err))
	receipt, readErr := s.readRetirement(id, "generation")
	require.NoError(t, readErr)
	require.Nil(t, receipt)
}

func TestDeleteIfGenerationCallerCancellationKeepsBackgroundResult(t *testing.T) {
	strictStarted := make(chan struct{})
	strictRelease := make(chan struct{})
	handler := &strictDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	handler.strictFn = func(_ context.Context, _, _ string) error {
		close(strictStarted)
		<-strictRelease
		return nil
	}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "cancel-uncertain"
	storeGenerationSandbox(t, s, id, "generation")

	callerCtx, cancel := context.WithCancel(context.Background())
	cancelledDone := make(chan error, 1)
	go func() {
		_, err := s.DeleteIfGeneration(callerCtx, &runtime.DeleteIfGenerationRequest{
			ID: id, ExpectedGeneration: "generation",
		})
		cancelledDone <- err
	}()
	<-strictStarted
	cancel()
	require.ErrorIs(t, <-cancelledDone, context.Canceled)

	// The caller timeout is not a retirement verdict: cleanup continues with
	// the detached context and the receipt decides the final outcome.
	close(strictRelease)
	require.Eventually(t, func() bool {
		receipt, err := s.readRetirement(id, "generation")
		return err == nil && receipt != nil && receipt.Complete
	}, 5*time.Second, 50*time.Millisecond, "background retirement never completed")

	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: "generation",
	})
	require.NoError(t, err)
	require.Equal(t, 1, handler.strictCount())
}

func TestAssignResourceGenerationIgnoresClientLabel(t *testing.T) {
	request := &runtime.StartRequest{
		Labels: map[string]string{resourceGenerationLabel: "client-chosen"},
	}
	generation := assignResourceGeneration(request)
	require.NotEqual(t, "client-chosen", generation)
	require.Equal(t, generation, request.Labels[resourceGenerationLabel])
	require.Len(t, generation, 36) // uuid v4 canonical form

	// Every incarnation gets a fresh identity, even for the same request.
	next := assignResourceGeneration(request)
	require.NotEqual(t, generation, next)

	freshRequest := &runtime.StartRequest{}
	fresh := assignResourceGeneration(freshRequest)
	require.Equal(t, fresh, freshRequest.Labels[resourceGenerationLabel])
}

func TestPhysicalLocksSerializeAndCancel(t *testing.T) {
	var locks physicalLocks
	unlockFirst, err := locks.acquire(context.Background(), "id")
	require.NoError(t, err)

	acquired := make(chan struct{})
	go func() {
		unlockSecond, err := locks.acquire(context.Background(), "id")
		if err != nil {
			t.Errorf("second acquire failed: %v", err)
			return
		}
		close(acquired)
		unlockSecond()
	}()
	select {
	case <-acquired:
		t.Fatal("second acquire entered the critical section concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	unlockFirst()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("second acquire never completed after release")
	}

	// A cancelled waiter releases its reference and must not wedge the key.
	unlockHeld, err := locks.acquire(context.Background(), "id")
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = locks.acquire(waitCtx, "id")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	unlockHeld()
	unlock, err := locks.acquire(context.Background(), "id")
	require.NoError(t, err)
	unlock()
}
