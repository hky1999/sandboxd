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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	stdruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// operationRuntimeHandler extends the intent-test runtime with checkpoint
// restore support, generation observation, an optional start gate, and an
// optional cancellation-respecting mode for shutdown tests.
type operationRuntimeHandler struct {
	*intentRuntimeHandler

	mu                sync.Mutex
	restores          []svc.StartConfig
	restoreFn         func(svc.StartConfig) error
	startGate         chan struct{}
	respectCtx        bool
	lastStartGen      string
	freshStartSawRoot bool
}

func newOperationRuntimeHandler() *operationRuntimeHandler {
	return &operationRuntimeHandler{
		intentRuntimeHandler: &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()},
	}
}

// enableStartGate makes every subsequent Start/Restore block until released,
// ignoring context cancellation (the "downstream refuses to converge" arm).
func (h *operationRuntimeHandler) enableStartGate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startGate = make(chan struct{})
}

// respectContext makes Start/Restore return on ctx.Done instead of ignoring it.
func (h *operationRuntimeHandler) respectContext() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.respectCtx = true
}

func (h *operationRuntimeHandler) releaseStarts() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.startGate != nil {
		close(h.startGate)
		h.startGate = nil
	}
}

func (h *operationRuntimeHandler) awaitStart(ctx context.Context) error {
	h.mu.Lock()
	gate, respectCtx := h.startGate, h.respectCtx
	h.mu.Unlock()
	if gate == nil {
		return nil
	}
	if respectCtx {
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-gate
	return nil
}

func (h *operationRuntimeHandler) Start(ctx context.Context, cfg svc.StartConfig) error {
	if err := h.awaitStart(ctx); err != nil {
		return err
	}
	h.mu.Lock()
	h.lastStartGen = cfg.Annotations[resourceGenerationLabel]
	if cfg.ExpectedCheckpointRoot != "" {
		h.freshStartSawRoot = true
	}
	h.mu.Unlock()
	return h.intentRuntimeHandler.Start(ctx, cfg)
}

// freshStartObservedRoot reports whether any fresh (non-restore) Start was
// handed an expected checkpoint root.
func (h *operationRuntimeHandler) freshStartObservedRoot() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.freshStartSawRoot
}

func (h *operationRuntimeHandler) Checkpoint(_ context.Context, cfg svc.CheckpointConfig) error {
	return os.WriteFile(filepath.Join(cfg.Directory, "checkpoint.img"), []byte("image"), 0600)
}

func (h *operationRuntimeHandler) Restore(ctx context.Context, cfg svc.StartConfig) error {
	h.mu.Lock()
	h.restores = append(h.restores, cfg)
	h.lastStartGen = cfg.Annotations[resourceGenerationLabel]
	restoreFn := h.restoreFn
	h.mu.Unlock()
	if err := h.awaitStart(ctx); err != nil {
		return err
	}
	if restoreFn != nil {
		return restoreFn(cfg)
	}
	return nil
}

// SupportsCheckpointRootVerification declares the capability the server
// requires before admitting an identified restore operation; the test
// handler records the expected root it was handed instead of enforcing it.
func (h *operationRuntimeHandler) SupportsCheckpointRootVerification() bool {
	return true
}

// observedExpectedRoot returns the checkpoint content root the runtime's
// Restore was last handed.
func (h *operationRuntimeHandler) observedExpectedRoot() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.restores) == 0 {
		return ""
	}
	return h.restores[len(h.restores)-1].ExpectedCheckpointRoot
}

func (h *operationRuntimeHandler) restoreCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.restores)
}

// observedGeneration returns the generation label the runtime last ran under.
func (h *operationRuntimeHandler) observedGeneration() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastStartGen
}

func operationWrapper(id string, start *runtime.StartRequest) *runtime.StartWithOperationRequest {
	return &runtime.StartWithOperationRequest{
		OperationID: id,
		SandboxID:   start.SandboxID,
		Start:       start,
	}
}

// --- admission, replay, and concurrency ---

// The same operation with the same request executes the runtime exactly once:
// concurrent replays join the admitted execution instead of racing it, and
// every caller observes the recorded success with the daemon-assigned
// generation the runtime actually saw. A caller-supplied generation label can
// never choose it.
func TestStartOperationConcurrentSameRequestExecutesOnce(t *testing.T) {
	handler := newOperationRuntimeHandler()
	handler.enableStartGate()
	t.Cleanup(handler.releaseStarts)
	s := newIntentTestService(t, handler)
	const id = "sbox-op-concurrent"
	start := intentTestStartRequest(t, id)
	start.Labels = map[string]string{resourceGenerationLabel: "client-forged-generation"}
	wrapper := operationWrapper("op-concurrent-1", start)

	const callers = 8
	generations := make(chan string, callers)
	failures := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.StartWithOperation(context.Background(), wrapper)
			failures <- err
			if err == nil {
				generations <- got.GetResourceGeneration()
			}
		}()
	}
	// Let every caller arrive (the executor blocks inside the runtime), then
	// release the gate so the single execution finishes.
	time.Sleep(100 * time.Millisecond)
	handler.releaseStarts()
	wg.Wait()
	close(failures)
	close(generations)
	for err := range failures {
		require.NoError(t, err)
	}
	seen := map[string]bool{}
	for generation := range generations {
		require.NotEmpty(t, generation)
		seen[generation] = true
	}
	require.Len(t, seen, 1, "every caller must observe the single admitted generation")

	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts, "concurrent same-operation replays must execute the runtime once")
	require.NotEqual(t, "client-forged-generation", handler.observedGeneration(),
		"a caller-supplied generation label must never be honored")

	// A replay after the terminal outcome answers from history and never
	// re-executes.
	again, err := s.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, again.GetState())
	require.Equal(t, handler.observedGeneration(), again.GetResourceGeneration())
	starts, _, _ = handler.counts()
	require.Equal(t, 1, starts)

	got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-concurrent-1"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, got.GetState())
	require.Equal(t, handler.observedGeneration(), got.GetResourceGeneration())
}

// A different request under the same operation ID is a conflict, not a retry.
func TestStartOperationDifferentRequestConflicts(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-op-conflict"

	first, err := s.StartWithOperation(context.Background(),
		operationWrapper("op-conflict-1", intentTestStartRequest(t, id)))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, first.GetState())

	// Same ID, different command: refused without touching the runtime.
	changed := intentTestStartRequest(t, id)
	changed.Command = []string{"/bin/other"}
	_, err = s.StartWithOperation(context.Background(), operationWrapper("op-conflict-1", changed))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "different request")
	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts)

	// A different sandbox ID is likewise refused.
	_, err = s.StartWithOperation(context.Background(),
		operationWrapper("op-conflict-1", intentTestStartRequest(t, "sbox-op-conflict-b")))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	starts, _, _ = handler.counts()
	require.Equal(t, 1, starts)
}

// Caller cancellation ends only the waiting: the admitted executor keeps
// running under the service lifecycle, the operation stays queryable through
// the cancellation, and completion is still recorded exactly once.
func TestStartOperationCallerCancelEndsOnlyTheWait(t *testing.T) {
	handler := newOperationRuntimeHandler()
	handler.enableStartGate()
	t.Cleanup(handler.releaseStarts)
	s := newIntentTestService(t, handler)
	const id = "sbox-op-cancel"
	wrapper := operationWrapper("op-cancel-1", intentTestStartRequest(t, id))

	// The first caller becomes the deterministic executor: wait until its
	// admission is visible before launching the joiner, so the joiner can
	// only join, never execute.
	executorDone := make(chan error, 1)
	go func() {
		_, err := s.StartWithOperation(context.Background(), wrapper)
		executorDone <- err
	}()
	waitForOperationState(t, s, "op-cancel-1", runtime.StartOperationState_START_OPERATION_STATE_RUNNING)

	// A second caller joins the running execution and gives up waiting.
	joinerCtx, cancel := context.WithCancel(context.Background())
	joinerDone := make(chan error, 1)
	go func() {
		_, err := s.StartWithOperation(joinerCtx, wrapper)
		joinerDone <- err
	}()
	// Let the joiner arrive, then end only its wait.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-joinerDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled joiner did not return")
	}

	// The admitted execution is untouched by the joiner's cancellation.
	got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-cancel-1"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RUNNING, got.GetState())

	handler.releaseStarts()
	require.NoError(t, <-executorDone)
	waitForOperationState(t, s, "op-cancel-1", runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED)
	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts)
}

// The success fact survives sandbox deletion: replaying the old operation
// reports the historical success with the original generation and never
// re-creates, while a new operation may create a fresh incarnation under the
// freed ID and the replaced incarnation never steals the old fact.
func TestStartOperationReplayAfterDeleteKeepsHistoricalSuccess(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-op-after-delete"
	wrapper := operationWrapper("op-after-delete-1", intentTestStartRequest(t, id))

	first, err := s.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, first.GetState())
	originalGeneration := first.GetResourceGeneration()

	// Stage the OCI spec a real runtime would have written, then delete.
	require.NoError(t, os.WriteFile(
		filepath.Join(s.config.RootDir, "containers", id, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0600,
	))
	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	require.NoError(t, err)

	// The old operation replays as its recorded historical success.
	afterDelete, err := s.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, afterDelete.GetState())
	require.Equal(t, originalGeneration, afterDelete.GetResourceGeneration(),
		"the historical success reports the original generation even though the sandbox is gone")
	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts, "replay after delete must never re-create")

	// A new operation may create again under the freed ID, with a fresh
	// daemon-assigned generation.
	second, err := s.StartWithOperation(context.Background(),
		operationWrapper("op-after-delete-2", intentTestStartRequest(t, id)))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, second.GetState())
	require.NotEqual(t, originalGeneration, second.GetResourceGeneration())
	starts, _, _ = handler.counts()
	require.Equal(t, 2, starts)

	// The replaced incarnation does not steal the old operation's fact.
	old, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-after-delete-1"})
	require.NoError(t, err)
	require.Equal(t, originalGeneration, old.GetResourceGeneration())
}

// --- durable write boundaries ---

// An admission write that cannot land spends the operation ID instead of
// pretending nothing happened: the runtime is never invoked and the same ID
// refuses to re-admit.
func TestStartOperationAdmissionWriteFailureSpendsID(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-op-admit-fail"
	// The request is built once: a replay must repeat it digest-identically.
	wrapper := operationWrapper("op-admit-fail-1", intentTestStartRequest(t, id))
	// A non-empty directory at the record path defeats the atomic rename.
	recordPath := startOperationPath(s.startOperations.dir, "op-admit-fail-1")
	require.NoError(t, os.MkdirAll(recordPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(recordPath, "child"), []byte("x"), 0600))

	_, err := s.StartWithOperation(context.Background(), wrapper)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Contains(t, err.Error(), "must not be retried")
	starts, _, _ := handler.counts()
	require.Zero(t, starts, "a failed admission must not reach the runtime")

	// The spent ID is answered from its recorded unknown outcome and never
	// executes.
	replay, rerr := s.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, rerr)
	require.NotNil(t, replay)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, replay.GetState())
	starts, _, _ = handler.counts()
	require.Zero(t, starts)

	got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-admit-fail-1"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, got.GetState())
}

// A success fact is published only after its durable write: while the write
// is delayed, concurrent queries keep reporting the running state and never
// observe success; when the write fails (including the rename-landed but
// directory-fsync-failed shape), no reader ever sees success and the flow
// resolves the operation to unknown.
func TestStartOperationSuccessPublishesOnlyAfterPersist(t *testing.T) {
	t.Run("delayed write keeps queries at running", func(t *testing.T) {
		handler := newOperationRuntimeHandler()
		s := newIntentTestService(t, handler)
		const id = "sbox-op-persist-delay"
		release := make(chan struct{})
		writeStarted := make(chan struct{}, 1)
		var released atomic.Bool

		s.startOperations.persistHook = func(record *startOperationRecord) error {
			if record.Phase == startOperationPhaseSucceeded {
				select {
				case writeStarted <- struct{}{}:
				default:
				}
				<-release
			}
			return s.startOperations.durablyWrite(record)
		}

		executorDone := make(chan error, 1)
		go func() {
			_, err := s.StartWithOperation(context.Background(),
				operationWrapper("op-persist-delay-1", intentTestStartRequest(t, id)))
			executorDone <- err
		}()

		// Observe the operation while the success write is blocked BEFORE its
		// durable write: a query that completes must report running, never
		// succeeded — the terminal phase and its durable write complete under
		// one lock, so nothing observable precedes durability.
		waitForOperationState(t, s, "op-persist-delay-1", runtime.StartOperationState_START_OPERATION_STATE_RUNNING)
		select {
		case <-writeStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("the success write never started")
		}
		type observation struct {
			state    runtime.StartOperationState
			released bool
		}
		observed := make(chan observation, 16)
		var observers sync.WaitGroup
		for i := 0; i < 4; i++ {
			observers.Add(1)
			go func() {
				defer observers.Done()
				got, err := s.GetStartOperation(context.Background(),
					&runtime.GetStartOperationRequest{OperationID: "op-persist-delay-1"})
				if err == nil {
					observed <- observation{state: got.GetState(), released: released.Load()}
				}
			}()
		}
		// Let the observers queue behind the blocked durable write, then let
		// the write finish; the queued queries can only complete afterwards.
		time.Sleep(50 * time.Millisecond)
		released.Store(true)
		close(release)
		observers.Wait()
		close(observed)
		for o := range observed {
			if !o.released {
				require.NotEqual(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, o.state,
					"a success fact must not be observable before its durable write completes")
			}
		}
		require.NoError(t, <-executorDone)
		got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-persist-delay-1"})
		require.NoError(t, err)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, got.GetState())
		record := readOperationRecordFromDisk(t, s, "op-persist-delay-1")
		require.Equal(t, startOperationPhaseSucceeded, record.Phase)
	})

	t.Run("failed write never reports success", func(t *testing.T) {
		handler := newOperationRuntimeHandler()
		s := newIntentTestService(t, handler)
		const id = "sbox-op-persist-fail"

		s.startOperations.persistHook = func(record *startOperationRecord) error {
			if record.Phase == startOperationPhaseSucceeded {
				// Models a rename that landed but whose directory fsync
				// failed: the durable outcome is unknowable from here.
				return os.ErrInvalid
			}
			return s.startOperations.durablyWrite(record)
		}

		wrapper := operationWrapper("op-persist-fail-1", intentTestStartRequest(t, id))
		status, err := s.StartWithOperation(context.Background(), wrapper)
		require.Error(t, err, "an unproven success fact must not be reported as success")
		require.NotNil(t, status)
		require.NotEqual(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, status.GetState())

		got, gerr := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-persist-fail-1"})
		require.NoError(t, gerr)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, got.GetState(),
			"a success write with unknown durability resolves to unknown, never success")
		record := readOperationRecordFromDisk(t, s, "op-persist-fail-1")
		require.NotEqual(t, startOperationPhaseSucceeded, record.Phase,
			"the on-disk record must not claim the unpersisted success")

		// The sandbox is running and never rolled back; the replay answers
		// unknown without re-executing.
		_, getErr := s.sandboxManager.Get(id)
		require.NoError(t, getErr)
		replay, rerr := s.StartWithOperation(context.Background(), wrapper)
		require.NoError(t, rerr)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, replay.GetState())
		starts, _, _ := handler.counts()
		require.Equal(t, 1, starts)
	})
}

// A success-fact write that fails after the committed intent record is
// durable keeps that record as the recoverable proof, and a restart resolves
// the operation through the committed-intent takeover. The control arm shows
// the unfaulted flow.
func TestStartOperationSuccessWriteFailureResolvedByRestart(t *testing.T) {
	for _, fault := range []bool{false, true} {
		name := "control"
		if fault {
			name = "success-write-failure"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			fsStateStore := store.NewMockStore()
			handler := newOperationRuntimeHandler()
			s := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
			const id = "sbox-op-success-write"
			originalDir := s.startOperations.dir

			if fault {
				blocker := filepath.Join(t.TempDir(), "regular-file")
				require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0600))
				handler.mu.Lock()
				handler.onStart = func(svc.StartConfig) {
					// Redirect the operation journal under a regular file so
					// the success-fact write fails with ENOTDIR after the
					// committed intent record is already durable.
					s.startOperations.dir = filepath.Join(blocker, "operations")
				}
				handler.mu.Unlock()
			}

			wrapper := operationWrapper("op-success-write-1", intentTestStartRequest(t, id))
			resp, err := s.StartWithOperation(context.Background(), wrapper)
			s.startOperations.dir = originalDir

			if !fault {
				require.NoError(t, err)
				require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, resp.GetState())
				_, getErr := s.sandboxManager.Get(id)
				require.NoError(t, getErr)
				return
			}

			require.Error(t, err, "an unproven success fact must not be reported as success")
			got, gerr := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-success-write-1"})
			require.NoError(t, gerr)
			require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, got.GetState(),
				"in-process the outcome stays unknown")
			_, getErr := s.sandboxManager.Get(id)
			require.NoError(t, getErr, "the running sandbox is never rolled back")

			// Daemon restart over the same durable state: the committed
			// intent record plus matching sandbox metadata proves the start,
			// and the operation is promoted from that committed evidence —
			// the promotion write happens before the intent record is
			// removed.
			restarted := newIntentTestServiceAtRoot(t, newOperationRuntimeHandler(), root, fsStateStore)
			promoted, perr := restarted.GetStartOperation(context.Background(),
				&runtime.GetStartOperationRequest{OperationID: "op-success-write-1"})
			require.NoError(t, perr)
			require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, promoted.GetState(),
				"the committed-intent takeover recovers the success fact")
			require.Equal(t, handler.observedGeneration(), promoted.GetResourceGeneration())
			_, statErr := os.Lstat(filepath.Join(root, startIntentsDirName, id+".json"))
			require.True(t, os.IsNotExist(statErr), "the takeover removed the committed intent record")

			// Replay after restart answers from the promoted fact.
			replay, rerr := restarted.StartWithOperation(context.Background(), wrapper)
			require.NoError(t, rerr)
			require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, replay.GetState())
			restartedHandler, ok := restarted.serviceHandler.Get(config.RuntimeNameRunsc)
			require.True(t, ok)
			starts, _, _ := restartedHandler.(*operationRuntimeHandler).counts()
			require.Equal(t, 0, starts, "replay must never re-execute")
		})
	}
}

// --- restart reload ---

// A durably succeeded operation survives the restart; a durably failed one
// keeps its verdict; an admitted operation whose executor died with the
// daemon resolves to unknown, never a guessed success, and never re-executes.
func TestStartOperationRestartReload(t *testing.T) {
	root := t.TempDir()
	fsStateStore := store.NewMockStore()
	handler := newOperationRuntimeHandler()
	first := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
	const id = "sbox-op-restart"

	done, err := first.StartWithOperation(context.Background(),
		operationWrapper("op-restart-done", intentTestStartRequest(t, id)))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, done.GetState())
	doneGeneration := done.GetResourceGeneration()

	// A clean runtime failure with the proven-cleanup contract rolls back
	// fully and records the failed verdict durably.
	handler.setStartErr(context.Canceled)
	failed, ferr := first.StartWithOperation(context.Background(),
		operationWrapper("op-restart-failed", intentTestStartRequest(t, "sbox-op-restart-fail")))
	require.Error(t, ferr, "the failed start still returns its start error")
	require.NotNil(t, failed)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_FAILED, failed.GetState(),
		"a fully rolled-back failed start records the failed verdict")
	handler.setStartErr(nil)

	// Simulate a crash after admission but before any terminal outcome: the
	// record on disk still says admitted.
	crashedID := "op-restart-crash"
	crashDraft := &startOperationRecord{
		OperationID:   crashedID,
		SandboxID:     "sbox-op-restart-crash",
		Generation:    newResourceGeneration(),
		Runtime:       config.RuntimeNameRunsc,
		RequestDigest: startOperationTestDigest(t, "crash"),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	crashDraft.Version = 1
	crashDraft.Phase = startOperationPhaseAdmitted
	crashDraft.CreatedAt = now
	crashDraft.UpdatedAt = now
	require.NoError(t, validateStartOperationRecord(crashDraft))
	first.startOperations.writeMu.Lock()
	require.NoError(t, first.startOperations.durablyWrite(crashDraft))
	first.startOperations.publish(crashDraft)
	first.startOperations.writeMu.Unlock()

	secondHandler := newOperationRuntimeHandler()
	second := newIntentTestServiceAtRoot(t, secondHandler, root, fsStateStore)

	kept, err := second.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-restart-done"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, kept.GetState())
	require.Equal(t, doneGeneration, kept.GetResourceGeneration())

	failedKept, err := second.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-restart-failed"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_FAILED, failedKept.GetState())

	crashed, err := second.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: crashedID})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, crashed.GetState(),
		"an admitted record without its executor resolves to unknown, never a guessed success")
	crashedDisk := readOperationRecordFromDisk(t, second, crashedID)
	require.Equal(t, startOperationPhaseUnknown, crashedDisk.Phase,
		"the restart must durably record the unknown resolution")

	// Both spent operations refuse re-execution.
	_, err = second.StartWithOperation(context.Background(),
		operationWrapper(crashedID, intentTestStartRequest(t, "sbox-op-restart-crash")))
	require.Error(t, err)
	_, err = second.StartWithOperation(context.Background(),
		operationWrapper("op-restart-failed", intentTestStartRequest(t, "sbox-op-restart-fail")))
	require.Error(t, err)
	starts, _, _ := secondHandler.counts()
	require.Zero(t, starts, "a restart-resolved operation must never re-execute")
}

// The committed-intent takeover promotes the operation's success fact BEFORE
// the committed intent record is removed: when the promotion write fails, the
// load fails closed and the proof record stays on disk.
func TestStartOperationTakeoverPersistFailureFailsClosed(t *testing.T) {
	root := t.TempDir()
	const id = "sbox-op-takeover-fail"
	// An operation record left admitted by the crash...
	operations, err := loadStartOperations(root)
	require.NoError(t, err)
	crashDraft := &startOperationRecord{
		OperationID:   "op-takeover-fail-1",
		SandboxID:     id,
		Generation:    "gen-takeover-fail",
		Runtime:       config.RuntimeNameRunsc,
		RequestDigest: startOperationTestDigest(t, "takeover"),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	crashDraft.Version = 1
	crashDraft.Phase = startOperationPhaseAdmitted
	crashDraft.CreatedAt = now
	crashDraft.UpdatedAt = now
	require.NoError(t, validateStartOperationRecord(crashDraft))
	operations.writeMu.Lock()
	require.NoError(t, operations.durablyWrite(crashDraft))
	operations.publish(crashDraft)
	operations.writeMu.Unlock()

	// ...a committed intent record plus matching metadata as the proof.
	require.NoError(t, os.MkdirAll(filepath.Join(root, startIntentsDirName), 0700))
	writeIntentFile(t, filepath.Join(root, startIntentsDirName), id, "gen-takeover-fail", startIntentPhaseCommitted)
	writeSandboxMetadataFile(t, root, id, config.RuntimeNameRunsc, "gen-takeover-fail")

	// The promotion write fails: the load fails and the intent record is kept.
	operations.persistHook = func(*startOperationRecord) error { return os.ErrInvalid }
	_, err = loadStartIntents(root, readSandboxMetadataIdentity(root), operations.promoteCommittedTakeover)
	require.Error(t, err, "a failed promotion must fail the load closed")
	require.Contains(t, err.Error(), "keeping the committed intent record as proof")
	require.FileExists(t, filepath.Join(root, startIntentsDirName, id+".json"),
		"the committed intent record must survive as the recoverable proof")
	disk := readOperationRecordFromDisk(t, &sandboxService{startOperations: operations}, "op-takeover-fail-1")
	require.NotEqual(t, startOperationPhaseSucceeded, disk.Phase,
		"no in-memory promotion may leak an unpersisted success")

	// Without the fault the same durable state promotes, then removes the
	// proof only after the promotion is durable.
	operations.persistHook = nil
	reloaded, err := loadStartIntents(root, readSandboxMetadataIdentity(root), operations.promoteCommittedTakeover)
	require.NoError(t, err)
	require.False(t, reloaded.Pending(id))
	promoted := operations.snapshot("op-takeover-fail-1")
	require.NotNil(t, promoted)
	require.Equal(t, startOperationPhaseSucceeded, promoted.Phase)
	disk = readOperationRecordFromDisk(t, &sandboxService{startOperations: operations}, "op-takeover-fail-1")
	require.Equal(t, startOperationPhaseSucceeded, disk.Phase)
	_, statErr := os.Lstat(filepath.Join(root, startIntentsDirName, id+".json"))
	require.True(t, os.IsNotExist(statErr), "the promotion precedes the proof removal")
}

// --- pod-identity reset keeps tombstones ---

// The historical fact does not require the sandbox to exist: the pod reset
// wipes sandbox state but keeps operation records, and an old operation still
// refuses re-execution afterwards.
func TestStartOperationPodResetKeepsTombstones(t *testing.T) {
	root := t.TempDir()
	fsStateStore := store.NewMockStore()
	handler := newOperationRuntimeHandler()
	s := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
	const id = "sbox-op-pod-reset"
	// The request is built once and replayed verbatim: the digest covers the
	// whole StartRequest, including the rootfs path.
	start := intentTestStartRequest(t, id)
	wrapper := operationWrapper("op-pod-reset-1", start)

	done, err := s.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, done.GetState())
	originalGeneration := done.GetResourceGeneration()

	storeDir := filepath.Join(t.TempDir(), "store")
	require.NoError(t, os.MkdirAll(storeDir, 0755))
	require.NoError(t, resetStateIfPodChanged(storeDir, root, ""))

	require.FileExists(t, filepath.Join(root, startOperationsDirName, "op-pod-reset-1.json"),
		"the pod reset must keep operation tombstones")

	// After the reset the old operation is still spent and still answers its
	// historical success; it must not re-execute against the wiped state.
	afterReset := newIntentTestServiceAtRoot(t, newOperationRuntimeHandler(), root, store.NewMockStore())
	replay, err := afterReset.StartWithOperation(context.Background(), wrapper)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, replay.GetState())
	require.Equal(t, originalGeneration, replay.GetResourceGeneration())
	restartedHandler, ok := afterReset.serviceHandler.Get(config.RuntimeNameRunsc)
	require.True(t, ok)
	starts, _, _ := restartedHandler.(*operationRuntimeHandler).counts()
	require.Zero(t, starts, "a tombstoned operation must not re-execute after the pod reset")
}

// --- shutdown lifecycle ---

// Shutdown closes admission atomically, cancels in-flight executions, and
// blocks until each executor has actually returned — never tearing resources
// an executor still uses, and never relying on a deadline for convergence.
func TestStartOperationShutdownWaitsForRealExit(t *testing.T) {
	t.Run("execution ignoring cancellation blocks teardown", func(t *testing.T) {
		handler := newOperationRuntimeHandler()
		handler.enableStartGate()
		t.Cleanup(handler.releaseStarts)
		s := newIntentTestService(t, handler)
		const id = "sbox-op-shutdown-stubborn"
		wrapper := operationWrapper("op-shutdown-1", intentTestStartRequest(t, id))

		executorDone := make(chan error, 1)
		go func() {
			_, err := s.StartWithOperation(context.Background(), wrapper)
			executorDone <- err
		}()
		waitForOperationState(t, s, "op-shutdown-1", runtime.StartOperationState_START_OPERATION_STATE_RUNNING)

		shutdownDone := make(chan struct{})
		go func() {
			s.Shutdown()
			close(shutdownDone)
		}()
		select {
		case <-shutdownDone:
			t.Fatal("shutdown tore resources down while an admitted execution was still running")
		case <-time.After(200 * time.Millisecond):
		}

		// Admission is closed while draining.
		_, err := s.StartWithOperation(context.Background(),
			operationWrapper("op-shutdown-2", intentTestStartRequest(t, "sbox-op-shutdown-other")))
		require.Equal(t, codes.Unavailable, status.Code(err))

		// Only the executor's real exit lets shutdown proceed.
		handler.releaseStarts()
		require.NoError(t, <-executorDone)
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown did not return after the executor exited")
		}
		got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-shutdown-1"})
		require.NoError(t, err)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, got.GetState())
	})

	t.Run("cancellation converges a respecting execution", func(t *testing.T) {
		handler := newOperationRuntimeHandler()
		handler.enableStartGate()
		handler.respectContext()
		t.Cleanup(handler.releaseStarts)
		s := newIntentTestService(t, handler)
		const id = "sbox-op-shutdown-respect"
		wrapper := operationWrapper("op-shutdown-respect-1", intentTestStartRequest(t, id))

		executorDone := make(chan error, 1)
		go func() {
			_, err := s.StartWithOperation(context.Background(), wrapper)
			executorDone <- err
		}()
		waitForOperationState(t, s, "op-shutdown-respect-1", runtime.StartOperationState_START_OPERATION_STATE_RUNNING)

		shutdownDone := make(chan struct{})
		go func() {
			s.Shutdown()
			close(shutdownDone)
		}()
		// The cancelled runtime start unrolls through the normal rollback
		// path, the executor returns, and shutdown proceeds.
		require.Error(t, <-executorDone)
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown did not converge after cancelling the execution context")
		}
		got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-shutdown-respect-1"})
		require.NoError(t, err)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_FAILED, got.GetState(),
			"a fully rolled-back cancelled start records the failed verdict")
		starts, _, _ := handler.counts()
		require.Zero(t, starts,
			"the cancelled runtime call never reached the counted Start; the convergence is the executor's exit")
	})
}

// --- restore artifact identity ---

// Local names for the real seal layout, previously defined by the server
// binding: the fixtures build directories shaped exactly like the runsc and
// Firecracker seals write them.
const (
	restoreManifestName       = "manifest.json"
	restoreOverlayName        = "overlay.ext4"
	restoreOverlaySidecarName = "overlay.ext4." + checkpointchunks.ManifestName
	restoreRunscPagesSidecar  = "pages.img." + checkpointchunks.ManifestName
)

// seedCheckpointDirectory writes a minimal sealed checkpoint directory: a
// manifest plus optional artifacts and raw extra files. Values in `files`
// that name a real chunk sidecar are written verbatim for malformed-input
// tests; use writeValidChunkSidecar for a sidecar the shared binder accepts.
func seedCheckpointDirectory(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "checkpoint")
	require.NoError(t, os.MkdirAll(dir, 0700))
	if manifest != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, restoreManifestName), []byte(manifest), 0600))
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	}
	return dir
}

// writeValidChunkSidecar builds a structurally valid chunk sidecar for the
// artifact bytes already on disk (chunks digest mode, root binding its
// entries, the seal's offset grid, matching sizes) so fixtures exercise the
// shared binder's real semantics instead of simplified JSON.
func writeValidChunkSidecar(t *testing.T, dir, artifact, sidecarName string, chunkBytes int64) *checkpointchunks.Manifest {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, artifact))
	require.NoError(t, err)
	size := int64(len(content))
	entries := make([]checkpointchunks.Chunk, 0, (size+chunkBytes-1)/chunkBytes)
	for offset := int64(0); offset < size; offset += chunkBytes {
		end := offset + chunkBytes
		if end > size {
			end = size
		}
		sum := sha256.Sum256(content[offset:end])
		entries = append(entries, checkpointchunks.Chunk{Offset: offset, Digest: hex.EncodeToString(sum[:])})
	}
	manifest := &checkpointchunks.Manifest{
		Version:        1,
		File:           artifact,
		FileSize:       size,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		FileDigest:     checkpointchunks.RootDigest(entries),
		ChunkBytes:     int(chunkBytes),
		ChunkCount:     len(entries),
		Entries:        entries,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, sidecarName), append(encoded, '\n'), 0600))
	return manifest
}

// seedFirecrackerLayout writes a real chunks-mode Firecracker v2 layout:
// manifest digesting vmstate and the memory root, valid memory and overlay
// sidecars next to their artifacts.
func seedFirecrackerLayout(t *testing.T, memory, overlay string) string {
	t.Helper()
	dir := seedCheckpointDirectory(t,
		`{"version":2,"snapshot_type":"Full","memory_size":`+fmt.Sprintf("%d", len(memory))+
			`,"memory_digest_mode":"chunks","digests":{"vmstate":"aa","memory":"bb"}}`,
		map[string]string{"vmstate": "state", "memory": memory, restoreOverlayName: overlay})
	writeValidChunkSidecar(t, dir, "memory", checkpointchunks.ManifestName, 16)
	writeValidChunkSidecar(t, dir, restoreOverlayName, restoreOverlaySidecarName, 16)
	return dir
}

func restoreWrapper(t *testing.T, opID, sandboxID, checkpointDir, expectedDigest string) *runtime.StartWithOperationRequest {
	t.Helper()
	rootfsDir := filepath.Join(t.TempDir(), "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0755))
	return &runtime.StartWithOperationRequest{
		OperationID: opID,
		SandboxID:   sandboxID,
		Start: &runtime.StartRequest{
			SandboxID: sandboxID,
			Runtime:   config.RuntimeNameRunsc,
			Rootfs: &runtime.RootfsConfig{
				Type:   runtime.RootfsSrcType_LOCAL,
				Source: &runtime.RootfsConfig_Path{Path: rootfsDir},
			},
			Command:        []string{"/bin/true"},
			Stdout:         os.DevNull,
			Stderr:         os.DevNull,
			CheckpointInfo: &runtime.CheckpointInfo{CheckpointDir: checkpointDir},
		},
		RestoreArtifacts: &runtime.RestoreArtifactIdentity{
			CheckpointDir:      checkpointDir,
			ExpectedRootDigest: expectedDigest,
		},
	}
}

// Restore starts require a complete artifact identity: the wrapper must pin
// the content root, the derived root must match the pin, and the directory
// must be verifiable on disk.
func TestStartOperationRestoreArtifactIdentity(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-op-restore"
	dir := seedCheckpointDirectory(t,
		`{"version":2,"snapshot_type":"runsc","digests":{"checkpoint.img":"aa"}}`,
		map[string]string{"checkpoint.img": "image"})
	binding, err := bindRestoreRoot(dir)
	require.NoError(t, err)

	// Missing identity is refused.
	missing := restoreWrapper(t, "op-restore-1", id, dir, binding.RootDigest)
	missing.RestoreArtifacts = nil
	_, err = s.StartWithOperation(context.Background(), missing)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "restore_artifacts is required")

	// Artifact identity without a restore is refused too.
	stray := operationWrapper("op-restore-stray", intentTestStartRequest(t, id))
	stray.RestoreArtifacts = &runtime.RestoreArtifactIdentity{
		CheckpointDir:      dir,
		ExpectedRootDigest: strings.Repeat("0", restoreDigestHexLen),
	}
	_, err = s.StartWithOperation(context.Background(), stray)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "only valid for restore starts")

	// An unpinned (empty) expected root is a weak binding and is refused.
	unpinned := restoreWrapper(t, "op-restore-unpinned", id, dir, "")
	_, err = s.StartWithOperation(context.Background(), unpinned)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "expected_root_digest")

	// Mismatched directories inside one wrapper are refused.
	mismatched := restoreWrapper(t, "op-restore-mismatch", id, dir, binding.RootDigest)
	mismatched.RestoreArtifacts.CheckpointDir = dir + "-other"
	_, err = s.StartWithOperation(context.Background(), mismatched)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "must equal")

	// A wrong expected digest is refused at admission, before any effect.
	wrong := restoreWrapper(t, "op-restore-2", id, dir,
		strings.Repeat("0", restoreDigestHexLen))
	_, err = s.StartWithOperation(context.Background(), wrong)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "does not match the expected digest")
	starts, _, _ := handler.counts()
	require.Zero(t, starts)

	// A successful identified restore binds the content root. The wrapper is
	// built once and reused verbatim for replays: the request digest covers
	// the whole StartRequest, so a replay must repeat it byte-equivalently.
	restore := restoreWrapper(t, "op-restore-3", id, dir, binding.RootDigest)
	first, err := s.StartWithOperation(context.Background(), restore)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, first.GetState())
	require.Equal(t, 1, handler.restoreCount())
	record := s.startOperations.snapshot("op-restore-3")
	require.NotNil(t, record.Restore)
	require.True(t, record.Restore.ManifestBound)
	require.Equal(t, binding.RootDigest, record.Restore.RootDigest)

	// Replaying the finished restore never re-reads the directory: delete it
	// and the replay still answers the recorded success without executing.
	require.NoError(t, os.RemoveAll(dir))
	replay, err := s.StartWithOperation(context.Background(), restore)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, replay.GetState())
	require.Equal(t, 1, handler.restoreCount(), "a finished restore replays without touching the artifacts")

	// A new operation pinning the ORIGINAL root against swapped content under
	// the same path is rejected: the derived root no longer matches the pin.
	dir2 := seedCheckpointDirectory(t,
		`{"version":2,"snapshot_type":"runsc","digests":{"checkpoint.img":"bb"}}`,
		map[string]string{"checkpoint.img": "swapped"})
	_, err = s.StartWithOperation(context.Background(),
		restoreWrapper(t, "op-restore-4", "sbox-op-restore-b", dir2, binding.RootDigest))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "does not match the expected digest")
}

// A restore admission rejects directories whose artifacts have no verifiable
// root: unsealed directories, undigested components, and overlays without
// their chunk sidecar are explicit errors, never path-only bindings.
func TestStartOperationRestoreRootRequiresCompleteCoverage(t *testing.T) {
	t.Run("unsealed directory is rejected", func(t *testing.T) {
		unsealed := seedCheckpointDirectory(t, "", map[string]string{"checkpoint.img": "x"})
		_, err := bindRestoreRoot(unsealed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no sealed manifest")
	})

	t.Run("manifest without digests is rejected", func(t *testing.T) {
		empty := seedCheckpointDirectory(t,
			`{"version":2,"snapshot_type":"runsc","digests":{}}`,
			map[string]string{"checkpoint.img": "x"})
		_, err := bindRestoreRoot(empty)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a complete seal")
	})

	t.Run("undigested memory component is rejected", func(t *testing.T) {
		partial := seedCheckpointDirectory(t,
			`{"version":2,"snapshot_type":"Full","digests":{"vmstate":"aa"}}`,
			map[string]string{"vmstate": "state", "memory": "cold-memory"})
		_, err := bindRestoreRoot(partial)
		require.Error(t, err)
		require.Contains(t, err.Error(), "memory")
		require.Contains(t, err.Error(), "no verifiable root")
	})

	t.Run("overlay without sidecar is rejected", func(t *testing.T) {
		noSidecar := seedCheckpointDirectory(t,
			`{"version":2,"snapshot_type":"Full","digests":{"vmstate":"aa","memory":"bb"}}`,
			map[string]string{"vmstate": "state", "memory": "cold", restoreOverlayName: "overlay"})
		_, err := bindRestoreRoot(noSidecar)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no chunk sidecar")
	})

	t.Run("symlink artifact is rejected", func(t *testing.T) {
		linked := seedCheckpointDirectory(t,
			`{"version":2,"snapshot_type":"runsc","digests":{"checkpoint.img":"aa"}}`,
			map[string]string{"checkpoint.img": "image"})
		require.NoError(t, os.Remove(filepath.Join(linked, "checkpoint.img")))
		require.NoError(t, os.Symlink("/etc/hosts", filepath.Join(linked, "checkpoint.img")))
		_, err := bindRestoreRoot(linked)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a regular file")
	})

	t.Run("full firecracker layout with sidecar binds", func(t *testing.T) {
		complete := seedFirecrackerLayout(t, "cold", "overlay-bytes")
		binding, err := bindRestoreRoot(complete)
		require.NoError(t, err)
		require.True(t, binding.ManifestBound)
		require.True(t, binding.OverlaySidecarBound)
		require.Len(t, binding.RootDigest, restoreDigestHexLen)
	})
}

// Real seals name chunk sidecars after their artifacts: the Firecracker
// memory sidecar is the plain chunks.json, the overlay and runsc pages
// sidecars are <artifact>.chunks.json. Directories shaped exactly like the
// current seals write them must bind, and a changed sidecar must change the
// root.
func TestStartOperationRootDigestBindsRealArtifactLayouts(t *testing.T) {
	t.Run("firecracker chunks-mode directory", func(t *testing.T) {
		fc := seedFirecrackerLayout(t, "cold-memory-bytes", "overlay-bytes")
		binding, err := bindRestoreRoot(fc)
		require.NoError(t, err, "a real-shaped chunks-mode Firecracker checkpoint must bind")
		require.True(t, binding.ManifestBound)
		require.True(t, binding.OverlaySidecarBound)

		// A re-chunked memory sidecar (different grid, still valid and
		// self-consistent) changes the identity.
		writeValidChunkSidecar(t, fc, "memory", checkpointchunks.ManifestName, 8)
		changed, err := bindRestoreRoot(fc)
		require.NoError(t, err)
		require.NotEqual(t, binding.RootDigest, changed.RootDigest)
	})

	t.Run("runsc sealed directory", func(t *testing.T) {
		// The pages content spans several chunks under both grids, so
		// re-chunking changes the entry set and the sidecar root.
		pages := strings.Repeat("pages-bytes-", 12)
		rs := seedCheckpointDirectory(t,
			`{"version":2,"snapshot_type":"runsc","digests":{"checkpoint.img":"cc","pages.img":"dd"}}`,
			map[string]string{"checkpoint.img": "image-bytes", "pages.img": pages})
		writeValidChunkSidecar(t, rs, "pages.img", restoreRunscPagesSidecar, 48)
		binding, err := bindRestoreRoot(rs)
		require.NoError(t, err, "a real-shaped runsc checkpoint must bind")
		require.True(t, binding.ManifestBound)
		require.False(t, binding.OverlaySidecarBound)
		require.Len(t, binding.RootDigest, restoreDigestHexLen)

		writeValidChunkSidecar(t, rs, "pages.img", restoreRunscPagesSidecar, 16)
		changed, err := bindRestoreRoot(rs)
		require.NoError(t, err)
		require.NotEqual(t, binding.RootDigest, changed.RootDigest)
	})
}

// Identical manifest bytes with a different sidecar must not share an
// operation identity, per the overlay binding correction in the plan.
func TestStartOperationRootDigestBindsUncoveredSidecars(t *testing.T) {
	manifest := `{"version":2,"snapshot_type":"Full","digests":{"vmstate":"aa","memory":"bb"}}`
	withSidecar := seedCheckpointDirectory(t, manifest, map[string]string{
		"vmstate":          "state",
		"memory":           "cold",
		restoreOverlayName: "overlay-bytes",
	})
	writeValidChunkSidecar(t, withSidecar, restoreOverlayName, restoreOverlaySidecarName, 16)
	withoutSidecar := seedCheckpointDirectory(t, manifest, map[string]string{
		"vmstate":          "state",
		"memory":           "cold",
		restoreOverlayName: "overlay-bytes",
	})

	first, err := bindRestoreRoot(withSidecar)
	require.NoError(t, err)
	require.True(t, first.OverlaySidecarBound)
	_, err = bindRestoreRoot(withoutSidecar)
	require.Error(t, err, "an overlay without its sidecar has no verifiable identity")

	// A different valid sidecar (different chunk grid over the same overlay)
	// under identical manifest bytes is a different identity.
	writeValidChunkSidecar(t, withSidecar, restoreOverlayName, restoreOverlaySidecarName, 8)
	changed, err := bindRestoreRoot(withSidecar)
	require.NoError(t, err)
	require.NotEqual(t, first.RootDigest, changed.RootDigest)

	// Different overlay bytes under the same manifest re-sealed with their
	// own valid sidecar is a different identity too.
	resizedDir := seedCheckpointDirectory(t, manifest, map[string]string{
		"vmstate":          "state",
		"memory":           "cold",
		restoreOverlayName: "overlay-bytes-longer",
	})
	writeValidChunkSidecar(t, resizedDir, restoreOverlayName, restoreOverlaySidecarName, 16)
	resized, err := bindRestoreRoot(resizedDir)
	require.NoError(t, err)
	require.NotEqual(t, first.RootDigest, resized.RootDigest)
}

// --- query and legacy-server contracts ---

func TestGetStartOperationUnknownAndInvalidIDs(t *testing.T) {
	s := newIntentTestService(t, newOperationRuntimeHandler())
	_, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-never"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "../escape"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// Old servers predate the RPC: the promoted Unimplemented embedding is the
// wire contract new clients must fail hard against.
func TestStartOperationLegacyServerUnimplemented(t *testing.T) {
	legacy := struct {
		runtime.UnimplementedSandboxServiceServer
	}{}
	_, err := legacy.StartWithOperation(context.Background(), &runtime.StartWithOperationRequest{})
	require.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = legacy.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{})
	require.Equal(t, codes.Unimplemented, status.Code(err))
}

// --- expected-root forwarding and runtime capability ---

// The admission-bound content root is forwarded to the runtime through the
// real StartConfig: the handler's Restore observes exactly the root the
// operation record carries, and the legacy Start carries none.
func TestStartOperationForwardsExpectedRootToRuntime(t *testing.T) {
	handler := newOperationRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-op-forward"
	dir := seedFirecrackerLayout(t, "cold-memory-bytes", "overlay-bytes")
	binding, err := bindRestoreRoot(dir)
	require.NoError(t, err)

	status, err := s.StartWithOperation(context.Background(),
		restoreWrapper(t, "op-forward-1", id, dir, binding.RootDigest))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED, status.GetState())
	require.Equal(t, 1, handler.restoreCount())
	require.Equal(t, binding.RootDigest, handler.observedExpectedRoot(),
		"the runtime must receive the admission-bound content root")
	record := s.startOperations.snapshot("op-forward-1")
	require.NotNil(t, record.Restore)
	require.Equal(t, handler.observedExpectedRoot(), record.Restore.RootDigest)

	// The legacy Start flow is untouched: a fresh start needs no capability
	// and observes no expected root (the empty-field semantics for legacy
	// restores are covered by the Firecracker entry tests).
	legacy, err := s.Start(context.Background(), intentTestStartRequest(t, "sbox-op-forward-legacy"))
	require.NoError(t, err)
	require.Equal(t, int32(0), legacy.GetCode())
	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts)
	require.False(t, handler.freshStartObservedRoot(),
		"a legacy fresh start must never carry an expected checkpoint root")
}

// A restore operation under a runtime without the verification capability is
// refused at admission — before any runtime call and before any record is
// written — instead of silently ignoring the binding.
func TestStartOperationRestoreRefusesUnsupportedRuntime(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-op-unsupported"
	dir := seedFirecrackerLayout(t, "cold-memory-bytes", "overlay-bytes")
	binding, err := bindRestoreRoot(dir)
	require.NoError(t, err)

	_, err = s.StartWithOperation(context.Background(),
		restoreWrapper(t, "op-unsupported-1", id, dir, binding.RootDigest))
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.Contains(t, err.Error(), "does not support checkpoint root verification")
	starts, _, _ := handler.counts()
	require.Zero(t, starts, "the unsupported runtime must never be invoked")

	// Nothing was recorded: the refusal precedes admission.
	_, err = s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-unsupported-1"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

// --- helpers ---

// startOperationTestDigest fabricates a valid hex digest for test records.
func startOperationTestDigest(t *testing.T, seed string) string {
	t.Helper()
	require.NotEmpty(t, seed)
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = seed[i%len(seed)]
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range digest {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0xf]
	}
	return string(out)
}

func readOperationRecordFromDisk(t *testing.T, s *sandboxService, id string) *startOperationRecord {
	t.Helper()
	record, err := readStartOperationRecord(s.startOperations.dir, id)
	require.NoError(t, err)
	return record
}

// waitForOperationState polls the durable operation state.
func waitForOperationState(
	t *testing.T,
	s *sandboxService,
	operationID string,
	want runtime.StartOperationState,
) *runtime.StartOperationStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: operationID})
		if err != nil {
			// The admission may still be racing this poll; only a NotFound is
			// retryable, anything else is a real failure.
			require.Equal(t, codes.NotFound, status.Code(err),
				"unexpected query error while waiting for %v", want)
		} else if got.GetState() == want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s never reached %v (last: %v err: %v)", operationID, want, got, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- deterministic interleavings for shutdown and admission races ---

// waitForGoroutineStack blocks until some goroutine's stack matches the
// pattern, making an interleaving (for example "shutdown is already waiting
// on the executor") observable without sleeps or lucky timing.
func waitForGoroutineStack(t *testing.T, pattern string) {
	t.Helper()
	matcher := regexp.MustCompile(pattern)
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := stdruntime.Stack(buf, true)
		if matcher.Match(buf[:n]) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never observed a goroutine stack matching %s", pattern)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// shutdownWaitingPattern matches a goroutine blocked receiving on the
// executor done channel inside startOperationStore.shutdown.
const shutdownWaitingPattern = `goroutine [0-9]+ \[chan receive\]:\n.*\(\*startOperationStore\)\.shutdown`

// waitForFile blocks until the path exists.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect %s: %v", path, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// newStartOperationDraft builds a minimal valid admission draft; admit stamps
// the remaining lifecycle fields.
func newStartOperationDraft(t *testing.T, opID, sandboxID string) *startOperationRecord {
	t.Helper()
	return &startOperationRecord{
		OperationID:   opID,
		SandboxID:     sandboxID,
		Generation:    newResourceGeneration(),
		Runtime:       config.RuntimeNameRunsc,
		RequestDigest: startOperationTestDigest(t, opID),
	}
}

// A cancellation registered while shutdown is ALREADY waiting on the
// executor's exit must still be applied: shutdown snapshots the cancel
// functions under the admission lock, so the late registration compensates
// from the closing flag instead of being lost. Reproduces the checker's
// interleaving (shutdown observed waiting via its stack) against the real
// store, under the race detector.
func TestStartOperationLateCancelRegistrationConverges(t *testing.T) {
	operationStore, err := loadStartOperations(t.TempDir())
	require.NoError(t, err)
	const opID = "op-late-cancel-1"
	exec, joined, err := operationStore.admit(newStartOperationDraft(t, opID, "sbox-op-late-cancel"))
	require.NoError(t, err)
	require.NotNil(t, exec)
	require.Nil(t, joined)

	finished := make(chan struct{})
	go func() {
		operationStore.shutdown()
		close(finished)
	}()
	waitForGoroutineStack(t, shutdownWaitingPattern)

	// The executor's context is created and registered only now — after
	// shutdown snapshotted an execution whose cancel was still nil.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	operationStore.registerExecutionCancel(opID, exec, cancel)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("the late-registered context was never cancelled")
	}

	// The executor returns; shutdown converges on the real exit.
	operationStore.finishExecution(opID, exec)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not converge after the executor exited")
	}
	// Admission stays closed afterwards.
	_, _, err = operationStore.admit(newStartOperationDraft(t, "op-late-cancel-2", "sbox-op-late-cancel-b"))
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// The admitted record becomes visible only together with its registered
// executor: while an admission sits between its durable write and the
// registration, queries see nothing and concurrent replays queue on the
// transition lock instead of reading a phantom admitted-without-executor
// (unknown) state.
func TestStartOperationAdmitPublishesOnlyWithRegisteredExecutor(t *testing.T) {
	operationStore, err := loadStartOperations(t.TempDir())
	require.NoError(t, err)
	const opID = "op-admit-window-1"
	const sandboxID = "sbox-op-admit-window"

	// Hold the admission lock so the admitting goroutine completes its
	// durable write but must block right before registration/publication.
	operationStore.lifeMu.Lock()
	admitted := make(chan *startOperationExecution, 1)
	admitErr := make(chan error, 1)
	go func() {
		exec, _, err := operationStore.admit(newStartOperationDraft(t, opID, sandboxID))
		admitted <- exec
		admitErr <- err
	}()
	waitForFile(t, startOperationPath(operationStore.dir, opID))
	require.Nil(t, operationStore.snapshot(opID),
		"the record must not be visible before its executor is registered")

	// A concurrent same-request replay: it cannot resolve the unpublished
	// admission on its fast path and queues behind the transition lock. It
	// builds its own draft so no memory is shared with the admitting caller.
	replayJoined := make(chan (<-chan struct{}), 1)
	replayErr := make(chan error, 1)
	go func() {
		_, joined, err := operationStore.admit(newStartOperationDraft(t, opID, sandboxID))
		replayJoined <- joined
		replayErr <- err
	}()

	operationStore.lifeMu.Unlock()
	exec := <-admitted
	require.NoError(t, <-admitErr)
	require.NotNil(t, exec)
	joined := <-replayJoined
	require.NoError(t, <-replayErr)
	require.NotNil(t, joined,
		"the concurrent replay must join the running execution, not read a phantom unknown")

	operationStore.finishExecution(opID, exec)
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("the joined replay never woke after the executor finished")
	}
}

// The same late-registration interleaving against the real service flow: a
// shutdown that begins between the admission and the executor's cancel
// registration must still converge the execution, and the operation records
// the failed verdict, never a phantom running state.
func TestStartOperationServiceShutdownDuringAdmissionGapConverges(t *testing.T) {
	handler := newOperationRuntimeHandler()
	handler.enableStartGate()
	handler.respectContext()
	t.Cleanup(handler.releaseStarts)
	s := newIntentTestService(t, handler)
	const id = "sbox-op-svc-late-cancel"
	wrapper := operationWrapper("op-svc-late-cancel-1", intentTestStartRequest(t, id))

	inGap := make(chan struct{})
	releaseGap := make(chan struct{})
	s.startOperations.admitHook = func() {
		close(inGap)
		<-releaseGap
	}
	executorDone := make(chan error, 1)
	go func() {
		_, err := s.StartWithOperation(context.Background(), wrapper)
		executorDone <- err
	}()
	<-inGap

	shutdownDone := make(chan struct{})
	go func() {
		s.Shutdown()
		close(shutdownDone)
	}()
	waitForGoroutineStack(t, shutdownWaitingPattern)

	close(releaseGap)
	require.Error(t, <-executorDone, "an admission raced by shutdown never executes")
	select {
	case <-shutdownDone:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not converge after the raced admission resolved")
	}
	got, err := s.GetStartOperation(context.Background(), &runtime.GetStartOperationRequest{OperationID: "op-svc-late-cancel-1"})
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_FAILED, got.GetState(),
		"an admission that never executed must not be reported as running or unknown-frozen")
	starts, _, _ := handler.counts()
	require.Zero(t, starts, "the runtime was never reached")
}
