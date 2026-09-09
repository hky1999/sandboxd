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

// The independent 1290 counterexample, imported verbatim (gofmt only): a
// recovery whose original executor never returns must still answer its
// requested deadline — the join is bounded by the recovery timeout even for a
// Background caller with no cancellation — and the waiting RPC must never
// release the original executor's slot.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReviewRecoveryTimeoutBoundsExistingExecutorJoin(t *testing.T) {
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), t.TempDir())
	req := checkpointOperationRequest("review-timeout", "sbox-review-timeout", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	digest, err := checkpointOperationRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	draft := &checkpointOperationRecord{OperationID: req.OperationID, SandboxID: req.Checkpoint.ID, Generation: req.ExpectedGeneration, Runtime: config.RuntimeNameRunsc, CheckpointDir: req.Checkpoint.CheckpointDir, RequestDigest: digest}
	exec, _, err := s.checkpointOperations.admit(draft)
	if err != nil || exec == nil {
		t.Fatalf("admit: %v", err)
	}
	defer s.checkpointOperations.finishExecution(req.OperationID, exec)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.RecoverCheckpointOperation(ctx, &runtime.RecoverCheckpointOperationRequest{Operation: req, RecoveryTimeoutSeconds: 1})
		done <- err
	}()
	select {
	case err := <-done:
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("expected requested deadline, got %v", err)
		}
		t.Logf("requested one-second recovery returned in %s", time.Since(start))
	case <-time.After(1800 * time.Millisecond):
		cancel()
		select {
		case err := <-done:
			t.Logf("only caller cancellation ended join: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("join failed to converge even on cleanup cancellation")
		}
		t.Error("one-second recovery timeout did not bound waiting for the original executor")
	}
	_, running := s.checkpointOperations.executionDone(req.OperationID)
	if !running {
		t.Error("waiting RPC released original executor")
	}
}

func TestReviewRecoveryTimeoutBoundsStoreAdmissionLock(t *testing.T) {
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), t.TempDir())
	req := checkpointOperationRequest("review-lock", "sbox-review-lock", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	digest, err := checkpointOperationRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	draft := &checkpointOperationRecord{OperationID: req.OperationID, SandboxID: req.Checkpoint.ID, Generation: req.ExpectedGeneration, Runtime: config.RuntimeNameRunsc, CheckpointDir: req.Checkpoint.CheckpointDir, RequestDigest: digest}
	exec, _, err := s.checkpointOperations.admit(draft)
	if err != nil || exec == nil {
		t.Fatalf("admit: %v", err)
	}
	defer s.checkpointOperations.finishExecution(req.OperationID, exec)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.checkpointOperations.writeMu.Lock()
	held := true
	unlock := func() {
		if held {
			s.checkpointOperations.writeMu.Unlock()
			held = false
		}
	}
	defer unlock()
	done := make(chan error, 1)
	go func() {
		_, err := s.RecoverCheckpointOperation(ctx, &runtime.RecoverCheckpointOperationRequest{Operation: req, RecoveryTimeoutSeconds: 1})
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("expected requested deadline, got %v", err)
		}
	case <-time.After(1800 * time.Millisecond):
		unlock()
		cancel()
		select {
		case err := <-done:
			t.Logf("only releasing the store lock let the RPC finish: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("RPC did not converge after test released its lock")
		}
		t.Error("one-second recovery timeout did not bound store admission lock wait")
	}
}
