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
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// storeGenerationRunningSandbox stores running metadata carrying the physical
// generation label, the shape the daemon persists after Start assigns it.
func storeGenerationRunningSandbox(t *testing.T, s *sandboxService, id, generation string) {
	t.Helper()
	storeRunningSandbox(t, s, id, "runsc")
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{resourceGenerationLabel: generation},
	}))
}

func TestCheckpointIfGenerationValidatesRequest(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeGenerationRunningSandbox(t, s, "sbox-validate", "gen-valid")

	for name, request := range map[string]*runtime.CheckpointIfGenerationRequest{
		"nil request": nil,
		"missing nested checkpoint": {
			ExpectedGeneration: "gen-valid",
		},
		"empty expected generation": {
			Checkpoint: &runtime.CheckpointRequest{
				ID:             "sbox-validate",
				CheckpointDir:  filepath.Join(t.TempDir(), "checkpoint"),
				TimeoutSeconds: 5,
			},
		},
		"whitespace expected generation": {
			Checkpoint: &runtime.CheckpointRequest{
				ID:             "sbox-validate",
				CheckpointDir:  filepath.Join(t.TempDir(), "checkpoint"),
				TimeoutSeconds: 5,
			},
			ExpectedGeneration: " \t ",
		},
		"overlong expected generation": {
			Checkpoint: &runtime.CheckpointRequest{
				ID:             "sbox-validate",
				CheckpointDir:  filepath.Join(t.TempDir(), "checkpoint"),
				TimeoutSeconds: 5,
			},
			ExpectedGeneration: strings.Repeat("g", 257),
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.CheckpointIfGeneration(context.Background(), request)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, handler.checkpoints)
		})
	}

	// The boundary itself stays admissible; only excess is rejected.
	directory := filepath.Join(t.TempDir(), "checkpoint")
	_, err := s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint: &runtime.CheckpointRequest{
			ID:             "sbox-validate",
			CheckpointDir:  directory,
			TimeoutSeconds: 5,
		},
		ExpectedGeneration: strings.Repeat("g", 256),
	})
	assert.NotEqual(t, codes.InvalidArgument, status.Code(err))
}

func TestCheckpointIfGenerationMatchesCurrentGeneration(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-match"
	storeGenerationRunningSandbox(t, s, id, "gen-current")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	response, err := s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint: &runtime.CheckpointRequest{
			ID:             id,
			CheckpointDir:  directory,
			TimeoutSeconds: 5,
			Compress:       true,
			LeaveRunning:   true,
		},
		ExpectedGeneration: "gen-current",
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, handler.checkpoints, 1)
	assert.Equal(t, svc.CheckpointConfig{
		ID:           id,
		Directory:    directory,
		Compress:     true,
		LeaveRunning: true,
	}, handler.checkpoints[0])
	assert.FileExists(t, filepath.Join(directory, "checkpoint.img"))
	assert.Zero(t, handler.deleteCalls)

	// The metadata keeps its generation: this checkpoint does not retire or
	// rewrite the source incarnation identity.
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "gen-current", current.Metadata.Labels[resourceGenerationLabel])
}

func TestCheckpointIfGenerationStaleRejectsWithoutSideEffects(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-stale"
	storeGenerationRunningSandbox(t, s, id, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	_, err := s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint: &runtime.CheckpointRequest{
			ID:             id,
			CheckpointDir:  directory,
			TimeoutSeconds: 5,
		},
		ExpectedGeneration: "gen-stale",
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "resource generation changed before checkpoint")
	// Zero side effects: neither the output directory nor the handler may be
	// touched when the expectation does not match the physical incarnation.
	assert.NoDirExists(t, directory)
	assert.Empty(t, handler.checkpoints)
	assert.Zero(t, handler.deleteCalls)

	// A missing generation label is not a wildcard: the incarnation identity
	// is unknown, so the conditional checkpoint is refused the same way.
	const unlabeled = "sbox-unlabeled"
	storeRunningSandbox(t, s, unlabeled, "runsc")
	unlabeledDir := filepath.Join(t.TempDir(), "checkpoint")
	_, err = s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint: &runtime.CheckpointRequest{
			ID:             unlabeled,
			CheckpointDir:  unlabeledDir,
			TimeoutSeconds: 5,
		},
		ExpectedGeneration: "gen-live",
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.NoDirExists(t, unlabeledDir)
	assert.Empty(t, handler.checkpoints)
}

func TestCheckpointIfGenerationRechecksGenerationAfterQueueWait(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-queued"
	storeGenerationRunningSandbox(t, s, id, "gen-queued")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	// Hold the physical lock, exactly as a concurrent delete or start for the
	// same ID would, so the conditional checkpoint queues behind it.
	unlock, err := s.resourceLocks.acquire(context.Background(), id)
	require.NoError(t, err)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
			Checkpoint: &runtime.CheckpointRequest{
				ID:             id,
				CheckpointDir:  directory,
				TimeoutSeconds: 10,
			},
			ExpectedGeneration: "gen-queued",
		})
		done <- err
	}()

	// Wait until the request has registered and is queueing on the lock, then
	// replace the incarnation under the same ID before releasing the lock.
	// The checkpoint must admit against the metadata it reads after it
	// finally acquires the lock, not against the caller's stale expectation.
	require.Eventually(t, func() bool {
		s.checkpointMu.Lock()
		defer s.checkpointMu.Unlock()
		_, queued := s.checkpointing[id]
		return queued
	}, 5*time.Second, 5*time.Millisecond, "conditional checkpoint did not queue behind the lock")

	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{resourceGenerationLabel: "gen-replacement"},
	}))
	unlock()
	unlock = nil

	select {
	case err := <-done:
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	case <-time.After(10 * time.Second):
		t.Fatal("conditional checkpoint did not return after the lock was released")
	}
	assert.NoDirExists(t, directory)
	assert.Empty(t, handler.checkpoints)
}

func TestCheckpointIfGenerationPendingStartIntentStillRejected(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-pending-start"
	storeGenerationRunningSandbox(t, s, id, "gen-pending")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	s.startIntents.mu.Lock()
	s.startIntents.pending[id] = &startIntentRecord{SandboxID: id}
	s.startIntents.mu.Unlock()
	require.True(t, s.startIntents.Pending(id))

	_, err := s.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint: &runtime.CheckpointRequest{
			ID:             id,
			CheckpointDir:  directory,
			TimeoutSeconds: 5,
		},
		ExpectedGeneration: "gen-pending",
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "pending start intent")
	assert.NoDirExists(t, directory)
	assert.Empty(t, handler.checkpoints)
}

func TestCheckpointLegacyIgnoresGenerationExpectation(t *testing.T) {
	handler := newCheckpointTestHandler()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-legacy"
	// The legacy RPC keeps its unconditional semantics: a changed generation
	// label is ordinary metadata and never gates the checkpoint.
	storeGenerationRunningSandbox(t, s, id, "gen-legacy")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	response, err := s.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             id,
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, handler.checkpoints, 1)
	assert.FileExists(t, filepath.Join(directory, "checkpoint.img"))
}
