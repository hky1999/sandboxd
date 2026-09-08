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
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// restoreResultWaitBoundaryContext deterministically runs its hook exactly
// when the restore RPC blocks in checkpointstate.(*Attempt).Wait — the same
// boundary the canonical reproducer uses — so completions race the post-wait
// revalidation without any sleep-based timing.
type restoreResultWaitBoundaryContext struct {
	context.Context
	once    sync.Once
	atWait  func()
	entered bool
}

func (c *restoreResultWaitBoundaryContext) Done() <-chan struct{} {
	pcs := make([]uintptr, 16)
	n := goruntime.Callers(1, pcs)
	frames := goruntime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.Contains(frame.Function, "checkpointstate.(*Attempt).Wait") {
			c.once.Do(func() { c.entered = true; c.atWait() })
			break
		}
		if !more {
			break
		}
	}
	return c.Context.Done()
}

// restoreRequestIdentity derives the restore identity restoreCheckpoint will
// fingerprint for this request.
func restoreRequestIdentity(t *testing.T, request *runtime.RestoreRequest) *runtime.RestoreIdentity {
	t.Helper()
	startConfig, err := normalizeRestoreConfig(request.Config)
	require.NoError(t, err)
	fingerprint, err := restoreFingerprint(startConfig, request.CheckpointID)
	require.NoError(t, err)
	return &runtime.RestoreIdentity{CheckpointID: request.CheckpointID, RequestSha256: fingerprint}
}

// beginJoinedRestore pre-registers the in-flight restore attempt so the RPC
// joins it as a non-executing waiter and the test owns the completion.
func beginJoinedRestore(t *testing.T, s *sandboxService, request *runtime.RestoreRequest) *checkpointstate.Attempt {
	t.Helper()
	identity := restoreRequestIdentity(t, request)
	attempt, execute, err := s.checkpointState.BeginRestore(
		request.Config.SandboxID, identity.RequestSha256)
	require.NoError(t, err)
	require.True(t, execute)
	return attempt
}

// stageRestorePhysicalRecord stores a COMMITTED record under the restore
// target ID; state and ports are shaped by the caller.
func stageRestorePhysicalRecord(
	t *testing.T, s *sandboxService, id, generation string,
	identity *runtime.RestoreIdentity, ports []string,
) {
	t.Helper()
	labels := map[string]string{}
	if generation != "" {
		labels[resourceGenerationLabel] = generation
	}
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:              id,
		RuntimeHandler:  "runsc",
		Labels:          labels,
		Ports:           ports,
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
	}))
}

// restoreOwnResult serializes the createSandbox completion this restore
// attempt would publish for its own incarnation.
func restoreOwnResult(t *testing.T, id, generation string, ports []string) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&runtime.StartResponse{
		ID: id, Ports: ports, ResourceGeneration: generation,
	})
	require.NoError(t, err)
	return encoded
}

// A completion carrying this restore's own result is answered with exactly
// that result once the current physical record still is the incarnation the
// result describes.
func TestRestoreReturnsOwnedCompletionResult(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-own-result"
	const generation = "generation-own"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	identity := restoreRequestIdentity(t, request)
	attempt := beginJoinedRestore(t, s, request)

	ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		stageRestorePhysicalRecord(t, s, id, generation, identity, nil)
		markSandboxRunning(t, s, id)
		s.checkpointState.CompleteWithResult(attempt,
			restoreOwnResult(t, id, generation, nil), nil)
	}
	response, err := s.Restore(ctx, request)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, id, response.ID)
	require.Equal(t, generation, response.ResourceGeneration)
	require.Zero(t, handler.calls, "an owned success needs no cleanup")
}

// The original reproducer's race, driven by a real completed result rather
// than an empty one: a foreign record landing under the target ID after this
// restore's successful completion must not be adopted as the reply.
func TestRestoreRejectsForeignRecordReplacingCompletedResult(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-foreign-race"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	attempt := beginJoinedRestore(t, s, request)

	ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		stageRestorePhysicalRecord(t, s, id, "foreign-generation", &runtime.RestoreIdentity{
			CheckpointID: "foreign-checkpoint", RequestSha256: "foreign-fingerprint",
		}, nil)
		markSandboxRunning(t, s, id)
		s.checkpointState.CompleteWithResult(attempt,
			restoreOwnResult(t, id, "generation-own", nil), nil)
	}
	response, err := s.Restore(ctx, request)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.Error(t, err, "a foreign physical record must not be adopted")
	require.Nil(t, response)
	require.Zero(t, handler.calls, "a rejected completion must trigger no cleanup")
	current, getErr := s.sandboxManager.Get(id)
	require.NoError(t, getErr)
	require.Equal(t, "foreign-generation", current.Metadata.Labels[resourceGenerationLabel])
}

// An equal RestoreIdentity does not license a replacement generation: the
// record must carry the generation of the original completed result.
func TestRestoreRejectsEqualIdentityDifferentGeneration(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-generation-swap"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	identity := restoreRequestIdentity(t, request)
	attempt := beginJoinedRestore(t, s, request)

	ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		stageRestorePhysicalRecord(t, s, id, "replacement-generation", identity, nil)
		markSandboxRunning(t, s, id)
		s.checkpointState.CompleteWithResult(attempt,
			restoreOwnResult(t, id, "generation-own", nil), nil)
	}
	response, err := s.Restore(ctx, request)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.ErrorContains(t, err, "is not this restore's completed result")
	require.Nil(t, response)
	require.Zero(t, handler.calls)
	current, getErr := s.sandboxManager.Get(id)
	require.NoError(t, getErr)
	require.Equal(t, "replacement-generation", current.Metadata.Labels[resourceGenerationLabel])
}

// Records that prove neither this incarnation nor any live replay — no
// generation, an EXITED body, or UNKNOWN state — fail the completion with no
// response and no cleanup.
func TestRestoreRejectsUnprovablePhysicalRecordAfterCompletion(t *testing.T) {
	for name, stage := range map[string]func(*testing.T, *sandboxService, string, *runtime.RestoreIdentity){
		"record without a resource generation": func(t *testing.T, s *sandboxService, id string, identity *runtime.RestoreIdentity) {
			stageRestorePhysicalRecord(t, s, id, "", identity, nil)
			markSandboxRunning(t, s, id)
		},
		"exited record": func(t *testing.T, s *sandboxService, id string, identity *runtime.RestoreIdentity) {
			stageRestorePhysicalRecord(t, s, id, "generation-own", identity, nil)
			require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
		},
		"unknown state": func(t *testing.T, s *sandboxService, id string, identity *runtime.RestoreIdentity) {
			stageRestorePhysicalRecord(t, s, id, "generation-own", identity, nil)
			markSandboxUnknown(t, s, id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, handler := newRestoreCleanupService(t)
			const id = "sbox-restore-unprovable"
			directory, fact := publishParkedArtifact(t, s,
				parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
			request := restoreCleanupRequest(directory, fact, id, t.TempDir())
			identity := restoreRequestIdentity(t, request)
			attempt := beginJoinedRestore(t, s, request)

			ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
			ctx.atWait = func() {
				stage(t, s, id, identity)
				s.checkpointState.CompleteWithResult(attempt,
					restoreOwnResult(t, id, "generation-own", nil), nil)
			}
			response, err := s.Restore(ctx, request)
			require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
			require.Error(t, err)
			require.Nil(t, response, "no non-running record may be answered with a live fact")
			require.Zero(t, handler.calls, "an unprovable record must trigger no cleanup")
			_, getErr := s.sandboxManager.Get(id)
			require.NoError(t, getErr, "the record must be retained untouched")
		})
	}
}

// The physical record disappearing after the completion is a failure, not a
// reason to resurrect or re-derive a response.
func TestRestoreRejectsRemovedMetadataAfterCompletion(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-removed"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	attempt := beginJoinedRestore(t, s, request)

	ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		s.checkpointState.CompleteWithResult(attempt,
			restoreOwnResult(t, id, "generation-own", nil), nil)
	}
	response, err := s.Restore(ctx, request)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.Error(t, err)
	require.Nil(t, response)
	require.Zero(t, handler.calls)
	_, getErr := s.sandboxManager.Get(id)
	require.Error(t, getErr, "a removed record must not be resurrected by the reply path")
}

// The current record's ports must still match the ports of the original
// completed result; a drifted port set rejects the completion.
func TestRestoreRejectsCurrentPortsConflictingWithOwnedResult(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-ports-conflict"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	identity := restoreRequestIdentity(t, request)
	attempt := beginJoinedRestore(t, s, request)

	ctx := &restoreResultWaitBoundaryContext{Context: context.Background()}
	ctx.atWait = func() {
		stageRestorePhysicalRecord(t, s, id, "generation-own", identity, nil)
		markSandboxRunning(t, s, id)
		// The completion claims a port the physical record never carried.
		s.checkpointState.CompleteWithResult(attempt,
			restoreOwnResult(t, id, "generation-own", []string{"1"}), nil)
	}
	response, err := s.Restore(ctx, request)
	require.True(t, ctx.entered, "test must reach the real attempt.Wait boundary")
	require.ErrorContains(t, err, "port count conflicts")
	require.Nil(t, response)
	require.Zero(t, handler.calls)
}

// The pre-dispatch replay keeps its semantics under the locking wrapper: a
// matching COMMITTED, RUNNING record with a nonempty generation replies
// immutably without touching the runtime or the artifact.
func TestRestorePreDispatchReplayRemainsValid(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-replay-owned"
	directory, fact := publishParkedArtifact(t, s,
		parkedSourceIdentity("source", "source-generation", "result-checkpoint"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	stageRestorePhysicalRecord(t, s, id, "generation-live",
		restoreRequestIdentity(t, request), nil)
	markSandboxRunning(t, s, id)

	response, err := s.Restore(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, id, response.ID)
	require.Equal(t, "generation-live", response.ResourceGeneration)
	require.Zero(t, handler.calls, "a replay must not touch the runtime")
}
