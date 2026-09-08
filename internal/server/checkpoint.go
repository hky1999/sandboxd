// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (h *sandboxService) Checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
) (*runtime.CheckpointResponse, error) {
	return h.checkpoint(ctx, request, "")
}

// CheckpointIfGeneration checkpoints only the physical incarnation identified
// by expected_generation. The expectation is validated inside the shared
// checkpoint path — never by a separate Get followed by an unguarded legacy
// call — so a stale generation is rejected before rootfs reads, handler
// lookup, or any mutation.
func (h *sandboxService) CheckpointIfGeneration(
	ctx context.Context,
	request *runtime.CheckpointIfGenerationRequest,
) (*runtime.CheckpointResponse, error) {
	if request == nil {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint request is required: %w", errord.ErrInvalidArgument))
	}
	if err := validateExpectedGeneration(request.ExpectedGeneration); err != nil {
		return nil, checkpointGRPCError(err)
	}
	return h.checkpoint(ctx, request.Checkpoint, request.ExpectedGeneration)
}

// validateExpectedGeneration enforces the conditional-precondition shape.
func validateExpectedGeneration(generation string) error {
	if strings.TrimSpace(generation) == "" {
		return fmt.Errorf("expected_generation is required: %w", errord.ErrInvalidArgument)
	}
	if len(generation) > 256 {
		return fmt.Errorf("expected_generation exceeds 256 bytes: %w", errord.ErrInvalidArgument)
	}
	return nil
}

// checkpoint is the shared implementation for the legacy and conditional RPCs.
// expectedGeneration is empty for the legacy path, which retains its
// unconditional semantics. When set, the captured source generation must equal
// it at every decision point: source lookup, artifact replay, and the
// in-flight fingerprint, so one checkpoint key cannot merge attempts made
// against different physical generations.
func (h *sandboxService) checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
	expectedGeneration string,
) (*runtime.CheckpointResponse, error) {
	if request == nil || request.ID == "" || request.CheckpointDir == "" || request.CheckpointID == "" {
		return nil, errord.ToGRPC(fmt.Errorf("id, checkpoint_dir, and checkpoint_id are required: %w", errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	existing, artifactErr := checkpoint.InspectAt(checkpointDir, request.CheckpointID)
	if artifactErr != nil {
		if _, statErr := os.Lstat(filepath.Join(checkpointDir, checkpoint.ManifestName)); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			return nil, checkpointGRPCError(artifactErr)
		}
		artifactErr = fmt.Errorf("checkpoint %q: %w", request.CheckpointID, errord.ErrNotFound)
	}
	if artifactErr == nil && (existing.Manifest.SourceID != request.ID ||
		existing.Manifest.LeaveRunning != request.LeaveRunning ||
		existing.Manifest.IncludeFilesystem != request.IncludeFilesystem) {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint %q source or physical mode conflicts with replay: %w",
			request.CheckpointID,
			errord.ErrFailedPrecondition))
	}
	// A conditional replay must match the generation that published the
	// completed artifact; reject before consulting live sandbox state, so an
	// absent sandbox can replay only its own generation's artifact.
	if artifactErr == nil && expectedGeneration != "" && existing.Manifest.SourceGeneration != expectedGeneration {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint %q belongs to source generation %q, want %q: %w",
			request.CheckpointID, existing.Manifest.SourceGeneration, expectedGeneration,
			errord.ErrFailedPrecondition))
	}
	sandbox, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		if artifactErr == nil && errors.Is(err, errord.ErrNotFound) {
			return checkpointResponse(existing), nil
		}
		return nil, checkpointGRPCError(err)
	}
	if sandbox.Metadata == nil || sandbox.Status == nil {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox %s metadata is incomplete: %w", request.ID, errord.ErrFailedPrecondition))
	}
	// Reject a stale expectation before any rootfs read, handler lookup, or
	// mutation. A live replacement of the ID is rejected even when a
	// completed artifact for the expected generation still exists.
	if expectedGeneration != "" && sandbox.Metadata.Labels[resourceGenerationLabel] != expectedGeneration {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint source generation changed, want %q: %w",
			expectedGeneration, errord.ErrFailedPrecondition))
	}

	rootfs, err := h.fsMgr.RootfsConfig(request.ID)
	if err != nil {
		return nil, checkpointGRPCError(fmt.Errorf("read source rootfs identity: %w", err))
	}
	identity, err := rootfsIdentity(rootfs)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	source := checkpoint.SourceIdentity{
		SourceGeneration:  sandbox.Metadata.Labels[resourceGenerationLabel],
		CheckpointID:      request.CheckpointID,
		SourceID:          request.ID,
		Runtime:           sandbox.Metadata.RuntimeHandler,
		RootfsSHA256:      hex.EncodeToString(identity[:]),
		LeaveRunning:      request.LeaveRunning,
		IncludeFilesystem: request.IncludeFilesystem,
	}
	if artifactErr == nil {
		exact, matchErr := checkpoint.MatchSource(existing, source)
		if matchErr != nil {
			return nil, checkpointGRPCError(matchErr)
		}
		return checkpointResponse(exact), nil
	}
	state := sandbox.Status.Get().State()
	if sandbox.Metadata.RuntimeHandler != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support checkpoint: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, checkpointGRPCError(errord.ErrNotImplemented)
	}
	checkpointHandler, ok := handler.(svc.ManagedCheckpointHandler)
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support checkpoint: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	fingerprint, err := checkpointSourceFingerprint(request, request.CheckpointID, source.SourceGeneration)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	releaseOperation, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox service is shutting down: %w", errord.ErrUnavailable))
	}
	key := checkpointstate.CheckpointKey{SandboxID: request.ID, CheckpointID: request.CheckpointID}
	attempt, execute, err := h.checkpointState.BeginCheckpoint(key, fingerprint)
	if err != nil {
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute && state != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		err := fmt.Errorf("sandbox %s is %s: %w",
			request.ID, state, errord.ErrFailedPrecondition)
		h.checkpointState.Complete(attempt, err)
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute {
		operationCtx := h.checkpointOperationContext(ctx)
		go func() {
			defer releaseOperation()
			h.executeCheckpoint(operationCtx, checkpointDir, key, checkpointHandler, source,
				svc.CheckpointOptions{
					LeaveRunning:      request.LeaveRunning,
					IncludeFilesystem: request.IncludeFilesystem,
				}, attempt)
		}()
	} else {
		releaseOperation()
	}
	if err := attempt.Wait(ctx); err != nil {
		return nil, checkpointGRPCError(err)
	}
	fact, err := checkpoint.InspectAt(checkpointDir, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	// Verify the published fact against the source identity captured for
	// this attempt before returning; a merged or raced operation must not
	// hand back an artifact bound to a different physical source.
	if _, err := checkpoint.MatchSource(fact, source); err != nil {
		return nil, checkpointGRPCError(err)
	}
	return checkpointResponse(fact), nil
}

func checkpointResponse(fact checkpoint.Fact) *runtime.CheckpointResponse {
	return &runtime.CheckpointResponse{
		Success: true, ArtifactPath: fact.Paths.Image,
		SourceGeneration: fact.Manifest.SourceGeneration,
		ArtifactSize:     fact.Manifest.ImageSize, ArtifactSha256: fact.Manifest.ImageSHA256,
	}
}

func (h *sandboxService) DeleteCheckpoint(
	_ context.Context,
	request *runtime.DeleteCheckpointRequest,
) (*runtime.DeleteCheckpointResponse, error) {
	if request == nil || request.CheckpointDir == "" || request.CheckpointID == "" ||
		request.SourceSandboxID == "" || request.ExpectedSize <= 0 || request.ExpectedSha256 == "" {
		return nil, checkpointGRPCError(fmt.Errorf(
			"checkpoint_dir, checkpoint_id, source_sandbox_id, expected_size, and expected_sha256 are required: %w",
			errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	err = checkpoint.DeleteAt(checkpointDir, checkpoint.DeleteIdentity{
		CheckpointID: request.CheckpointID,
		SourceID:     request.SourceSandboxID,
		ImageSize:    request.ExpectedSize,
		ImageSHA256:  request.ExpectedSha256,
	})
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return &runtime.DeleteCheckpointResponse{}, nil
}

func (h *sandboxService) Restore(
	ctx context.Context,
	request *runtime.RestoreRequest,
) (*runtime.StartResponse, error) {
	if request == nil || request.Config == nil || request.CheckpointDir == "" {
		return nil, checkpointGRPCError(fmt.Errorf(
			"config and checkpoint_dir are required: %w", errord.ErrInvalidArgument))
	}
	if request.CheckpointID != "" || request.ExpectedSha256 != "" || request.ExpectedSize != 0 {
		return h.restoreCheckpoint(ctx, request)
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	startConfig, err := normalizeRestoreConfig(request.Config)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	if startConfig.Runtime != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf(
			"runtime %q does not support restore: %w", startConfig.Runtime, errord.ErrNotImplemented))
	}
	imagePath := filepath.Join(checkpointDir, checkpoint.ImageName)
	info, err := os.Lstat(imagePath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, checkpointGRPCError(fmt.Errorf(
			"legacy checkpoint image is missing or not a regular file: %w", errord.ErrFailedPrecondition))
	}
	// W7-P1.1: same resource-limit override as the managed path.
	if err := applyCheckpointResourceLimits(startConfig, checkpointDir); err != nil {
		return nil, checkpointGRPCError(fmt.Errorf("%v: %w", err, errord.ErrFailedPrecondition))
	}
	response, err := h.createSandbox(ctx, startConfig, createOptions{checkpointImage: imagePath})
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return response, nil
}

func (h *sandboxService) restoreCheckpoint(
	ctx context.Context,
	request *runtime.RestoreRequest,
) (*runtime.StartResponse, error) {
	if request == nil || request.Config == nil || request.Config.SandboxID == "" ||
		request.CheckpointDir == "" || request.CheckpointID == "" ||
		request.ExpectedSha256 == "" || request.ExpectedSize <= 0 {
		return nil, checkpointGRPCError(fmt.Errorf(
			"config, config.sandbox_id, checkpoint_dir, checkpoint_id, expected_sha256, and expected_size are required: %w",
			errord.ErrInvalidArgument))
	}
	checkpointDir, err := h.resolveManagedCheckpointDir(request.CheckpointDir)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	startConfig, err := normalizeRestoreConfig(request.Config)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	// W7-P1.1: prefer the limits snapshotted at checkpoint time (ladder/
	// task-variant changes) over the caller's original booking. Missing
	// sidecar keeps legacy behavior. Applied BEFORE the fingerprint so the
	// restore identity covers the config actually applied.
	if err := applyCheckpointResourceLimits(startConfig, checkpointDir); err != nil {
		return nil, checkpointGRPCError(fmt.Errorf("%v: %w", err, errord.ErrFailedPrecondition))
	}
	fingerprint, err := restoreFingerprint(startConfig, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	restoreIdentity := &runtime.RestoreIdentity{
		CheckpointID: request.CheckpointID, RequestSha256: fingerprint,
	}
	// The lookup is read only. A matching RUNNING record replays without
	// requiring the artifact — an already-restored sandbox stays a valid
	// replay after its checkpoint artifact has been garbage collected.
	// Everything else fails here; a possible park leftover is only marked as
	// a candidate, and the actual cleanup waits for the verified admission
	// below, so an identity comparison alone can never authorize a delete.
	parkedCandidate := false
	if existing, found, existingErr := h.existingRestorePhysicalFact(ctx, startConfig, restoreIdentity); existingErr != nil {
		if !errors.Is(existingErr, errRestoreParkedSourceCandidate) {
			return nil, checkpointGRPCError(existingErr)
		}
		parkedCandidate = true
	} else if found {
		return existing, nil
	}
	imagePath, err := verifyExternalCheckpoint(checkpointDir, request.ExpectedSize, request.ExpectedSha256)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	// A checkpoint published with a filesystem artifact must restore it;
	// silently dropping the writable layer would rewind workload state. The
	// committed fact is also the identity evidence the verified park cleanup
	// admits against — an invalid manifest or digest must never reach a Delete.
	fact, err := checkpoint.InspectAt(checkpointDir, request.CheckpointID)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	if startConfig.Runtime != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf(
			"runtime %q does not support restore: %w", startConfig.Runtime, errord.ErrNotImplemented))
	}
	releaseOperation, ok := h.acquireCheckpointOperation()
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox service is shutting down: %w", errord.ErrUnavailable))
	}
	if parkedCandidate {
		// Conditional deletion continues independently of the RPC caller.
		// Keep the admitted operation alive until that cleanup actually settles.
		if err := h.cleanupVerifiedParkedSource(context.WithoutCancel(ctx), startConfig, request.CheckpointID, fact); err != nil {
			releaseOperation()
			return nil, checkpointGRPCError(err)
		}
	}
	attempt, execute, err := h.checkpointState.BeginRestore(startConfig.SandboxID, fingerprint)
	if err != nil {
		releaseOperation()
		return nil, checkpointGRPCError(err)
	}
	if execute {
		operationCtx := h.checkpointOperationContext(ctx)
		go func() {
			defer releaseOperation()
			h.executeRestore(operationCtx, imagePath, startConfig, restoreIdentity, attempt)
		}()
	} else {
		releaseOperation()
	}
	// The response is owned by this attempt's completion payload, never by a
	// fresh Get: whatever physical record sits under the ID after the wait is
	// revalidated against the original createSandbox result, and a missing or
	// replaced record fails instead of being silently adopted.
	result, err := attempt.WaitResult(ctx)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	original, err := decodeRestoreResult(startConfig.SandboxID, result)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	response, err := h.validateRestoredPhysicalFact(ctx, startConfig, restoreIdentity, original)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	return response, nil
}

// errRestoreParkedSourceCandidate marks a COMMITTED, genuinely EXITED physical
// record under the restore target ID whose restore identity differs from this
// request — the shape of a park (checkpoint leaveRunning=false) leftover. The
// sentinel itself authorizes no mutation: restoreCheckpoint must admit the
// candidate through cleanupVerifiedParkedSource, which re-observes the record
// and verifies the committed artifact fact, source identity, generation and
// EXITED state before the generation-conditional delete.
var errRestoreParkedSourceCandidate = errors.New("sandbox is a parked-source cleanup candidate")

// existingRestorePhysicalFact is a READ-ONLY lookup of the physical record
// under the restore target ID, taken under that ID's physical resource lock
// so it cannot interleave with create, delete or checkpoint mutations. It
// never mutates: a park leftover is only reported through
// errRestoreParkedSourceCandidate for the verified cleanup admission, and no
// identity or state combination grants a delete here.
func (h *sandboxService) existingRestorePhysicalFact(
	ctx context.Context,
	request *runtime.StartRequest,
	expectedIdentity *runtime.RestoreIdentity,
) (*runtime.StartResponse, bool, error) {
	if request == nil || request.SandboxID == "" {
		return nil, false, nil
	}
	unlock, err := h.resourceLocks.acquire(ctx, request.SandboxID)
	if err != nil {
		return nil, true, err
	}
	defer unlock()
	return h.existingRestorePhysicalFactLocked(request, expectedIdentity)
}

// existingRestorePhysicalFactLocked is the lock-held core of the replay
// lookup. The caller must already hold the target ID's physical resource
// lock — the post-wait revalidation reuses it without double locking. It
// never mutates and answers success only for a COMMITTED, RUNNING record with
// a nonempty generation under exactly the requested ID; the reply is
// immutable, with cloned ports.
func (h *sandboxService) existingRestorePhysicalFactLocked(
	request *runtime.StartRequest,
	expectedIdentity *runtime.RestoreIdentity,
) (*runtime.StartResponse, bool, error) {
	if request == nil || request.SandboxID == "" {
		return nil, false, nil
	}
	physical, err := h.sandboxManager.Get(request.SandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if physical == nil || physical.Metadata == nil || physical.Status == nil {
		return nil, true, fmt.Errorf("sandbox %s physical record is incomplete: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	metadata := physical.Metadata
	if metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED {
		return nil, true, fmt.Errorf("sandbox %s physical record is not committed: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	// A park (checkpoint with leaveRunning=false) exits the sandbox but keeps
	// the physical record until cleanup removes it, and an in-flight destroy
	// leaves the state UNKNOWN for a while. Only a live RUNNING sandbox with
	// an EQUAL restore identity is a genuine idempotent replay: a non-RUNNING
	// record is never answered with a live StartResponse, and UNKNOWN proves
	// neither exit nor liveness, so it cannot even become a cleanup candidate.
	state := physical.Status.Get().State()
	identityMatches := expectedIdentity != nil && metadata.RestoreIdentity != nil &&
		proto.Equal(metadata.RestoreIdentity, expectedIdentity)
	switch state {
	case runtime.SandboxState_SANDBOX_STATE_RUNNING:
		if !identityMatches {
			return nil, true, fmt.Errorf("sandbox %s is RUNNING; cannot restore onto a live sandbox: %w",
				request.SandboxID, errord.ErrFailedPrecondition)
		}
	case runtime.SandboxState_SANDBOX_STATE_EXITED:
		if !identityMatches {
			if expectedIdentity == nil {
				return nil, true, fmt.Errorf("sandbox %s is EXITED; cannot restore onto a non-running sandbox: %w",
					request.SandboxID, errord.ErrFailedPrecondition)
			}
			return nil, true, fmt.Errorf("sandbox %s is EXITED with a different restore identity: %w",
				request.SandboxID, errRestoreParkedSourceCandidate)
		}
		return nil, true, fmt.Errorf("sandbox %s is EXITED; matching restore identity is not a live replay: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	default:
		return nil, true, fmt.Errorf("sandbox %s state is %s, which proves neither a live replay nor an exit: %w",
			request.SandboxID, state, errord.ErrFailedPrecondition)
	}
	// A replay answer must describe exactly the requested incarnation: the
	// stored ID and a nonempty resource generation, so a caller can never be
	// handed another sandbox's or a generation-less record's identity.
	if metadata.ID != request.SandboxID {
		return nil, true, fmt.Errorf("sandbox %s physical record describes ID %q: %w",
			request.SandboxID, metadata.ID, errord.ErrFailedPrecondition)
	}
	generation := metadata.Labels[resourceGenerationLabel]
	if generation == "" {
		return nil, true, fmt.Errorf("sandbox %s physical record carries no resource generation: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	if metadata.RuntimeHandler != request.Runtime {
		return nil, true, fmt.Errorf("sandbox %s runtime conflicts with restore replay: %w",
			request.SandboxID, errord.ErrFailedPrecondition)
	}
	for key, expected := range request.Labels {
		if metadata.Labels[key] != expected {
			return nil, true, fmt.Errorf("sandbox %s label %q conflicts with restore replay: %w",
				request.SandboxID, key, errord.ErrFailedPrecondition)
		}
	}
	if err := validateReplayPorts(request.SandboxID, request.Ports, metadata.Ports); err != nil {
		return nil, true, err
	}
	return &runtime.StartResponse{
		ID:                 metadata.ID,
		Ports:              clonePorts(metadata.Ports),
		ResourceGeneration: generation,
	}, true, nil
}

// validateRestoredPhysicalFact re-observes the physical record under the
// restore target's resource lock after the coordinated attempt completed, and
// answers only with the ORIGINAL createSandbox result: the current record
// must still be the exact incarnation this attempt created — matching restore
// identity, generation, runtime, labels and ports. A missing, replaced,
// exited or UNKNOWN record fails with no cleanup and no response, and a later
// generation is never silently adopted even when it carries an equal
// RestoreIdentity. The lock is acquired here only, never held across the
// attempt wait or creation.
func (h *sandboxService) validateRestoredPhysicalFact(
	ctx context.Context,
	startConfig *runtime.StartRequest,
	restoreIdentity *runtime.RestoreIdentity,
	original *runtime.StartResponse,
) (*runtime.StartResponse, error) {
	unlock, err := h.resourceLocks.acquire(ctx, startConfig.SandboxID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, found, factErr := h.existingRestorePhysicalFactLocked(startConfig, restoreIdentity)
	if factErr != nil {
		// A parked candidate is meaningful only before dispatch. The reply
		// path never admits cleanup and reports a failed identity check.
		if errors.Is(factErr, errRestoreParkedSourceCandidate) {
			return nil, fmt.Errorf("completed restore no longer owns its physical record: %w", errord.ErrFailedPrecondition)
		}
		return nil, factErr
	}
	if !found {
		return nil, fmt.Errorf("restored sandbox %s physical record is missing: %w",
			startConfig.SandboxID, errord.ErrNotFound)
	}
	if current.ResourceGeneration != original.ResourceGeneration {
		return nil, fmt.Errorf(
			"sandbox %s generation %q is not this restore's completed result %q: %w",
			startConfig.SandboxID, current.ResourceGeneration, original.ResourceGeneration,
			errord.ErrFailedPrecondition)
	}
	if err := validateReplayPorts(startConfig.SandboxID, original.Ports, current.Ports); err != nil {
		return nil, err
	}
	// Return the attempt's own completion — cloned, ports included — not a
	// fresh observation: the response identity stays owned by the restore
	// that produced it.
	replay := proto.Clone(original).(*runtime.StartResponse)
	replay.Ports = clonePorts(original.Ports)
	return replay, nil
}

// decodeRestoreResult reconstructs the completion payload owned by one
// restore attempt. A missing, malformed or foreign success payload can never
// be turned into a success.
func decodeRestoreResult(sandboxID string, encoded []byte) (*runtime.StartResponse, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("restore of sandbox %s completed without a result: %w",
			sandboxID, errord.ErrFailedPrecondition)
	}
	original := &runtime.StartResponse{}
	if err := proto.Unmarshal(encoded, original); err != nil {
		return nil, fmt.Errorf("decode restore result of sandbox %s: %w", sandboxID, err)
	}
	if original.ID != sandboxID || original.ResourceGeneration == "" || original.Code != 0 {
		return nil, fmt.Errorf("restore result does not describe sandbox %s: %w",
			sandboxID, errord.ErrFailedPrecondition)
	}
	return original, nil
}

// cleanupVerifiedParkedSource deletes one VERIFIED park leftover so the
// restore may recreate the target ID. Admission requires the committed
// artifact fact of THIS request's checkpoint: a non-leave-running source with
// a nonempty generation whose source ID is the restore target, a runtime
// agreed by the artifact, the source metadata and the request, a COMMITTED
// record still carrying that exact generation, and a genuinely EXITED state.
// Legacy or generation-less artifacts, wrong sources, leave-running
// checkpoints, UNKNOWN state, corrupt artifacts and replacement generations
// are rejected WITHOUT any Delete. The delete is generation-conditional:
// deleteSandbox rechecks the captured generation under the physical resource
// lock and records the durable retirement receipt, so a replacement generation
// that raced this observation survives. A completed receipt alone never
// clears a replacement either — the subsequent create path rechecks the
// physical state itself.
func (h *sandboxService) cleanupVerifiedParkedSource(
	ctx context.Context,
	startConfig *runtime.StartRequest,
	checkpointID string,
	fact checkpoint.Fact,
) error {
	sandboxID := startConfig.SandboxID
	manifest := fact.Manifest
	if manifest.CheckpointID != checkpointID || manifest.SourceID != sandboxID ||
		manifest.LeaveRunning || manifest.SourceGeneration == "" {
		return fmt.Errorf("checkpoint %q is not a generation-bound park of sandbox %s: %w",
			checkpointID, sandboxID, errord.ErrFailedPrecondition)
	}
	physical, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return fmt.Errorf("re-observe parked source %s: %w", sandboxID, err)
	}
	if physical == nil || physical.Metadata == nil || physical.Status == nil ||
		physical.Metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED {
		return fmt.Errorf("sandbox %s physical record is not committed: %w",
			sandboxID, errord.ErrFailedPrecondition)
	}
	metadata := physical.Metadata
	if state := physical.Status.Get().State(); state != runtime.SandboxState_SANDBOX_STATE_EXITED {
		return fmt.Errorf("sandbox %s is %s; only a genuinely EXITED park can be cleaned: %w",
			sandboxID, state, errord.ErrFailedPrecondition)
	}
	if manifest.Runtime != metadata.RuntimeHandler || manifest.Runtime != startConfig.Runtime {
		return fmt.Errorf("sandbox %s runtime %q conflicts with parked checkpoint %q runtime %q: %w",
			sandboxID, metadata.RuntimeHandler, checkpointID, manifest.Runtime, errord.ErrFailedPrecondition)
	}
	generation := metadata.Labels[resourceGenerationLabel]
	if generation == "" || generation != manifest.SourceGeneration {
		return fmt.Errorf("sandbox %s resource generation %q is not the parked source generation %q: %w",
			sandboxID, generation, manifest.SourceGeneration, errord.ErrFailedPrecondition)
	}
	if err := h.deleteSandbox(ctx, sandboxID, generation); err != nil {
		return fmt.Errorf("clean up verified parked sandbox %s before restore: %w", sandboxID, err)
	}
	return nil
}

func validateReplayPorts(sandboxID string, requested, physical []string) error {
	if len(requested) != len(physical) {
		return fmt.Errorf("sandbox %s port count conflicts with restore replay: %w",
			sandboxID, errord.ErrFailedPrecondition)
	}
	for index := range requested {
		want, wantErr := parseDnatRule(sandboxID, requested[index], "")
		actual, actualErr := parseDnatRule(sandboxID, physical[index], "")
		if wantErr != nil || actualErr != nil || actual.DstPort == 0 || !portRequestMatchesFact(want, actual) {
			return fmt.Errorf("sandbox %s port request conflicts with physical fact: %w",
				sandboxID, errord.ErrFailedPrecondition)
		}
	}
	return nil
}

func (h *sandboxService) executeRestore(
	ctx context.Context,
	imagePath string,
	startConfig *runtime.StartRequest,
	restoreIdentity *runtime.RestoreIdentity,
	attempt *checkpointstate.Attempt,
) {
	response, err := h.restorePhysicalSandbox(ctx, imagePath, startConfig, restoreIdentity)
	if err != nil {
		h.checkpointState.Complete(attempt, err)
		return
	}
	// Only a completion that actually describes this restore's incarnation
	// may become a success; nil or malformed responses complete as errors.
	if response == nil || response.ID != startConfig.SandboxID ||
		response.ResourceGeneration == "" || response.Code != 0 {
		h.checkpointState.Complete(attempt, fmt.Errorf(
			"restore completion does not describe sandbox %s: %w",
			startConfig.SandboxID, errord.ErrFailedPrecondition))
		return
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		h.checkpointState.Complete(attempt, fmt.Errorf(
			"serialize restore result of sandbox %s: %w", startConfig.SandboxID, err))
		return
	}
	h.checkpointState.CompleteWithResult(attempt, encoded, nil)
}

func (h *sandboxService) restorePhysicalSandbox(
	ctx context.Context, imagePath string, startConfig *runtime.StartRequest,
	restoreIdentity *runtime.RestoreIdentity,
) (*runtime.StartResponse, error) {
	if err := h.reconcileRestoreIntent(ctx, startConfig, restoreIdentity); err != nil {
		return nil, err
	}
	response, err := h.createSandbox(ctx, startConfig, createOptions{
		checkpointImage: imagePath,
		restoreIdentity: restoreIdentity,
		onReserved: func(_ *runtime.StartRequest, sandboxID string) error {
			if sandboxID != startConfig.SandboxID {
				return fmt.Errorf("restore reserved sandbox %q, want %q: %w",
					sandboxID, startConfig.SandboxID, errord.ErrFailedPrecondition)
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func normalizeRestoreConfig(input *runtime.StartRequest) (*runtime.StartRequest, error) {
	if input == nil || input.Rootfs == nil {
		return nil, fmt.Errorf("rootfs is required: %w", errord.ErrInvalidArgument)
	}
	configCopy := proto.Clone(input).(*runtime.StartRequest)
	// Physical incarnations belong to createSandbox, never to restore callers.
	delete(configCopy.Labels, resourceGenerationLabel)
	if rootfsLimit := configCopy.Rootfs.WritableLayerSizeBytes; rootfsLimit > 0 {
		if configCopy.WritableLayerLimitBytes > 0 && configCopy.WritableLayerLimitBytes != rootfsLimit {
			return nil, fmt.Errorf("conflicting writable layer limits: %w", errord.ErrInvalidArgument)
		}
		configCopy.WritableLayerLimitBytes = rootfsLimit
	}
	if configCopy.Runtime == "" {
		configCopy.Runtime = config.RuntimeNameRunsc
	}
	if configCopy.Cwd == "" {
		configCopy.Cwd = "/"
	}
	if configCopy.Stdout == "" {
		configCopy.Stdout = os.DevNull
	}
	if configCopy.Stderr == "" {
		configCopy.Stderr = os.DevNull
	}
	if configCopy.Network == "" {
		configCopy.Network = "sandbox"
	}
	configCopy.TraceID = ""
	return configCopy, nil
}

func restoreFingerprint(config *runtime.StartRequest, canonicalDir string) (string, error) {
	normalized, err := normalizeRestoreConfig(config)
	if err != nil {
		return "", err
	}
	identity, err := physicalstate.NewRestoreIdentity(canonicalDir, normalized)
	if err != nil {
		return "", err
	}
	return identity.RequestSha256, nil
}

func (h *sandboxService) checkpointOperationContext(requestCtx context.Context) context.Context {
	base := h.operationCtx
	if base == nil {
		base = context.Background()
	}
	traceID, spanID := trace.GetContextID(requestCtx)
	ctx := context.WithValue(base, trace.ContextKeyTraceId, traceID.String())
	return context.WithValue(ctx, trace.ContextKeySpanId, spanID.String())
}

func (h *sandboxService) executeCheckpoint(
	ctx context.Context,
	checkpointDir string,
	key checkpointstate.CheckpointKey,
	checkpointHandler svc.ManagedCheckpointHandler,
	source checkpoint.SourceIdentity,
	options svc.CheckpointOptions,
	attempt *checkpointstate.Attempt,
) {
	unlock, lockErr := h.resourceLocks.acquire(ctx, key.SandboxID)
	if lockErr != nil {
		h.checkpointState.Complete(attempt, lockErr)
		return
	}
	defer unlock()
	// Source metadata was read before waiting for the physical operation lock.
	// Revalidate the lifetime while replacement/resize/delete are excluded.
	current, identityErr := h.sandboxManager.Get(key.SandboxID)
	if identityErr != nil || current == nil || current.Metadata == nil || current.Metadata.Labels[resourceGenerationLabel] != source.SourceGeneration {
		if identityErr == nil {
			identityErr = fmt.Errorf("checkpoint source generation changed: %w", errord.ErrFailedPrecondition)
		}
		h.checkpointState.Complete(attempt, identityErr)
		return
	}
	_, err := checkpoint.PublishAt(checkpointDir, source, func(imagePath string) error {
		// W7-P1.1: snapshot the effective cgroup limits BEFORE the runtime
		// checkpoint (sandbox still alive) so the restore can re-apply them
		// instead of the caller's original booking.
		if cerr := h.captureResourceLimits(key.SandboxID, filepath.Dir(imagePath)); cerr != nil {
			return fmt.Errorf("capture resource limits: %w", cerr)
		}
		if err := checkpointHandler.Checkpoint(ctx, key.SandboxID, filepath.Dir(imagePath), options); err != nil {
			return fmt.Errorf("runtime checkpoint failed: %w", err)
		}
		if options.LeaveRunning {
			return nil
		}
		status, err := h.sandboxManager.WaitForExit(ctx, key.SandboxID)
		if err != nil {
			return fmt.Errorf("wait for sandbox exit after checkpoint: %w", err)
		}
		if state := status.State(); state != runtime.SandboxState_SANDBOX_STATE_EXITED {
			return fmt.Errorf("sandbox state after checkpoint is %s: %w", state,
				errord.ErrFailedPrecondition)
		}
		return nil
	})
	h.checkpointState.Complete(attempt, err)
}

func checkpointFingerprint(request *runtime.CheckpointRequest, canonicalDir string) (string, error) {
	normalized := proto.Clone(request).(*runtime.CheckpointRequest)
	normalized.CheckpointID = canonicalDir
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal checkpoint request: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// checkpointSourceFingerprint binds the in-flight checkpoint fingerprint to
// the physical source generation captured for this attempt, so the same
// checkpoint key cannot merge attempts made across physical generations.
// Both the legacy and the conditional RPC use the captured generation.
func checkpointSourceFingerprint(request *runtime.CheckpointRequest, canonicalDir, sourceGeneration string) (string, error) {
	base, err := checkpointFingerprint(request, canonicalDir)
	if err != nil {
		return "", err
	}
	// base is a fixed-length hexadecimal digest, so concatenating the
	// generation is unambiguous.
	sum := sha256.Sum256([]byte(base + sourceGeneration))
	return hex.EncodeToString(sum[:]), nil
}

func verifyExternalCheckpoint(directory string, expectedSize int64, expectedSHA256 string) (string, error) {
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint directory: %w", errord.ErrInvalidArgument)
	}
	info, err := os.Lstat(cleaned)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("checkpoint directory must be a real directory: %w",
			errord.ErrFailedPrecondition)
	}
	imagePath := filepath.Join(cleaned, checkpoint.ImageName)
	image, err := os.Open(imagePath)
	if err != nil {
		return "", fmt.Errorf("open checkpoint image: %w", errord.ErrFailedPrecondition)
	}
	defer image.Close()
	imageInfo, err := image.Stat()
	if err != nil || !imageInfo.Mode().IsRegular() || imageInfo.Size() != expectedSize {
		return "", fmt.Errorf("checkpoint image size differs from SnapshotInfo: %w",
			errord.ErrFailedPrecondition)
	}
	digest := sha256.New()
	written, err := io.Copy(digest, image)
	if err != nil || written != expectedSize ||
		!strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expectedSHA256) {
		return "", fmt.Errorf("checkpoint image digest differs from SnapshotInfo: %w",
			errord.ErrFailedPrecondition)
	}
	return imagePath, nil
}

func (h *sandboxService) resolveManagedCheckpointDir(directory string) (string, error) {
	root, err := filepath.Abs(filepath.Join(h.config.RootDir, "checkpoints"))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint root: %w", errord.ErrInvalidArgument)
	}
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", fmt.Errorf("resolve checkpoint directory: %w", errord.ErrInvalidArgument)
	}
	relative, err := filepath.Rel(root, cleaned)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("checkpoint directory must be below %s: %w",
			root, errord.ErrInvalidArgument)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("create checkpoint root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("checkpoint root must be a real directory: %w",
			errord.ErrFailedPrecondition)
	}
	current := root
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect managed checkpoint path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("managed checkpoint path contains a non-directory or symlink: %w",
				errord.ErrFailedPrecondition)
		}
	}
	return cleaned, nil
}

func rootfsIdentity(rootfs *runtime.RootfsConfig) ([32]byte, error) {
	if rootfs == nil || rootfs.Source == nil {
		return [32]byte{}, fmt.Errorf("rootfs source is required: %w", errord.ErrFailedPrecondition)
	}
	normalized := proto.Clone(rootfs).(*runtime.RootfsConfig)
	normalized.WritableLayerSizeBytes = 0
	if s3 := normalized.GetS3Config(); s3 != nil {
		s3.AccessKeyID = ""
		s3.AccessKeySecret = ""
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal rootfs identity: %w", err)
	}
	return sha256.Sum256(data), nil
}

func checkpointGRPCError(err error) error {
	if err == nil {
		return nil
	}
	mapped := errord.ToGRPC(err)
	if _, ok := status.FromError(mapped); ok {
		return mapped
	}
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
