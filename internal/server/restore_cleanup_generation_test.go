// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/stretchr/testify/require"
)

// markSandboxRunning makes RUNNING an explicit durable status observation
// instead of the load-time default that a missing status file gets.
func markSandboxRunning(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.NoError(t, current.Status.UpdateSync(func(status sandbox.Status) (sandbox.Status, error) {
		status.Unknown = false
		status.StartedAt = time.Now().Format(time.RFC3339)
		status.FinishedAt = ""
		return status, nil
	}))
}

// markSandboxUnknown marks the observed status as not fully loaded; UNKNOWN
// proves neither liveness nor exit.
func markSandboxUnknown(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.NoError(t, current.Status.UpdateSync(func(status sandbox.Status) (sandbox.Status, error) {
		status.Unknown = true
		return status, nil
	}))
}

func newRestoreCleanupService(t *testing.T) (*sandboxService, *recordingDeleteHandler) {
	t.Helper()
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	// The restore RPC coordinates in-flight operations through the checkpoint
	// coordinator, which newTestService does not wire.
	s.checkpointState = checkpointstate.NewCoordinator()
	return s, handler
}

// stageParkedSource stores a COMMITTED, genuinely EXITED physical record for a
// parked (checkpoint leaveRunning=false) source, plus the OCI spec the
// synchronous delete path reads.
func stageParkedSource(t *testing.T, s *sandboxService, id, generation string) {
	t.Helper()
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{resourceGenerationLabel: generation},
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
	}))
	require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	bundleDir := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(bundleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`), 0o644))
}

func parkedSourceIdentity(id, generation, checkpointID string) checkpoint.SourceIdentity {
	return checkpoint.SourceIdentity{
		CheckpointID:     checkpointID,
		SourceID:         id,
		SourceGeneration: generation,
		Runtime:          "runsc",
		RootfsSHA256:     strings.Repeat("a", 64),
		LeaveRunning:     false,
	}
}

func publishParkedArtifact(t *testing.T, s *sandboxService, source checkpoint.SourceIdentity) (string, checkpoint.Fact) {
	t.Helper()
	directory := filepath.Join(s.config.RootDir, "checkpoints", source.CheckpointID)
	fact, err := checkpoint.PublishAt(directory, source, writeReplayCheckpointImage)
	require.NoError(t, err)
	return directory, fact
}

func restoreCleanupRequest(directory string, fact checkpoint.Fact, id, rootfsPath string) *runtime.RestoreRequest {
	return &runtime.RestoreRequest{
		Config: &runtime.StartRequest{
			SandboxID: id,
			Runtime:   "runsc",
			Rootfs: &runtime.RootfsConfig{
				Type:   runtime.RootfsSrcType_LOCAL,
				Source: &runtime.RootfsConfig_Path{Path: rootfsPath},
			},
		},
		CheckpointDir:  directory,
		CheckpointID:   fact.Manifest.CheckpointID,
		ExpectedSize:   fact.Manifest.ImageSize,
		ExpectedSha256: fact.Manifest.ImageSHA256,
	}
}

// The read-only lookup classifies by physical state, never by restore-identity
// text: only a genuinely EXITED record with a foreign identity becomes a
// cleanup candidate; UNKNOWN and live records are hard refusals, and a
// matching identity on a non-running record is never a live success.
func TestExistingRestorePhysicalFactClassifiesStateNotIdentityText(t *testing.T) {
	identity := &runtime.RestoreIdentity{CheckpointID: "case", RequestSha256: "fingerprint"}
	const id = "sbox-state-classification"
	request := &runtime.StartRequest{SandboxID: id, Runtime: "runsc"}
	for name, prepare := range map[string]func(*testing.T, *sandboxService) (*runtime.StartResponse, bool, error){
		"exited with foreign identity is a cleanup candidate": func(t *testing.T, s *sandboxService) (*runtime.StartResponse, bool, error) {
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:             id,
				RuntimeHandler: "runsc",
				PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
			}))
			require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
			return s.existingRestorePhysicalFact(context.Background(), request, identity)
		},
		"exited with matching identity stays unresolved": func(t *testing.T, s *sandboxService) (*runtime.StartResponse, bool, error) {
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:              id,
				RuntimeHandler:  "runsc",
				PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
				RestoreIdentity: identity,
			}))
			require.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
			return s.existingRestorePhysicalFact(context.Background(), request, identity)
		},
		"unknown with foreign identity is never a candidate": func(t *testing.T, s *sandboxService) (*runtime.StartResponse, bool, error) {
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:             id,
				RuntimeHandler: "runsc",
				PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
			}))
			markSandboxUnknown(t, s, id)
			return s.existingRestorePhysicalFact(context.Background(), request, identity)
		},
		"unknown with matching identity stays unresolved": func(t *testing.T, s *sandboxService) (*runtime.StartResponse, bool, error) {
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:              id,
				RuntimeHandler:  "runsc",
				PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
				RestoreIdentity: identity,
			}))
			markSandboxUnknown(t, s, id)
			return s.existingRestorePhysicalFact(context.Background(), request, identity)
		},
		"running with foreign identity is a hard conflict": func(t *testing.T, s *sandboxService) (*runtime.StartResponse, bool, error) {
			require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
				ID:             id,
				RuntimeHandler: "runsc",
				PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
			}))
			markSandboxRunning(t, s, id)
			return s.existingRestorePhysicalFact(context.Background(), request, identity)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			response, found, err := prepare(t, s)
			switch name {
			case "exited with foreign identity is a cleanup candidate":
				require.ErrorIs(t, err, errRestoreParkedSourceCandidate)
				require.True(t, found)
			default:
				require.Error(t, err)
				require.NotErrorIs(t, err, errRestoreParkedSourceCandidate)
				require.True(t, found)
			}
			require.Nil(t, response, "no non-running record may be answered with a live fact")
			_, gerr := s.sandboxManager.Get(id)
			require.NoError(t, gerr, "the read-only lookup must retain the record")
		})
	}
}

// An artifact that cannot be verified against the request or its own manifest
// must never authorize deleting the park candidate.
func TestRestoreInvalidArtifactCannotDeleteParkedCandidate(t *testing.T) {
	t.Run("image digest differs from the request", func(t *testing.T) {
		s, handler := newRestoreCleanupService(t)
		const id = "sbox-park-bad-digest"
		const generation = "generation-parked"
		stageParkedSource(t, s, id, generation)
		directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, generation, "case"))
		request := restoreCleanupRequest(directory, fact, id, t.TempDir())
		request.ExpectedSha256 = strings.Repeat("0", 64)
		_, err := s.Restore(context.Background(), request)
		require.Error(t, err)
		require.Zero(t, handler.calls, "an unverifiable artifact must not authorize deletion")
		_, gerr := s.sandboxManager.Get(id)
		require.NoError(t, gerr, "candidate record must be retained")
	})
	t.Run("committed manifest is corrupt", func(t *testing.T) {
		s, handler := newRestoreCleanupService(t)
		const id = "sbox-park-bad-manifest"
		const generation = "generation-parked"
		stageParkedSource(t, s, id, generation)
		directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, generation, "case"))
		require.NoError(t, os.WriteFile(filepath.Join(directory, checkpoint.ManifestName),
			[]byte("not a manifest"), 0o600))
		request := restoreCleanupRequest(directory, fact, id, t.TempDir())
		_, err := s.Restore(context.Background(), request)
		require.Error(t, err)
		require.Zero(t, handler.calls, "a corrupt manifest must not authorize deletion")
		_, gerr := s.sandboxManager.Get(id)
		require.NoError(t, gerr, "candidate record must be retained")
	})
}

// Every park-candidate shape the verified admission rejects must keep the
// record and never touch the runtime.
func TestRestoreRejectsUnverifiableParkCandidatesWithoutDelete(t *testing.T) {
	const id = "sbox-park-unverified"
	const parkedGeneration = "generation-parked"
	const replacementGeneration = "generation-replacement"
	type parkCandidateCase struct {
		source           checkpoint.SourceIdentity
		recordGeneration string
		unknownState     bool
		completedReceipt bool
	}
	leaveRunning := parkedSourceIdentity(id, parkedGeneration, "case")
	leaveRunning.LeaveRunning = true
	legacyArtifact := parkedSourceIdentity(id, parkedGeneration, "case")
	legacyArtifact.SourceGeneration = ""
	foreignSource := parkedSourceIdentity("sbox-other", parkedGeneration, "case")
	foreignRuntime := parkedSourceIdentity(id, parkedGeneration, "case")
	foreignRuntime.Runtime = "kata"
	matching := parkedSourceIdentity(id, parkedGeneration, "case")
	cases := map[string]parkCandidateCase{
		"leave-running checkpoint":                           {source: leaveRunning, recordGeneration: parkedGeneration},
		"legacy artifact without source generation":          {source: legacyArtifact, recordGeneration: parkedGeneration},
		"artifact of another source":                         {source: foreignSource, recordGeneration: parkedGeneration},
		"artifact of another runtime":                        {source: foreignRuntime, recordGeneration: parkedGeneration},
		"unknown state is not an exit":                       {source: matching, recordGeneration: parkedGeneration, unknownState: true},
		"replacement generation under the ID":                {source: matching, recordGeneration: replacementGeneration},
		"completed receipt alone cannot clear a replacement": {source: matching, recordGeneration: replacementGeneration, completedReceipt: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, handler := newRestoreCleanupService(t)
			stageParkedSource(t, s, id, tc.recordGeneration)
			if tc.completedReceipt {
				require.NoError(t, s.writeRetirement(id, tc.source.SourceGeneration, true))
			}
			directory, fact := publishParkedArtifact(t, s, tc.source)
			if tc.unknownState {
				markSandboxUnknown(t, s, id)
			}
			request := restoreCleanupRequest(directory, fact, id, t.TempDir())
			_, err := s.Restore(context.Background(), request)
			require.Error(t, err)
			require.Zero(t, handler.calls, "an unverified candidate must never be deleted")
			current, gerr := s.sandboxManager.Get(id)
			require.NoError(t, gerr)
			require.Equal(t, tc.recordGeneration, current.Metadata.Labels[resourceGenerationLabel])
		})
	}
	t.Run("helper refuses an unknown physical state", func(t *testing.T) {
		s, handler := newRestoreCleanupService(t)
		stageParkedSource(t, s, id, parkedGeneration)
		markSandboxUnknown(t, s, id)
		directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, parkedGeneration, "case"))
		startConfig, err := normalizeRestoreConfig(restoreCleanupRequest(directory, fact, id, t.TempDir()).Config)
		require.NoError(t, err)
		err = s.cleanupVerifiedParkedSource(context.Background(), startConfig, "case", fact)
		require.ErrorContains(t, err, "only a genuinely EXITED park can be cleaned")
		require.Zero(t, handler.calls)
		_, gerr := s.sandboxManager.Get(id)
		require.NoError(t, gerr)
	})
}

// A fully verified park is retired through the generation-conditional delete
// with the generation captured from the artifact, and the restore continues
// into the recreation path. The unit environment has no cgroup/interface
// managers, so recreation stops at resource preparation — strictly after the
// cleanup has admitted and run.
func TestRestoreCleansVerifiedParkedSourceWithCapturedGeneration(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-park-verified"
	const generation = "generation-parked"
	stageParkedSource(t, s, id, generation)
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, generation, "case"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())

	response, err := s.Restore(context.Background(), request)
	require.Error(t, err)
	require.Nil(t, response)
	require.ErrorContains(t, err, "manager not configured")
	require.Equal(t, 1, handler.calls, "the verified park must be deleted exactly once")
	require.Equal(t, id, handler.sandboxID)
	receipt, rerr := s.readRetirement(id, generation)
	require.NoError(t, rerr)
	require.NotNil(t, receipt)
	require.True(t, receipt.Complete, "the retirement must be durably recorded for the captured generation")
	require.Equal(t, generation, receipt.Generation)
	_, gerr := s.sandboxManager.Get(id)
	require.Error(t, gerr, "the parked source must be retired before recreation")
}

// The restore observed the parked source (read-only lookup plus committed
// artifact fact, in the restore path's own order); a replacement generation
// landing after that observation must not be deleted.
func TestRestoreStaleObservationCannotDeleteReplacementGeneration(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-park-replaced"
	const parkedGeneration = "generation-parked"
	const replacementGeneration = "generation-replacement"
	stageParkedSource(t, s, id, parkedGeneration)
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, parkedGeneration, "case"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())

	startConfig, err := normalizeRestoreConfig(request.Config)
	require.NoError(t, err)
	fingerprint, err := restoreFingerprint(startConfig, request.CheckpointID)
	require.NoError(t, err)
	expectedIdentity := &runtime.RestoreIdentity{CheckpointID: request.CheckpointID, RequestSha256: fingerprint}
	_, found, lookupErr := s.existingRestorePhysicalFact(context.Background(), startConfig, expectedIdentity)
	require.True(t, found)
	require.ErrorIs(t, lookupErr, errRestoreParkedSourceCandidate)
	committed, err := checkpoint.InspectAt(directory, request.CheckpointID)
	require.NoError(t, err)

	// The replacement lands after the observation.
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{
		resourceGenerationLabel: replacementGeneration,
	}))

	cleanupErr := s.cleanupVerifiedParkedSource(context.Background(), startConfig, request.CheckpointID, committed)
	require.Error(t, cleanupErr)
	require.NotErrorIs(t, cleanupErr, errRestoreParkedSourceCandidate)
	require.Zero(t, handler.calls, "a replacement generation must never be deleted")
	current, gerr := s.sandboxManager.Get(id)
	require.NoError(t, gerr)
	require.Equal(t, replacementGeneration, current.Metadata.Labels[resourceGenerationLabel])
}

// Even a cleanup that admitted against the old observation cannot clear a
// replacement: the generation-conditional delete rechecks identity under the
// physical resource lock. A replacement landing while the delete is queued on
// the lock is refused before the runtime handler is touched.
func TestRestoreConditionalDeleteRechecksReplacementUnderPhysicalLock(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-park-lock-race"
	const parkedGeneration = "generation-parked"
	const replacementGeneration = "generation-replacement"
	stageParkedSource(t, s, id, parkedGeneration)
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, parkedGeneration, "case"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	unlock, err := s.resourceLocks.acquire(context.Background(), id)
	require.NoError(t, err)
	deleteErr := make(chan error, 1)
	done := make(chan struct{})
	defer func() {
		unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("cleanup goroutine did not settle after lock release")
		}
	}()
	go func() {
		defer close(done)
		deleteErr <- s.cleanupVerifiedParkedSource(context.Background(), request.Config, request.CheckpointID, fact)
	}()
	// The actual new wrapper has observed the old generation and reached
	// physical delete only when it has registered the second lock reference.
	require.Eventually(t, func() bool {
		s.resourceLocks.mu.Lock()
		defer s.resourceLocks.mu.Unlock()
		entry := s.resourceLocks.keys[id]
		return entry != nil && entry.refs == 2
	}, 5*time.Second, time.Millisecond)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{
		resourceGenerationLabel: replacementGeneration,
	}))
	unlock()
	select {
	case err := <-deleteErr:
		require.ErrorContains(t, err, "resource generation changed before delete")
	case <-time.After(5 * time.Second):
		t.Fatal("conditional cleanup did not settle")
	}
	require.Zero(t, handler.calls)
	current, gerr := s.sandboxManager.Get(id)
	require.NoError(t, gerr)
	require.Equal(t, replacementGeneration, current.Metadata.Labels[resourceGenerationLabel])
	receipt, rerr := s.readRetirement(id, parkedGeneration)
	require.NoError(t, rerr)
	require.Nil(t, receipt)
}

// A matching RUNNING replay is returned before the artifact is required: an
// already-restored sandbox stays a valid replay after artifact GC.
func TestRestoreReplaysMatchingRunningSandboxWithoutArtifact(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "sbox-restore-replay"
	directory := filepath.Join(s.config.RootDir, "checkpoints", "case")
	request := &runtime.RestoreRequest{
		Config: &runtime.StartRequest{
			SandboxID: id,
			Runtime:   "runsc",
			Rootfs: &runtime.RootfsConfig{
				Type:   runtime.RootfsSrcType_LOCAL,
				Source: &runtime.RootfsConfig_Path{Path: t.TempDir()},
			},
		},
		CheckpointDir:  directory,
		CheckpointID:   "case",
		ExpectedSize:   int64(len("checkpoint")),
		ExpectedSha256: strings.Repeat("0", 64),
	}
	startConfig, err := normalizeRestoreConfig(request.Config)
	require.NoError(t, err)
	fingerprint, err := restoreFingerprint(startConfig, request.CheckpointID)
	require.NoError(t, err)
	identity := &runtime.RestoreIdentity{CheckpointID: request.CheckpointID, RequestSha256: fingerprint}
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:              id,
		RuntimeHandler:  "runsc",
		Labels:          map[string]string{resourceGenerationLabel: "generation-live"},
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
	}))
	markSandboxRunning(t, s, id)

	response, err := s.Restore(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, id, response.ID)
	require.Equal(t, "generation-live", response.ResourceGeneration)
	require.Zero(t, handler.calls)
}

// Restoring onto a different, absent destination needs no source cleanup: the
// parked source keeps its record and runtime.
func TestRestoreToFreshDestinationLeavesParkedSourceUntouched(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const sourceID = "sbox-park-elsewhere"
	const generation = "generation-parked"
	stageParkedSource(t, s, sourceID, generation)
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(sourceID, generation, "case"))
	request := restoreCleanupRequest(directory, fact, "sbox-restore-destination", t.TempDir())

	_, err := s.Restore(context.Background(), request)
	require.Error(t, err) // unit environment: resource preparation fails
	require.ErrorContains(t, err, "manager not configured")
	require.Zero(t, handler.calls, "a fresh destination must not clean the source")
	_, gerr := s.sandboxManager.Get(sourceID)
	require.NoError(t, gerr, "the parked source must be retained for its own lifecycle")
}

func TestRestoreShutdownAdmissionPreventsParkCleanup(t *testing.T) {
	s, handler := newRestoreCleanupService(t)
	const id = "park-shutdown"
	stageParkedSource(t, s, id, "old-generation")
	directory, fact := publishParkedArtifact(t, s, parkedSourceIdentity(id, "old-generation", "case"))
	request := restoreCleanupRequest(directory, fact, id, t.TempDir())
	s.stopCheckpointOperations()
	response, err := s.Restore(context.Background(), request)
	require.ErrorContains(t, err, "shutting down")
	require.Nil(t, response)
	require.Zero(t, handler.calls)
	_, err = s.sandboxManager.Get(id)
	require.NoError(t, err)
}
