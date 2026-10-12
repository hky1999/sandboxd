// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// Uses private metadata, a controlled runtime and the existing query API.
// No physical sandbox, mount, cgroup or model service is involved.
func TestFailedCreationRetirementPublishesOriginalStartCompletion(t *testing.T) {
	handler := &recordingPreparedCleanupHandler{recordingDeleteHandler: &recordingDeleteHandler{
		FakeRuntimeHandler: svc.NewFakeRuntimeHandler(),
	}}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	t.Cleanup(s.closeRetirementProgressJournal)
	request := startOperationRequest()
	record := admitPendingStartOperation(t, s, request)
	id, err := s.sandboxManager.ReserveID(record.SandboxID)
	require.NoError(t, err)
	metadata := &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc",
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
		Labels:        map[string]string{resourceGenerationLabel: record.Generation, startOperationLabel: record.OperationID},
	}
	require.NoError(t, s.sandboxManager.PersistMetadata(id, metadata))
	root := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.WriteFile(filepath.Join(root, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`), 0600))
	stageFilesystemOwner(t, s, id, record.Generation)

	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.NoDirExists(t, root)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State,
		"fully cleaned original creation must publish the durable proof consumed by its query")
	require.Equal(t, record.Generation, response.Result.ResourceGeneration)
	require.Equal(t, 1, handler.cleanupCalls)

	// Repeated cleanup must replay the original proof, including after the
	// metadata directory is gone, without repeating prepared-state effects.
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Equal(t, 1, handler.cleanupCalls)
}
