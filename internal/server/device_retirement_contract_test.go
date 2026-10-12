// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// A void, ID-only release is not evidence for the original generation. These
// cases use the public conditional delete and a real local retirement journal,
// without a physical runtime, device, mount, network or model operation.
func TestFailedCreationRetirementDeviceManagerWithoutGenerationCannotComplete(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	devices := &recordingXPULeaseManager{}
	s.xpuMgr = devices
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel],
	})
	require.Error(t, err, "a legacy device manager cannot prove original-generation cleanup")
	require.Empty(t, devices.released, "do not fall back to unconditional device release")
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotContains(t, progress.Steps, "devices")
}

type deviceConfirmationBlocker struct {
	xpuLeaseManager
	generationDeviceLeaseManager
	confirmationErr error
}

func (m *deviceConfirmationBlocker) ConfirmReleasedForGeneration(id, generation string) error {
	if m.confirmationErr != nil {
		return m.confirmationErr
	}
	return m.generationDeviceLeaseManager.ConfirmReleasedForGeneration(id, generation)
}

func TestFailedCreationRetirementDeviceConfirmationFailureKeepsPendingUntilReopen(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	original := s.xpuMgr
	devices := &deviceConfirmationBlocker{xpuLeaseManager: original, generationDeviceLeaseManager: original.(generationDeviceLeaseManager), confirmationErr: errors.New("original device completion read failed")}
	s.xpuMgr = devices
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.ErrorContains(t, err, "completion read failed")
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotContains(t, progress.Steps, "devices")
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	// The allocator release itself is durable; a separate completion read
	// failed. Reopen its original database and use only that original receipt.
	s.xpuMgr = original
	reopened := reopenFailedCreationRetirement(t, s, handler)
	reopened.fsMgr = s.fsMgr
	_, err = reopened.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.NoError(t, err)
	response, err = reopened.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
}

func TestFailedCreationRetirementMissingOriginalDeviceJournalCannotBorrowCurrentEmptyInventory(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	s.xpuMgr = deviceLeaseFixture(t, t.TempDir()) // An empty independent owner is not the original proof.
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.ErrorContains(t, err, "missing or changed")
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotContains(t, progress.Steps, "devices")
}

func TestRetirementProgressLegacyDeviceAcknowledgementCannotPublishCompletion(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	// Reproduce a historical ordered progress prefix. Its void device release
	// acknowledgement never carried the new independent completion protocol.
	p.DeviceProtocol = 0
	p.Steps = append([]string(nil), retirementProgressSteps[:len(retirementProgressSteps)-1]...)
	p.RootPending = true
	p.IntegritySHA256 = progressDigest(*p)
	_, path := s.retirementProgressPath(p.SandboxID, p.Generation)
	data, err := json.Marshal(p)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	require.NoError(t, os.RemoveAll(filepath.Join(s.config.RootDir, "containers", p.SandboxID)))
	complete, err := s.resumeRetirementCompletion(p.SandboxID, p.Generation)
	require.ErrorContains(t, err, "legacy device acknowledgement")
	require.False(t, complete)
	receipt, err := s.readRetirement(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.Nil(t, receipt)
}

func TestRetirementProgressDeviceProofSurvivesRootRemovalButCannotBorrowAnotherJournal(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	original := s.xpuMgr
	require.NoError(t, s.releaseDeviceLease(p.SandboxID, p.Generation))
	for _, step := range retirementProgressSteps[:len(retirementProgressSteps)-1] {
		require.NoError(t, s.completeRetirementProgressStep(p, step))
	}
	p.RootPending = true
	require.NoError(t, s.writeRetirementProgress(p))
	require.NoError(t, os.RemoveAll(filepath.Join(s.config.RootDir, "containers", p.SandboxID)))
	s.xpuMgr = deviceLeaseFixture(t, t.TempDir())
	complete, err := s.resumeRetirementCompletion(p.SandboxID, p.Generation)
	require.Error(t, err)
	require.False(t, complete)
	s.xpuMgr = original
	complete, err = s.resumeRetirementCompletion(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.True(t, complete)
}
