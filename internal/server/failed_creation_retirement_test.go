// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func failedCreationRetirementFixture(t *testing.T, handler svc.Handler) (*sandboxService, *runtime.SandboxMetadata, *runtime.StartOperationRequest) {
	t.Helper()
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	request := startOperationRequest()
	record := admitPendingStartOperation(t, s, request)
	id, err := s.sandboxManager.ReserveID(record.SandboxID)
	require.NoError(t, err)
	metadata := &runtime.SandboxMetadata{ID: id, RuntimeHandler: "runsc",
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
		Labels:        map[string]string{resourceGenerationLabel: record.Generation, startOperationLabel: record.OperationID}}
	require.NoError(t, s.sandboxManager.PersistMetadata(id, metadata))
	root := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.WriteFile(filepath.Join(root, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`), 0600))
	stageFilesystemOwner(t, s, id, record.Generation)
	return s, metadata, request
}

func reopenFailedCreationRetirement(t *testing.T, original *sandboxService, handler svc.Handler) *sandboxService {
	t.Helper()
	original.closeRetirementProgressJournal()
	original.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": handler})
	reopened.config.RootDir = original.config.RootDir
	var err error
	reopened.sandboxManager, err = sandbox.NewManager(original.config.RootDir, reopened.serviceHandler, make(chan bool, 10), nil, 1000)
	require.NoError(t, err)
	return reopened
}

type failedCreationReceiptBlocker struct {
	*failedCreationHandler
	service    *sandboxService
	generation string
	blocked    bool
}

func (h *failedCreationReceiptBlocker) CleanupPreparedState(ctx context.Context, id string) error {
	if err := h.failedCreationHandler.CleanupPreparedState(ctx, id); err != nil {
		return err
	}
	if !h.blocked {
		h.blocked = true
		_, path := h.service.retirementPath(id, h.generation)
		if err := os.Rename(path, path+".original-pending"); err != nil {
			return err
		}
		return os.Mkdir(path, 0700)
	}
	return nil
}

func unblockFailedCreationReceipt(t *testing.T, s *sandboxService, metadata *runtime.SandboxMetadata) {
	t.Helper()
	_, path := s.retirementPath(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Rename(path+".original-pending", path))
}

func TestFailedCreationRetirementCompletionFailureRecoversAfterServiceReopen(t *testing.T) {
	handler := &failedCreationReceiptBlocker{failedCreationHandler: &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	handler.service, handler.generation = s, metadata.Labels[resourceGenerationLabel]
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.NoDirExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID))
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1, "publication failure retains the original reservation owner")
	_, err := s.sandboxManager.ReserveID(metadata.ID)
	require.Error(t, err)
	unblockFailedCreationReceipt(t, s, metadata)
	reopened := reopenFailedCreationRetirement(t, s, handler)
	require.Empty(t, reopened.sandboxManager.ListPhysicalIntents(), "original metadata has really disappeared")
	require.NoError(t, reopened.reconcilePhysicalIntents(context.Background()))
	response, err := reopened.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
	require.Equal(t, 1, handler.prepared, "history discovery must not repeat prepared-state cleanup")
	require.Zero(t, handler.deletes)
}

func TestFailedCreationRetirementCompletionFailureRetainsIDUntilRetry(t *testing.T) {
	handler := &failedCreationReceiptBlocker{failedCreationHandler: &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}}
	s, metadata, _ := failedCreationRetirementFixture(t, handler)
	handler.service, handler.generation = s, metadata.Labels[resourceGenerationLabel]
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	unblockFailedCreationReceipt(t, s, metadata)
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Empty(t, s.sandboxManager.ListPhysicalIntents())
	id, err := s.sandboxManager.ReserveID(metadata.ID)
	require.NoError(t, err, "only the confirmed original reservation may be released")
	require.Equal(t, metadata.ID, id)
	require.Equal(t, 1, handler.prepared)
}

func TestFailedCreationRetirementResourceFailureRemainsPendingAcrossRetry(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	cgroups := &failingCgroupMgr{recycleErr: errors.New("original cgroup cleanup failed")}
	s.cgroupMgr = cgroups
	require.ErrorIs(t, s.reconcilePhysicalIntent(context.Background(), metadata), cgroups.recycleErr)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	cgroups.recycleErr = nil
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	response, err = s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
	require.Equal(t, []string{"original-cgroup", "original-cgroup"}, cgroups.recycles)
}

func TestFailedCreationRetirementMissingResourcesCannotProveCompletion(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	require.NoError(t, os.Remove(filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxSpecFile)))
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Zero(t, handler.prepared)
	require.Zero(t, handler.deletes)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
}

func TestFailedCreationRetirementMissingDNATIdentityCannotComplete(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	metadata.Ports = []string{"8080:30000"}
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	cgroups := &failingCgroupMgr{}
	s.cgroupMgr = cgroups
	require.ErrorContains(t, s.reconcilePhysicalIntent(context.Background(), metadata), "original network resource")
	require.Empty(t, cgroups.recycles, "unconfirmed DNAT removal keeps the original resource lease")
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
}

func TestFailedCreationRetirementReplacementRootSurvivesCompletionRetry(t *testing.T) {
	handler := &failedCreationReceiptBlocker{failedCreationHandler: &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	handler.service, handler.generation = s, metadata.Labels[resourceGenerationLabel]
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	unblockFailedCreationReceipt(t, s, metadata)
	replacement := proto.Clone(metadata).(*runtime.SandboxMetadata)
	replacement.Labels[resourceGenerationLabel] = uuid.NewString()
	require.NoError(t, s.sandboxManager.PersistMetadata(replacement.ID, replacement))
	marker := filepath.Join(s.config.RootDir, "containers", metadata.ID, "replacement")
	require.NoError(t, os.WriteFile(marker, []byte("replacement"), 0600))
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.FileExists(t, marker)
	require.Equal(t, 1, handler.prepared)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
}

func TestFailedCreationRetirementCompletedReplayPreservesReplacementReservation(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	_, err := s.sandboxManager.ReserveID(metadata.ID)
	require.NoError(t, err)
	replacement := proto.Clone(metadata).(*runtime.SandboxMetadata)
	replacement.Labels[resourceGenerationLabel] = uuid.NewString()
	require.NoError(t, s.sandboxManager.PersistMetadata(replacement.ID, replacement))
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	_, err = s.sandboxManager.ReserveID(metadata.ID)
	require.Error(t, err, "replaying old completion cannot release the replacement reservation")
	intents := s.sandboxManager.ListPhysicalIntents()
	require.Len(t, intents, 1)
	require.True(t, proto.Equal(replacement, intents[0]))
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
	require.Equal(t, 1, handler.prepared)
}

func TestFailedCreationRetirementRecoveryRejectsCorruptOrRenamedHistory(t *testing.T) {
	for _, mode := range []string{"corrupt", "renamed"} {
		t.Run(mode, func(t *testing.T) {
			handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s, metadata, _ := failedCreationRetirementFixture(t, handler)
			require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
			directory, path := s.retirementProgressPath(metadata.ID, metadata.Labels[resourceGenerationLabel])
			if mode == "corrupt" {
				require.NoError(t, os.WriteFile(path, []byte(`{"version":1}`), 0600))
			} else {
				require.NoError(t, os.Rename(path, filepath.Join(directory, strings.Repeat("e", 64)+".json")))
			}
			reopened := reopenFailedCreationRetirement(t, s, handler)
			require.Error(t, reopened.reconcilePhysicalIntents(context.Background()))
			require.Equal(t, 1, handler.prepared)
		})
	}
}

func TestFailedCreationRetirementRecoveryCannotCompleteAnIncompleteHistory(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	cgroups := &failingCgroupMgr{recycleErr: errors.New("original cgroup cleanup failed")}
	s.cgroupMgr = cgroups
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	// Model missing metadata after a separate failure. Incomplete prior steps
	// and no durable root-removal intent must keep the creation unresolved.
	require.NoError(t, os.RemoveAll(filepath.Join(s.config.RootDir, "containers", metadata.ID)))
	reopened := reopenFailedCreationRetirement(t, s, handler)
	require.Error(t, reopened.reconcilePhysicalIntents(context.Background()))
	response, err := reopened.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	require.Equal(t, 1, handler.prepared)
}

func TestFailedCreationRetirementProgressFailurePreventsRuntimeCleanup(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, _ := failedCreationRetirementFixture(t, handler)
	directory, path := s.retirementProgressPath(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, os.Mkdir(path, 0700))
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Zero(t, handler.prepared)
	require.Zero(t, handler.deletes)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
}

func TestFailedCreationRetirementConditionalDeleteReconcilesUnpublishedIntent(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	_, err := s.sandboxManager.Get(metadata.ID)
	require.Error(t, err, "failed creation is intentionally absent from published inventory")
	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel],
	})
	require.NoError(t, err, "the existing conditional API must reconcile the original unpublished intent")
	require.Equal(t, metadata.Labels[resourceGenerationLabel], response.RetiredGeneration)
	queried, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, queried.State)
	require.Equal(t, 1, handler.prepared)
}

func TestFailedCreationRetirementConditionalDeleteRejectsStaleIntentGeneration(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s, metadata, _ := failedCreationRetirementFixture(t, handler)
	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: metadata.ID, ExpectedGeneration: uuid.NewString(),
	})
	require.Error(t, err)
	require.Nil(t, response)
	require.Zero(t, handler.prepared)
	require.Zero(t, handler.deletes)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
}

func TestFailedCreationRetirementConditionalDeleteRecoversCompletionFailure(t *testing.T) {
	handler := &failedCreationReceiptBlocker{failedCreationHandler: &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}}
	s, metadata, _ := failedCreationRetirementFixture(t, handler)
	handler.service, handler.generation = s, metadata.Labels[resourceGenerationLabel]
	request := &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: handler.generation}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.NoDirExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID))
	unblockFailedCreationReceipt(t, s, metadata)
	response, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, handler.generation, response.RetiredGeneration)
	require.Equal(t, 1, handler.prepared)
	require.Empty(t, s.sandboxManager.ListPhysicalIntents())
}
