// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testHistoryBoundary() *runtime.HistoryBoundary {
	return &runtime.HistoryBoundary{Authority: "unit-control", CoordinatorEpoch: 3, AssignmentGeneration: 20, CatalogRevision: 100}
}
func testHistoryRequest(t *testing.T, generation uint64) *runtime.StartOperationRequest {
	t.Helper()
	r := startOperationRequest()
	identity := &runtime.HistoryIdentity{Authority: "unit-control", EnvironmentID: "unit-env", RuntimeID: "unit-env-7", AssignmentGeneration: generation}
	if generation != 7 {
		identity.RuntimeID = "unit-env-21"
	}
	r.HistoryIdentity = identity
	var err error
	r.OperationID, err = historyOperationID(identity, r.RequestFingerprint)
	require.NoError(t, err)
	r.Start.Labels = map[string]string{"adx.environment_id": identity.EnvironmentID, "adx.runtime_id": identity.RuntimeID, "adx.generation": "7"}
	if generation != 7 {
		r.Start.Labels["adx.generation"] = "21"
	}
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	return r
}
func TestHistoryBoundaryCannotReopenClosedAssignment(t *testing.T) {
	b := testHistoryBoundary()
	p := &runtime.HistoryProtection{EnvironmentID: "env", AssignmentGeneration: 7, SpecificationSha256: strings.Repeat("a", 64), MinimumRuntimeRevision: 9, EnvironmentRevision: 10}
	next := testHistoryBoundary()
	next.CatalogRevision++
	next.Protected = []*runtime.HistoryProtection{p}
	require.Error(t, historyBoundaryAdvances(b, next))
	b.Protected = []*runtime.HistoryProtection{p}
	require.NoError(t, historyBoundaryAdvances(b, next))
	for _, rid := range []string{"env-7", "env-7-r8"} {
		closed, err := historyClosed(b, &runtime.HistoryIdentity{Authority: b.Authority, EnvironmentID: "env", RuntimeID: rid, AssignmentGeneration: 7})
		require.NoError(t, err)
		require.True(t, closed)
	}
	for _, rid := range []string{"env-7-r9", "env-7-r10"} {
		closed, err := historyClosed(b, &runtime.HistoryIdentity{Authority: b.Authority, EnvironmentID: "env", RuntimeID: rid, AssignmentGeneration: 7})
		require.NoError(t, err)
		require.False(t, closed)
	}
	_, err := historyClosed(b, &runtime.HistoryIdentity{Authority: b.Authority, EnvironmentID: "env", RuntimeID: "foreign-7-r9", AssignmentGeneration: 7})
	require.Error(t, err)
}
func TestHistoryOperationIDBindsCompleteAllocation(t *testing.T) {
	r := testHistoryRequest(t, 7)
	old := r.OperationID
	require.Equal(t, "90ce0456-de69-803e-9644-bf02848f96c6", old)
	r.HistoryIdentity.RuntimeID = "unit-env-7-r8"
	changed, err := historyOperationID(r.HistoryIdentity, r.RequestFingerprint)
	require.NoError(t, err)
	require.NotEqual(t, old, changed)
	r.HistoryIdentity.Authority = "other-control"
	changed, err = historyOperationID(r.HistoryIdentity, r.RequestFingerprint)
	require.NoError(t, err)
	require.NotEqual(t, old, changed)
}
func TestHistoryCompactsTerminalPairsAndRefusesOldAdmissionAcrossRestart(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := testHistoryRequest(t, 7)
	response, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	candidate := &runtime.HistoryCandidate{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint, DeadlineUnixMillis: r.DeadlineUnixMillis, Identity: r.HistoryIdentity, SandboxID: response.Result.ID, ResourceGeneration: response.Result.ResourceGeneration}
	gc := &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary(), Candidates: []*runtime.HistoryCandidate{candidate}}
	ack, err := s.CollectHistory(context.Background(), gc)
	require.NoError(t, err)
	require.EqualValues(t, 2, ack.RemovedFiles)
	require.Zero(t, ack.RemainingStartOperations)
	ack, err = s.CollectHistory(context.Background(), gc)
	require.NoError(t, err)
	require.Zero(t, ack.RemovedFiles)
	require.Equal(t, []string{r.OperationID}, ack.AcknowledgedOperationIds)
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	_, err = reopened.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	query := startOperationQuery(r)
	query.HistoryIdentity = r.HistoryIdentity
	query.SealMissing = true
	_, err = reopened.GetStartOperation(context.Background(), query)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	legacy := startOperationRequest()
	_, err = reopened.StartOperation(context.Background(), legacy)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	fresh := testHistoryRequest(t, 21)
	response, err = reopened.StartOperation(context.Background(), fresh)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
}
func TestHistoryUnknownOperationRetainedAndPartialTransactionResumes(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := testHistoryRequest(t, 7)
	response, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	s.startOperationMu.Lock()
	j, err := s.openStartOperationJournal()
	require.NoError(t, err)
	record, err := j.read(r.OperationID)
	require.NoError(t, err)
	record.State = runtime.StartOperationState_START_OPERATION_STATE_PENDING
	require.NoError(t, j.writeFile(r.OperationID+".json", record, false))
	s.startOperationMu.Unlock()
	c := &runtime.HistoryCandidate{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint, DeadlineUnixMillis: r.DeadlineUnixMillis, Identity: r.HistoryIdentity, SandboxID: response.Result.ID, ResourceGeneration: response.Result.ResourceGeneration}
	_, err = s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary(), Candidates: []*runtime.HistoryCandidate{c}})
	require.Error(t, err)
	s.startOperationMu.Lock()
	record.State = runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED
	require.NoError(t, j.writeFile(r.OperationID+".json", record, false))
	files, err := s.historyCandidate(context.Background(), j, testHistoryBoundary(), c)
	require.NoError(t, err)
	state := &historyState{Version: 1, Boundary: testHistoryBoundary(), Pending: &historyPending{OperationIDs: []string{r.OperationID}, Files: files}}
	require.NoError(t, j.saveHistory(state))
	require.NoError(t, j.rewriteHistoryIndex(nil))
	require.NoError(t, os.Remove(filepath.Join(s.config.RootDir, files[0].Path)))
	require.NoError(t, syncRetirementDirectory(filepath.Dir(filepath.Join(s.config.RootDir, files[0].Path))))
	s.startOperationMu.Unlock()
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	ack, err := reopened.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary(), Candidates: []*runtime.HistoryCandidate{c}})
	require.NoError(t, err)
	require.Zero(t, ack.RemainingStartOperations)
}

func TestHistoryMissingFenceAndChangedFileFailClosed(t *testing.T) {
	t.Run("missing-fence", func(t *testing.T) {
		s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
		_, err := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(s.config.RootDir, "scheduler-start-operations.history")))
		_, err = s.StartOperation(context.Background(), testHistoryRequest(t, 21))
		require.Equal(t, codes.Unavailable, status.Code(err))
		s.closeStartOperationJournal()
		reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
		reopened.config.RootDir = s.config.RootDir
		_, err = reopened.StartOperation(context.Background(), testHistoryRequest(t, 21))
		require.Equal(t, codes.Unavailable, status.Code(err))
	})
	t.Run("changed-file", func(t *testing.T) {
		s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
		r := testHistoryRequest(t, 7)
		response, err := s.StartOperation(context.Background(), r)
		require.NoError(t, err)
		s.startOperationMu.Lock()
		defer s.startOperationMu.Unlock()
		j, err := s.openStartOperationJournal()
		require.NoError(t, err)
		c := &runtime.HistoryCandidate{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint, DeadlineUnixMillis: r.DeadlineUnixMillis, Identity: r.HistoryIdentity, SandboxID: response.Result.ID, ResourceGeneration: response.Result.ResourceGeneration}
		files, err := s.historyCandidate(context.Background(), j, testHistoryBoundary(), c)
		require.NoError(t, err)
		state := &historyState{Version: 1, Boundary: testHistoryBoundary(), Pending: &historyPending{OperationIDs: []string{r.OperationID}, Files: files}}
		require.NoError(t, j.saveHistory(state))
		require.NoError(t, j.rewriteHistoryIndex(nil))
		path := filepath.Join(s.config.RootDir, files[0].Path)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, os.Rename(path, path+".original"))
		require.NoError(t, os.WriteFile(path, data, 0600))
		_, _, err = s.finishHistory(j, state)
		require.Error(t, err)
		preserved, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, data, preserved)
	})
}
func TestHistoryExactRetiredIncarnationPreservesReplacement(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	r := testHistoryRequest(t, 7)
	record := admitPendingStartOperation(t, s, r)
	storeSandboxForDelete(t, s, record.SandboxID)
	labels := map[string]string{resourceGenerationLabel: record.Generation, "adx.environment_id": r.HistoryIdentity.EnvironmentID, "adx.runtime_id": r.HistoryIdentity.RuntimeID, "adx.generation": "7", startOperationLabel: r.OperationID}
	require.NoError(t, s.sandboxManager.UpdateLabels(record.SandboxID, labels))
	stageFilesystemOwner(t, s, record.SandboxID, record.Generation)
	stageEmptyDeviceOwner(t, s, record.SandboxID, record.Generation)
	receipt, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: record.SandboxID, ExpectedGeneration: record.Generation})
	require.NoError(t, err)
	require.Equal(t, record.Generation, receipt.RetiredGeneration)
	require.Equal(t, 1, handler.calls)
	storeSandboxForDelete(t, s, record.SandboxID)
	require.NoError(t, s.sandboxManager.UpdateLabels(record.SandboxID, map[string]string{resourceGenerationLabel: "replacement-generation"}))
	stageFilesystemOwner(t, s, record.SandboxID, "replacement-generation")
	stageEmptyDeviceOwner(t, s, record.SandboxID, "replacement-generation")
	c := &runtime.HistoryCandidate{OperationID: record.OperationID, RequestFingerprint: record.RequestFingerprint, DeadlineUnixMillis: record.DeadlineUnixMillis, Identity: r.HistoryIdentity, SandboxID: record.SandboxID, ResourceGeneration: record.Generation}
	ack, err := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary(), Candidates: []*runtime.HistoryCandidate{c}})
	require.NoError(t, err)
	require.GreaterOrEqual(t, ack.RemovedFiles, uint64(4))
	require.Zero(t, ack.RemainingStartOperations)
	current, err := s.sandboxManager.Get(record.SandboxID)
	require.NoError(t, err)
	require.Equal(t, "replacement-generation", current.Metadata.Labels[resourceGenerationLabel])
	require.Equal(t, 1, handler.calls, "history collection must never invoke physical deletion")
	old, err := s.readRetirement(record.SandboxID, record.Generation)
	require.NoError(t, err)
	require.Nil(t, old, "reclaimed receipt is not new retirement evidence")
}

func TestHistoryOversizedManifestCannotReplaceDurableBoundary(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	_, err := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: testHistoryBoundary()})
	require.NoError(t, err)
	path := filepath.Join(s.config.RootDir, "scheduler-start-operations.history")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	s.startOperationMu.Lock()
	j, err := s.openStartOperationJournal()
	require.NoError(t, err)
	next := testHistoryBoundary()
	next.AssignmentGeneration = 21
	next.CatalogRevision++
	err = j.saveHistory(&historyState{Version: 1, Boundary: next, Pending: &historyPending{Files: make([]historyFile, historyManifestFileLimit+1)}})
	require.Error(t, err)
	s.startOperationMu.Unlock()
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	response, err := s.StartOperation(context.Background(), testHistoryRequest(t, 21))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
}
