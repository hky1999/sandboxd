package server

import (
	"context"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"testing"
)

func runtimeFenceQuery(t *testing.T, r *runtime.StartOperationRequest) *runtime.GetStartOperationRequest {
	q := startOperationQuery(r)
	q.SealMissing = true
	q.SealRuntime = true
	q.HistoryIdentity = r.HistoryIdentity
	return q
}
func TestRuntimeFenceBlocksEveryFingerprintAcrossReopen(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := testHistoryRequest(t, 7)
	_, installErr := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: &runtime.HistoryBoundary{Authority: "unit-control", CoordinatorEpoch: 3, AssignmentGeneration: 0, CatalogRevision: 1}})
	require.NoError(t, installErr)
	originalQuery := runtimeFenceQuery(t, r)
	response, err := s.GetStartOperation(context.Background(), originalQuery)
	require.NoError(t, err)
	require.True(t, response.RuntimeFenced)
	_, legacyErr := s.Start(context.Background(), r.Start)
	require.Equal(t, codes.FailedPrecondition, status.Code(legacyErr))
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	r.RequestFingerprint = strings.Repeat("b", 64)
	r.OperationID, err = historyOperationID(r.HistoryIdentity, r.RequestFingerprint)
	require.NoError(t, err)
	_, err = reopened.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	response, err = reopened.GetStartOperation(context.Background(), originalQuery)
	require.NoError(t, err)
	require.True(t, response.RuntimeFenced)
}
func TestRuntimeFenceRetainsAnyPreviouslyAdmittedAlternative(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := testHistoryRequest(t, 7)
	_, installErr := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: &runtime.HistoryBoundary{Authority: "unit-control", CoordinatorEpoch: 3, AssignmentGeneration: 0, CatalogRevision: 1}})
	require.NoError(t, installErr)
	_, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	r.RequestFingerprint = strings.Repeat("c", 64)
	r.OperationID, err = historyOperationID(r.HistoryIdentity, r.RequestFingerprint)
	require.NoError(t, err)
	_, err = s.GetStartOperation(context.Background(), runtimeFenceQuery(t, r))
	require.Error(t, err)
}
func TestRuntimeFenceExplicitlyDisabledProfilesDoNotBlockEmptyInventory(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	s.config.PluginConfig.RuntimeConfig.RuntimeBinary["kata"] = ""
	s.config.PluginConfig.RuntimeConfig.RuntimeBinary["firecracker"] = ""
	_, err := s.CollectHistory(context.Background(), &runtime.CollectHistoryRequest{Boundary: &runtime.HistoryBoundary{Authority: "unit-control", CoordinatorEpoch: 3, CatalogRevision: 1}})
	require.NoError(t, err)
	r := testHistoryRequest(t, 7)
	response, err := s.GetStartOperation(context.Background(), runtimeFenceQuery(t, r))
	require.NoError(t, err)
	require.True(t, response.RuntimeFenced)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
}
func TestRuntimeFenceRequiresCompleteIdentity(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	q := runtimeFenceQuery(t, r)
	_, err := s.GetStartOperation(context.Background(), q)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
