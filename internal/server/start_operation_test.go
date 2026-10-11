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

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func startOperationRequest() *runtime.StartOperationRequest {
	return &runtime.StartOperationRequest{
		Start: &runtime.StartRequest{Runtime: "runsc", Command: []string{"/bin/true"},
			Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
				Source: &runtime.RootfsConfig_Path{Path: "/unit-test-start-rootfs"}}},
		OperationID: uuid.NewString(), RequestFingerprint: strings.Repeat("a", 64),
		DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()),
	}
}

func startOperationQuery(r *runtime.StartOperationRequest) *runtime.GetStartOperationRequest {
	return &runtime.GetStartOperationRequest{OperationID: r.OperationID,
		RequestFingerprint: r.RequestFingerprint, DeadlineUnixMillis: r.DeadlineUnixMillis}
}

func TestStartOperationUnknownIsNotNonCreation(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(r))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, response.State)
	require.Equal(t, r.OperationID, response.OperationID)
	require.Nil(t, response.Result)
}

func TestStartOperationMissingSealBlocksLateCreationAcrossReopen(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	query := startOperationQuery(r)
	query.SealMissing = true
	response, err := s.GetStartOperation(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, response.State)
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	query = startOperationQuery(r)
	query.SealMissing = true
	response, err = s.GetStartOperation(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	_, err = s.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	response, err = reopened.GetStartOperation(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	_, err = reopened.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

type startOperationInventoryHandler struct {
	*svc.FakeRuntimeHandler
	states []*svc.State
	err    error
}

func (h *startOperationInventoryHandler) List(context.Context) ([]*svc.State, error) {
	return h.states, h.err
}

func TestStartOperationMissingSealRequiresKnownPhysicalInventory(t *testing.T) {
	for _, mode := range []string{"runtime", "metadata", "unavailable", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			r := startOperationRequest()
			r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
			handler := &startOperationInventoryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			switch mode {
			case "runtime":
				handler.states = []*svc.State{{ID: "sbox-" + r.OperationID}}
			case "metadata":
				require.NoError(t, os.MkdirAll(filepath.Join(s.config.RootDir, "containers", "sbox-"+r.OperationID), 0700))
			case "unavailable":
				s.serviceHandler.Remove("runsc")
			case "recovery":
				s.recoveryReady.Store(false)
			}
			query := startOperationQuery(r)
			query.SealMissing = true
			_, err := s.GetStartOperation(context.Background(), query)
			require.Equal(t, codes.Unavailable, status.Code(err))
			query.SealMissing = false
			response, err := s.GetStartOperation(context.Background(), query)
			require.NoError(t, err)
			require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN, response.State)
		})
	}
}

func TestStartOperationSealedPendingPublicationRecoversAfterReopen(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	query := startOperationQuery(r)
	query.SealMissing = true
	_, err := s.GetStartOperation(context.Background(), query)
	require.NoError(t, err)
	func() {
		s.startOperationMu.Lock()
		defer s.startOperationMu.Unlock()
		record, err := s.startJournal.read(r.OperationID)
		require.NoError(t, err)
		record.State = runtime.StartOperationState_START_OPERATION_STATE_PENDING
		require.NoError(t, s.startJournal.writeFile(r.OperationID+".json", record, false))
	}()
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	response, err := reopened.GetStartOperation(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	_, err = reopened.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestStartOperationExpiredRequestIsDurablySealedAndPayloadBound(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	response, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
	replay, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, response, replay)
	r.Start.Envs = map[string]string{"TOKEN": "changed-payload-must-not-be-recorded"}
	_, err = s.StartOperation(context.Background(), r)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	files, err := os.ReadDir(filepath.Join(s.config.RootDir, "scheduler-start-operations"))
	require.NoError(t, err)
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(s.config.RootDir, "scheduler-start-operations", file.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(data), "changed-payload-must-not-be-recorded")
	}
}

func TestStartOperationMissingOutcomeAndCorruptionFailClosed(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	_, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	path := filepath.Join(s.config.RootDir, "scheduler-start-operations", r.OperationID+".json")
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err = s.GetStartOperation(context.Background(), startOperationQuery(r))
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.NoError(t, os.Remove(path))
	_, err = s.StartOperation(context.Background(), r)
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestStartOperationMissingBothRecordsCannotDispatchAgainAfterReopen(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	_, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	dir := filepath.Join(s.config.RootDir, "scheduler-start-operations")
	require.NoError(t, os.Remove(filepath.Join(dir, r.OperationID+".json")))
	require.NoError(t, os.Remove(filepath.Join(dir, r.OperationID+".intent.json")))
	_, err = s.StartOperation(context.Background(), r)
	require.Equal(t, codes.Unavailable, status.Code(err))
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	_, err = reopened.StartOperation(context.Background(), r)
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = reopened.GetStartOperation(context.Background(), startOperationQuery(r))
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestStartOperationMissingIndexOrDirectoryFailsClosed(t *testing.T) {
	for _, missing := range []string{"index", "directory"} {
		t.Run(missing, func(t *testing.T) {
			s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			r := startOperationRequest()
			r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
			_, err := s.StartOperation(context.Background(), r)
			require.NoError(t, err)
			dir := filepath.Join(s.config.RootDir, "scheduler-start-operations")
			if missing == "index" {
				require.NoError(t, os.Remove(dir+".index"))
			} else {
				require.NoError(t, os.RemoveAll(dir))
			}
			_, err = s.StartOperation(context.Background(), r)
			require.Equal(t, codes.Unavailable, status.Code(err))
			s.closeStartOperationJournal()
			reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			reopened.config.RootDir = s.config.RootDir
			_, err = reopened.StartOperation(context.Background(), r)
			require.Equal(t, codes.Unavailable, status.Code(err))
		})
	}
}

func TestStartOperationPendingRequiresExactRetirementReceipt(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	record := &startOperationRecord{Version: 1, OperationID: r.OperationID,
		RequestFingerprint: r.RequestFingerprint, PayloadFingerprint: strings.Repeat("c", 64),
		DeadlineUnixMillis: r.DeadlineUnixMillis, SandboxID: "sbox-" + r.OperationID,
		Generation: uuid.NewString(), State: runtime.StartOperationState_START_OPERATION_STATE_PENDING}
	func() {
		s.startOperationMu.Lock()
		defer s.startOperationMu.Unlock()
		j, err := s.openStartOperationJournal()
		require.NoError(t, err)
		require.NoError(t, j.admit(record))
	}()
	for _, receipt := range []struct {
		generation string
		complete   bool
	}{
		{record.Generation, false}, {uuid.NewString(), true},
	} {
		require.NoError(t, s.writeRetirement(record.SandboxID, receipt.generation, receipt.complete))
		response, err := s.GetStartOperation(context.Background(), startOperationQuery(r))
		require.NoError(t, err)
		require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	}
	require.NoError(t, s.writeRetirement(record.SandboxID, record.Generation, true))
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(r))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
	require.Equal(t, record.Generation, response.Result.ResourceGeneration)
}

func TestStartOperationRejectsSecondWriterAndSurvivesReopen(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	first, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	reopened := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	reopened.config.RootDir = s.config.RootDir
	_, err = reopened.GetStartOperation(context.Background(), startOperationQuery(r))
	require.Equal(t, codes.Unavailable, status.Code(err))
	s.closeStartOperationJournal()
	second, err := reopened.GetStartOperation(context.Background(), startOperationQuery(r))
	require.NoError(t, err)
	require.Equal(t, first, second)
	_, err = reopened.StartOperation(context.Background(), r)
	require.NoError(t, err)
}

func TestStartOperationQueryCannotChangeOriginalFingerprintOrDeadline(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	r := startOperationRequest()
	r.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	_, err := s.StartOperation(context.Background(), r)
	require.NoError(t, err)
	query := startOperationQuery(r)
	query.RequestFingerprint = strings.Repeat("b", 64)
	_, err = s.GetStartOperation(context.Background(), query)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	query = startOperationQuery(r)
	query.DeadlineUnixMillis++
	_, err = s.GetStartOperation(context.Background(), query)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
