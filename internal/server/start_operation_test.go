// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	states    []*svc.State
	err       error
	afterList func()
}

func (h *startOperationInventoryHandler) List(context.Context) ([]*svc.State, error) {
	if h.afterList != nil {
		h.afterList()
	}
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

func admitPendingStartOperation(t *testing.T, s *sandboxService, r *runtime.StartOperationRequest) *startOperationRecord {
	t.Helper()
	record := &startOperationRecord{Version: 1, OperationID: r.OperationID,
		RequestFingerprint: r.RequestFingerprint, PayloadFingerprint: strings.Repeat("c", 64),
		DeadlineUnixMillis: r.DeadlineUnixMillis, SandboxID: "sbox-" + r.OperationID,
		Generation: uuid.NewString(), State: runtime.StartOperationState_START_OPERATION_STATE_PENDING}
	s.startOperationMu.Lock()
	defer s.startOperationMu.Unlock()
	j, err := s.openStartOperationJournal()
	require.NoError(t, err)
	require.NoError(t, j.admit(record))
	return record
}

func TestStartOperationRecoversCommittedResultAfterReopen(t *testing.T) {
	handler := &startOperationInventoryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	r := startOperationRequest()
	record := admitPendingStartOperation(t, s, r)
	storeSandboxForDelete(t, s, record.SandboxID)
	ports := []string{"8080:30000"}
	require.NoError(t, s.sandboxManager.StoreMetadata(record.SandboxID, &runtime.SandboxMetadata{
		ID: record.SandboxID, RuntimeHandler: "runsc", Ports: ports,
		Labels:        map[string]string{startOperationLabel: record.OperationID, resourceGenerationLabel: record.Generation},
		ResourceFacts: map[string]string{config.ResourceNameInterface: (&networkmanager.NetResource{Ip: net.ParseIP("10.0.0.23")}).ToString()},
	}))
	handler.states = []*svc.State{{ID: record.SandboxID, Status: svc.SandboxStatusRunning}}
	s.closeStartOperationJournal()
	reopened := newTestService(t, map[string]svc.Handler{"runsc": handler})
	reopened.config.RootDir = s.config.RootDir
	var err error
	reopened.sandboxManager, err = sandbox.NewManager(s.config.RootDir, reopened.serviceHandler, make(chan bool, 10), nil, 1000)
	require.NoError(t, err)
	response, err := reopened.GetStartOperation(context.Background(), startOperationQuery(r))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_STARTED, response.State)
	require.True(t, proto.Equal(&runtime.StartResponse{ID: record.SandboxID, ResourceGeneration: record.Generation, SandboxIp: "10.0.0.23", Ports: ports}, response.Result))
	// The recovered outcome itself must be durable. A later query does not
	// rely on the old in-memory sandbox status or a fresh runtime observation.
	reopened.closeStartOperationJournal()
	replay := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	replay.config.RootDir = s.config.RootDir
	recovered, err := replay.GetStartOperation(context.Background(), startOperationQuery(r))
	require.NoError(t, err)
	require.True(t, proto.Equal(response, recovered))
}

func TestStartOperationRecoveryRequiresOriginalPhysicalFacts(t *testing.T) {
	for _, condition := range []string{"generation", "operation", "missing-runtime", "stopped-runtime", "duplicate-runtime", "runtime-error", "missing-network", "malformed-network", "recovery", "changed-identity", "changed-ports", "changed-network"} {
		t.Run(condition, func(t *testing.T) {
			handler := &startOperationInventoryHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			r := startOperationRequest()
			record := admitPendingStartOperation(t, s, r)
			storeSandboxForDelete(t, s, record.SandboxID)
			metadata := &runtime.SandboxMetadata{ID: record.SandboxID, RuntimeHandler: "runsc",
				Labels:        map[string]string{startOperationLabel: record.OperationID, resourceGenerationLabel: record.Generation},
				ResourceFacts: map[string]string{config.ResourceNameInterface: (&networkmanager.NetResource{Ip: net.ParseIP("10.0.0.23")}).ToString()}}
			handler.states = []*svc.State{{ID: record.SandboxID, Status: svc.SandboxStatusRunning}}
			expectError := false
			switch condition {
			case "generation":
				metadata.Labels[resourceGenerationLabel] = uuid.NewString()
			case "operation":
				metadata.Labels[startOperationLabel] = uuid.NewString()
			case "missing-runtime":
				handler.states = nil
			case "stopped-runtime":
				handler.states[0].Status = svc.SandboxStatusExited
			case "duplicate-runtime":
				handler.states = append(handler.states, &svc.State{ID: record.SandboxID, Status: svc.SandboxStatusRunning})
			case "runtime-error":
				handler.err = errors.New("inventory unavailable")
				expectError = true
			case "missing-network":
				metadata.ResourceFacts = nil
			case "malformed-network":
				metadata.ResourceFacts[config.ResourceNameInterface] = "broken"
				expectError = true
			case "recovery":
				s.recoveryReady.Store(false)
			case "changed-identity", "changed-ports", "changed-network":
				handler.afterList = func() {
					replacement := proto.Clone(metadata).(*runtime.SandboxMetadata)
					switch condition {
					case "changed-identity":
						replacement.Labels[resourceGenerationLabel] = uuid.NewString()
					case "changed-ports":
						replacement.Ports = []string{"8080:30001"}
					case "changed-network":
						replacement.ResourceFacts[config.ResourceNameInterface] = (&networkmanager.NetResource{Ip: net.ParseIP("10.0.0.24")}).ToString()
					}
					require.NoError(t, s.sandboxManager.StoreMetadata(record.SandboxID, replacement))
				}
				expectError = true
			}
			require.NoError(t, s.sandboxManager.StoreMetadata(record.SandboxID, metadata))
			response, err := s.GetStartOperation(context.Background(), startOperationQuery(r))
			if expectError {
				require.Equal(t, codes.Unavailable, status.Code(err))
			} else {
				require.NoError(t, err)
				require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
			}
			s.startOperationMu.Lock()
			defer s.startOperationMu.Unlock()
			durable, err := s.startJournal.read(r.OperationID)
			require.NoError(t, err)
			require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, durable.State)
			require.Nil(t, durable.Result)
		})
	}
}
