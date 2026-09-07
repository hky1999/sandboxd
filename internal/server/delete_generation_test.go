// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeleteIfGenerationRejectsStaleAndReturnsPhysicalReceipt(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "generation-delete"
	store := func(generation string) {
		storeSandboxForDelete(t, s, id)
		require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
			ID: id, RuntimeHandler: "runsc", Labels: map[string]string{resourceGenerationLabel: generation},
		}))
	}
	store("physical-one")
	for _, request := range []*runtime.DeleteIfGenerationRequest{nil, {ID: id}, {ExpectedGeneration: "physical-one"}} {
		_, err := s.DeleteIfGeneration(context.Background(), request)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "wrong"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err)
	require.Equal(t, "physical-one", response.RetiredGeneration)
	require.Equal(t, 1, handler.calls)
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err) // replay the durable receipt
	store("physical-two")
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err) // old-generation receipt cannot delete the replacement
	require.Equal(t, 1, handler.calls)
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "physical-two", current.Metadata.Labels[resourceGenerationLabel])
}

func TestRetirementReceiptSurvivesServiceReopen(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "receipt-reopen"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "generation"}))
	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	reopenedHandler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	reopened := newTestService(t, map[string]svc.Handler{"runsc": reopenedHandler})
	// A fresh service has no in-memory sandbox/receipt state, but uses the journal directory.
	reopened.config.RootDir = s.config.RootDir
	receipt, err := reopened.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "generation", receipt.RetiredGeneration)
	require.Zero(t, reopenedHandler.calls)
}

func TestPendingOrCorruptRetirementCannotProveDeletion(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	request := &runtime.DeleteIfGenerationRequest{ID: "missing", ExpectedGeneration: "generation"}
	require.NoError(t, s.writeRetirement(request.ID, request.ExpectedGeneration, false))
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Equal(t, codes.NotFound, status.Code(err))
	_, path := s.retirementPath(request.ID, request.ExpectedGeneration)
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.Zero(t, handler.calls)
}

func TestRetirementJournalFailurePreventsPhysicalDelete(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeSandboxForDelete(t, s, "blocked")
	require.NoError(t, s.sandboxManager.UpdateLabels("blocked", map[string]string{resourceGenerationLabel: "generation"}))
	require.NoError(t, os.WriteFile(filepath.Join(s.config.RootDir, "scheduler-retirements"), []byte("not a directory"), 0600))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: "blocked", ExpectedGeneration: "generation"})
	require.Error(t, err)
	require.Zero(t, handler.calls)
	_, err = s.sandboxManager.Get("blocked")
	require.NoError(t, err)
}

func TestPendingRetirementRetriesOnlyMatchingLiveGeneration(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "pending-live"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "new"}))
	require.NoError(t, s.writeRetirement(id, "old", false))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "old"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	require.NoError(t, s.writeRetirement(id, "new", false))
	receipt, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "new"})
	require.NoError(t, err)
	require.Equal(t, "new", receipt.RetiredGeneration)
	require.Equal(t, 1, handler.calls)
	saved, err := s.readRetirement(id, "new")
	require.NoError(t, err)
	require.True(t, saved.Complete)
}
