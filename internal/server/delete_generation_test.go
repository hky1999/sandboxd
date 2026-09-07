// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
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
	require.Equal(t, codes.NotFound, status.Code(err))
	store("physical-two")
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, 1, handler.calls)
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "physical-two", current.Metadata.Labels[resourceGenerationLabel])
}
