// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

type nativeRetirementHandler struct {
	failedCreationHandler
	nativeCalls, legacyCalls int
	id, generation           string
	nativeResult             error
}

func (h *nativeRetirementHandler) VerifyRuntimeGeneration(context.Context, string, string) error {
	return nil
}
func (h *nativeRetirementHandler) DeleteRuntimeIfGeneration(_ context.Context, id, generation string) error {
	h.nativeCalls++
	h.id, h.generation = id, generation
	return h.nativeResult
}
func (h *nativeRetirementHandler) Delete(context.Context, string) error {
	h.legacyCalls++
	return errors.New("unexpected legacy delete")
}
func (h *nativeRetirementHandler) List(context.Context) ([]*svc.State, error) {
	return []*svc.State{{ID: h.id, Status: "running"}}, nil
}

func TestFailedCreationUsesNativeConditionalDeleteAndKeepsUnknownBudget(t *testing.T) {
	handler := &nativeRetirementHandler{failedCreationHandler: failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}, nativeResult: errors.New("native result unknown")}
	s, metadata, request := failedCreationRetirementFixture(t, handler)
	handler.id = metadata.ID
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.ErrorContains(t, err, "native result unknown")
	require.Equal(t, 1, handler.nativeCalls)
	require.Zero(t, handler.legacyCalls)
	require.Equal(t, metadata.ID, handler.id)
	require.Equal(t, metadata.Labels[resourceGenerationLabel], handler.generation)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	require.Error(t, s.xpuMgr.(generationDeviceLeaseManager).ConfirmReleasedForGeneration(metadata.ID, handler.generation))
}

type verifierWithoutNativeDelete struct {
	svc.Handler
	legacyCalls int
}

func (*verifierWithoutNativeDelete) VerifyRuntimeGeneration(context.Context, string, string) error {
	return nil
}
func (h *verifierWithoutNativeDelete) Delete(context.Context, string) error {
	h.legacyCalls++
	return nil
}

func TestReadonlyRuntimeVerifierCannotAuthorizeUnconditionalDeletion(t *testing.T) {
	handler := &verifierWithoutNativeDelete{Handler: svc.NewFakeRuntimeHandler()}
	require.ErrorContains(t, deleteOriginalRuntime(context.Background(), handler, "original", "generation-original"), "cannot authorize")
	require.Zero(t, handler.legacyCalls)
	require.NoError(t, deleteOriginalRuntime(context.Background(), handler, "legacy", ""))
	require.Equal(t, 1, handler.legacyCalls)
}
