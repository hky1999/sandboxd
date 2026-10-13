// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

type parkCgroupRuntime struct {
	*closeRetirementRuntime
	service *sandboxService
}

func (r *parkCgroupRuntime) DeleteRuntimeAfterCgroupClosed(ctx context.Context, id, generation string, proof svc.CgroupRuntimeProof) error {
	if err := r.closeRetirementRuntime.DeleteRuntimeAfterCgroupClosed(ctx, id, generation, proof); err != nil {
		return err
	}
	return r.service.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false)
}

func TestForcedParkRetirementUsesOriginalCgroupAndKeepsResources(t *testing.T) {
	s, metadata, _, original, groups := newRuntimeCloseFixture(t)
	require.NoError(t, s.sandboxManager.StoreMetadata(metadata.ID, metadata))
	groups.provideFreshProof(t)
	handler := &parkCgroupRuntime{closeRetirementRuntime: original, service: s}
	require.NoError(t, s.forceRetireParkedSource(context.Background(), metadata.ID, handler))
	require.Zero(t, original.legacyCalls)
	require.Zero(t, original.nativeCalls)
	require.Equal(t, 1, groups.closeCalls)
	require.Equal(t, 1, original.proofCalls)
	require.Zero(t, groups.releases, "park exit alone does not recycle other resources")
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotNil(t, progress.CgroupClose)
	require.Equal(t, []string{"runtime"}, progress.Steps)
	receipt, err := s.readRetirement(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.Nil(t, receipt, "runtime exit is not a completed full retirement receipt")
}

func TestForcedParkRetirementRefusesUnverifiedOriginalSource(t *testing.T) {
	s, metadata, _, original, groups := newRuntimeCloseFixture(t)
	require.NoError(t, s.sandboxManager.StoreMetadata(metadata.ID, metadata))
	original.sourceError = errors.New("original native source differs")
	handler := &parkCgroupRuntime{closeRetirementRuntime: original, service: s}
	require.ErrorContains(t, s.forceRetireParkedSource(context.Background(), metadata.ID, handler), "original native source differs")
	require.Zero(t, original.legacyCalls)
	require.Zero(t, original.proofCalls)
	require.Zero(t, groups.closeCalls)
	require.True(t, original.present)
}

func TestForcedParkRetirementKeepsUnknownNativeResult(t *testing.T) {
	s, metadata, _, original, groups := newRuntimeCloseFixture(t)
	require.NoError(t, s.sandboxManager.StoreMetadata(metadata.ID, metadata))
	groups.provideFreshProof(t)
	original.nativeError = errors.New("original native cleanup result unknown")
	handler := &parkCgroupRuntime{closeRetirementRuntime: original, service: s}
	require.ErrorContains(t, s.forceRetireParkedSource(context.Background(), metadata.ID, handler), "result unknown")
	require.Zero(t, original.legacyCalls)
	require.Zero(t, groups.releases)
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.Empty(t, progress.Steps)
	require.NotNil(t, progress.CgroupClose)
}

func TestForcedParkRetirementIntentFailurePreventsEffects(t *testing.T) {
	s, metadata, _, original, groups := newRuntimeCloseFixture(t)
	require.NoError(t, s.sandboxManager.StoreMetadata(metadata.ID, metadata))
	path := filepath.Join(s.config.RootDir, "scheduler-retirement-progress")
	require.NoError(t, os.WriteFile(path, []byte("original blocking file"), 0600))
	handler := &parkCgroupRuntime{closeRetirementRuntime: original, service: s}
	require.Error(t, s.forceRetireParkedSource(context.Background(), metadata.ID, handler))
	require.Zero(t, original.legacyCalls)
	require.Zero(t, groups.closeCalls)
	require.True(t, original.present)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original blocking file", string(data))
}
