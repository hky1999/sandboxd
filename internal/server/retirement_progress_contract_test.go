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
)

// Private files and a controlled runtime only; no physical sandbox, kernel
// mount, cgroup, daemon fault or external service is involved.
type retirementCompletionBlocker struct {
	*svc.FakeRuntimeHandler
	service *sandboxService
	calls   int
	blocked bool
}

func (h *retirementCompletionBlocker) Delete(_ context.Context, id string) error {
	h.calls++
	if !h.blocked {
		h.blocked = true
		_, path := h.service.retirementPath(id, "generation")
		if err := os.Rename(path, path+".original-pending"); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	return nil
}

func TestRetirementProgressCompletionFailureRetriesWithoutOriginalMetadata(t *testing.T) {
	handler := &retirementCompletionBlocker{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	handler.service = s
	t.Cleanup(s.closeRetirementProgressJournal)
	const id = "completion-gap"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "generation"}))
	stageFilesystemOwner(t, s, id, "generation")
	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err, "completion publication is deliberately obstructed")
	require.NoDirExists(t, filepath.Join(s.config.RootDir, "containers", id))
	_, path := s.retirementPath(id, "generation")
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Rename(path+".original-pending", path))
	// The original identity was removed. A durable cleanup history must allow
	// receipt publication without borrowing a new execution or repeating Delete.
	response, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err, "matching fully retired operation must remain recoverable")
	require.Equal(t, "generation", response.RetiredGeneration)
	require.Equal(t, 1, handler.calls, "receipt retry must not repeat a physical effect")
}
