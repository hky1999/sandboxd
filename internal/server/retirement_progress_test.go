// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

func retirementProgressFixture(t *testing.T) (*sandboxService, *retirementProgress, *recordingDeleteHandler) {
	t.Helper()
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	t.Cleanup(s.closeRetirementProgressJournal)
	const id = "progress-original"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "generation"}))
	stageFilesystemOwner(t, s, id, "generation")
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	resources, err := s.physicalResources(current.Metadata)
	require.NoError(t, err)
	progress, err := s.beginRetirementProgress(current.Metadata, resources)
	require.NoError(t, err)
	return s, progress, handler
}

func TestRetirementProgressOriginalSnapshotAndStepOrderCannotChange(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	require.Error(t, s.completeRetirementProgressStep(p, "filesystem"))
	require.NoError(t, s.completeRetirementProgressStep(p, "runtime"))
	p.Steps = nil
	require.Error(t, s.writeRetirementProgress(p), "a confirmed step cannot regress")
	stored, err := s.readRetirementProgress(p.SandboxID, p.Generation)
	require.NoError(t, err)
	stored.Resources.Resources["cgroup"] = "/neighbor/lease"
	require.Error(t, s.writeRetirementProgress(stored))
}

func TestRetirementProgressPendingResourcesCannotResolveMissingMetadata(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	require.NoError(t, os.RemoveAll(filepath.Join(s.config.RootDir, "containers", p.SandboxID)))
	completed, err := s.resumeRetirementCompletion(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.False(t, completed)
	receipt, err := s.readRetirement(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.Nil(t, receipt)
}

func TestRetirementProgressRootRemovalIntentRequiresEveryPriorStep(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	p.RootPending = true
	require.Error(t, s.writeRetirementProgress(p))
	require.Error(t, s.completeRetirementProgressStep(p, "root"))
}

func TestRetirementProgressDirectoryAndLockReplacementFailClosed(t *testing.T) {
	for _, kind := range []string{"directory", "lock"} {
		t.Run(kind, func(t *testing.T) {
			s, p, _ := retirementProgressFixture(t)
			directory, _ := s.retirementProgressPath(p.SandboxID, p.Generation)
			path := directory
			if kind == "lock" {
				path = filepath.Join(directory, ".lock")
			}
			require.NoError(t, os.Rename(path, path+"-original"))
			if kind == "directory" {
				require.NoError(t, os.Mkdir(path, 0700))
			} else {
				require.NoError(t, os.WriteFile(path, nil, 0600))
			}
			_, err := s.readRetirementProgress(p.SandboxID, p.Generation)
			require.Error(t, err)
			require.Error(t, s.writeRetirementProgress(p))
		})
	}
}

func TestRetirementProgressSecondServiceCannotPublishUntilOriginalOwnerCloses(t *testing.T) {
	s, p, _ := retirementProgressFixture(t)
	second := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	second.config.RootDir = s.config.RootDir
	t.Cleanup(second.closeRetirementProgressJournal)
	_, err := second.readRetirementProgress(p.SandboxID, p.Generation)
	require.Error(t, err)
	s.closeRetirementProgressJournal()
	stored, err := second.readRetirementProgress(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.Equal(t, p.Original, stored.Original)
}

func TestRetirementProgressRejectsCorruptDuplicateAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"integrity", "duplicate", "trailing", "symlink", "hardlink", "permissions", "fifo", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			s, p, _ := retirementProgressFixture(t)
			_, path := s.retirementProgressPath(p.SandboxID, p.Generation)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			switch kind {
			case "integrity":
				var record retirementProgress
				require.NoError(t, json.Unmarshal(data, &record))
				record.RootPending = true
				data, err = json.Marshal(record)
				require.NoError(t, err)
			case "duplicate":
				data = []byte(strings.Replace(string(data), "\"version\":1", "\"version\":1,\"version\":1", 1))
			case "trailing":
				data = append(data, []byte("{}")...)
			case "symlink":
				require.NoError(t, os.Rename(path, path+"-original"))
				require.NoError(t, os.Symlink(path+"-original", path))
			case "hardlink":
				require.NoError(t, os.Link(path, path+"-alias"))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, syscall.Mkfifo(path, 0600))
			case "oversized":
				data = make([]byte, retirementProgressBytes+1)
			}
			if kind == "integrity" || kind == "duplicate" || kind == "trailing" || kind == "oversized" {
				require.NoError(t, os.WriteFile(path, data, 0600))
			}
			_, err = s.readRetirementProgress(p.SandboxID, p.Generation)
			require.Error(t, err)
		})
	}
}

func TestRetirementProgressCompletedResourcesPreserveReplacementRoot(t *testing.T) {
	s, p, handler := retirementProgressFixture(t)
	for _, step := range retirementProgressSteps[:len(retirementProgressSteps)-1] {
		require.NoError(t, s.completeRetirementProgressStep(p, step))
	}
	p.RootPending = true
	require.NoError(t, s.writeRetirementProgress(p))
	root := filepath.Join(s.config.RootDir, "containers", p.SandboxID)
	require.NoError(t, os.Rename(root, root+"-original"))
	require.NoError(t, os.Mkdir(root, 0700))
	marker := filepath.Join(root, "neighbor")
	require.NoError(t, os.WriteFile(marker, []byte("neighbor"), 0600))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: p.SandboxID, ExpectedGeneration: p.Generation})
	require.Error(t, err)
	require.FileExists(t, marker)
	require.Zero(t, handler.calls)
}

type remainingRuntimeHandler struct {
	*recordingDeleteHandler
	id string
}

func (h *remainingRuntimeHandler) List(context.Context) ([]*svc.State, error) {
	return []*svc.State{{ID: h.id, Status: svc.SandboxStatusRunning}}, nil
}

func TestRetirementProgressDeleteReturnDoesNotProveRuntimeAbsence(t *testing.T) {
	s, p, handler := retirementProgressFixture(t)
	s.serviceHandler.Set("runsc", &remainingRuntimeHandler{recordingDeleteHandler: handler, id: p.SandboxID})
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: p.SandboxID, ExpectedGeneration: p.Generation})
	require.Error(t, err)
	stored, err := s.readRetirementProgress(p.SandboxID, p.Generation)
	require.NoError(t, err)
	require.Empty(t, stored.Steps)
	_, err = s.sandboxManager.Get(p.SandboxID)
	require.False(t, errors.Is(err, errord.ErrNotFound))
}
