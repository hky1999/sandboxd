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

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type failedCreationHandler struct {
	*svc.FakeRuntimeHandler
	afterList   func()
	afterDelete func()
	states      []*svc.State
	keepRuntime bool
	lists       int
	deletes     int
	prepared    int
}

func (h *failedCreationHandler) Start(context.Context, svc.StartConfig) error {
	return context.DeadlineExceeded
}

func (h *failedCreationHandler) Restore(context.Context, svc.StartConfig, string) error {
	return errors.New("restore reply lost")
}

func (*failedCreationHandler) Checkpoint(context.Context, string, string, svc.CheckpointOptions) error {
	return nil
}

func (h *failedCreationHandler) List(context.Context) ([]*svc.State, error) {
	h.lists++
	if h.afterList != nil {
		h.afterList()
	}
	return h.states, nil
}

func (h *failedCreationHandler) Delete(_ context.Context, id string) error {
	h.deletes++
	if !h.keepRuntime {
		remaining := make([]*svc.State, 0, len(h.states))
		for _, state := range h.states {
			if state == nil || state.ID != id {
				remaining = append(remaining, state)
			}
		}
		h.states = remaining
	}
	if h.afterDelete != nil {
		h.afterDelete()
	}
	return nil
}

func (h *failedCreationHandler) CleanupPreparedState(context.Context, string) error {
	h.prepared++
	return nil
}

func stageFailedCreationIntent(t *testing.T, s *sandboxService) *runtime.SandboxMetadata {
	t.Helper()
	id := "sbox-" + uuid.NewString()
	_, err := s.sandboxManager.ReserveID(id)
	require.NoError(t, err)
	root := filepath.Join(s.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(root, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`), 0600))
	metadata := &runtime.SandboxMetadata{ID: id, RuntimeHandler: "runsc",
		PhysicalPhase: runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT,
		Labels:        map[string]string{resourceGenerationLabel: uuid.NewString(), startOperationLabel: uuid.NewString()}}
	require.NoError(t, s.sandboxManager.PersistMetadata(id, metadata))
	return metadata
}

func TestFailedRuntimeCreationPreservesOriginalIntent(t *testing.T) {
	for _, kind := range []string{"start", "restore"} {
		t.Run(kind, func(t *testing.T) {
			handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			metadata := stageFailedCreationIntent(t, s)
			start := svc.StartConfig{ID: metadata.ID}
			var err error
			if kind == "start" {
				err = s.startSandboxRuntime(context.Background(), "runsc", start, metadata)
			} else {
				err = s.restoreSandboxRuntime(context.Background(), "runsc", start, "checkpoint.img", metadata)
			}
			require.Error(t, err)
			require.ErrorIs(t, err, svc.ErrRuntimeCreationUnconfirmed)
			intents := s.sandboxManager.ListPhysicalIntents()
			require.Len(t, intents, 1, "an RPC error cannot erase physical ownership")
			require.True(t, proto.Equal(metadata, intents[0]))
			require.FileExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
			require.Zero(t, handler.deletes)
		})
	}
}

func TestCreateSandboxDeferPreservesUnconfirmedRuntimeIntent(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	id := "sbox-" + uuid.NewString()
	_, err := s.createSandbox(context.Background(), &runtime.StartRequest{
		SandboxID: id, Runtime: "runsc",
		Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
	}, createOptions{onReserved: func(*runtime.StartRequest, string) error {
		intents := s.sandboxManager.ListPhysicalIntents()
		require.Len(t, intents, 1)
		return s.startSandboxRuntime(context.Background(), "runsc", svc.StartConfig{ID: id}, intents[0])
	}})
	require.Error(t, err)
	intents := s.sandboxManager.ListPhysicalIntents()
	require.Len(t, intents, 1, "the shared create rollback must preserve uncertain runtime ownership")
	require.Equal(t, id, intents[0].ID)
	_, err = s.sandboxManager.ReserveID(id)
	require.Error(t, err, "the same ID must stay reserved for authoritative reconciliation")
}

func TestReconcilePhysicalIntentRejectsChangedFacts(t *testing.T) {
	for _, kind := range []string{"generation", "resources", "committed"} {
		t.Run(kind, func(t *testing.T) {
			handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			metadata := stageFailedCreationIntent(t, s)
			handler.states = []*svc.State{{ID: metadata.ID, Status: svc.SandboxStatusRunning}}
			handler.afterList = func() {
				replacement := proto.Clone(metadata).(*runtime.SandboxMetadata)
				switch kind {
				case "generation":
					replacement.Labels[resourceGenerationLabel] = uuid.NewString()
				case "resources":
					replacement.ResourceFacts = map[string]string{config.ResourceNameCgroup: "replacement-cgroup"}
				case "committed":
					replacement.PhysicalPhase = runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED
				}
				require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, replacement))
			}
			err := s.reconcilePhysicalIntent(context.Background(), metadata)
			require.Error(t, err)
			require.Zero(t, handler.deletes, "changed physical facts cannot authorize deleting a runtime")
			require.Zero(t, handler.prepared)
			require.FileExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
		})
	}
}

func TestReconcilePhysicalIntentRejectsIncompleteRuntimeInventory(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler(), states: []*svc.State{nil}}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	err := s.reconcilePhysicalIntent(context.Background(), metadata)
	require.Error(t, err)
	require.Zero(t, handler.prepared, "unknown inventory cannot authorize prepared-state cleanup")
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
}

func TestReconcilePhysicalIntentRespectsPhysicalLock(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	unlock, err := s.resourceLocks.acquire(context.Background(), metadata.ID)
	require.NoError(t, err)
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = s.reconcilePhysicalIntent(ctx, metadata)
	require.Error(t, err)
	require.Zero(t, handler.lists, "reconciliation must acquire the physical lock before observations")
	require.Zero(t, handler.prepared)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
}

func TestReconcilePhysicalIntentVerifiesDeleteBeforeRecycling(t *testing.T) {
	for _, kind := range []string{"still-running", "changed-generation", "incomplete-inventory", "duplicate-inventory"} {
		t.Run(kind, func(t *testing.T) {
			handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			metadata := stageFailedCreationIntent(t, s)
			metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
			require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
			cgroups := &failingCgroupMgr{}
			s.cgroupMgr = cgroups
			handler.states = []*svc.State{{ID: metadata.ID, Status: svc.SandboxStatusRunning}}
			switch kind {
			case "still-running":
				handler.keepRuntime = true
			case "changed-generation":
				handler.afterDelete = func() {
					replacement := proto.Clone(metadata).(*runtime.SandboxMetadata)
					replacement.Labels[resourceGenerationLabel] = uuid.NewString()
					require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, replacement))
				}
			case "incomplete-inventory":
				handler.afterDelete = func() { handler.states = []*svc.State{nil} }
			case "duplicate-inventory":
				handler.states = append(handler.states, &svc.State{ID: metadata.ID, Status: svc.SandboxStatusRunning})
			}
			err := s.reconcilePhysicalIntent(context.Background(), metadata)
			require.Error(t, err)
			require.Empty(t, cgroups.recycles, "a returned delete alone cannot authorize resource recycling")
			require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
			require.FileExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
		})
	}
}

func TestReconcilePhysicalIntentCleansOriginalAndPreservesNeighbor(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	cgroups := &failingCgroupMgr{}
	s.cgroupMgr = cgroups
	neighbor := &svc.State{ID: "sbox-neighbor", Status: svc.SandboxStatusRunning}
	handler.states = []*svc.State{{ID: metadata.ID, Status: svc.SandboxStatusRunning}, neighbor}
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Equal(t, 1, handler.deletes)
	require.Equal(t, 2, handler.lists)
	require.Equal(t, []*svc.State{neighbor}, handler.states)
	require.Equal(t, []string{"original-cgroup"}, cgroups.recycles)
	require.Empty(t, s.sandboxManager.ListPhysicalIntents())
	require.NoDirExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID))
	// This boundary only verifies cleanup ownership. A durable completed
	// retirement proof for a failed creation is still a separate requirement.
	receipt, err := s.readRetirement(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.Nil(t, receipt)
}
