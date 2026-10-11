// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"syscall"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type postStartFailureHandler struct {
	*svc.FakeRuntimeHandler
	root    string
	starts  int
	deletes int
}

func (h *postStartFailureHandler) Start(_ context.Context, start svc.StartConfig) error {
	h.starts++
	return os.WriteFile(filepath.Join(h.root, "containers", start.ID, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","root":{"path":"rootfs"},"linux":{},"annotations":{}}`), 0600)
}

func (h *postStartFailureHandler) Delete(context.Context, string) error {
	h.deletes++
	return nil
}

func TestPostStartFailurePreservesOriginalOwnership(t *testing.T) {
	for _, failure := range []string{"dnat", "publication"} {
		t.Run(failure, func(t *testing.T) {
			handler := &postStartFailureHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newTestService(t, map[string]svc.Handler{"runsc": handler})
			handler.root = s.config.RootDir
			s.config.DisableCgroup = true
			s.fsMgr = newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
			id, generation := "sbox-post-start-"+failure, uuid.NewString()
			encoded := `{"interface":{"Name":"test-tap","Index":11},"ip":"10.88.0.7","type":"tap","leaseID":"` + uuid.NewString() + `"}`
			network, err := networkmanager.NewNetResource(encoded)
			require.NoError(t, err)
			prepare := gomonkey.ApplyPrivateMethod(s, "prepareStartResources",
				func(_ *sandboxService, _, actualID, actualGeneration string) (*preparedStartResources, error) {
					return &preparedStartResources{OccupiedResource: sandbox.OccupiedResource{
						ID: actualID, Generation: actualGeneration,
						Resources: map[string]string{config.ResourceNameInterface: encoded},
					}, sandboxIP: "10.88.0.7", network: network}, nil
				})
			defer prepare.Reset()
			var inlineReleases int
			release := gomonkey.ApplyPrivateMethod(s, "releaseStartResources",
				func(_ *sandboxService, _ sandbox.OccupiedResource) error {
					inlineReleases++
					return errors.New("injected resource release failure")
				})
			defer release.Reset()
			request := &runtime.StartRequest{SandboxID: id, Runtime: "runsc",
				Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
					Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
			}
			if failure == "dnat" {
				const backend = "post-start-ownership-test"
				networkmanager.NetworkManagers[backend] = &fakeNetworkManager{failNext: true}
				t.Cleanup(func() { delete(networkmanager.NetworkManagers, backend) })
				s.networkMgr.natBackend = backend
				request.Ports = []string{"tcp:12345:8000"}
			} else {
				publish := gomonkey.ApplyMethod(s.sandboxManager, "ActivateMetadata",
					func(*sandbox.Manager, string) error { return errors.New("injected publication failure") })
				defer publish.Reset()
			}
			_, err = s.createSandbox(context.Background(), request, createOptions{resourceGeneration: generation})
			require.Error(t, err)
			require.Equal(t, 1, handler.starts, "the failure must occur after the runtime returned success")
			require.Zero(t, handler.deletes, "an error return must retain ownership for authoritative reconciliation")
			require.Zero(t, inlineReleases)
			bytes, readErr := os.ReadFile(filepath.Join(s.config.RootDir, "containers", id, config.SandboxMetaFile))
			require.NoError(t, readErr)
			metadata := &runtime.SandboxMetadata{}
			require.NoError(t, proto.Unmarshal(bytes, metadata))
			require.Equal(t, generation, metadata.Labels[resourceGenerationLabel])
			require.Equal(t, encoded, metadata.ResourceFacts[config.ResourceNameInterface])
			_, reserveErr := s.sandboxManager.ReserveID(id)
			require.Error(t, reserveErr)
			_, fsErr := s.fsMgr.RootfsConfig(id)
			require.NoError(t, fsErr)
			reopened, openErr := sandbox.NewManager(s.config.RootDir, s.serviceHandler, make(chan bool, 10), nil, 1000)
			require.NoError(t, openErr)
			t.Cleanup(reopened.Stop)
			require.True(t, reopened.HasPhysicalRecord(id))
			_, reserveErr = reopened.ReserveID(id)
			require.Error(t, reserveErr)
			recoveredFS := newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
			require.NoError(t, recoveredFS.Restore(reopened.HasPhysicalRecord))
			_, fsErr = recoveredFS.RootfsConfig(id)
			require.NoError(t, fsErr)
		})
	}
}

func TestPhysicalIntentCallbackErrorPreservesIdentity(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	id := "sbox-original-callback-error"
	failure := errors.New("reserved identity publication failed")
	_, err := s.createSandbox(context.Background(), &runtime.StartRequest{
		SandboxID: id, Runtime: "runsc", Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
	}, createOptions{onReserved: func(*runtime.StartRequest, string) error { return failure }})
	require.ErrorIs(t, err, failure)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	require.FileExists(t, filepath.Join(s.config.RootDir, "containers", id, config.SandboxMetaFile))
	_, reserveErr := s.sandboxManager.ReserveID(id)
	require.Error(t, reserveErr)
}

func TestPhysicalIntentACLFailureStopsResourceRecycling(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	cgroups := &failingCgroupMgr{}
	s.cgroupMgr = cgroups
	s.aclMgr = &networkacl.Manager{}
	failure := errors.New("network ACL cleanup failed")
	var removals int
	remove := gomonkey.ApplyMethod(s.aclMgr, "Remove", func(*networkacl.Manager, string) error {
		removals++
		return failure
	})
	defer remove.Reset()
	err := s.reconcilePhysicalIntent(context.Background(), metadata)
	require.ErrorIs(t, err, failure)
	require.Equal(t, 1, removals)
	require.Empty(t, cgroups.recycles)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	require.FileExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
}

func TestPhysicalIntentNetworkFailureRetainsFilesystemAndPolicy(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	metadata.ResourceFacts = map[string]string{
		config.ResourceNameCgroup:    "original-cgroup",
		config.ResourceNameInterface: `{"interface":{"Name":"original-tap","Index":11},"ip":"10.88.0.7","type":"tap","leaseID":"` + uuid.NewString() + `"}`,
	}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	s.fsMgr = newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
	prepared, err := s.fsMgr.Prepare(&runtime.StartRequest{SandboxID: metadata.ID,
		Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
	})
	require.NoError(t, err)
	require.NoError(t, s.fsMgr.Commit(metadata.ID, prepared))
	cgroups := &failingCgroupMgr{}
	s.cgroupMgr = cgroups
	s.aclMgr = &networkacl.Manager{}
	var removals int
	remove := gomonkey.ApplyMethod(s.aclMgr, "Remove", func(*networkacl.Manager, string) error {
		removals++
		return nil
	})
	defer remove.Reset()
	failure := errors.New("original endpoint disconnection failed")
	disconnect := gomonkey.ApplyPrivateMethod(s, "deactivateStartNetwork",
		func(_ *sandboxService, resources sandbox.OccupiedResource) error {
			require.Equal(t, metadata.ID, resources.ID)
			require.Equal(t, metadata.Labels[resourceGenerationLabel], resources.Generation)
			require.Equal(t, metadata.ResourceFacts, resources.Resources)
			return failure
		})
	defer disconnect.Reset()
	err = s.reconcilePhysicalIntent(context.Background(), metadata)
	require.ErrorIs(t, err, failure)
	require.Zero(t, removals, "ACL removal must wait for original endpoint disconnection")
	require.Empty(t, cgroups.recycles)
	recoveredFS := newFSManager(nil, store.NewStoreImp(filepath.Join(s.config.RootDir, "fs.db")))
	require.NoError(t, recoveredFS.Restore(s.sandboxManager.HasPhysicalRecord))
	_, fsErr := recoveredFS.RootfsConfig(metadata.ID)
	require.NoError(t, fsErr, "network cleanup failure must not erase the persisted filesystem owner")
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
}

// The same binary can run under strace's second-fsync EIO injection. Lock the
// test thread so the file fsync and the post-rename directory fsync belong to
// one injection counter. This is syscall failure coverage, not power-loss proof.
func TestCreationMetadataPublicationFailureKeepsOriginalIdentity(t *testing.T) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	id, generation := "sbox-initial-publication", uuid.NewString()
	failure := errors.New("identity callback failed")
	var callbacks int
	_, err := s.createSandbox(context.Background(), &runtime.StartRequest{
		SandboxID: id, Runtime: "runsc", Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
	}, createOptions{resourceGeneration: generation, onReserved: func(*runtime.StartRequest, string) error {
		callbacks++
		return failure
	}})
	if os.Getenv("AKERNEL_TEST_METADATA_FSYNC_FAILURE") == "1" {
		require.ErrorIs(t, err, syscall.EIO)
		require.Zero(t, callbacks, "post-rename failure must stop before later side effects")
	} else {
		require.ErrorIs(t, err, failure)
		require.Equal(t, 1, callbacks)
	}
	bytes, readErr := os.ReadFile(filepath.Join(s.config.RootDir, "containers", id, config.SandboxMetaFile))
	require.NoError(t, readErr)
	metadata := &runtime.SandboxMetadata{}
	require.NoError(t, proto.Unmarshal(bytes, metadata))
	require.Equal(t, generation, metadata.Labels[resourceGenerationLabel])
	require.Equal(t, runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT, metadata.PhysicalPhase)
	_, reserveErr := s.sandboxManager.ReserveID(id)
	require.Error(t, reserveErr)
	reopened, openErr := sandbox.NewManager(s.config.RootDir, s.serviceHandler, make(chan bool, 10), nil, 1000)
	require.NoError(t, openErr)
	t.Cleanup(reopened.Stop)
	intents := reopened.ListPhysicalIntents()
	require.Len(t, intents, 1)
	require.True(t, proto.Equal(metadata, intents[0]))
	_, reserveErr = reopened.ReserveID(id)
	require.Error(t, reserveErr)
}
