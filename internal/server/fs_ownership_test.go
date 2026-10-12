// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type ownershipImageService struct {
	*fsTestImageService
	mu            sync.Mutex
	mountErrors   map[string]error
	unmountErrors map[string]error
}

func newOwnershipImageService() *ownershipImageService {
	return &ownershipImageService{fsTestImageService: newFSTestImageService(),
		mountErrors: make(map[string]error), unmountErrors: make(map[string]error)}
}

func (s *ownershipImageService) MountOCI(r *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	s.mu.Lock()
	err := s.mountErrors[r.ImageURL]
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.fsTestImageService.MountOCI(r)
}

func (s *ownershipImageService) UmountOCI(r *imageapi.OCIUmountRequest) error {
	s.mu.Lock()
	err := s.unmountErrors[r.ImageURL]
	s.mu.Unlock()
	_ = s.fsTestImageService.UmountOCI(r)
	return err
}

type ownershipStore struct {
	store.DbStore
	mu       sync.Mutex
	failNext bool
	failWhen func([]byte) bool
}

func (s *ownershipStore) StoreRaw(key string, data []byte) error {
	s.mu.Lock()
	fail := key == config.SandboxFSStateBucket && (s.failNext || (s.failWhen != nil && s.failWhen(data)))
	if fail {
		s.failNext = false
		s.failWhen = nil
	}
	s.mu.Unlock()
	if fail {
		return errors.New("injected filesystem journal write failure")
	}
	return s.DbStore.StoreRaw(key, data)
}

func newOwnershipStore(t *testing.T) *ownershipStore {
	t.Helper()
	return &ownershipStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "fs.db"))}
}

func TestFSOwnershipCommitFailureRetainsSource(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepared, err := m.Prepare(fsTestStartRequest("commit-owner"))
	require.NoError(t, err)
	st.failNext = true
	require.Error(t, m.Commit("commit-owner", prepared))
	_, err = m.RootfsConfig("commit-owner")
	require.NoError(t, err, "a failed write must not erase ownership after mounting")
	require.NoError(t, m.Release("commit-owner"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipPrepareFailureRetainsPartialSource(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	service.mountErrors["registry.example/data:latest"] = errors.New("additional mount failed")
	m := newFSManager(service, st)
	prepared, err := m.Prepare(fsTestStartRequest("partial-owner"))
	require.Error(t, err)
	require.NotNil(t, prepared, "return the original partial owner instead of an inline rollback")
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	_, err = m.RootfsConfig("partial-owner")
	require.NoError(t, err)
	delete(service.mountErrors, "registry.example/data:latest")
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	_, err = reopened.RootfsConfig("partial-owner")
	require.NoError(t, err, "the original source must survive a real database reopen")
}

func TestFSOwnershipReleaseFailureRetainsDurableSource(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepareAndCommitFS(t, m, "release-owner")
	failure := errors.New("rootfs unmount failed")
	service.unmountErrors["registry.example/rootfs:latest"] = failure
	require.ErrorIs(t, m.Release("release-owner"), failure)
	_, err := m.RootfsConfig("release-owner")
	require.NoError(t, err)
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	_, err = reopened.RootfsConfig("release-owner")
	require.NoError(t, err)
	delete(service.unmountErrors, "registry.example/rootfs:latest")
	require.NoError(t, reopened.Release("release-owner"))
	_, err = reopened.RootfsConfig("release-owner")
	require.Error(t, err)
}

func TestFSOwnershipRetryDoesNotReleaseSharedNeighbor(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	request := fsTestStartRequest("retry-owner")
	request.Mounts = append(request.Mounts, &runtime.Mount{Target: "/opt/private", Options: []string{"ro"},
		Source: &runtime.Mount_ImageUrl{ImageUrl: "registry.example/private:latest"}})
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit("retry-owner", prepared))
	prepareAndCommitFS(t, m, "neighbor")
	service.unmountErrors["registry.example/private:latest"] = errors.New("private mount unmount failed")
	require.Error(t, m.Release("retry-owner"))
	delete(service.unmountErrors, "registry.example/private:latest")
	require.NoError(t, m.Release("retry-owner"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/data:latest"))
	_, err = m.RootfsConfig("neighbor")
	require.NoError(t, err)
	require.NoError(t, m.Release("neighbor"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
}

func TestFSOwnershipJournalFailurePreventsMount(t *testing.T) {
	st := newOwnershipStore(t)
	st.failNext = true
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	_, err := m.Prepare(fsTestStartRequest("unpublished-owner"))
	require.Error(t, err, "mounting requires a durable owner first")
	require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.mountCalls("registry.example/data:latest"))
}

func TestFSOwnershipRootAndAdditionalMountShareReferences(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	request := fsTestStartRequest("root-owner")
	request.Mounts = nil
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit("root-owner", prepared))
	request = fsTestStartRequest("additional-owner")
	request.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
		Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}}
	request.Mounts[0].Source = &runtime.Mount_ImageUrl{ImageUrl: "registry.example/rootfs:latest"}
	prepared, err = m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit("additional-owner", prepared))
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"), "one source must have one shared mount authority")
	require.NoError(t, m.Release("root-owner"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"), "the additional owner still uses this rootfs image")
	require.NoError(t, m.Release("additional-owner"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipConfirmationFailureDoesNotRepeatRelease(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepareAndCommitFS(t, m, "confirmation-owner")
	prepareAndCommitFS(t, m, "neighbor")
	st.failWhen = func(data []byte) bool {
		var journal storedSandboxFSStates
		require.NoError(t, json.Unmarshal(data, &journal))
		return journal.Items["confirmation-owner"].RootfsPhase == fsReleased
	}
	require.Error(t, m.Release("confirmation-owner"))
	require.NoError(t, m.Release("confirmation-owner"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/data:latest"))
	require.NoError(t, m.Release("neighbor"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
}

func TestFSOwnershipRestartAfterPartialReleaseProtectsNeighbor(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	request := fsTestStartRequest("restart-owner")
	request.Mounts = append(request.Mounts, &runtime.Mount{Target: "/opt/private", Options: []string{"ro"},
		Source: &runtime.Mount_ImageUrl{ImageUrl: "registry.example/private:latest"}})
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	prepareAndCommitFS(t, m, "neighbor")
	service.unmountErrors["registry.example/private:latest"] = errors.New("private unmount failed")
	require.Error(t, m.Release("restart-owner"))
	delete(service.unmountErrors, "registry.example/private:latest")
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.Release("restart-owner"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/data:latest"))
	require.NoError(t, reopened.Release("neighbor"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
}

func TestFSOwnershipOriginalGenerationReplayProtectsReplacement(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	oldGeneration, newGeneration := uuid.NewString(), uuid.NewString()
	request := fsTestStartRequest("reused-id")
	request.Labels = map[string]string{resourceGenerationLabel: oldGeneration}
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	require.Error(t, m.Release(request.SandboxID), "unconditional release cannot retire a generation-owned source")
	require.Error(t, m.ReleaseIfGeneration(request.SandboxID, newGeneration))
	require.NoError(t, m.ReleaseIfGeneration(request.SandboxID, oldGeneration))
	request.Labels[resourceGenerationLabel] = newGeneration
	prepared, err = m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.ReleaseIfGeneration(request.SandboxID, oldGeneration))
	require.NoError(t, reopened.ReleaseIfGeneration(request.SandboxID, oldGeneration))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
	_, err = reopened.RootfsConfig(request.SandboxID)
	require.NoError(t, err)
	require.NoError(t, reopened.ReleaseIfGeneration(request.SandboxID, newGeneration))
	require.Equal(t, 2, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipMissingCompletionIsUnknown(t *testing.T) {
	m := newFSManager(newOwnershipImageService(), newOwnershipStore(t))
	require.Error(t, m.ReleaseIfGeneration("missing-owner", uuid.NewString()))
	require.Error(t, m.ReleaseIfGeneration("missing-owner", ""))
}

func TestFSOwnershipShutdownPreservesFailedCleanup(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepareAndCommitFS(t, m, "shutdown-owner")
	service.unmountErrors["registry.example/rootfs:latest"] = errors.New("unmount failed")
	require.Error(t, m.Release("shutdown-owner"))
	m.Shutdown()
	_, err := m.RootfsConfig("shutdown-owner")
	require.NoError(t, err)
	delete(service.unmountErrors, "registry.example/rootfs:latest")
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.Release("shutdown-owner"))
}

func TestFSOwnershipCorruptJournalDoesNotMountOrOverwrite(t *testing.T) {
	st := newOwnershipStore(t)
	bad := []byte(`{"schema_version":99,"items":{}}`)
	require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, bad))
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	require.Error(t, m.Restore(func(string) bool { return true }))
	m.Shutdown()
	_, err := m.Prepare(fsTestStartRequest("corrupt-owner"))
	require.Error(t, err)
	require.Zero(t, service.mountCalls("registry.example/rootfs:latest"))
	current, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	require.Equal(t, bad, current)
}

func TestFSOwnershipUnconfirmedUnmountQuarantinesSource(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	prepareAndCommitFS(t, m, "quarantine-owner")
	service.unmountErrors["registry.example/rootfs:latest"] = errors.New("unknown unmount result")
	require.Error(t, m.Release("quarantine-owner"))
	_, err := m.Prepare(fsTestStartRequest("blocked-owner"))
	require.Error(t, err, "an uncertain source cannot accept another owner")
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
	delete(service.unmountErrors, "registry.example/rootfs:latest")
	require.NoError(t, m.Release("quarantine-owner"), "a rejected new acquire must not block the original cleanup")
	require.NoError(t, m.Release("blocked-owner"), "the new owner only reserved sources and must not unmount them")
	require.Equal(t, 2, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSOwnershipCompletionWriteFailureRetainsReleasedStages(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	request := fsTestStartRequest("receipt-owner")
	request.Labels = map[string]string{resourceGenerationLabel: uuid.NewString()}
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	st.failWhen = func(data []byte) bool {
		var journal storedSandboxFSStates
		require.NoError(t, json.Unmarshal(data, &journal))
		return len(journal.Completed) > 0
	}
	require.Error(t, m.ReleaseIfGeneration(request.SandboxID, prepared.generation))
	_, err = m.RootfsConfig(request.SandboxID)
	require.NoError(t, err, "completed physical steps remain owned until receipt persistence")
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.ReleaseIfGeneration(request.SandboxID, prepared.generation))
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
}

func TestFSOwnershipRetiredGenerationCannotBeAllocatedAgain(t *testing.T) {
	m := newFSManager(newOwnershipImageService(), newOwnershipStore(t))
	request := fsTestStartRequest("retired-owner")
	request.Labels = map[string]string{resourceGenerationLabel: uuid.NewString()}
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	require.NoError(t, m.ReleaseIfGeneration(request.SandboxID, prepared.generation))
	_, err = m.Prepare(request)
	require.Error(t, err)
}

type ownershipS3Service struct {
	*ownershipImageService
	unmountErr   error
	unmountCalls int
}

func (s *ownershipS3Service) UmountOSS(*imageapi.OSSUmountRequest) error {
	s.unmountCalls++
	return s.unmountErr
}

func TestFSOwnershipS3SharesReferencesAndRetainsFailedUnmount(t *testing.T) {
	st := newOwnershipStore(t)
	service := &ownershipS3Service{ownershipImageService: newOwnershipImageService()}
	m := newFSManager(service, st)
	source := &runtime.S3Config{Endpoint: "https://s3.example", Bucket: "test", Object: "shared"}
	request := fsTestStartRequest("s3-root-owner")
	request.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_S3,
		Source: &runtime.RootfsConfig_S3Config{S3Config: source}}
	request.Mounts = []*runtime.Mount{{Target: "/data", Options: []string{"ro"},
		Source: &runtime.Mount_S3Config{S3Config: source}}}
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	request.SandboxID = "s3-additional-owner"
	request.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
		Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}}
	prepared, err = m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	require.NoError(t, m.Release("s3-root-owner"))
	require.Zero(t, service.unmountCalls)
	failure := errors.New("S3 unmount result unknown")
	service.unmountErr = failure
	require.ErrorIs(t, m.Release("s3-additional-owner"), failure)
	request.SandboxID = "s3-blocked-owner"
	_, err = m.Prepare(request)
	require.Error(t, err)
	require.NoError(t, m.Release("s3-blocked-owner"), "reserved sources cannot consume another owner's reference")
	require.Equal(t, 1, service.unmountCalls)
	service.unmountErr = nil
	require.NoError(t, m.Release("s3-additional-owner"))
	require.Equal(t, 2, service.unmountCalls)
}

func TestFSOwnershipConcurrentDuplicateReleasesConsumeOneReference(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	m := newFSManager(service, st)
	generation := uuid.NewString()
	request := fsTestStartRequest("concurrent-owner")
	request.Labels = map[string]string{resourceGenerationLabel: generation}
	prepared, err := m.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, m.Commit(request.SandboxID, prepared))
	prepareAndCommitFS(t, m, "neighbor")
	results := make(chan error, 16)
	var done sync.WaitGroup
	for range 16 {
		done.Add(1)
		go func() {
			defer done.Done()
			results <- m.ReleaseIfGeneration(request.SandboxID, generation)
		}()
	}
	done.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/data:latest"))
	require.NoError(t, m.Release("neighbor"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, service.umountCalls("registry.example/data:latest"))
}

func TestFSOwnershipMissingJournalStopsPhysicalReconciliation(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	metadata := stageFailedCreationIntent(t, s)
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "original-cgroup"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	s.fsMgr = newFSManager(nil, newOwnershipStore(t))
	cgroups := &failingCgroupMgr{}
	s.cgroupMgr = cgroups
	err := s.reconcilePhysicalIntent(context.Background(), metadata)
	require.ErrorContains(t, err, "filesystem completion is unknown")
	require.Empty(t, cgroups.recycles)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	require.FileExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID, config.SandboxMetaFile))
	receipt, err := s.readRetirement(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.NotNil(t, receipt, "failed creation registers pending retirement before cleanup")
	require.False(t, receipt.Complete, "missing filesystem ownership cannot prove completion")
}

func TestFSOwnershipMissingPublishedOwnerBlocksOrphanCleanup(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	beforeCrash := newFSManager(service, st)
	prepareAndCommitFS(t, beforeCrash, "orphan")
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	storeSandboxForDelete(t, s, "unrecorded-live")
	require.NoError(t, s.sandboxManager.UpdateLabels("unrecorded-live", map[string]string{resourceGenerationLabel: uuid.NewString()}))
	s.fsMgr = newFSManager(service, st)
	err := s.recoverPhysicalState(context.Background())
	require.ErrorContains(t, err, "filesystem owner unrecorded-live is missing or changed")
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	_, err = s.fsMgr.RootfsConfig("orphan")
	require.NoError(t, err, "validation must precede any orphan release")
}

func TestFSOwnershipPublishedGenerationMismatchBlocksReconstruction(t *testing.T) {
	st := newOwnershipStore(t)
	service := newOwnershipImageService()
	beforeCrash := newFSManager(service, st)
	request := fsTestStartRequest("changed-owner")
	request.Labels = map[string]string{resourceGenerationLabel: uuid.NewString()}
	prepared, err := beforeCrash.Prepare(request)
	require.NoError(t, err)
	require.NoError(t, beforeCrash.Commit(request.SandboxID, prepared))
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	storeSandboxForDelete(t, s, request.SandboxID)
	require.NoError(t, s.sandboxManager.UpdateLabels(request.SandboxID, map[string]string{resourceGenerationLabel: uuid.NewString()}))
	s.fsMgr = newFSManager(service, st)
	require.Error(t, s.recoverPhysicalState(context.Background()))
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
}
