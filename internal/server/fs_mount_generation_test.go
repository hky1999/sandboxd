// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/langrtmanager"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/stretchr/testify/require"
)

func TestFSMountGenerationSavedBeforeRelease(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("original-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "logical-original-generation"}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	raw, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	stored, err := decodeFSJournal(raw)
	require.NoError(t, err)
	state := stored.Items[r.SandboxID]
	service.fsTestImageService.mu.Lock()
	expected := service.physicalGenerations[r.Rootfs.GetImageUrl()]
	service.fsTestImageService.mu.Unlock()
	require.Equal(t, expected, state.RootfsMountGeneration)
	require.Len(t, state.OCIMountGenerations, 1)
	require.NotEmpty(t, state.OCIMountGenerations[0])
}

type fsGuardedMountService struct {
	*ownershipImageService
	attemptGeneration string
}

func (s *fsGuardedMountService) UmountOCI(r *imageapi.OCIUmountRequest) error {
	s.attemptGeneration = r.PhysicalGeneration
	s.fsTestImageService.mu.Lock()
	current := s.physicalGenerations[r.ImageURL]
	s.fsTestImageService.mu.Unlock()
	if current != r.PhysicalGeneration {
		return fmt.Errorf("original producer generation changed")
	}
	return s.ownershipImageService.UmountOCI(r)
}

func TestFSMountGenerationDefaultRootMounterPreservesBirthForRelease(t *testing.T) {
	service := &fsGuardedMountService{ownershipImageService: newOwnershipImageService()}
	image := "registry.example/default-root:tag"
	root, err := langrtmanager.NewRootFS(langrtmanager.RootfsConfig{SrcType: runtime.RootfsSrcType_IMAGE, ImageUrl: image, RequirePhysicalGeneration: true}, langrtmanager.NewDefaultMounter(service), nil)
	require.NoError(t, err)
	require.NoError(t, root.IncRef())
	original := root.PhysicalGeneration()
	require.NotEmpty(t, original)
	service.physicalGenerations[image] = strings.Repeat("b", 64)
	require.Error(t, root.DecRef())
	require.Equal(t, original, service.attemptGeneration)
	require.Equal(t, 1, service.mountCalls(image))
	require.Zero(t, service.umountCalls(image))
}

func TestFSMountGenerationKnownBindingCannotBeRewritten(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("immutable-binding")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	before, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	state := cloneFSState(m.sandboxState[r.SandboxID])
	state.RootfsMountGeneration = strings.Repeat("b", 64)
	m.persistMu.Lock()
	err = m.saveStateLocked(r.SandboxID, state)
	m.persistMu.Unlock()
	require.Error(t, err)
	after, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestFSMountGenerationChangedSharedReferenceIsNotDecremented(t *testing.T) {
	service := newOwnershipImageService()
	m := newOciMountManager(service)
	first, err := m.mountOCIGeneration("registry.example/shared:tag", "", true, false)
	require.NoError(t, err)
	_, err = m.mountOCIGeneration("registry.example/shared:tag", "", true, false)
	require.NoError(t, err)
	m.entries["registry.example/shared:tag"].physicalGeneration = strings.Repeat("b", 64)
	require.Error(t, m.unmountOCIGeneration("registry.example/shared:tag", first.physicalGeneration))
	require.Equal(t, 2, m.entries["registry.example/shared:tag"].refcount)
	require.Zero(t, service.umountCalls("registry.example/shared:tag"))
}

func TestFSMountGenerationUnknownInventoryStopsAllReferenceRecovery(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("a-valid-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	r.SandboxID = "z-unknown-owner"
	r.Mounts[0].Source = &runtime.Mount_ImageUrl{ImageUrl: "registry.example/unknown:tag"}
	service.mountErrors["registry.example/unknown:tag"] = errors.New("reply lost")
	_, err = m.Prepare(r)
	require.Error(t, err)
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	require.Empty(t, reopened.sandboxRootfs)
	require.Empty(t, reopened.oci.entries)
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountGenerationS3SharedOwnersRecoverOriginalIdentity(t *testing.T) {
	st := newOwnershipStore(t)
	service := &ownershipS3Service{ownershipImageService: newOwnershipImageService()}
	m := newFSManager(service, st)
	source := &runtime.S3Config{Endpoint: "https://s3.example", Bucket: "controlled", Object: "original"}
	r := fsTestStartRequest("s3-original")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_S3, Source: &runtime.RootfsConfig_S3Config{S3Config: source}}
	r.Mounts = []*runtime.Mount{{Target: "/data", Options: []string{"ro"}, Source: &runtime.Mount_S3Config{S3Config: source}}}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	r.SandboxID = "s3-neighbor"
	r.Labels[resourceGenerationLabel] = "neighbor-generation"
	_, err = m.Prepare(r)
	require.NoError(t, err)
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	original := reopened.sandboxState["s3-original"]
	require.NotEmpty(t, original.RootfsMountGeneration)
	require.Equal(t, []string{original.RootfsMountGeneration}, original.S3MountGenerations)
	require.NoError(t, reopened.ReleaseIfGeneration("s3-original", "original-generation"))
	require.Zero(t, service.unmountCalls)
	require.NoError(t, reopened.ReleaseIfGeneration("s3-neighbor", "neighbor-generation"))
	require.Equal(t, 1, service.unmountCalls)
}

func TestFSMountGenerationSchemaThreeRequiresOriginalOwnershipMigration(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		t.Run(fmt.Sprint(nonempty), func(t *testing.T) {
			st, service := newOwnershipStore(t), newOwnershipImageService()
			journal := storedSandboxFSStates{SchemaVersion: 3, Items: make(map[string]sandboxFSState)}
			if nonempty {
				m := newFSManager(service, st)
				_, err := m.Prepare(fsTestStartRequest("old-owner"))
				require.NoError(t, err)
				state := cloneFSState(m.sandboxState["old-owner"])
				state.RootfsMountGeneration, state.S3MountGenerations, state.OCIMountGenerations = "", nil, nil
				journal.Items["old-owner"] = state
			}
			var err error
			journal.IntegritySHA256, err = fsJournalIntegrity(journal)
			require.NoError(t, err)
			raw, err := json.Marshal(journal)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, raw))
			m := newFSManager(service, st)
			err = m.Restore(func(string) bool { return true })
			if nonempty {
				require.Error(t, err)
				m.Shutdown()
				after, err := st.LoadRaw(config.SandboxFSStateBucket)
				require.NoError(t, err)
				require.Equal(t, raw, after)
				require.Empty(t, m.sandboxRootfs)
			} else {
				require.NoError(t, err)
				after, err := st.LoadRaw(config.SandboxFSStateBucket)
				require.NoError(t, err)
				decoded, err := decodeFSJournal(after)
				require.NoError(t, err)
				require.Equal(t, fsJournalSchema, decoded.SchemaVersion)
			}
		})
	}
}

// A controlled producer owns original completions independently of its current
// source route, just as the image API's durable completion bucket does.
type fsCompletedMountService struct {
	*ownershipImageService
	completed map[string]bool
}

func (s *fsCompletedMountService) MountOCI(r *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	if r.PhysicalGeneration != "" && s.completed[r.ImageURL+"\x00"+r.PhysicalGeneration] {
		return &imageapi.OCIMountResponse{MountPath: "/mnt/oci/" + r.ImageURL, PhysicalGeneration: r.PhysicalGeneration, Released: true}, nil
	}
	return s.ownershipImageService.MountOCI(r)
}

func (s *fsCompletedMountService) UmountOCI(r *imageapi.OCIUmountRequest) error {
	key := r.ImageURL + "\x00" + r.PhysicalGeneration
	if s.completed[key] {
		return nil
	}
	if err := s.ownershipImageService.UmountOCI(r); err != nil {
		return err
	}
	s.completed[key] = true
	return nil
}

func (s *fsCompletedMountService) QueryMountOperation(query *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	s.fsTestImageService.mu.Lock()
	record, exists := s.operations[query.OperationID]
	s.fsTestImageService.mu.Unlock()
	if exists && s.completed[record.Source+"\x00"+record.Result.PhysicalGeneration] {
		if record.Result.RequestFingerprint != query.RequestFingerprint {
			return nil, fmt.Errorf("original completion request changed")
		}
		result := record.Result
		result.State = "released"
		return &result, nil
	}
	return s.fsTestImageService.QueryMountOperation(query)
}

func TestFSMountGenerationCompletedProducerResumesPendingCleanupAfterReplacement(t *testing.T) {
	st := newOwnershipStore(t)
	service := &fsCompletedMountService{ownershipImageService: newOwnershipImageService(), completed: make(map[string]bool)}
	m := newFSManager(service, st)
	r := fsTestStartRequest("pending-cleanup")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	r.Mounts = nil
	_, err := m.Prepare(r)
	require.NoError(t, err)
	st.failWhen = func(raw []byte) bool {
		var j storedSandboxFSStates
		require.NoError(t, json.Unmarshal(raw, &j))
		return j.Items[r.SandboxID].RootfsPhase == fsReleased
	}
	require.Error(t, m.ReleaseIfGeneration(r.SandboxID, "original-generation"))
	service.physicalGenerations[r.Rootfs.GetImageUrl()] = strings.Repeat("b", 64)
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, "original-generation"))
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()))
	require.Equal(t, 1, service.umountCalls(r.Rootfs.GetImageUrl()))
	require.Equal(t, strings.Repeat("b", 64), service.physicalGenerations[r.Rootfs.GetImageUrl()])
}

func TestFSMountGenerationActiveOwnerCannotUseCompletedProducer(t *testing.T) {
	st := newOwnershipStore(t)
	service := &fsCompletedMountService{ownershipImageService: newOwnershipImageService(), completed: make(map[string]bool)}
	m := newFSManager(service, st)
	r := fsTestStartRequest("active-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	r.Mounts = nil
	_, err := m.Prepare(r)
	require.NoError(t, err)
	g := m.sandboxState[r.SandboxID].RootfsMountGeneration
	service.completed[r.Rootfs.GetImageUrl()+"\x00"+g] = true
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	require.Empty(t, reopened.sandboxRootfs)
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()))
	require.Zero(t, service.umountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountGenerationLostAcquisitionConfirmationNeverRemounts(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("lost-confirmation")
	r.Labels = map[string]string{resourceGenerationLabel: "original-generation"}
	st.failWhen = func(raw []byte) bool {
		var j storedSandboxFSStates
		require.NoError(t, json.Unmarshal(raw, &j))
		return j.Items[r.SandboxID].RootfsPhase == fsAcquired
	}
	_, err := m.Prepare(r)
	require.Error(t, err)
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NotEmpty(t, reopened.sandboxRootfs)
	require.Equal(t, service.physicalGenerations[r.Rootfs.GetImageUrl()], reopened.sandboxState[r.SandboxID].RootfsMountGeneration)
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()))
	require.Zero(t, service.umountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountGenerationRecoveryNeverMountsReplacement(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("restart-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "logical-original-generation"}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	before := service.mountCalls(r.Rootfs.GetImageUrl())
	service.fsTestImageService.mu.Lock()
	service.physicalGenerations[r.Rootfs.GetImageUrl()] = strings.Repeat("b", 64)
	service.fsTestImageService.mu.Unlock()
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	require.Equal(t, before, service.mountCalls(r.Rootfs.GetImageUrl()), "recovery must query the original lease, never create a replacement")
	require.Zero(t, service.umountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountGenerationUnknownAcquisitionCannotAdoptCurrentSource(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	image := "registry.example/data:latest"
	service.mountErrors[image] = errors.New("mount response unavailable")
	m := newFSManager(service, st)
	r := fsTestStartRequest("unknown-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "logical-original-generation"}
	_, err := m.Prepare(r)
	require.Error(t, err)
	delete(service.mountErrors, image)
	service.fsTestImageService.mu.Lock()
	service.physicalGenerations[image] = strings.Repeat("b", 64)
	service.fsTestImageService.mu.Unlock()
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	require.Zero(t, service.mountCalls(image))
	require.Zero(t, service.umountCalls(image))
}

func TestFSMountGenerationLastReferenceUsesOriginalLease(t *testing.T) {
	st, service := newOwnershipStore(t), newOwnershipImageService()
	m := newFSManager(service, st)
	r := fsTestStartRequest("retiring-owner")
	r.Labels = map[string]string{resourceGenerationLabel: "logical-original-generation"}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	service.fsTestImageService.mu.Lock()
	root, extra := service.physicalGenerations[r.Rootfs.GetImageUrl()], service.physicalGenerations["registry.example/data:latest"]
	service.fsTestImageService.mu.Unlock()
	require.NoError(t, m.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	service.fsTestImageService.mu.Lock()
	defer service.fsTestImageService.mu.Unlock()
	require.ElementsMatch(t, []string{root, extra}, service.unmountedGenerations)
}
