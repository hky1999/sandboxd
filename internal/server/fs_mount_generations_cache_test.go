// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/stretchr/testify/require"
)

// Original completions remain separate from the current physical source. This
// models the producer's durable completion contract, not a real kernel mount.
type generationCacheProducer struct {
	*fsTestImageService
	mu            sync.Mutex
	completions   map[string]bool
	ossMounts     int
	ossReleases   int
	ossFileSuffix string
}

func newGenerationCacheProducer() *generationCacheProducer {
	return &generationCacheProducer{fsTestImageService: newFSTestImageService(), completions: make(map[string]bool)}
}

func (s *generationCacheProducer) replaceCompletedSource(source, original, replacement string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completions[source+"\x00"+original] = true
	s.fsTestImageService.mu.Lock()
	defer s.fsTestImageService.mu.Unlock()
	s.physicalGenerations[source] = replacement
}

func (s *generationCacheProducer) MountOCI(r *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.PhysicalGeneration != "" && s.completions[r.ImageURL+"\x00"+r.PhysicalGeneration] {
		return &imageapi.OCIMountResponse{MountPath: "/mnt/oci/" + r.ImageURL, PhysicalGeneration: r.PhysicalGeneration, Released: true}, nil
	}
	return s.fsTestImageService.MountOCI(r)
}

func (s *generationCacheProducer) MountOSS(r *imageapi.OSSMountRequest) (*imageapi.MountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.Endpoint + "\x00" + r.Bucket + "\x00" + r.Object
	if r.PhysicalGeneration != "" && s.completions[key+"\x00"+r.PhysicalGeneration] {
		return &imageapi.MountInfo{MountPoint: "/mnt/s3/" + r.Object, FilePath: "/mnt/s3/" + r.Object + s.ossFileSuffix, PhysicalGeneration: r.PhysicalGeneration, Released: true}, nil
	}
	if r.PhysicalGeneration == "" {
		s.ossMounts++
	}
	info, err := s.fsTestImageService.MountOSS(r)
	if info != nil {
		info.FilePath += s.ossFileSuffix
	}
	return info, err
}

func (s *generationCacheProducer) QueryMountOperation(q *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fsTestImageService.mu.Lock()
	record, ok := s.operations[q.OperationID]
	s.fsTestImageService.mu.Unlock()
	if ok && s.completions[record.Source+"\x00"+record.Result.PhysicalGeneration] {
		if record.Result.RequestFingerprint != q.RequestFingerprint {
			return nil, fmt.Errorf("original completed operation changed")
		}
		r := record.Result
		r.State = "released"
		return &r, nil
	}
	return s.fsTestImageService.QueryMountOperation(q)
}

func (s *generationCacheProducer) UmountOCI(r *imageapi.OCIUmountRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completions[r.ImageURL+"\x00"+r.PhysicalGeneration] {
		return nil
	}
	s.fsTestImageService.mu.Lock()
	current := s.physicalGenerations[r.ImageURL]
	s.fsTestImageService.mu.Unlock()
	if r.PhysicalGeneration == "" || current != r.PhysicalGeneration {
		return fmt.Errorf("conditional release does not own this generation")
	}
	if err := s.fsTestImageService.UmountOCI(r); err != nil {
		return err
	}
	s.completions[r.ImageURL+"\x00"+r.PhysicalGeneration] = true
	return nil
}

func (s *generationCacheProducer) UmountOSS(r *imageapi.OSSUmountRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.Endpoint + "\x00" + r.Bucket + "\x00" + r.Object
	if s.completions[key+"\x00"+r.PhysicalGeneration] {
		return nil
	}
	s.fsTestImageService.mu.Lock()
	current := s.physicalGenerations[key]
	s.fsTestImageService.mu.Unlock()
	if r.PhysicalGeneration == "" || current != r.PhysicalGeneration {
		return fmt.Errorf("conditional S3 release does not own this generation")
	}
	s.ossReleases++
	s.completions[key+"\x00"+r.PhysicalGeneration] = true
	return nil
}

func cacheGenerationRequest(id, kind string) (*runtime.StartRequest, string) {
	r := fsOperationRequest(id)
	if kind == "s3" {
		source := &runtime.S3Config{Endpoint: "https://s3.example", Bucket: "controlled", Object: "shared"}
		r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_S3, Source: &runtime.RootfsConfig_S3Config{S3Config: source}}
		r.Mounts = []*runtime.Mount{{Target: "/data", Options: []string{"ro"}, Source: &runtime.Mount_S3Config{S3Config: source}}}
		return r, s3MountKey(source)
	}
	r.Mounts[0].Source = &runtime.Mount_ImageUrl{ImageUrl: r.Rootfs.GetImageUrl()}
	return r, r.Rootfs.GetImageUrl()
}

func TestFSMountOperationCompletedAndLiveGenerationsRecoverIndependently(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		for _, oldFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-old-first-%t", kind, oldFirst), func(t *testing.T) {
				st, producer := newOwnershipStore(t), newGenerationCacheProducer()
				oldID, newID := "z-old", "a-live"
				if oldFirst {
					oldID, newID = "a-old", "z-live"
				}
				r, source := cacheGenerationRequest(oldID, kind)
				before := newFSManager(producer, st)
				_, err := before.Prepare(r)
				require.NoError(t, err)
				old := cloneFSState(before.sandboxState[oldID])
				old.ReleaseRequested = true
				producer.replaceCompletedSource(source, old.RootfsMountGeneration, strings.Repeat("b", 64))
				// Preserve two independently valid ownership rows. Recovery must
				// reconcile this inventory regardless of owner iteration order.
				liveRequest, _ := cacheGenerationRequest(newID, kind)
				liveManager := newFSManager(producer, newOwnershipStore(t))
				_, err = liveManager.Prepare(liveRequest)
				require.NoError(t, err)
				live := cloneFSState(liveManager.sandboxState[newID])
				j := storedSandboxFSStates{SchemaVersion: fsJournalSchema, Items: map[string]sandboxFSState{oldID: old, newID: live}}
				j.IntegritySHA256, err = fsJournalIntegrity(j)
				require.NoError(t, err)
				raw, err := json.Marshal(j)
				require.NoError(t, err)
				require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, raw))
				reopened := newFSManager(producer, st)
				require.NoError(t, reopened.Restore(func(string) bool { return true }))
				requireCacheGenerationReferences(t, reopened, kind, source, old.RootfsMountGeneration, 2)
				requireCacheGenerationReferences(t, reopened, kind, source, live.RootfsMountGeneration, 2)
				require.NoError(t, reopened.ReleaseIfGeneration(oldID, r.Labels[resourceGenerationLabel]))
				requireCacheGenerationReferences(t, reopened, kind, source, old.RootfsMountGeneration, 0)
				requireCacheGenerationReferences(t, reopened, kind, source, live.RootfsMountGeneration, 2)
				producer.fsTestImageService.mu.Lock()
				current := producer.physicalGenerations[source]
				producer.fsTestImageService.mu.Unlock()
				require.Equal(t, strings.Repeat("b", 64), current)
				require.Zero(t, producer.umountCalls(source))
				require.Zero(t, producer.ossReleases)
				require.NoError(t, reopened.ReleaseIfGeneration(oldID, r.Labels[resourceGenerationLabel]), "old completion replay cannot consume a live reference")
				require.NoError(t, reopened.ReleaseIfGeneration(newID, liveRequest.Labels[resourceGenerationLabel]))
				if kind == "oci" {
					require.Equal(t, 1, producer.umountCalls(source))
					require.Equal(t, 2, producer.mountCalls(source))
				} else {
					require.Equal(t, 1, producer.ossReleases)
					require.Equal(t, 2, producer.ossMounts)
				}
				require.Empty(t, reopened.sandboxState)
				require.Empty(t, reopened.oci.generations)
				require.Empty(t, reopened.s3.generations)
			})
		}
	}
}

func requireCacheGenerationReferences(t *testing.T, m *fsManager, kind, source, generation string, count int) {
	t.Helper()
	entries := m.oci.generations
	if kind == "s3" {
		entries = m.s3.generations
	}
	entry := entries[imageMountIdentity{Source: source, Generation: generation}]
	if count == 0 {
		require.Nil(t, entry)
		return
	}
	require.NotNil(t, entry)
	require.Equal(t, count, entry.refcount)
	require.Equal(t, generation, entry.physicalGeneration)
}

type cacheObservationProducer struct {
	*generationCacheProducer
	changeResult func(*imageapi.MountOperationResult)
	failRelease  string
}

func (s *cacheObservationProducer) QueryMountOperation(q *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	r, err := s.generationCacheProducer.QueryMountOperation(q)
	if r != nil && s.changeResult != nil {
		s.changeResult(r)
	}
	return r, err
}

func (s *cacheObservationProducer) UmountOCI(r *imageapi.OCIUmountRequest) error {
	if r.PhysicalGeneration == s.failRelease {
		return fmt.Errorf("original release confirmation lost")
	}
	return s.generationCacheProducer.UmountOCI(r)
}

func (s *cacheObservationProducer) UmountOSS(r *imageapi.OSSUmountRequest) error {
	if r.PhysicalGeneration == s.failRelease {
		return fmt.Errorf("original S3 release confirmation lost")
	}
	return s.generationCacheProducer.UmountOSS(r)
}

func cacheRetiringOwner(t *testing.T, kind string, producer imageapi.Service) (*fsManager, *runtime.StartRequest, string, string) {
	t.Helper()
	m := newFSManager(producer, newOwnershipStore(t))
	r, source := cacheGenerationRequest("original-owner", kind)
	_, err := m.Prepare(r)
	require.NoError(t, err)
	state := cloneFSState(m.sandboxState[r.SandboxID])
	state.ReleaseRequested = true
	m.persistMu.Lock()
	err = m.saveStateLocked(r.SandboxID, state)
	m.persistMu.Unlock()
	require.NoError(t, err)
	return m, r, source, state.RootfsMountGeneration
}

func TestFSMountOperationCacheUnconfirmedOrChangedCompletionBlocksNewOwner(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		for _, observation := range []string{"release_pending", "target_changed", "generation_changed"} {
			t.Run(kind+"-"+observation, func(t *testing.T) {
				producer := &cacheObservationProducer{generationCacheProducer: newGenerationCacheProducer()}
				m, _, source, original := cacheRetiringOwner(t, kind, producer)
				producer.replaceCompletedSource(source, original, strings.Repeat("b", 64))
				producer.changeResult = func(r *imageapi.MountOperationResult) {
					switch observation {
					case "release_pending":
						r.State = "release_pending"
					case "target_changed":
						r.MountPoint = "/different-original-target"
					case "generation_changed":
						r.PhysicalGeneration = strings.Repeat("c", 64)
					}
				}
				newOwner, _ := cacheGenerationRequest("blocked-owner", kind)
				_, err := m.Prepare(newOwner)
				require.Error(t, err)
				requireCacheGenerationReferences(t, m, kind, source, original, 2)
				if observation == "release_pending" {
					requireCacheReservedOwner(t, m, newOwner.SandboxID)
				} else {
					require.NotContains(t, m.sandboxState, newOwner.SandboxID)
				}
				require.Equal(t, 1, producer.mountCalls(source)+producer.ossMounts)
				require.Zero(t, producer.umountCalls(source)+producer.ossReleases)
			})
		}
	}
}

func TestFSMountOperationCacheCompletionCannotRegress(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		for _, state := range []string{"ready", "release_pending"} {
			t.Run(kind+"-"+state, func(t *testing.T) {
				producer := &cacheObservationProducer{generationCacheProducer: newGenerationCacheProducer()}
				m, _, source, original := cacheRetiringOwner(t, kind, producer)
				producer.replaceCompletedSource(source, original, strings.Repeat("b", 64))
				require.NoError(t, m.Restore(func(string) bool { return true }))
				producer.changeResult = func(r *imageapi.MountOperationResult) { r.State = state }
				newOwner, _ := cacheGenerationRequest("blocked-owner", kind)
				_, err := m.Prepare(newOwner)
				require.ErrorContains(t, err, "completion regressed")
				requireCacheGenerationReferences(t, m, kind, source, original, 2)
				require.NotContains(t, m.sandboxState, newOwner.SandboxID)
				require.Equal(t, 1, producer.mountCalls(source)+producer.ossMounts)
				require.Zero(t, producer.umountCalls(source)+producer.ossReleases)
			})
		}
	}
}

func TestFSMountOperationCachePendingOriginalBehindLiveAliasBlocksAdmission(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		t.Run(kind, func(t *testing.T) {
			producer := &cacheObservationProducer{generationCacheProducer: newGenerationCacheProducer()}
			oldManager, old, source, original := cacheRetiringOwner(t, kind, producer)
			producer.replaceCompletedSource(source, original, strings.Repeat("b", 64))
			producer.changeResult = func(r *imageapi.MountOperationResult) {
				if r.PhysicalGeneration == original {
					r.State = "release_pending"
				}
			}
			live, _ := cacheGenerationRequest("replacement-owner", kind)
			liveManager := newFSManager(producer, newOwnershipStore(t))
			_, err := liveManager.Prepare(live)
			require.NoError(t, err)
			journal := storedSandboxFSStates{SchemaVersion: fsJournalSchema, Items: map[string]sandboxFSState{
				old.SandboxID:  cloneFSState(oldManager.sandboxState[old.SandboxID]),
				live.SandboxID: cloneFSState(liveManager.sandboxState[live.SandboxID]),
			}}
			journal.IntegritySHA256, err = fsJournalIntegrity(journal)
			require.NoError(t, err)
			raw, err := json.Marshal(journal)
			require.NoError(t, err)
			st := newOwnershipStore(t)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, raw))
			m := newFSManager(producer, st)
			require.NoError(t, m.Restore(func(string) bool { return true }))
			current := m.oci.entries[source]
			if kind == "s3" {
				current = m.s3.entries[source]
			}
			require.NotNil(t, current)
			require.Equal(t, strings.Repeat("b", 64), current.physicalGeneration)
			require.False(t, current.releaseUnconfirmed)
			third, _ := cacheGenerationRequest("blocked-third-owner", kind)
			_, err = m.Prepare(third)
			require.ErrorContains(t, err, "source release is unconfirmed")
			requireCacheReservedOwner(t, m, third.SandboxID)
			requireCacheGenerationReferences(t, m, kind, source, original, 2)
			requireCacheGenerationReferences(t, m, kind, source, strings.Repeat("b", 64), 2)
			require.Equal(t, 2, producer.mountCalls(source)+producer.ossMounts)
			require.Zero(t, producer.umountCalls(source)+producer.ossReleases)
		})
	}
}

func requireCacheReservedOwner(t *testing.T, m *fsManager, id string) {
	t.Helper()
	state, exists := m.sandboxState[id]
	require.True(t, exists, "the durable source reservation precedes admission")
	require.Equal(t, fsReserved, state.RootfsPhase)
	require.Empty(t, state.RootfsMountGeneration)
	for i, phase := range state.S3Phases {
		require.Equal(t, fsReserved, phase)
		require.Empty(t, state.S3MountGenerations[i])
	}
	for i, phase := range state.OCIPhases {
		require.Equal(t, fsReserved, phase)
		require.Empty(t, state.OCIMountGenerations[i])
	}
	require.NotContains(t, m.sandboxRootfs, id)
	require.Empty(t, m.sandboxS3Mount[id])
	require.Empty(t, m.sandboxOCIMount[id])
}

func TestFSMountOperationCacheOldReleaseFailurePreservesLiveGeneration(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		t.Run(kind, func(t *testing.T) {
			producer := &cacheObservationProducer{generationCacheProducer: newGenerationCacheProducer()}
			m, old, source, original := cacheRetiringOwner(t, kind, producer)
			producer.replaceCompletedSource(source, original, strings.Repeat("b", 64))
			live, _ := cacheGenerationRequest("live-owner", kind)
			_, err := m.Prepare(live)
			require.NoError(t, err)
			producer.failRelease = original
			for range 2 {
				require.Error(t, m.ReleaseIfGeneration(old.SandboxID, old.Labels[resourceGenerationLabel]))
				requireCacheGenerationReferences(t, m, kind, source, original, 1)
				requireCacheGenerationReferences(t, m, kind, source, strings.Repeat("b", 64), 2)
				require.Zero(t, producer.umountCalls(source)+producer.ossReleases)
			}
			require.NoError(t, m.ReleaseIfGeneration(live.SandboxID, live.Labels[resourceGenerationLabel]))
			require.Equal(t, 1, producer.umountCalls(source)+producer.ossReleases)
			requireCacheGenerationReferences(t, m, kind, source, original, 1)
			producer.failRelease = ""
			require.NoError(t, m.ReleaseIfGeneration(old.SandboxID, old.Labels[resourceGenerationLabel]))
			require.Equal(t, 1, producer.umountCalls(source)+producer.ossReleases)
			require.Empty(t, m.sandboxState)
			require.Empty(t, m.oci.generations)
			require.Empty(t, m.s3.generations)
		})
	}
}

func TestFSMountOperationCacheS3RegularFileKeepsProducerMountTarget(t *testing.T) {
	producer := newGenerationCacheProducer()
	producer.ossFileSuffix = "/root.erofs"
	m, old, source, original := cacheRetiringOwner(t, "s3", producer)
	producer.replaceCompletedSource(source, original, strings.Repeat("b", 64))
	live, _ := cacheGenerationRequest("live-owner", "s3")
	_, err := m.Prepare(live)
	require.NoError(t, err)
	require.NoError(t, m.ReleaseIfGeneration(old.SandboxID, old.Labels[resourceGenerationLabel]))
	require.Zero(t, producer.ossReleases)
	require.NoError(t, m.ReleaseIfGeneration(live.SandboxID, live.Labels[resourceGenerationLabel]))
	require.Equal(t, 1, producer.ossReleases)
}

func TestFSMountOperationCacheLegacyShutdownKeepsManagedReferences(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		t.Run(kind, func(t *testing.T) {
			producer := newGenerationCacheProducer()
			m, owner, source, original := cacheRetiringOwner(t, kind, producer)
			m.oci.cleanupAllOciUnmounts()
			m.s3.cleanupAllS3Unmounts()
			requireCacheGenerationReferences(t, m, kind, source, original, 2)
			require.Zero(t, producer.umountCalls(source)+producer.ossReleases)
			require.Contains(t, m.sandboxState, owner.SandboxID)
			require.NoError(t, m.ReleaseIfGeneration(owner.SandboxID, owner.Labels[resourceGenerationLabel]))
			require.Equal(t, 1, producer.umountCalls(source)+producer.ossReleases)
		})
	}
}

func TestFSMountOperationCachedCompletedGenerationAllowsNewOwner(t *testing.T) {
	for _, kind := range []string{"oci", "s3"} {
		t.Run(kind, func(t *testing.T) {
			st, producer := newOwnershipStore(t), newGenerationCacheProducer()
			m := newFSManager(producer, st)
			old, source := cacheGenerationRequest("old-owner", kind)
			_, err := m.Prepare(old)
			require.NoError(t, err)
			state := cloneFSState(m.sandboxState[old.SandboxID])
			state.ReleaseRequested = true
			m.persistMu.Lock()
			err = m.saveStateLocked(old.SandboxID, state)
			m.persistMu.Unlock()
			require.NoError(t, err)
			producer.replaceCompletedSource(source, state.RootfsMountGeneration, strings.Repeat("b", 64))
			live, _ := cacheGenerationRequest("new-owner", kind)
			_, err = m.Prepare(live)
			require.NoError(t, err)
			require.NoError(t, m.ReleaseIfGeneration(old.SandboxID, old.Labels[resourceGenerationLabel]))
			require.Zero(t, producer.umountCalls(source))
			require.Zero(t, producer.ossReleases)
			require.NoError(t, m.ReleaseIfGeneration(live.SandboxID, live.Labels[resourceGenerationLabel]))
			if kind == "oci" {
				require.Equal(t, 1, producer.umountCalls(source))
			} else {
				require.Equal(t, 1, producer.ossReleases)
			}
		})
	}
}
