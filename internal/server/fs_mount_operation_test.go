// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/langrtmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

// The producer's operation database is reopened on every read/write. It is
// independent of the upper filesystem journal and survives replacing this service.
type fsOperationProducer struct {
	*fsTestImageService
	journal     store.DbStore
	mu          sync.Mutex
	requests    []*imageapi.OCIMountRequest
	ossUnmounts []*imageapi.OSSUmountRequest
	queries     []imageapi.MountOperationQuery
	loseReply   string
}

type fsOperationProducerRecord struct {
	Source string                        `json:"source"`
	Result imageapi.MountOperationResult `json:"result"`
}

func newFSOperationProducer(t *testing.T) *fsOperationProducer {
	t.Helper()
	return &fsOperationProducer{fsTestImageService: newFSTestImageService(), journal: store.NewStoreImp(filepath.Join(t.TempDir(), "producer.db"))}
}

func (s *fsOperationProducer) MountOCI(req *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *req
	s.requests = append(s.requests, &copy)
	fingerprint, err := imageapi.MountRequestFingerprint(req)
	if err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		raw, err := s.journal.LoadRaw("operation-" + req.OperationID)
		if err == nil {
			var record fsOperationProducerRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				return nil, err
			}
			if record.Result.RequestFingerprint != fingerprint || req.PhysicalGeneration != "" && req.PhysicalGeneration != record.Result.PhysicalGeneration {
				return nil, fmt.Errorf("original controlled operation changed")
			}
			if record.Result.State == "released" {
				return &imageapi.OCIMountResponse{MountPath: record.Result.MountPoint, PhysicalGeneration: record.Result.PhysicalGeneration, Released: true}, nil
			}
			copy.PhysicalGeneration = record.Result.PhysicalGeneration
			return s.fsTestImageService.MountOCI(&copy)
		}
		if !errord.IsNotFound(err) {
			return nil, err
		}
	}
	response, err := s.fsTestImageService.MountOCI(req)
	if err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		record := fsOperationProducerRecord{Source: req.ImageURL, Result: imageapi.MountOperationResult{OperationID: req.OperationID, RequestFingerprint: fingerprint, Kind: "oci", State: "ready", PhysicalGeneration: response.PhysicalGeneration, MountPoint: response.MountPath}}
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if err := s.journal.StoreRaw("operation-"+req.OperationID, raw); err != nil {
			return nil, err
		}
	}
	if s.loseReply == req.ImageURL {
		s.loseReply = ""
		return nil, errors.New("controlled successful mount reply lost")
	}
	return response, nil
}

func (s *fsOperationProducer) QueryMountOperation(query *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, *query)
	raw, err := s.journal.LoadRaw("operation-" + query.OperationID)
	if errord.IsNotFound(err) {
		return &imageapi.MountOperationResult{OperationID: query.OperationID, RequestFingerprint: query.RequestFingerprint, State: "absent"}, nil
	}
	if err != nil {
		return nil, err
	}
	var record fsOperationProducerRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	if record.Result.OperationID != query.OperationID || record.Result.RequestFingerprint != query.RequestFingerprint {
		return nil, fmt.Errorf("controlled operation identity changed")
	}
	if record.Result.State != "released" {
		s.fsTestImageService.mu.Lock()
		current := s.physicalGenerations[record.Source]
		s.fsTestImageService.mu.Unlock()
		if current != record.Result.PhysicalGeneration {
			record.Result.State = "unresolved"
		}
	}
	return &record.Result, nil
}

func (s *fsOperationProducer) MountOSS(req *imageapi.OSSMountRequest) (*imageapi.MountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fingerprint, err := imageapi.MountRequestFingerprint(req)
	if err != nil {
		return nil, err
	}
	source := req.Endpoint + "\x00" + req.Bucket + "\x00" + req.Object
	copy := *req
	if req.OperationID != "" {
		raw, err := s.journal.LoadRaw("operation-" + req.OperationID)
		if err == nil {
			var record fsOperationProducerRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				return nil, err
			}
			if record.Result.RequestFingerprint != fingerprint || req.PhysicalGeneration != "" && req.PhysicalGeneration != record.Result.PhysicalGeneration {
				return nil, fmt.Errorf("original controlled S3 operation changed")
			}
			copy.PhysicalGeneration = record.Result.PhysicalGeneration
			return s.fsTestImageService.MountOSS(&copy)
		}
		if !errord.IsNotFound(err) {
			return nil, err
		}
	}
	response, err := s.fsTestImageService.MountOSS(req)
	if err != nil {
		return nil, err
	}
	if req.OperationID != "" {
		record := fsOperationProducerRecord{Source: source, Result: imageapi.MountOperationResult{OperationID: req.OperationID, RequestFingerprint: fingerprint, Kind: "oss", State: "ready", PhysicalGeneration: response.PhysicalGeneration, MountPoint: response.MountPoint}}
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if err := s.journal.StoreRaw("operation-"+req.OperationID, raw); err != nil {
			return nil, err
		}
	}
	if s.loseReply == source {
		s.loseReply = ""
		return nil, errors.New("controlled successful S3 reply lost")
	}
	return response, nil
}

func (s *fsOperationProducer) UmountOSS(req *imageapi.OSSUmountRequest) error {
	s.mu.Lock()
	copy := *req
	s.ossUnmounts = append(s.ossUnmounts, &copy)
	s.mu.Unlock()
	return s.fsTestImageService.UmountOSS(req)
}

func fsOperationRequest(id string) *runtime.StartRequest {
	r := fsTestStartRequest(id)
	r.Labels = map[string]string{resourceGenerationLabel: id + "-original-generation"}
	return r
}

func TestFSMountOperationSharedRootAndExtraRegisterEveryOwner(t *testing.T) {
	st, service := newOwnershipStore(t), newFSOperationProducer(t)
	m := newFSManager(service, st)
	for _, id := range []string{"owner-a", "owner-b"} {
		r := fsOperationRequest(id)
		r.Mounts[0].Source = &runtime.Mount_ImageUrl{ImageUrl: r.Rootfs.GetImageUrl()}
		_, err := m.Prepare(r)
		require.NoError(t, err)
	}
	ids := make(map[string]bool)
	for _, req := range service.requests {
		require.NotEmpty(t, req.OperationID)
		require.False(t, ids[req.OperationID])
		ids[req.OperationID] = true
	}
	require.Len(t, ids, 4, "rootfs reuse and source cache hits cannot skip per-owner registration")
	require.Equal(t, 1, service.mountCalls("registry.example/rootfs:latest"))
	require.NoError(t, m.ReleaseIfGeneration("owner-a", "owner-a-original-generation"))
	require.Zero(t, service.umountCalls("registry.example/rootfs:latest"))
	require.NoError(t, m.ReleaseIfGeneration("owner-b", "owner-b-original-generation"))
	require.Equal(t, 1, service.umountCalls("registry.example/rootfs:latest"))
}

func TestFSMountOperationLostReplyFindsOriginalResultAfterBothJournalsReopen(t *testing.T) {
	st, service := newOwnershipStore(t), newFSOperationProducer(t)
	r := fsOperationRequest("lost-reply")
	service.loseReply = r.Rootfs.GetImageUrl()
	m := newFSManager(service, st)
	_, err := m.Prepare(r)
	require.Error(t, err)
	reopenedProducer := &fsOperationProducer{fsTestImageService: service.fsTestImageService, journal: service.journal}
	reopened := newFSManager(reopenedProducer, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NotEmpty(t, reopened.sandboxState[r.SandboxID].RootfsMountGeneration)
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()), "recovery must query, never mount a replacement by URL")
	require.NotEmpty(t, reopenedProducer.queries)
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
}

func TestFSMountOperationLostUpperConfirmationRecoversProducerBinding(t *testing.T) {
	st, service := newOwnershipStore(t), newFSOperationProducer(t)
	r := fsOperationRequest("lost-confirmation")
	st.failWhen = func(raw []byte) bool {
		var j storedSandboxFSStates
		require.NoError(t, json.Unmarshal(raw, &j))
		return j.Items[r.SandboxID].RootfsPhase == fsAcquired
	}
	_, err := newFSManager(service, st).Prepare(r)
	require.Error(t, err)
	reopened := newFSManager(&fsOperationProducer{fsTestImageService: service.fsTestImageService, journal: service.journal}, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.Equal(t, 1, service.mountCalls(r.Rootfs.GetImageUrl()))
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	raw, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	j, err := decodeFSJournal(raw)
	require.NoError(t, err)
	require.Empty(t, j.Items)
	require.Contains(t, j.Completed, fsCompletionKey(r.SandboxID, r.Labels[resourceGenerationLabel]))
}

// Embedding only Service deliberately hides the producer's query extension.
type fsMountServiceWithoutQueries struct{ imageapi.Service }

type fsFaultyOperationQuery struct {
	*fsOperationProducer
	fault func(*imageapi.MountOperationResult) (*imageapi.MountOperationResult, error)
}

func (s *fsFaultyOperationQuery) QueryMountOperation(q *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	r, err := s.fsOperationProducer.QueryMountOperation(q)
	if err != nil || s.fault == nil {
		return r, err
	}
	return s.fault(r)
}

func TestFSMountOperationRequiresJournalAndQueryableProducerBeforeDispatch(t *testing.T) {
	for _, missing := range []string{"journal", "query-extension"} {
		t.Run(missing, func(t *testing.T) {
			producer := newFSOperationProducer(t)
			var svc imageapi.Service = producer
			var st store.DbStore = newOwnershipStore(t)
			if missing == "journal" {
				st = nil
			} else {
				svc = &fsMountServiceWithoutQueries{Service: producer}
			}
			m := newFSManager(svc, st)
			_, err := m.Prepare(fsOperationRequest("unsupported"))
			require.Error(t, err)
			require.Empty(t, producer.requests)
			require.Empty(t, m.sandboxState)
		})
	}
}

func TestFSMountOperationQueryIdentityAndUnknownResultsBlockRecovery(t *testing.T) {
	faults := map[string]func(*imageapi.MountOperationResult) (*imageapi.MountOperationResult, error){
		"nil": func(*imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) { return nil, nil },
		"error": func(*imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			return nil, errors.New("controlled query failure")
		},
		"operation": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.OperationID = strings.Repeat("b", 64)
			return r, nil
		},
		"fingerprint": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.RequestFingerprint = strings.Repeat("b", 64)
			return r, nil
		},
		"kind": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.Kind = "oss"
			return r, nil
		},
		"generation": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.PhysicalGeneration = strings.Repeat("b", 64)
			return r, nil
		},
		"path": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.MountPoint = "relative/target"
			return r, nil
		},
		"different-target": func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.MountPoint = "/another/target"
			return r, nil
		},
	}
	for _, phase := range []string{"absent", "intent", "unresolved", "released", "release_pending", "invalid-state"} {
		faults[phase] = func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
			r.State = phase
			return r, nil
		}
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			st, producer := newOwnershipStore(t), newFSOperationProducer(t)
			r := fsOperationRequest("wrong-result")
			r.Mounts = nil
			_, err := newFSManager(producer, st).Prepare(r)
			require.NoError(t, err)
			m := newFSManager(&fsFaultyOperationQuery{fsOperationProducer: producer, fault: fault}, st)
			require.Error(t, m.Restore(func(string) bool { return true }))
			require.Empty(t, m.sandboxRootfs)
			require.Empty(t, m.oci.entries)
			require.Equal(t, 1, producer.mountCalls(r.Rootfs.GetImageUrl()))
			require.Zero(t, producer.umountCalls(r.Rootfs.GetImageUrl()))
		})
	}
}

func TestFSMountOperationQueriesEntireInventoryBeforeReferences(t *testing.T) {
	st, producer := newOwnershipStore(t), newFSOperationProducer(t)
	m := newFSManager(producer, st)
	for _, id := range []string{"a-valid", "z-invalid"} {
		_, err := m.Prepare(fsOperationRequest(id))
		require.NoError(t, err)
	}
	badID := fsMountOperationID(m.sandboxState["z-invalid"], "oci", 0)
	service := &fsFaultyOperationQuery{fsOperationProducer: producer, fault: func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
		if r.OperationID == badID {
			r.State = "unresolved"
		}
		return r, nil
	}}
	reopened := newFSManager(service, st)
	require.Error(t, reopened.Restore(func(string) bool { return true }))
	require.Empty(t, reopened.sandboxRootfs)
	require.Empty(t, reopened.oci.entries)
	require.Equal(t, 1, producer.mountCalls("registry.example/rootfs:latest"))
	require.Zero(t, producer.umountCalls("registry.example/rootfs:latest"))
}

func TestFSMountOperationSchemaFourPreservesBindingsWithoutInventingOperations(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			st, producer := newOwnershipStore(t), newFSOperationProducer(t)
			r := fsOperationRequest("old-owner")
			r.Mounts = nil
			m := newFSManager(producer, st)
			_, err := m.Prepare(r)
			require.NoError(t, err)
			state := cloneFSState(m.sandboxState[r.SandboxID])
			state.MountOperationProtocol = 0
			if unknown {
				state.RootfsPhase = fsAcquiring
				state.RootfsMountGeneration = ""
			}
			j := storedSandboxFSStates{SchemaVersion: 4, Items: map[string]sandboxFSState{r.SandboxID: state}}
			j.IntegritySHA256, err = fsJournalIntegrity(j)
			require.NoError(t, err)
			raw, err := json.Marshal(j)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, raw))
			beforeQueries := len(producer.queries)
			reopened := newFSManager(producer, st)
			err = reopened.Restore(func(string) bool { return true })
			if unknown {
				require.Error(t, err)
				require.Empty(t, reopened.sandboxRootfs)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint8(0), reopened.sandboxState[r.SandboxID].MountOperationProtocol)
				require.Empty(t, fsMountOperationID(reopened.sandboxState[r.SandboxID], "rootfs", 0))
				require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
			}
			require.Len(t, producer.queries, beforeQueries, "old owners cannot acquire post-hoc operation identities")
			require.Equal(t, 1, producer.mountCalls(r.Rootfs.GetImageUrl()))
		})
	}
}

func TestFSMountOperationSchemaFourRejectsNewOwnershipFields(t *testing.T) {
	for _, field := range []string{"mount_operation_protocol", "release_requested"} {
		t.Run(field, func(t *testing.T) {
			st, producer := newOwnershipStore(t), newFSOperationProducer(t)
			r := fsOperationRequest("old-fields")
			r.Mounts = nil
			m := newFSManager(producer, st)
			_, err := m.Prepare(r)
			require.NoError(t, err)
			state := cloneFSState(m.sandboxState[r.SandboxID])
			state.MountOperationProtocol = 0
			j := storedSandboxFSStates{SchemaVersion: 4, Items: map[string]sandboxFSState{r.SandboxID: state}}
			j.IntegritySHA256, err = fsJournalIntegrity(j)
			require.NoError(t, err)
			raw, err := json.Marshal(j)
			require.NoError(t, err)
			var envelope map[string]any
			require.NoError(t, json.Unmarshal(raw, &envelope))
			owner := envelope["items"].(map[string]any)[r.SandboxID].(map[string]any)
			if field == "mount_operation_protocol" {
				owner[field] = 0
			} else {
				owner[field] = false
			}
			raw, err = json.Marshal(envelope)
			require.NoError(t, err)
			require.NoError(t, st.StoreRaw(config.SandboxFSStateBucket, raw))
			reopened := newFSManager(producer, st)
			require.Error(t, reopened.Restore(func(string) bool { return true }))
			reopened.Shutdown()
			after, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			require.Equal(t, raw, after)
		})
	}
}

func TestFSMountOperationProtocolAndCleanupIntentCannotRegress(t *testing.T) {
	st, producer := newOwnershipStore(t), newFSOperationProducer(t)
	r := fsOperationRequest("monotonic-owner")
	m := newFSManager(producer, st)
	_, err := m.Prepare(r)
	require.NoError(t, err)
	state := cloneFSState(m.sandboxState[r.SandboxID])
	state.ReleaseRequested = true
	m.persistMu.Lock()
	require.NoError(t, m.saveStateLocked(r.SandboxID, state))
	m.persistMu.Unlock()
	before, err := st.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	for _, change := range []string{"protocol", "cleanup-intent"} {
		next := cloneFSState(state)
		if change == "protocol" {
			next.MountOperationProtocol = 0
		} else {
			next.ReleaseRequested = false
		}
		m.persistMu.Lock()
		err = m.saveStateLocked(r.SandboxID, next)
		m.persistMu.Unlock()
		require.Error(t, err)
		after, err := st.LoadRaw(config.SandboxFSStateBucket)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
}

func TestFSMountOperationOrphanCompletedProducerContinuesOriginalCleanup(t *testing.T) {
	st := newOwnershipStore(t)
	producer := &fsCompletedMountService{ownershipImageService: newOwnershipImageService(), completed: make(map[string]bool)}
	r := fsOperationRequest("orphan-completed")
	r.Mounts = nil
	m := newFSManager(producer, st)
	_, err := m.Prepare(r)
	require.NoError(t, err)
	g := m.sandboxState[r.SandboxID].RootfsMountGeneration
	producer.completed[r.Rootfs.GetImageUrl()+"\x00"+g] = true
	producer.physicalGenerations[r.Rootfs.GetImageUrl()] = strings.Repeat("b", 64)
	reopened := newFSManager(producer, st)
	require.NoError(t, reopened.Restore(func(string) bool { return false }))
	require.Empty(t, reopened.sandboxState)
	require.Contains(t, reopened.completed, fsCompletionKey(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Equal(t, strings.Repeat("b", 64), producer.physicalGenerations[r.Rootfs.GetImageUrl()])
	require.Zero(t, producer.umountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountOperationDefaultMounterVerifiesIndependentResult(t *testing.T) {
	producer := newFSOperationProducer(t)
	service := &fsFaultyOperationQuery{fsOperationProducer: producer, fault: func(r *imageapi.MountOperationResult) (*imageapi.MountOperationResult, error) {
		r.MountPoint = "/different/target"
		return r, nil
	}}
	_, err := langrtmanager.NewRootFS(langrtmanager.RootfsConfig{SrcType: runtime.RootfsSrcType_IMAGE, ImageUrl: "registry.example/default:tag", RequirePhysicalGeneration: true, MountOperationID: strings.Repeat("a", 64)}, langrtmanager.NewDefaultMounter(service), nil)
	require.Error(t, err)
	require.Equal(t, 1, producer.mountCalls("registry.example/default:tag"))
	require.Zero(t, producer.umountCalls("registry.example/default:tag"))
}

func TestFSMountOperationLocalRootDoesNotNeedImageService(t *testing.T) {
	m := newFSManager(nil, newOwnershipStore(t))
	r := fsOperationRequest("local-root")
	r.Mounts = nil
	r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}}
	_, err := m.Prepare(r)
	require.NoError(t, err)
	require.Empty(t, fsMountOperationID(m.sandboxState[r.SandboxID], "rootfs", 0))
	require.NoError(t, m.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
}

func TestFSMountOperationRepeatedSourceSlotsKeepDistinctStableOperations(t *testing.T) {
	st, producer := newOwnershipStore(t), newFSOperationProducer(t)
	r := fsOperationRequest("repeated-slots")
	r.Mounts = []*runtime.Mount{{Target: "/one", Options: []string{"ro"}, Source: &runtime.Mount_ImageUrl{ImageUrl: r.Rootfs.GetImageUrl()}}, {Target: "/two", Options: []string{"ro"}, Source: &runtime.Mount_ImageUrl{ImageUrl: r.Rootfs.GetImageUrl()}}}
	m := newFSManager(producer, st)
	_, err := m.Prepare(r)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, req := range producer.requests {
		require.NotEmpty(t, req.OperationID)
		require.False(t, ids[req.OperationID])
		ids[req.OperationID] = true
	}
	require.Len(t, ids, 3)
	reopenedProducer := &fsOperationProducer{fsTestImageService: producer.fsTestImageService, journal: producer.journal}
	reopened := newFSManager(reopenedProducer, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	for _, req := range reopenedProducer.requests {
		require.True(t, ids[req.OperationID])
	}
	require.Equal(t, 1, producer.mountCalls(r.Rootfs.GetImageUrl()))
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Equal(t, 1, producer.umountCalls(r.Rootfs.GetImageUrl()))
}

func TestFSMountOperationS3LostReplyRecoversOriginalProducerBinding(t *testing.T) {
	st, producer := newOwnershipStore(t), newFSOperationProducer(t)
	source := &runtime.S3Config{Endpoint: "https://s3.example", Bucket: "controlled", Object: "original"}
	key := source.Endpoint + "\x00" + source.Bucket + "\x00" + source.Object
	r := fsOperationRequest("s3-lost-reply")
	r.Mounts = nil
	r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_S3, Source: &runtime.RootfsConfig_S3Config{S3Config: source}}
	producer.loseReply = key
	_, err := newFSManager(producer, st).Prepare(r)
	require.Error(t, err)
	original := producer.physicalGenerations[key]
	reopenedProducer := &fsOperationProducer{fsTestImageService: producer.fsTestImageService, journal: producer.journal}
	reopened := newFSManager(reopenedProducer, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.Equal(t, original, reopened.sandboxState[r.SandboxID].RootfsMountGeneration)
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Len(t, reopenedProducer.ossUnmounts, 1)
	require.Equal(t, original, reopenedProducer.ossUnmounts[0].PhysicalGeneration)
}

func TestFSMountOperationIntentWriteFailureStopsTheCorrespondingDispatch(t *testing.T) {
	for _, step := range []string{"rootfs", "additional-image"} {
		t.Run(step, func(t *testing.T) {
			st, producer := newOwnershipStore(t), newFSOperationProducer(t)
			r := fsOperationRequest("failed-intent")
			st.failWhen = func(raw []byte) bool {
				var j storedSandboxFSStates
				require.NoError(t, json.Unmarshal(raw, &j))
				state, exists := j.Items[r.SandboxID]
				if !exists {
					return false
				}
				if step == "rootfs" {
					return state.RootfsPhase == fsAcquiring
				}
				return state.OCIPhases[0] == fsAcquiring
			}
			_, err := newFSManager(producer, st).Prepare(r)
			require.Error(t, err)
			if step == "rootfs" {
				require.Empty(t, producer.requests)
			} else {
				require.Len(t, producer.requests, 1)
				require.Equal(t, r.Rootfs.GetImageUrl(), producer.requests[0].ImageURL)
			}
			require.Zero(t, producer.mountCalls(r.Mounts[0].GetImageUrl()))
		})
	}
}
