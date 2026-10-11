// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
	"github.com/inclusionAI/sandboxd/pkg/store"
)

type fsTestImageService struct {
	operations           map[string]fsOperationProducerRecord
	physicalGenerations  map[string]string
	unmountedGenerations []string
	mu                   sync.Mutex
	ociMountCalls        map[string]int
	ociUmountCalls       map[string]int
}

func newFSTestImageService() *fsTestImageService {
	return &fsTestImageService{
		ociMountCalls:  make(map[string]int),
		ociUmountCalls: make(map[string]int),
	}
}

func (s *fsTestImageService) MountOSS(req *imageapi.OSSMountRequest) (*imageapi.MountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.physicalGenerationLocked(req.Endpoint + "\x00" + req.Bucket + "\x00" + req.Object)
	if req.PhysicalGeneration != "" && req.PhysicalGeneration != g {
		return nil, fmt.Errorf("original test mount generation changed")
	}
	path := "/mnt/s3/" + req.Object
	if err := s.recordOperationLocked(req, req.OperationID, req.Endpoint+"\x00"+req.Bucket+"\x00"+req.Object, "oss", g, path); err != nil {
		return nil, err
	}
	return &imageapi.MountInfo{FilePath: path, MountPoint: path, PhysicalGeneration: g}, nil
}

func (s *fsTestImageService) UmountOSS(*imageapi.OSSUmountRequest) error { return nil }

func (s *fsTestImageService) MountOCI(req *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.physicalGenerationLocked(req.ImageURL)
	if err := s.recordOperationLocked(req, req.OperationID, req.ImageURL, "oci", g, "/mnt/oci/"+req.ImageURL); err != nil {
		return nil, err
	}
	if req.PhysicalGeneration != "" {
		if req.PhysicalGeneration != g {
			return nil, fmt.Errorf("original test mount generation changed")
		}
		return &imageapi.OCIMountResponse{MountPath: "/mnt/oci/" + req.ImageURL, PhysicalGeneration: g}, nil
	}
	s.ociMountCalls[req.ImageURL]++
	return &imageapi.OCIMountResponse{MountPath: "/mnt/oci/" + req.ImageURL, PhysicalGeneration: g}, nil
}

func (s *fsTestImageService) recordOperationLocked(request any, id, source, kind, generation, path string) error {
	if id == "" {
		return nil
	}
	fingerprint, err := imageapi.MountRequestFingerprint(request)
	if err != nil {
		return err
	}
	if s.operations == nil {
		s.operations = make(map[string]fsOperationProducerRecord)
	}
	record := fsOperationProducerRecord{Source: source, Result: imageapi.MountOperationResult{OperationID: id, RequestFingerprint: fingerprint, Kind: kind, State: "ready", PhysicalGeneration: generation, MountPoint: path}}
	if old, ok := s.operations[id]; ok && old != record {
		return fmt.Errorf("original controlled producer operation changed")
	}
	s.operations[id] = record
	return nil
}

func (s *fsTestImageService) QueryMountOperation(query *imageapi.MountOperationQuery) (*imageapi.MountOperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.operations[query.OperationID]
	if !ok {
		return &imageapi.MountOperationResult{OperationID: query.OperationID, RequestFingerprint: query.RequestFingerprint, State: "absent"}, nil
	}
	if record.Result.RequestFingerprint != query.RequestFingerprint {
		return nil, fmt.Errorf("original controlled operation request changed")
	}
	result := record.Result
	if s.physicalGenerations[record.Source] != result.PhysicalGeneration {
		result.State = "unresolved"
	}
	return &result, nil
}

func (s *fsTestImageService) physicalGenerationLocked(source string) string {
	if s.physicalGenerations == nil {
		s.physicalGenerations = make(map[string]string)
	}
	if s.physicalGenerations[source] == "" {
		h := sha256.Sum256([]byte("controlled-original-mount:" + source))
		s.physicalGenerations[source] = hex.EncodeToString(h[:])
	}
	return s.physicalGenerations[source]
}

func (s *fsTestImageService) ImageProcess(string) (*imageconfig.Process, error) {
	return &imageconfig.Process{}, nil
}

func (s *fsTestImageService) UmountOCI(req *imageapi.OCIUmountRequest) error {
	s.mu.Lock()
	s.unmountedGenerations = append(s.unmountedGenerations, req.PhysicalGeneration)
	s.ociUmountCalls[req.ImageURL]++
	s.mu.Unlock()
	return nil
}

func (s *fsTestImageService) MountNydus(*imageapi.NydusMountRequest) (*imageapi.MountInfo, error) {
	return &imageapi.MountInfo{}, nil
}

func (s *fsTestImageService) UmountNydus(*imageapi.NydusUmountRequest) error { return nil }
func (s *fsTestImageService) CleanupDaemon(*imageapi.CleanupDaemonRequest) error {
	return nil
}
func (s *fsTestImageService) ListDaemons() ([]distillfs.DaemonInfo, error) { return nil, nil }
func (s *fsTestImageService) ListMountedOCIImages() ([]string, error)      { return nil, nil }
func (s *fsTestImageService) ListMountedOCIDetails() ([]oci.OciMountRecord, error) {
	return nil, nil
}

func (s *fsTestImageService) mountCalls(imageURL string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ociMountCalls[imageURL]
}

func (s *fsTestImageService) umountCalls(imageURL string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ociUmountCalls[imageURL]
}

func fsTestStartRequest(id string) *runtime.StartRequest {
	return &runtime.StartRequest{
		SandboxID: id,
		Rootfs: &runtime.RootfsConfig{
			Type: runtime.RootfsSrcType_IMAGE,
			Source: &runtime.RootfsConfig_ImageUrl{
				ImageUrl: "registry.example/rootfs:latest",
			},
		},
		Mounts: []*runtime.Mount{
			{
				Target:  "/opt/data",
				Options: []string{"ro"},
				Source: &runtime.Mount_ImageUrl{
					ImageUrl: "registry.example/data:latest",
				},
			},
		},
	}
}

func prepareAndCommitFS(t *testing.T, manager *fsManager, sandboxID string) {
	t.Helper()
	prepared, err := manager.Prepare(fsTestStartRequest(sandboxID))
	if err != nil {
		t.Fatalf("Prepare(%s) failed: %v", sandboxID, err)
	}
	if err := manager.Commit(sandboxID, prepared); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
}

func TestFSManagerCommitRetainsFailedPersistence(t *testing.T) {
	stateStore := newOwnershipStore(t)
	manager := newFSManager(newFSTestImageService(), stateStore)
	prepared, err := manager.Prepare(fsTestStartRequest("sbox-failed"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	stateStore.failNext = true

	if err := manager.Commit("sbox-failed", prepared); err == nil {
		t.Fatal("Commit() error = nil, want persistence failure")
	}
	if _, exists := manager.sandboxState["sbox-failed"]; !exists {
		t.Fatal("failed filesystem commit lost the original owner")
	}
	if err := prepared.Rollback(); err != nil {
		t.Fatalf("confirmed filesystem cleanup failed: %v", err)
	}
}

func TestFSManagerRestoresSharedRootfsAndMountReferences(t *testing.T) {
	stateStore := store.NewMockStore()
	service := newFSTestImageService()
	beforeCrash := newFSManager(service, stateStore)
	prepareAndCommitFS(t, beforeCrash, "sandbox-a")
	prepareAndCommitFS(t, beforeCrash, "sandbox-b")

	if got := service.mountCalls("registry.example/rootfs:latest"); got != 1 {
		t.Fatalf("rootfs mount calls before restart = %d, want 1", got)
	}
	if got := service.mountCalls("registry.example/data:latest"); got != 1 {
		t.Fatalf("additional mount calls before restart = %d, want 1", got)
	}

	afterCrash := newFSManager(service, stateStore)
	if err := afterCrash.Restore(func(string) bool { return true }); err != nil {
		t.Fatalf("Restore() failed: %v", err)
	}
	if got := afterCrash.oci.entries["registry.example/data:latest"].refcount; got != 2 {
		t.Fatalf("restored additional mount refcount = %d, want 2", got)
	}

	afterCrash.Release("sandbox-a")
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 0 {
		t.Fatalf("rootfs unmounted while sandbox-b still uses it: calls=%d", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 0 {
		t.Fatalf("additional mount unmounted while sandbox-b still uses it: calls=%d", got)
	}

	afterCrash.Release("sandbox-b")
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 1 {
		t.Fatalf("rootfs unmount calls after last release = %d, want 1", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 1 {
		t.Fatalf("additional unmount calls after last release = %d, want 1", got)
	}

	data, err := stateStore.LoadRaw(config.SandboxFSStateBucket)
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	var persisted storedSandboxFSStates
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted state: %v", err)
	}
	if len(persisted.Items) != 0 {
		t.Fatalf("persisted state not empty after releases: %+v", persisted.Items)
	}
}

func TestFSManagerRestoreCleansOrphanState(t *testing.T) {
	stateStore := store.NewMockStore()
	service := newFSTestImageService()
	beforeCrash := newFSManager(service, stateStore)
	prepareAndCommitFS(t, beforeCrash, "a-orphan")
	prepareAndCommitFS(t, beforeCrash, "z-live")

	afterCrash := newFSManager(service, stateStore)
	if err := afterCrash.Restore(func(id string) bool { return id == "z-live" }); err != nil {
		t.Fatalf("Restore() failed: %v", err)
	}
	if len(afterCrash.sandboxState) != 1 || afterCrash.sandboxState["z-live"].Rootfs == nil {
		t.Fatalf("restored filesystem state = %+v, want only z-live", afterCrash.sandboxState)
	}
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 0 {
		t.Fatalf("shared live rootfs was unmounted during restore: calls=%d", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 0 {
		t.Fatalf("shared live mount was unmounted during restore: calls=%d", got)
	}
}
