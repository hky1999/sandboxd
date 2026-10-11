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
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
)

// Only private files and native journals are used. OCI fails before backend
// admission; S3's controlled transport does not deliver the original request.
type fsNoAllocationProducer struct {
	*imageapi.HttpWorker
	ossRequest   *imageapi.OSSMountRequest
	ociRequest   *imageapi.OCIMountRequest
	retireCalls  int
	unmountCalls int
	failRetire   bool
}

func (s *fsNoAllocationProducer) MountOCI(r *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	copy := *r
	s.ociRequest = &copy
	return s.HttpWorker.MountOCI(r)
}

func (s *fsNoAllocationProducer) MountOSS(r *imageapi.OSSMountRequest) (*imageapi.MountInfo, error) {
	copy := *r
	s.ossRequest = &copy
	return nil, errors.New("controlled S3 request not delivered")
}

func (s *fsNoAllocationProducer) RetireMountOperation(r *imageapi.MountOperationRetirement) (*imageapi.MountOperationResult, error) {
	s.retireCalls++
	if s.failRetire {
		return nil, errors.New("controlled allocation fence unavailable")
	}
	return s.HttpWorker.RetireMountOperation(r)
}

func (s *fsNoAllocationProducer) UmountOSS(r *imageapi.OSSUmountRequest) error {
	s.unmountCalls++
	return s.HttpWorker.UmountOSS(r)
}

func (s *fsNoAllocationProducer) UmountOCI(r *imageapi.OCIUmountRequest) error {
	s.unmountCalls++
	return s.HttpWorker.UmountOCI(r)
}

func fsNoAllocationNative(t *testing.T) (*fsNoAllocationProducer, distillfs.Manager, *distillfs.ManagerConfig) {
	t.Helper()
	cfgRoot := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(cfgRoot, name)
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0600))
		return p
	}
	cfg := &distillfs.ManagerConfig{Root: t.TempDir(), DisableCgroup: true, OSSCfgPath: file("oss.json"), NydusCfgPath: file("nydus.json"), OSSAuthsPath: file("objects.json"), RegistryAuthsPath: file("registry.json")}
	m, err := distillfs.NewManager(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background())) })
	w, err := imageapi.NewHttpWorker(&imageapi.HttpWorkerConfig{Manager: m, DBPath: filepath.Join(cfg.Root, "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	return &fsNoAllocationProducer{HttpWorker: w}, m, cfg
}

func TestFSMountOperationNoAllocationCleanupSurvivesNativeAndFilesystemReopen(t *testing.T) {
	for _, source := range []string{"root-oci", "root-s3", "extra-oci", "extra-s3"} {
		t.Run(source, func(t *testing.T) {
			service, native, cfg := fsNoAllocationNative(t)
			st := newOwnershipStore(t)
			r := fsOperationRequest("original-" + source)
			r.Mounts = nil
			objects := &runtime.S3Config{Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
			switch source {
			case "root-s3":
				r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_S3, Source: &runtime.RootfsConfig_S3Config{S3Config: objects}}
			case "extra-oci", "extra-s3":
				r.Rootfs = &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL, Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}}
				mount := &runtime.Mount{Target: "/data", Options: []string{"ro"}}
				if source == "extra-oci" {
					mount.Source = &runtime.Mount_ImageUrl{ImageUrl: "registry.example/original:fixed"}
				} else {
					mount.Source = &runtime.Mount_S3Config{S3Config: objects}
				}
				r.Mounts = []*runtime.Mount{mount}
			}
			m := newFSManager(service, st)
			prepared, err := m.Prepare(r)
			require.Error(t, err)
			require.NotNil(t, prepared)
			var request any
			var operationID, kind string
			if strings.HasSuffix(source, "s3") {
				request, operationID, kind = service.ossRequest, service.ossRequest.OperationID, "oss"
			} else {
				request, operationID, kind = service.ociRequest, service.ociRequest.OperationID, "oci"
			}
			require.NoError(t, service.CloseWithContext(context.Background()))
			require.NoError(t, native.(distillfs.ManagerLifecycle).Close(context.Background()))
			native, err = distillfs.NewManager(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, native.(distillfs.ManagerLifecycle).Close(context.Background())) })
			worker, err := imageapi.NewHttpWorker(&imageapi.HttpWorkerConfig{Manager: native, DBPath: filepath.Join(cfg.Root, "mounts.db")})
			require.NoError(t, err)
			t.Cleanup(worker.Close)
			service = &fsNoAllocationProducer{HttpWorker: worker}
			m = newFSManager(service, st)
			require.Error(t, m.Restore(func(string) bool { return true }), "live-owner recovery cannot authorize allocation retirement")
			require.Zero(t, service.retireCalls)
			require.Error(t, m.ReleaseIfGeneration(r.SandboxID, "replacement-generation"))
			require.Zero(t, service.retireCalls)
			require.NoError(t, m.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
			require.Equal(t, 1, service.retireCalls)
			require.Zero(t, service.unmountCalls, "unallocated sources cannot borrow or release a source reference")
			proof, err := imageapi.QueryOriginalMountOperation(service, request, operationID, kind, true)
			require.NoError(t, err)
			require.Equal(t, "not_allocated", proof.State)
			require.Empty(t, proof.PhysicalGeneration)
			raw, err := st.LoadRaw(config.SandboxFSStateBucket)
			require.NoError(t, err)
			var saved storedSandboxFSStates
			require.NoError(t, json.Unmarshal(raw, &saved))
			require.Empty(t, saved.Items)
			receipt := saved.Completed[fsCompletionKey(r.SandboxID, r.Labels[resourceGenerationLabel])]
			require.Equal(t, r.SandboxID, receipt.SandboxID)
			require.Equal(t, r.Labels[resourceGenerationLabel], receipt.Generation)
			reopened := newFSManager(service, st)
			require.NoError(t, reopened.Restore(func(string) bool { return true }))
			require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, receipt.Generation))
			require.Equal(t, 1, service.retireCalls)
			if req, ok := request.(*imageapi.OSSMountRequest); ok {
				_, err = worker.MountOSS(req)
			} else {
				_, err = worker.MountOCI(request.(*imageapi.OCIMountRequest))
			}
			require.Error(t, err, "the original filesystem operation remains fenced after upper completion")
			allocations, err := filepath.Glob(filepath.Join(cfg.Root, "allocations", "*"))
			require.NoError(t, err)
			require.Empty(t, allocations)
		})
	}
}

func TestFSMountOperationNoAllocationFailedFenceAndConfirmationRetainOwner(t *testing.T) {
	service, _, _ := fsNoAllocationNative(t)
	st := newOwnershipStore(t)
	r := fsOperationRequest("confirmation-failure")
	r.Mounts = nil
	m := newFSManager(service, st)
	_, err := m.Prepare(r)
	require.Error(t, err)
	service.failRetire = true
	require.Error(t, m.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Empty(t, m.completed)
	require.Equal(t, fsAcquiring, m.sandboxState[r.SandboxID].RootfsPhase)
	service.failRetire = false
	st.failWhen = func(raw []byte) bool {
		var state storedSandboxFSStates
		require.NoError(t, json.Unmarshal(raw, &state))
		return state.Items[r.SandboxID].RootfsPhase == fsReleased
	}
	require.Error(t, m.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Empty(t, m.completed, "a failed upper confirmation cannot publish whole filesystem completion")
	reopened := newFSManager(service, st)
	require.NoError(t, reopened.Restore(func(string) bool { return true }))
	require.NoError(t, reopened.ReleaseIfGeneration(r.SandboxID, r.Labels[resourceGenerationLabel]))
	require.Zero(t, service.unmountCalls)
	require.NotEmpty(t, reopened.completed)
}
