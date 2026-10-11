// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
)

// Native manager and native database, with cgroups disabled and no daemon,
// registry, mount, signal or model request. Only private files are allocated.
func TestMountOperationPreparationUnboundOriginalSurvivesFullReopen(t *testing.T) {
	for _, kind := range []string{"oss", "nydus", "oci"} {
		t.Run(kind, func(t *testing.T) {
			m, cfg := workerOwnershipManager(t)
			path := filepath.Join(cfg.Root, "mounts.db")
			w, err := NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: path})
			require.NoError(t, err)
			t.Cleanup(w.Close)
			op := strings.Repeat("c", 64)
			url := "registry.example/original@sha256:" + strings.Repeat("a", 64)
			var request any
			var opts *distillfs.DaemonCreateOpt
			facade := ""
			switch kind {
			case "oss":
				r := &OSSMountRequest{OperationID: op, Endpoint: "https://objects.example", Bucket: "original", Object: "root.erofs"}
				request = r
				opts = &distillfs.DaemonCreateOpt{ID: generateOSSID(r.Endpoint, r.Bucket, r.Object), Name: "root.erofs"}
			case "nydus":
				request = &NydusMountRequest{OperationID: op, ImageURL: url}
				opts = &distillfs.DaemonCreateOpt{ID: generateNydusID(url), Name: "original", SourceType: "nydus", ImageURL: url}
			case "oci":
				facade = "registry.example/facade:original"
				request = &OCIMountRequest{OperationID: op, ImageURL: facade, RequirePhysicalGeneration: true}
				opts = &distillfs.DaemonCreateOpt{ID: generateNydusID(url), Name: "original", SourceType: "nydus", ImageURL: url}
			}
			_, err = w.executeMountOperation(op, kind, facade, "", request, func(bind mountBinding) (*MountInfo, error) {
				failedBinding := *bind
				failedBinding.publish = func(string, string, string, string) error { return errors.New("controlled upper binding failure") }
				return nil, w.prepareDaemonForMount(opts, &failedBinding)
			})
			require.ErrorContains(t, err, "controlled upper binding failure")
			fp, err := MountRequestFingerprint(request)
			require.NoError(t, err)
			query := &MountOperationQuery{OperationID: op, RequestFingerprint: fp}
			original, err := w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "release_pending", original.State)
			require.NotEmpty(t, original.PhysicalGeneration)
			require.NoDirExists(t, filepath.Dir(original.MountPoint))
			stored, err := w.mountStore.getMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "intent", stored.Phase, "query must not publish a recovered binding")
			require.NoError(t, w.CloseWithContext(context.Background()))
			require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background()))
			m, err = distillfs.NewManager(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background())) })
			w, err = NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: path})
			require.NoError(t, err)
			t.Cleanup(w.Close)
			reopened, err := w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, original, reopened)
			_, err = w.QueryMountOperation(&MountOperationQuery{OperationID: op, RequestFingerprint: strings.Repeat("f", 64)})
			require.Error(t, err)
			var pending bool
			switch r := request.(type) {
			case *OSSMountRequest:
				info, err := w.MountOSS(r)
				require.NoError(t, err)
				pending = info.ReleasePending
			case *NydusMountRequest:
				info, err := w.MountNydus(r)
				require.NoError(t, err)
				pending = info.ReleasePending
			case *OCIMountRequest:
				info, err := w.MountOCI(r)
				require.NoError(t, err)
				pending = info.ReleasePending
			}
			require.True(t, pending, "retry only restores original cleanup ownership")
			require.NoDirExists(t, filepath.Dir(original.MountPoint))
			stored, err = w.mountStore.getMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "bound", stored.Phase)
			require.NoError(t, m.GetDaemon(opts.ID).UnmountIfPhysicalGeneration(original.PhysicalGeneration))
			result, err := w.QueryMountOperation(query)
			require.NoError(t, err)
			require.Equal(t, "released", result.State)
		})
	}
}

func TestMountOperationPreparationQueryDoesNotWaitForOriginalBinding(t *testing.T) {
	m, cfg := workerOwnershipManager(t)
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: filepath.Join(cfg.Root, "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	request := &OSSMountRequest{OperationID: strings.Repeat("a", 64), Endpoint: "https://objects.example", Bucket: "original", Object: "root.erofs"}
	opts := &distillfs.DaemonCreateOpt{ID: generateOSSID(request.Endpoint, request.Bucket, request.Object), Name: "root.erofs"}
	entered, proceed := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := w.executeMountOperation(request.OperationID, "oss", "", "", request, func(bind mountBinding) (*MountInfo, error) {
			interrupted := *bind
			interrupted.publish = func(string, string, string, string) error {
				close(entered)
				<-proceed
				return errors.New("binding interrupted")
			}
			return nil, w.prepareDaemonForMount(opts, &interrupted)
		})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original producer did not enter binding")
	}
	fp, err := MountRequestFingerprint(request)
	require.NoError(t, err)
	queried := make(chan *MountOperationResult, 1)
	go func() {
		result, _ := w.QueryMountOperation(&MountOperationQuery{OperationID: request.OperationID, RequestFingerprint: fp})
		queried <- result
	}()
	select {
	case result := <-queried:
		require.NotNil(t, result)
		require.Equal(t, "unresolved", result.State)
		require.NotEmpty(t, result.PhysicalGeneration)
	case <-time.After(time.Second):
		t.Fatal("independent query blocked behind producer binding")
	}
	close(proceed)
	require.Error(t, <-done)
}

func TestMountOperationPreparationRejectsLegacyAllocatorBeforeAnyEffect(t *testing.T) {
	w, _, _ := mountOperationFixture(t)
	calls := 0
	w.mgr.(*mockManager).createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { calls++; return nil }
	request := &OSSMountRequest{OperationID: strings.Repeat("e", 64), Endpoint: "https://objects.example", Bucket: "original", Object: "root.erofs"}
	_, err := w.MountOSS(request)
	require.ErrorContains(t, err, "pre-allocation ownership")
	require.Zero(t, calls, "managed requests never silently fall back to legacy allocation")
}
