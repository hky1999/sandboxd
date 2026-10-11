// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
)

type cleanupOnlyManager struct {
	*mockManager
	activations int
}

func (m *cleanupOnlyManager) SetDaemonReferencedIfPhysicalGeneration(string, string, bool) error {
	m.activations++
	return fmt.Errorf("cleanup-only ownership must not activate a source")
}

// This fixture loads private persisted metadata through the production reader.
// It performs no mounts, signals, process starts, or cgroup modifications.
func cleanupMountOperationFixture(t *testing.T, kind, phase string, noDispatch bool) (*HttpWorker, any, *mountOperationRecord, *cleanupOnlyManager) {
	t.Helper()
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: newMockManager(), DBPath: filepath.Join(t.TempDir(), "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	operation, generation := strings.Repeat("c", 64), strings.Repeat("a", 64)
	image := "registry.example/original:nydus"
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "original-mount")
	var request any
	backend, facade, daemonID := image, "", generateNydusID(image)
	switch kind {
	case "oss":
		request = &OSSMountRequest{OperationID: operation, PhysicalGeneration: generation, Endpoint: "objects.example", Bucket: "original", Object: "root.erofs"}
		backend = ""
		daemonID = generateOSSID("objects.example", "original", "root.erofs")
	case "nydus":
		request = &NydusMountRequest{OperationID: operation, PhysicalGeneration: generation, ImageURL: image}
	case "oci":
		facade = "registry.example/original:tag"
		request = &OCIMountRequest{OperationID: operation, PhysicalGeneration: generation, ImageURL: facade, RequirePhysicalGeneration: true}
	default:
		t.Fatalf("unsupported fixture kind %q", kind)
	}
	fingerprint, err := MountRequestFingerprint(request)
	require.NoError(t, err)
	record := &mountOperationRecord{OperationID: operation, RequestFingerprint: fingerprint, Kind: kind, Phase: "bound", PhysicalGeneration: generation, DaemonID: daemonID, MountPoint: target, ImageURL: facade, NydusImageURL: backend}
	seedMountOperation(t, w, record)
	if kind == "oci" {
		require.NoError(t, w.mountStore.Put(facade, &MountRecord{ImageURL: facade, MountType: "nydus", NydusImageURL: backend, MountPoint: target, PhysicalGeneration: generation}))
	}
	meta := distillfs.DaemonMeta{SchemaVersion: 1, ID: daemonID, Name: "root.erofs", DaemonDir: dir, CfgPath: filepath.Join(dir, "config.json"), MountPoint: target, PidFilePath: filepath.Join(dir, "pid-"+generation), SourceType: "oss"}
	if kind != "oss" {
		meta.SourceType, meta.ImageURL = "nydus", backend
	}
	physical, err := json.Marshal(map[string]any{"physical_identity": map[string]any{
		"generation": generation, "target": target, "pid_file": meta.PidFilePath,
		"executable_sha256": strings.Repeat("d", 64), "arguments_sha256": strings.Repeat("e", 64), "source_sha256": strings.Repeat("f", 64),
		"phase": phase, "no_dispatch_confirmed": noDispatch, "unmount_succeeded": false,
		"scope": map[string]any{"boot_id": "11111111-2222-3333-4444-555555555555", "mount_namespace_device": 1, "mount_namespace_inode": 2, "pid_namespace_device": 3, "pid_namespace_inode": 4},
	}})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(physical, &meta))
	canonical, err := json.Marshal(meta)
	require.NoError(t, err)
	digest := sha256.Sum256(canonical)
	meta.IntegritySHA256 = hex.EncodeToString(digest[:])
	raw, err := json.Marshal(meta)
	require.NoError(t, err)
	metadataPath := filepath.Join(dir, "metadata.json")
	require.NoError(t, os.WriteFile(metadataPath, raw, 0600))
	require.NoError(t, os.WriteFile(meta.CfgPath, []byte("{}"), 0600))
	mgr := &cleanupOnlyManager{mockManager: newMockManager()}
	mgr.createDaemonFunc = func(*distillfs.DaemonCreateOpt) error { t.Fatal("recovery must not allocate a daemon"); return nil }
	mgr.getDaemonFunc = func(id string) *distillfs.Daemon {
		require.Equal(t, daemonID, id)
		d := &distillfs.Daemon{}
		require.NoError(t, d.LoadExisted(metadataPath))
		return d
	}
	w.mgr = mgr
	return w, request, record, mgr
}

func replayCleanupMount(t *testing.T, w *HttpWorker, request any) (*MountInfo, error) {
	t.Helper()
	switch req := request.(type) {
	case *OSSMountRequest:
		return w.MountOSS(req)
	case *NydusMountRequest:
		return w.MountNydus(req)
	case *OCIMountRequest:
		response, err := w.MountOCI(req)
		if err != nil {
			return nil, err
		}
		return &MountInfo{MountPoint: response.MountPath, PhysicalGeneration: response.PhysicalGeneration, Released: response.Released, ReleasePending: response.ReleasePending}, nil
	default:
		t.Fatal("unsupported fixture request")
		return nil, nil
	}
}

func TestMountOperationFailedStartRecoveryKeepsCleanupOnly(t *testing.T) {
	for _, kind := range []string{"oss", "nydus", "oci"} {
		for _, phase := range []string{"not_started", "releasing", "released"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				w, request, record, mgr := cleanupMountOperationFixture(t, kind, phase, true)
				query := &MountOperationQuery{record.OperationID, record.RequestFingerprint}
				for attempt := 0; attempt < 2; attempt++ {
					result, err := w.QueryMountOperation(query)
					require.NoError(t, err)
					state := "release_pending"
					if phase == "released" {
						state = "released"
					}
					require.Equal(t, state, result.State)
					_, err = QueryOriginalMountOperation(w, request, record.OperationID, kind, false)
					require.Error(t, err, "cleanup cannot become a runnable source")
					_, err = QueryOriginalMountOperation(w, request, record.OperationID, kind, true)
					require.NoError(t, err)
					info, err := replayCleanupMount(t, w, request)
					require.NoError(t, err)
					require.Equal(t, record.PhysicalGeneration, info.PhysicalGeneration)
					require.Equal(t, record.MountPoint, info.MountPoint)
					require.Equal(t, phase == "released", info.Released)
					require.Equal(t, phase != "released", info.ReleasePending)
					stored, err := w.mountStore.getMountOperation(query)
					require.NoError(t, err)
					require.Equal(t, record, stored, "recovery must not persist a success confirmation for an unstarted or released mount")
					require.Zero(t, mgr.activations)
					reopenMountOperationWorker(t, w)
				}
			})
		}
	}
}

func TestMountOperationNewCleanupOwnerNeverConfirmsReady(t *testing.T) {
	for _, kind := range []string{"oss", "nydus", "oci"} {
		t.Run(kind, func(t *testing.T) {
			w, request, original, mgr := cleanupMountOperationFixture(t, kind, "not_started", true)
			operation := strings.Repeat("b", 64)
			switch req := request.(type) {
			case *OSSMountRequest:
				req.OperationID = operation
			case *NydusMountRequest:
				req.OperationID = operation
			case *OCIMountRequest:
				req.OperationID = operation
			}
			info, err := replayCleanupMount(t, w, request)
			require.NoError(t, err)
			require.True(t, info.ReleasePending)
			stored, err := w.mountStore.getMountOperation(&MountOperationQuery{operation, original.RequestFingerprint})
			require.NoError(t, err)
			expected := *original
			expected.OperationID = operation
			require.Equal(t, &expected, stored)
			require.Zero(t, mgr.activations)
		})
	}
}

func TestMountOperationInterruptedBirthReopenCannotBecomeReady(t *testing.T) {
	for _, phase := range []string{"launching", "releasing"} {
		t.Run(phase, func(t *testing.T) {
			w, request, record, mgr := cleanupMountOperationFixture(t, "oss", phase, false)
			for attempt := 0; attempt < 2; attempt++ {
				result, err := w.QueryMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
				require.NoError(t, err)
				require.NotEqual(t, "ready", result.State)
				require.NotEqual(t, "released", result.State, "a missing original birth is not completed release")
				_, err = QueryOriginalMountOperation(w, request, record.OperationID, "oss", false)
				require.Error(t, err)
				info, err := replayCleanupMount(t, w, request)
				if phase == "launching" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.True(t, info.ReleasePending)
					require.False(t, info.Released)
				}
				stored, err := w.mountStore.getMountOperation(&MountOperationQuery{record.OperationID, record.RequestFingerprint})
				require.NoError(t, err)
				require.Equal(t, record, stored)
				require.Zero(t, mgr.activations)
				reopenMountOperationWorker(t, w)
			}
		})
	}
}
