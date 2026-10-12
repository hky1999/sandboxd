// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This case must run on the designated physical test host in an independently
// verified private mount namespace. It uses production manager, process and
// mount paths without replacing any observation, dispatch or cleanup function.
func TestDaemonManagedLaunchPhysicalOriginalMountRetirementAndReopen(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_MANAGED_LAUNCH_INTEGRATION") != "1" {
		t.Skip("requires explicitly enabled physical managed-launch integration")
	}
	require.Equal(t, "1", os.Getenv("SCHEDULER_MANAGED_TEST_PRIVATE_NAMESPACE"), "an external observer must verify the private namespace before execution")
	require.Zero(t, os.Geteuid(), "physical integration requires its isolated container's root")
	device, err := os.Stat("/dev/fuse")
	require.NoError(t, err)
	require.NotZero(t, device.Mode()&os.ModeCharDevice)
	bin := os.Getenv("SCHEDULER_MANAGED_TEST_BINARY")
	require.True(t, filepath.IsAbs(bin))
	executable, err := os.ReadFile(bin)
	require.NoError(t, err)
	executableSHA := os.Getenv("SCHEDULER_MANAGED_TEST_BINARY_SHA256")
	require.True(t, validPhysicalSHA(executableSHA))
	require.Equal(t, executableSHA, metadataSHA(executable))
	evidenceDir := os.Getenv("SCHEDULER_MANAGED_TEST_EVIDENCE_DIR")
	require.True(t, filepath.IsAbs(evidenceDir))
	_, err = readDirectoryBirth(evidenceDir)
	require.NoError(t, err, "acceptance evidence must have a private pre-existing directory")
	writeEvidence := func(name string, value any) {
		t.Helper()
		data, encodeErr := json.MarshalIndent(value, "", "  ")
		require.NoError(t, encodeErr)
		f, openErr := os.OpenFile(filepath.Join(evidenceDir, name+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		require.NoError(t, openErr)
		_, writeErr := f.Write(append(data, '\n'))
		syncErr, closeErr := f.Sync(), f.Close()
		require.NoError(t, writeErr)
		require.NoError(t, syncErr)
		require.NoError(t, closeErr)
		require.NoError(t, syncPreparationDirectory(evidenceDir))
	}
	checks := make(map[string]bool)
	defer func() {
		writeEvidence("acceptance", map[string]any{
			"schema_version": 1, "finished_at_utc": time.Now().UTC(),
			"producer_sha256": executableSHA, "checks": checks, "test_failed": t.Failed(),
			"scope": "Two real managed FUSE producers; original process and mount identity, conditional retirement, live neighbor protection and manager reopen. No scheduler sandbox, runtime, budget, daemon crash or model acceptance.",
		})
	}()

	// OSS forms bucket.endpoint. The split loopback address requires neither
	// external DNS nor credentials; the isolated HTTP fixture ignores auth.
	expected := []byte("original managed producer file contents\n")
	source := filepath.Join(t.TempDir(), "root.erofs")
	require.NoError(t, os.WriteFile(source, expected, 0600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, source) }))
	defer server.Close()
	cfg := ownershipManagerConfig(t)
	cfg.BinPath, cfg.ChunkDBSize = bin, "8MiB"
	require.NoError(t, os.Chmod(cfg.Root, 0700))
	cfg.OSSCfgPath = createTestConfigFile(t, t.TempDir(), "oss-loopback.json", BackendConfig{
		BackendType: "oss", Oss: &OssConfig{Scheme: "http", BucketName: "127", Endpoint: strings.TrimPrefix(server.URL, "http://127."), AccessKeyId: "test", AccessKeySecret: "test"},
	})
	mgr := ownedManager(t, cfg)
	originalGenerations := make(map[string]string)
	defer func() {
		if mgr.ownership.closeRequested.Load() {
			return
		}
		for id, generation := range originalGenerations {
			if d := mgr.GetDaemon(id); d != nil {
				if cleanupErr := d.UnmountIfPhysicalGeneration(generation); cleanupErr != nil {
					t.Errorf("original managed producer cleanup: %v", cleanupErr)
				}
			}
		}
	}()

	start := func(id string, owner PreparationOwner) (*Daemon, *physicalIdentity) {
		t.Helper()
		var generation, target string
		require.NoError(t, mgr.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "root.erofs"}, owner, func(g, path string) error {
			generation, target = g, path
			originalGenerations[id] = g
			// The actual binding is durable before any producer dispatch.
			writeEvidence(id+"-binding", map[string]any{"daemon_id": id, "owner": owner, "generation": g, "target": path})
			return nil
		}))
		d := mgr.GetDaemon(id)
		require.NotNil(t, d)
		require.NoError(t, d.Mount())
		p := d.originalPhysicalIdentity()
		require.NotNil(t, p)
		require.Equal(t, generation, p.Generation)
		require.Equal(t, target, p.Target)
		require.Equal(t, "running", p.Phase)
		require.NotNil(t, p.ManagedLaunch)
		require.NotNil(t, p.Process)
		require.NotNil(t, p.Mount)
		require.Equal(t, owner.OperationID, p.ManagedLaunch.Manifest.OperationID)
		require.Equal(t, owner.RequestFingerprint, p.ManagedLaunch.Manifest.RequestFingerprint)
		require.Equal(t, executableSHA, p.Process.ExecutableSHA256)
		require.NotZero(t, p.Process.StartTicks)
		require.NotZero(t, p.Mount.UniqueMountID)
		require.Equal(t, "fuse.distill_fs", p.Mount.Filesystem)
		require.Equal(t, "akernel-"+generation, p.Mount.Source)
		observedProcess, processErr := d.observeOriginalProcess(p.Process.PID)
		require.NoError(t, processErr)
		require.Equal(t, p.Process, observedProcess)
		observedMount, mountErr := d.observeOriginalMount()
		require.NoError(t, mountErr)
		require.Equal(t, p.Mount, observedMount)
		require.NoFileExists(t, p.PIDFile, "managed identity must not come from a mutable PID file")
		for _, kind := range []string{"process", "mount"} {
			for _, path := range []string{filepath.Join(d.meta.DaemonDir, "launch-birth-"+generation+"-"+kind+".json"), d.physicalBirthPath(p, kind)} {
				data, readErr := os.ReadFile(path)
				require.NoError(t, readErr)
				var fact any
				require.NoError(t, json.Unmarshal(data, &fact))
				writeEvidence(id+"-"+filepath.Base(path), map[string]any{"sha256": metadataSHA(data), "fact": fact})
			}
		}
		data, readErr := os.ReadFile(filepath.Join(d.MountPoint(), "root.erofs"))
		require.NoError(t, readErr)
		require.Equal(t, expected, data)
		writeEvidence(id+"-running", p)
		return d, p
	}
	original, birth := start(strings.Repeat("a", 64), preparationOwner())
	neighbor, neighborBirth := start(strings.Repeat("b", 64), PreparationOwner{OperationID: strings.Repeat("e", 64), RequestFingerprint: strings.Repeat("f", 64)})
	checks["both_original_births_and_reads_verified"] = true

	require.Error(t, original.UnmountIfPhysicalGeneration(neighborBirth.Generation))
	require.Equal(t, birth, original.originalPhysicalIdentity())
	process, err := original.observeOriginalProcess(birth.Process.PID)
	require.NoError(t, err)
	require.Equal(t, birth.Process, process)
	mount, err := original.observeOriginalMount()
	require.NoError(t, err)
	require.Equal(t, birth.Mount, mount)
	data, err := os.ReadFile(filepath.Join(original.MountPoint(), "root.erofs"))
	require.NoError(t, err)
	require.Equal(t, expected, data)
	checks["wrong_generation_rejected_without_effect"] = true

	require.NoError(t, original.UnmountIfPhysicalGeneration(birth.Generation))
	released := original.originalPhysicalIdentity()
	require.Equal(t, "released", released.Phase)
	require.Equal(t, birth.Process, released.Process)
	require.Equal(t, birth.Mount, released.Mount)
	require.True(t, released.UnmountSucceeded)
	process, err = original.observeOriginalProcess(birth.Process.PID)
	require.NoError(t, err)
	require.Nil(t, process)
	mount, err = original.observeOriginalMount()
	require.NoError(t, err)
	require.Nil(t, mount)
	writeEvidence("original-released", released)
	checks["original_process_exited_and_mount_removed"] = true

	// Reopen the production manager while the unrelated original producer is
	// still live. Replaying the completed generation must not touch that peer.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, mgr.Close(ctx))
	mgr = ownedManager(t, cfg)
	original, neighbor = mgr.GetDaemon(original.meta.ID), mgr.GetDaemon(neighbor.meta.ID)
	require.NotNil(t, original)
	require.NotNil(t, neighbor)
	require.Equal(t, released, original.originalPhysicalIdentity())
	require.Equal(t, neighborBirth, neighbor.originalPhysicalIdentity())
	require.NoError(t, original.UnmountIfPhysicalGeneration(birth.Generation))
	require.NoError(t, mgr.CleanupDaemon(original.meta.ID))
	require.NoFileExists(t, original.savedPath)
	require.NoDirExists(t, original.originalPreparation().Directory)
	process, err = neighbor.observeOriginalProcess(neighborBirth.Process.PID)
	require.NoError(t, err)
	require.Equal(t, neighborBirth.Process, process)
	mount, err = neighbor.observeOriginalMount()
	require.NoError(t, err)
	require.Equal(t, neighborBirth.Mount, mount)
	data, err = os.ReadFile(filepath.Join(neighbor.MountPoint(), "root.erofs"))
	require.NoError(t, err)
	require.Equal(t, expected, data)
	writeEvidence("neighbor-after-original-cleanup-and-reopen", neighbor.originalPhysicalIdentity())
	checks["reopen_replay_and_cleanup_preserve_live_neighbor"] = true

	require.NoError(t, neighbor.UnmountIfPhysicalGeneration(neighborBirth.Generation))
	writeEvidence("neighbor-released", neighbor.originalPhysicalIdentity())
	require.NoError(t, mgr.CleanupDaemon(neighbor.meta.ID))
	require.Empty(t, mgr.ListDaemons())
	require.NoError(t, mgr.Close(context.Background()))
	mgr = ownedManager(t, cfg)
	require.Empty(t, mgr.ListDaemons())
	checks["both_cleanups_survive_empty_manager_reopen"] = true
}
