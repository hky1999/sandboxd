// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Explicit BareMetal1 fixture: real empty groups, persisted original-parent
// recovery and separate pool settlement. No processes, signals, native runtime
// cleanup, daemon restart, OOM watcher acceptance or node budget are exercised.
func TestRealGenerationClosePersistsAndRecoversOriginalParent(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_CGROUP_CLOSE_INTEGRATION") != "1" {
		t.Skip("requires explicit owned BareMetal1 generation cgroup close fixture")
	}
	evidence := os.Getenv("CGROUP_CLOSE_EVIDENCE")
	require.True(t, filepath.IsAbs(evidence))
	var expected struct {
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
	}
	require.NoError(t, json.Unmarshal([]byte(os.Getenv("CGROUP_CLOSE_ROOT_IDENTITY")), &expected))
	rootInfo, err := os.Stat("/sys/fs/cgroup")
	require.NoError(t, err)
	root, err := cgroupIdentityFromInfo("/", rootInfo)
	require.NoError(t, err)
	require.Equal(t, expected.Device, root.Device)
	require.Equal(t, expected.Inode, root.Inode)
	require.NoError(t, os.MkdirAll(evidence, 0700))
	save := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
	}
	parent := "/generation-close-fixture"
	parentActual := filepath.Join("/sys/fs/cgroup", parent)
	require.NoError(t, os.Mkdir(parentActual, 0755))
	for _, scenario := range []string{"completed", "completion-save-failed", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			path := parent + "/" + scenario
			actual := filepath.Join("/sys/fs/cgroup", path)
			require.NoError(t, os.Mkdir(actual, 0755))
			db := store.NewStoreImp(filepath.Join(evidence, scenario+".bbolt"))
			ops := &cgroupV2{mountpoint: "/sys/fs/cgroup"}
			makeManager := func(db store.DbStore) *CgroupManager {
				return &CgroupManager{rootName: parent, max: 1, cacheSize: 1, usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](), gcQueue: util.New(""), gcWake: make(chan struct{}, 1), ops: ops, oom: newFakeOOMWatcher(), total: 1, db: db}
			}
			m := makeManager(db)
			m.cgroups.Set(path, struct{}{})
			m.idleID.Push(path)
			generation := "physical-" + scenario
			allocated, err := m.AllocateForGeneration(generation)
			require.NoError(t, err)
			require.Equal(t, path, allocated)
			original := m.leaseIdentities[path]
			originalData, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			save(scenario+"-allocated.json", json.RawMessage(originalData))
			request := GenerationCgroupCloseRequest{Path: path, Generation: generation, OperationID: "close-" + scenario, Deadline: time.Now().Add(10 * time.Second).UTC()}
			fault := &closeFaultStore{DbStore: db}
			if scenario == "completion-save-failed" {
				fault.failAt = 2
				m.db = fault
			}
			proof, err := m.CloseForGeneration(context.Background(), request)
			if scenario == "completion-save-failed" {
				require.ErrorContains(t, err, "injected close journal failure")
				require.Nil(t, proof)
				require.False(t, m.leaseClosures[path].Closed)
			} else {
				require.NoError(t, err)
				require.NotNil(t, proof.Directory)
				held, err := originalCgroupDirectory(int(proof.Directory.Fd()), path)
				require.NoError(t, err)
				require.Equal(t, original, held)
				for _, name := range []string{"cgroup.procs", "cgroup.events"} {
					fd, err := unix.Openat(int(proof.Directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
					if err == nil {
						_ = unix.Close(fd)
					}
					require.ErrorIs(t, err, unix.ENOENT)
				}
				require.NoError(t, proof.Close())
			}
			_, err = os.Stat(actual)
			require.True(t, os.IsNotExist(err))
			require.True(t, m.usingID.Has(path))
			require.Equal(t, 1, m.total)
			require.Empty(t, m.idleID.List())
			closedData, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			save(scenario+"-after-close.json", json.RawMessage(closedData))
			var state storedCgroupIDs
			require.NoError(t, json.Unmarshal(closedData, &state))
			reopened := makeManager(db)
			for _, active := range state.Items {
				reopened.usingID.Set(active, struct{}{})
			}
			require.NoError(t, reopened.restoreGenerationLeases(state))
			if scenario == "replacement" {
				require.NoError(t, os.Mkdir(actual, 0755))
				replacement, err := ops.identity(path)
				require.NoError(t, err)
				require.NotEqual(t, original.Inode, replacement.Inode)
				controls := func() map[string]string {
					values := map[string]string{}
					for _, name := range []string{"cgroup.procs", "cgroup.events", "cgroup.freeze", "cgroup.type"} {
						data, err := os.ReadFile(filepath.Join(actual, name))
						require.NoError(t, err)
						values[name] = string(data)
					}
					return values
				}
				before := controls()
				_, err = reopened.CloseForGeneration(context.Background(), request)
				require.Error(t, err)
				require.Error(t, reopened.RecycleForGeneration(path, generation))
				require.Equal(t, before, controls())
				unchanged, err := db.LoadRaw(config.CgroupBucket)
				require.NoError(t, err)
				require.Equal(t, closedData, unchanged)
				require.True(t, reopened.usingID.Has(path))
				require.Empty(t, reopened.idleID.List())
				save("replacement-refusal.json", map[string]any{"original": original, "replacement": replacement, "before": before, "after": controls(), "original_journal_unchanged": true, "using_retained": true, "signals_sent": false})
				require.NoError(t, os.Remove(actual))
			}
			proof, err = reopened.CloseForGeneration(context.Background(), request)
			require.NoError(t, err)
			require.Nil(t, proof.Directory, "reopened proof must not fabricate a removed original directory handle")
			require.NotNil(t, proof.Parent)
			fd, err := unix.Openat(int(proof.Parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err == nil {
				_ = unix.Close(fd)
			}
			require.ErrorIs(t, err, unix.ENOENT)
			require.NoError(t, proof.Close())
			require.True(t, reopened.usingID.Has(path))
			require.NoError(t, reopened.RecycleForGeneration(path, generation))
			require.False(t, reopened.usingID.Has(path))
			require.Empty(t, reopened.idleID.List())
			require.Equal(t, 0, reopened.total)
			require.NoError(t, reopened.RecycleForGeneration(path, generation))
			settled, err := db.LoadRaw(config.CgroupBucket)
			require.NoError(t, err)
			save(scenario+"-settled.json", json.RawMessage(settled))
			save(scenario+"-verdict.json", map[string]any{"request": request, "original": original, "original_parent": state.LeaseClosures[path].Parent, "original_scope": state.LeaseClosures[path].Scope, "removed_original_control_entries": true, "original_parent_absence_after_reopen": true, "close_kept_lease": true, "separate_pool_release": true, "idle_count": 0, "using_count": 0, "pool_total": 0, "completion_write_failure_injected": scenario == "completion-save-failed", "signals_sent": false, "native_runtime_tested": false, "daemon_restart_tested": false, "node_budget_tested": false})
		})
	}
	require.NoError(t, os.Remove(parentActual))
	save("fixture-cleanup.json", map[string]any{"owned_parent_and_leaves_normally_removed": true, "force_used": false, "signals_sent": false})
}
