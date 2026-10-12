// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

// 显式 BareMetal1 用例只验证真实替代目录拒绝；不发送信号或验收回收完成。
func TestRealGenerationLeaseRejectsSameNameReplacementAfterReopen(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_CGROUP_LEASE_INTEGRATION") != "1" {
		t.Skip("requires explicit owned BareMetal1 cgroup lease identity fixture")
	}
	evidence := os.Getenv("CGROUP_LEASE_EVIDENCE")
	require.True(t, filepath.IsAbs(evidence))
	var expected struct {
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
	}
	require.NoError(t, json.Unmarshal([]byte(os.Getenv("CGROUP_LEASE_ROOT_IDENTITY")), &expected))
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
	parent := "/lease-identity-fixture"
	path := parent + "/original"
	actual := filepath.Join("/sys/fs/cgroup", path)
	require.NoError(t, os.Mkdir(filepath.Join("/sys/fs/cgroup", parent), 0755))
	require.NoError(t, os.Mkdir(actual, 0755))
	db := store.NewStoreImp(filepath.Join(evidence, "leases.sqlite"))
	ops := &cgroupV2{mountpoint: "/sys/fs/cgroup"}
	makeManager := func() *CgroupManager {
		return &CgroupManager{rootName: parent, max: 1, cacheSize: 1, usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](), gcQueue: util.New(""), gcWake: make(chan struct{}, 1), ops: ops, oom: newFakeOOMWatcher(), total: 1, db: db}
	}
	m := makeManager()
	m.cgroups.Set(path, struct{}{})
	m.idleID.Push(path)
	allocated, err := m.AllocateForGeneration("generation-physical-original")
	require.NoError(t, err)
	require.Equal(t, path, allocated)
	original := m.leaseIdentities[path]
	require.NotZero(t, original.Inode)
	data, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	save("original-lease-journal.json", json.RawMessage(data))
	members, err := os.ReadFile(filepath.Join(actual, "cgroup.procs"))
	require.NoError(t, err)
	require.Empty(t, string(members))
	require.NoError(t, os.Remove(actual))
	require.NoError(t, os.Mkdir(actual, 0755))
	replacement, err := ops.identity(path)
	require.NoError(t, err)
	require.NotEqual(t, original.Inode, replacement.Inode)
	controls := func() map[string]string {
		result := map[string]string{}
		for _, name := range []string{"cpu.max", "memory.max", "memory.high", "cgroup.freeze", "cgroup.events", "cgroup.procs"} {
			data, err := os.ReadFile(filepath.Join(actual, name))
			require.NoError(t, err)
			result[name] = string(data)
		}
		return result
	}
	before := controls()
	err = m.RecycleForGeneration(path, "generation-physical-original")
	require.Error(t, err)
	require.Equal(t, before, controls())
	require.True(t, m.usingID.Has(path))
	require.Empty(t, m.idleID.List())
	var state storedCgroupIDs
	require.NoError(t, json.Unmarshal(data, &state))
	reopened := makeManager()
	reopened.cgroups.Set(path, struct{}{})
	for _, active := range state.Items {
		reopened.usingID.Set(active, struct{}{})
	}
	require.NoError(t, reopened.restoreGenerationLeases(state))
	err = reopened.RecycleForGeneration(path, "generation-physical-original")
	require.Error(t, err)
	require.Equal(t, before, controls())
	require.True(t, reopened.usingID.Has(path))
	require.Empty(t, reopened.idleID.List())
	require.Equal(t, 1, reopened.total)
	journalAfter, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	require.Equal(t, data, journalAfter)
	save("replacement-refusal.json", map[string]any{"original": original, "replacement": replacement, "original_scope": m.leaseScopes[path], "before": before, "after": controls(), "lease_reopen_refused": true, "journal_bytes_unchanged": true, "using_retained": true, "idle_count": 0, "total_retained": 1, "signals_sent": false, "scope": "真实内核替代目录及持久日志重开拒绝；没有完成回收、沙箱或节点预算。"})
	require.NoError(t, os.Remove(actual))
	require.NoError(t, os.Remove(filepath.Join("/sys/fs/cgroup", parent)))
	save("fixture-cleanup.json", map[string]any{"both_owned_empty_directories_normally_removed": true, "force_used": false})
}
