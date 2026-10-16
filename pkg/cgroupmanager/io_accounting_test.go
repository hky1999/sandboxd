// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/require"
)

func ioControllerFixture(t *testing.T, missing string) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range []string{"", "owner", "owner/sandboxes"} {
		path := filepath.Join(root, relative)
		require.NoError(t, os.MkdirAll(path, 0755))
		controllers := "cpu memory pids io\n"
		if relative == missing {
			controllers = "cpu memory pids\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.controllers"), []byte(controllers), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), nil, 0644))
		require.NoError(t, os.WriteFile(filepath.Join(path, "io.max"), []byte("7:0 rbps=1234\n"), 0644))
	}
	return root
}

func TestCgroupIOAccountingDelegatesEveryAncestor(t *testing.T) {
	mount := ioControllerFixture(t, "not-a-group")
	ops := &cgroupV2{mountpoint: mount, ioAccounting: true}
	require.NoError(t, ops.prepareRoot("/owner/sandboxes", 64))
	for _, relative := range []string{"", "owner", "owner/sandboxes"} {
		data, err := os.ReadFile(filepath.Join(mount, relative, "cgroup.subtree_control"))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"+cpu", "+memory", "+pids", "+io"}, strings.Fields(string(data)))
		limit, err := os.ReadFile(filepath.Join(mount, relative, "io.max"))
		require.NoError(t, err)
		require.Equal(t, "7:0 rbps=1234\n", string(limit), "accounting must not change I/O throttling")
	}
}

func TestCgroupIOAccountingRequiresDelegationAtEachAncestor(t *testing.T) {
	for _, relative := range []string{"", "owner", "owner/sandboxes"} {
		name := relative
		if name == "" {
			name = "mount"
		}
		t.Run(name, func(t *testing.T) {
			mount := ioControllerFixture(t, relative)
			ops := &cgroupV2{mountpoint: mount, ioAccounting: true}
			require.ErrorContains(t, ops.prepareRoot("/owner/sandboxes", 0), `controller "io" is not delegated`)
		})
	}
}

func TestCgroupIOAccountingOptOutKeepsLegacyControllers(t *testing.T) {
	mount := ioControllerFixture(t, "not-a-group")
	for _, relative := range []string{"", "owner", "owner/sandboxes"} {
		require.NoError(t, os.WriteFile(filepath.Join(mount, relative, "cgroup.controllers"), []byte("cpu memory pids\n"), 0644))
	}
	ops := &cgroupV2{mountpoint: mount}
	require.NoError(t, ops.prepareRoot("/owner/sandboxes", 0))
	for _, relative := range []string{"", "owner", "owner/sandboxes"} {
		data, err := os.ReadFile(filepath.Join(mount, relative, "cgroup.subtree_control"))
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"+cpu", "+memory"}, strings.Fields(string(data)))
	}
}

func TestCgroupIOAccountingPropagatesControllerWriteFailure(t *testing.T) {
	mount := ioControllerFixture(t, "not-a-group")
	path := filepath.Join(mount, "owner", "cgroup.subtree_control")
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0755))
	ops := &cgroupV2{mountpoint: mount, ioAccounting: true}
	require.ErrorContains(t, ops.prepareRoot("/owner/sandboxes", 64), "enable cgroup v2 controllers")
}

func TestCgroupIOAccountingRequiresUnifiedBackend(t *testing.T) {
	original := detectCgroupMode
	t.Cleanup(func() { detectCgroupMode = original })
	for _, mode := range []cgroups.CGMode{cgroups.Legacy, cgroups.Hybrid, cgroups.Unavailable, cgroups.Unified} {
		detectCgroupMode = func() cgroups.CGMode { return mode }
		ops, err := newCgroupOps(0, true)
		if mode != cgroups.Unified {
			require.ErrorContains(t, err, "cgroup_io_accounting requires cgroup v2")
			continue
		}
		require.NoError(t, err)
		require.True(t, ops.(*cgroupV2).ioAccounting)
	}
}

func TestCgroupIOAccountingManagerRejectsDisabledPool(t *testing.T) {
	for _, cfg := range []config.ResourceConfig{
		{CgroupIOAccounting: true, DisableCgroup: true, CgroupCacheSize: 1},
		{CgroupIOAccounting: true, CgroupCacheSize: 0},
	} {
		_, err := NewCgroupManager(nil, cfg, 1)
		require.ErrorContains(t, err, "cgroup_io_accounting")
	}
}
