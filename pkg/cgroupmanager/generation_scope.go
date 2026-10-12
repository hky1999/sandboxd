// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// 设备号与 inode 需要绑定同一启动和观察环境，不能跨环境采用同号目录。
type generationLeaseScope struct {
	BootID                string `json:"boot_id"`
	CgroupNamespaceDevice uint64 `json:"cgroup_namespace_device"`
	CgroupNamespaceInode  uint64 `json:"cgroup_namespace_inode"`
	MountNamespaceDevice  uint64 `json:"mount_namespace_device"`
	MountNamespaceInode   uint64 `json:"mount_namespace_inode"`
	PIDNamespaceDevice    uint64 `json:"pid_namespace_device"`
	PIDNamespaceInode     uint64 `json:"pid_namespace_inode"`
	MountRootDevice       uint64 `json:"mount_root_device"`
	MountRootInode        uint64 `json:"mount_root_inode"`
}

func (s generationLeaseScope) valid() bool {
	return s.BootID != "" && len(s.BootID) <= 128 && s.CgroupNamespaceInode != 0 && s.MountNamespaceInode != 0 && s.PIDNamespaceInode != 0 && s.MountRootInode != 0
}

func currentGenerationLeaseScope() (generationLeaseScope, error) {
	var scope generationLeaseScope
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 128 {
		return scope, errors.New("original cgroup lease boot identity unavailable")
	}
	scope.BootID = strings.TrimSpace(string(boot))
	for _, entry := range []struct {
		path          string
		device, inode *uint64
	}{
		{"/proc/thread-self/ns/cgroup", &scope.CgroupNamespaceDevice, &scope.CgroupNamespaceInode},
		{"/proc/thread-self/ns/mnt", &scope.MountNamespaceDevice, &scope.MountNamespaceInode},
		{"/proc/thread-self/ns/pid", &scope.PIDNamespaceDevice, &scope.PIDNamespaceInode},
		{"/sys/fs/cgroup", &scope.MountRootDevice, &scope.MountRootInode},
	} {
		var stat unix.Stat_t
		if err := unix.Lstat(entry.path, &stat); err != nil {
			return scope, err
		}
		if strings.HasPrefix(entry.path, "/proc/") {
			if err := unix.Stat(entry.path, &stat); err != nil {
				return scope, err
			}
		} else if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return scope, errors.New("cgroup mount root is not an original directory")
		}
		*entry.device, *entry.inode = stat.Dev, stat.Ino
	}
	if !scope.valid() {
		return scope, errors.New("original cgroup lease scope incomplete")
	}
	return scope, nil
}

func (c *CgroupManager) generationScope() (generationLeaseScope, error) {
	if c.readGenerationScope != nil {
		return c.readGenerationScope()
	}
	return currentGenerationLeaseScope()
}

func (c *CgroupManager) verifyGenerationDirectory(path, generation string) error {
	if c.leaseOwners[path] != generation || !c.usingID.Has(path) {
		return errors.New("original generation-owned cgroup lease changed")
	}
	original, known := c.leaseIdentities[path]
	scope, scoped := c.leaseScopes[path]
	if !known || original.Path != path || original.Device == 0 || original.Inode == 0 || !scoped || !scope.valid() {
		return errors.New("original generation-owned cgroup directory or scope missing")
	}
	currentScope, err := c.generationScope()
	if err != nil || currentScope != scope {
		return errors.New("original generation-owned cgroup observation scope changed")
	}
	current, err := c.ops.identity(path)
	if current.Path == "" {
		current.Path = path
	}
	if err != nil || current != original {
		return errors.New("original generation-owned cgroup directory missing or changed")
	}
	return nil
}
