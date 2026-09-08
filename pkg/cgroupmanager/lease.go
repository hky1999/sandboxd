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

package cgroupmanager

import (
	"fmt"
	"os"
	"syscall"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"

	"github.com/containerd/cgroups/v3"
)

// Prepare applies the per-sandbox controls to an allocated, already-clean
// cgroup. Cleanup and OOM state reset happen when the previous owner recycles
// the cgroup.
func (c *CgroupManager) Prepare(
	name string,
	resource *runtime.LinuxSandboxResources,
) error {
	if !belongsToRoot(name, c.rootName) || !c.usingID.Has(name) {
		return fmt.Errorf("cgroup %s is not an allocated child of %s", name, c.rootName)
	}
	if err := c.ops.update(name, sandboxResources(resource)); err != nil {
		return fmt.Errorf("update cgroup %s: %w", name, err)
	}
	return nil
}

// OOMKilled reports the flag maintained by the manager-level kernel watcher.
func (c *CgroupManager) OOMKilled(name string) (bool, error) {
	if !belongsToRoot(name, c.rootName) ||
		!c.cgroups.Has(name) ||
		!c.usingID.Has(name) {
		return false, fmt.Errorf("cgroup %s is not an active child of %s", name, c.rootName)
	}
	return c.oom.OOMKilled(name)
}

// Stats loads normalized accounting for a sandbox path or the logical root
// path "/".
func (c *CgroupManager) Stats(name string) (Stats, error) {
	if name != "/" && !belongsToRoot(name, c.rootName) {
		return Stats{}, fmt.Errorf("cgroup %s is outside owned root %s", name, c.rootName)
	}
	return c.ops.stat(name)
}

// ReadMemoryLimit reports the current memory.max (cgroup v2) or
// memory.limit_in_bytes (cgroup v1) of the named cgroup in bytes.
// Callers use it to validate live kernel state against their persisted
// steady-state limit; it must not be treated as that steady-state source
// because it may include a transient expansion left by a previous process.
func (c *CgroupManager) ReadMemoryLimit(name string) (int64, error) {
	stats, err := c.Stats(name)
	if err != nil {
		return 0, err
	}
	return int64(stats.MemoryLimitBytes), nil

// SupportsMemoryShrink reports whether the detected backend can run the
// freeze-guarded memory decrease: only cgroup v2 has cgroup.freeze and
// memory.high.
func (c *CgroupManager) SupportsMemoryShrink() bool {
	return c.ops.mode() == cgroups.Unified
}

// ReadFreeze reports the freeze request bit and the kernel-confirmed state of
// an allocated sandbox cgroup.
func (c *CgroupManager) ReadFreeze(name string) (FreezeState, error) {
	if !belongsToRoot(name, c.rootName) || !c.cgroups.Has(name) {
		return FreezeState{}, fmt.Errorf("cgroup %s is not an owned child of %s", name, c.rootName)
	}
	return c.ops.readFreeze(name)
}

// WriteFreeze sets the freeze request bit of an allocated sandbox cgroup.
func (c *CgroupManager) WriteFreeze(name string, frozen bool) error {
	if !belongsToRoot(name, c.rootName) || !c.cgroups.Has(name) {
		return fmt.Errorf("cgroup %s is not an owned child of %s", name, c.rootName)
	}
	return c.ops.writeFreeze(name, frozen)
}

// WriteMemoryLimits applies the two memory controls in the fixed shrink order
// (memory.high, then memory.max) to an allocated sandbox cgroup.
func (c *CgroupManager) WriteMemoryLimits(name string, highBytes, maxBytes uint64) error {
	if !belongsToRoot(name, c.rootName) || !c.cgroups.Has(name) {
		return fmt.Errorf("cgroup %s is not an owned child of %s", name, c.rootName)
	}
	return c.ops.writeMemoryLimits(name, highBytes, maxBytes)
}

// CgroupIdentity proves the physical directory of an owned cgroup name.
func (c *CgroupManager) CgroupIdentity(name string) (CgroupIdentity, error) {
	if !belongsToRoot(name, c.rootName) || !c.cgroups.Has(name) {
		return CgroupIdentity{}, fmt.Errorf("cgroup %s is not an owned child of %s", name, c.rootName)
	}
	return c.ops.identity(name)
}

// cgroupIdentityFromInfo extracts the inode/device pair from a stat result.
func cgroupIdentityFromInfo(name string, info os.FileInfo) (CgroupIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return CgroupIdentity{}, fmt.Errorf("cgroup %s stat lacks inode identity", name)
	}
	return CgroupIdentity{Path: name, Inode: stat.Ino, Device: uint64(stat.Dev)}, nil
}
