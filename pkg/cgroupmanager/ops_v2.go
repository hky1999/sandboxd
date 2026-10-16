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
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/config"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultV2CPUWeight  = "100"
	defaultV2MemoryMax  = "max"
	defaultV2MemoryHigh = "max"
)

type cgroupV2 struct {
	mountpoint string
	// memoryHighRatio enables writing memory.high alongside every finite
	// memory.max (see ResourceConfig.MemoryHighRatio). Zero disables.
	memoryHighRatio float64
	ioAccounting    bool
}

func (*cgroupV2) mode() cgroups.CGMode { return cgroups.Unified }

func (o *cgroupV2) prepareRoot(root string, pidsMax int64) error {
	required := []string{"cpu", "memory"}
	if pidsMax > 0 {
		required = append(required, "pids")
	}
	if o.ioAccounting {
		required = append(required, "io")
	}
	return o.enableControllers(root, required)
}

func (o *cgroupV2) enableControllers(group string, controllers []string) error {
	current := o.mountpoint
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(group), "/"), "/")
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
			if err := os.MkdirAll(current, 0755); err != nil {
				return fmt.Errorf("create delegated cgroup %s: %w", current, err)
			}
		}
		availableData, err := os.ReadFile(filepath.Join(current, "cgroup.controllers"))
		if err != nil {
			return fmt.Errorf("read controllers at %s: %w", current, err)
		}
		available := make(map[string]struct{})
		for controller := range strings.FieldsSeq(string(availableData)) {
			available[controller] = struct{}{}
		}
		for _, controller := range controllers {
			if _, ok := available[controller]; !ok {
				return fmt.Errorf(
					"cgroup v2 controller %q is not delegated at %s (available: %s)",
					controller,
					current,
					strings.TrimSpace(string(availableData)),
				)
			}
		}
		value := make([]string, 0, len(controllers))
		for _, controller := range controllers {
			value = append(value, "+"+controller)
		}
		if err := os.WriteFile(
			filepath.Join(current, "cgroup.subtree_control"),
			[]byte(strings.Join(value, " ")),
			0644,
		); err != nil {
			return fmt.Errorf(
				"enable cgroup v2 controllers %v at %s: %w",
				controllers,
				current,
				err,
			)
		}
	}
	return nil
}

func (o *cgroupV2) list(root string) ([]string, error) {
	groupDirs, err := os.ReadDir(filepath.Join(o.mountpoint, root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	result := make([]string, 0, len(groupDirs))
	for _, dir := range groupDirs {
		if dir.IsDir() {
			result = append(result, filepath.Join(root, dir.Name()))
		}
	}
	return result, nil
}

func (o *cgroupV2) create(name string, resources *specs.LinuxResources) error {
	_, err := cgroup2.NewManager(o.mountpoint, name, cgroup2.ToResources(resources))
	return err
}

func (o *cgroupV2) reset(name string) error {
	groupPath := filepath.Join(o.mountpoint, name)
	values := map[string]string{
		"cpu.weight":    defaultV2CPUWeight,
		"cpu.max":       "max " + strconv.FormatUint(config.DefaultCPUPeriodMicros, 10),
		"memory.max":    defaultV2MemoryMax,
		"memory.high":   defaultV2MemoryHigh,
		"cgroup.freeze": "0",
	}
	for filename, value := range values {
		if err := os.WriteFile(filepath.Join(groupPath, filename), []byte(value), 0644); err != nil {
			return fmt.Errorf("reset %s for cgroup %s: %w", filename, name, err)
		}
	}
	return nil
}

func (o *cgroupV2) setPidsLimit(name string, limit int64) error {
	pidsPath := filepath.Join(o.mountpoint, name, "pids.max")
	if _, err := os.Stat(pidsPath); err != nil {
		if os.IsNotExist(err) && limit == 0 {
			return nil
		}
		return err
	}
	value := unlimitedPidsString
	if limit > 0 {
		value = strconv.FormatInt(limit, 10)
	}
	if err := os.WriteFile(pidsPath, []byte(value), 0644); err != nil {
		return fmt.Errorf("set pids.max for cgroup %s: %w", name, err)
	}
	return nil
}

func (o *cgroupV2) update(name string, resources *specs.LinuxResources) error {
	if resources == nil {
		return nil
	}
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	if err := group.Update(cgroup2.ToResources(resources)); err != nil {
		return err
	}
	// containerd's cgroup2 writer has no memory.high support, so the soft
	// limit is applied directly: every finite memory.max lands together with
	// high = ceil(ratio * max), giving the node-side upgrade ladder an
	// interception window before the hard limit kills
	if o.memoryHighRatio <= 0 || resources.Memory == nil ||
		resources.Memory.Limit == nil || *resources.Memory.Limit <= 0 {
		return nil
	}
	high := MemoryHighBytes(uint64(*resources.Memory.Limit), o.memoryHighRatio)
	if high == 0 {
		return nil
	}
	if err := os.WriteFile(
		filepath.Join(o.mountpoint, name, "memory.high"),
		[]byte(strconv.FormatUint(high, 10)),
		0644,
	); err != nil {
		return fmt.Errorf("set memory.high for cgroup %s: %w", name, err)
	}
	return nil
}

func (o *cgroupV2) stat(name string) (Stats, error) {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return Stats{}, err
	}
	metrics, err := group.Stat()
	if err != nil {
		return Stats{}, err
	}
	groupPath := filepath.Join(o.mountpoint, name)
	result := readV2PressureStats(groupPath)
	result.CPUQuotaUsec, result.CPUPeriodUsec, result.CPULimitsKnown = readCPUMax(filepath.Join(groupPath, "cpu.max"))
	if metrics.CPU != nil {
		result.CPUUsageNanos = usecToNS(metrics.CPU.UsageUsec)
		result.CPUUserNanos = usecToNS(metrics.CPU.UserUsec)
		result.CPUKernelNanos = usecToNS(metrics.CPU.SystemUsec)
	}
	if metrics.Memory != nil {
		result.MemoryUsageBytes = metrics.Memory.Usage
		result.MemoryLimitBytes = metrics.Memory.UsageLimit
		result.MemoryMaxUsageBytes = readUintFile(filepath.Join(groupPath, "memory.peak"))
		if result.MemoryMaxUsageBytes == 0 {
			result.MemoryMaxUsageBytes = result.MemoryUsageBytes
		}
	}
	// Known readings are decided only by the bounded strict reads below: the
	// containerd struct above cannot distinguish an absent source file from an
	// observed zero and is kept purely as the legacy numeric fallback.
	if usageUsec, ok := readV2CPUUsageUsec(filepath.Join(groupPath, "cpu.stat")); ok {
		result.CPUUsageNanos = usecToNS(usageUsec)
		result.CPUUsageKnown = true
	}
	if usage, ok := readUsageCounter(filepath.Join(groupPath, "memory.current")); ok {
		result.MemoryUsageBytes = usage
		result.MemoryUsageKnown = true
	}
	if limit, ok := readUsageLimit(filepath.Join(groupPath, "memory.max")); ok {
		result.MemoryLimitBytes = limit
		result.MemoryLimitKnown = true
	}
	// A measured memory.peak — including a genuine 0 — replaces the legacy
	// current-usage substitution above; without one the numbers stay as the
	// backwards-compatible fallback and the flag stays false.
	if peak, ok := readUsageCounter(filepath.Join(groupPath, "memory.peak")); ok {
		result.MemoryMaxUsageBytes = peak
		result.MemoryPeakKnown = true
	}
	if high, ok := readUsageLimit(filepath.Join(groupPath, "memory.high")); ok {
		result.MemoryHighBytes = high
		result.MemoryHighKnown = true
		result.MemoryHighUnlimited = high == math.MaxUint64
	}
	// cgroup.events' kernel-confirmed frozen state was set by
	// readV2PressureStats under the strict 0/1 rule; the request bit in
	// cgroup.freeze stays available through readFreeze.
	// The absolute directory this read came from: a read-only locator for
	// event watchers, never a write target.
	result.MemoryCgroupPath = groupPath
	return result, nil
}

// identity proves the physical cgroup directory behind a manager-relative
// name through its inode and device.
func (o *cgroupV2) identity(name string) (CgroupIdentity, error) {
	info, err := os.Stat(filepath.Join(o.mountpoint, name))
	if err != nil {
		return CgroupIdentity{}, fmt.Errorf("stat cgroup %s: %w", name, err)
	}
	if !info.IsDir() {
		return CgroupIdentity{}, fmt.Errorf("cgroup %s is not a directory", name)
	}
	return cgroupIdentityFromInfo(name, info)
}

// readFreeze reports both freeze facts of a cgroup: the request bit the
// controller wrote and the state the kernel has actually reached. Unknown
// files never become an observed false.
func (o *cgroupV2) readFreeze(name string) (FreezeState, error) {
	groupPath := filepath.Join(o.mountpoint, name)
	var state FreezeState
	if value, ok := readUsageFile(filepath.Join(groupPath, "cgroup.freeze")); ok {
		switch value {
		case "0":
			state.RequestKnown, state.RequestFrozen = true, false
		case "1":
			state.RequestKnown, state.RequestFrozen = true, true
		}
	}
	state.Frozen, state.EventsKnown = readFrozenState(filepath.Join(groupPath, "cgroup.events"))
	return state, nil
}

// writeFreeze sets the cgroup.freeze request bit. Confirming that the kernel
// reached the state is the caller's bounded poll of readFreeze.
func (o *cgroupV2) writeFreeze(name string, frozen bool) error {
	value := "0"
	if frozen {
		value = "1"
	}
	if err := os.WriteFile(filepath.Join(o.mountpoint, name, "cgroup.freeze"), []byte(value), 0644); err != nil {
		return fmt.Errorf("set cgroup.freeze=%s for cgroup %s: %w", value, name, err)
	}
	return nil
}

// writeMemoryLimits lowers or raises the two memory controls of an allocated
// cgroup in the fixed shrink order: memory.high first, then memory.max. Each
// value is written exactly once so a returned error still leaves a truthful
// partial state for the caller's readback; the two files have no atomic
// combined update in the kernel.
func (o *cgroupV2) writeMemoryLimits(name string, highBytes, maxBytes uint64) error {
	groupPath := filepath.Join(o.mountpoint, name)
	if err := os.WriteFile(filepath.Join(groupPath, "memory.high"), []byte(strconv.FormatUint(highBytes, 10)), 0644); err != nil {
		return fmt.Errorf("set memory.high=%d for cgroup %s: %w", highBytes, name, err)
	}
	if err := os.WriteFile(filepath.Join(groupPath, "memory.max"), []byte(strconv.FormatUint(maxBytes, 10)), 0644); err != nil {
		return fmt.Errorf("set memory.max=%d for cgroup %s: %w", maxBytes, name, err)
	}
	return nil
}

func readUintFile(filename string) uint64 {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return ^uint64(0)
	}
	result, _ := strconv.ParseUint(value, 10, 64)
	return result
}

func (o *cgroupV2) newOOMWatcher() (oomWatcher, error) {
	return newV2OOMWatcher(o.mountpoint)
}

func (o *cgroupV2) kill(name string) error {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	// Do not use cgroup.kill while supported kernels may lack Linux commit
	// 8e3599202166 ("cgroup: fix spurious SIGKILL of CLONE_INTO_CGROUP
	// children"). On affected kernels, cgroup.kill changes a persistent
	// sequence number that can cause future processes cloned into this cached
	// cgroup to be killed. Explicit signals avoid changing that sequence.
	processes, err := group.Procs(true)
	if err != nil {
		return err
	}
	if err := killCgroupProcesses(processes); err != nil {
		return fmt.Errorf("drain cgroup %s: %w", name, err)
	}

	for deadline := time.Now().Add(cgroupDrainTimeout); ; {
		processes, err = group.Procs(true)
		if err != nil {
			return err
		}
		tasks, tracksTasks, err := readV2PidsCurrent(
			filepath.Join(o.mountpoint, name, "pids.current"),
		)
		if err != nil {
			return err
		}
		if len(processes) == 0 && (!tracksTasks || tasks == 0) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"timed out waiting for cgroup %s to drain (%d processes, %d tasks)",
				name,
				len(processes),
				tasks,
			)
		}
		time.Sleep(cgroupDrainPoll)
	}
}

func readV2PidsCurrent(filename string) (uint64, bool, error) {
	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read %s: %w", filename, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("parse %s: %w", filename, err)
	}
	return value, true, nil
}

func (o *cgroupV2) delete(name string) error {
	group, err := cgroup2.Load(name, cgroup2.WithMountpoint(o.mountpoint))
	if err != nil {
		return err
	}
	if err := group.Delete(); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// readCPUMax keeps missing or malformed telemetry distinct from unlimited.
func readCPUMax(path string) (int64, uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, false
	}
	period, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return 0, 0, false
	}
	if fields[0] == "max" {
		return -1, period, true
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, 0, false
	}
	return quota, period, true
}
