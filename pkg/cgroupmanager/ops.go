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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"

	"github.com/containerd/cgroups/v3"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	cgroupMountpoint   = "/sys/fs/cgroup"
	cgroupDrainTimeout = 2 * time.Second
	cgroupDrainPoll    = 10 * time.Millisecond
)

// killCgroupProcesses accepts process IDs, never kill(2) process-group selectors.
// Validate the complete snapshot before signaling anything. A PID outside our
// namespace may be reported as zero; a uint64-to-int conversion can also turn
// a malformed PID into a negative process-group selector. Fail closed instead
// of killing the caller's process group or recycling a still-populated cgroup.
func killCgroupProcesses(processes []uint64) error {
	if err := validateCgroupProcesses(processes); err != nil {
		return err
	}
	for _, pid := range processes {
		if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("kill cgroup process %d: %w", pid, err)
		}
	}
	return nil
}

func validateCgroupProcesses(processes []uint64) error {
	for _, pid := range processes {
		if pid <= 1 || pid > math.MaxInt32 || pid == uint64(os.Getpid()) {
			return fmt.Errorf("unsafe cgroup PID %d: refusing to signal it", pid)
		}
	}
	return nil
}

// Stats is the version-neutral subset of cgroup accounting exposed by
// sandboxd. CPU accounting uses nanoseconds; quota/period use microseconds.
// Memory values are bytes. Every usage/limit/peak numeric keeps a legacy
// fallback value when its known flag is false; only the flag distinguishes a
// strict direct kernel-file reading (cgroup v1 never proves one).
type Stats struct {
	CPUPressureKnown    bool
	CPUPeriods          uint64
	CPUThrottledPeriods uint64
	CPUThrottledNanos   uint64
	MemoryPressureKnown bool
	MemoryHighEvents    uint64
	MemoryOOMEvents     uint64
	MemoryOOMKillEvents uint64

	CPUQuotaUsec        int64 // -1 means unlimited; consult CPULimitsKnown
	CPUPeriodUsec       uint64
	CPULimitsKnown      bool
	CPUUsageNanos       uint64
	CPUUsageKnown       bool // strict cpu.stat usage_usec reading
	CPUUserNanos        uint64
	CPUKernelNanos      uint64
	MemoryUsageBytes    uint64
	MemoryUsageKnown    bool // strict memory.current reading
	MemoryLimitBytes    uint64
	MemoryLimitKnown    bool // strict memory.max reading; "max" = unlimited
	MemoryMaxUsageBytes uint64
	MemoryPeakKnown     bool // measured memory.peak, not the usage fallback
	// Enforced memory.high under the same strict rules; the cgroup v1 backend
	// has no memory.high and proves none of these.
	MemoryHighBytes     uint64
	MemoryHighKnown     bool
	MemoryHighUnlimited bool
	// Kernel-observed frozen state from cgroup.events; the freeze request bit
	// is tracked separately by FreezeState.
	Frozen      bool
	FrozenKnown bool
	// MemoryCgroupPath is the absolute cgroup v2 directory this Stats call
	// actually read (mountpoint joined with the manager-relative name). It is
	// a read-only locator for observers such as inotify watches; the cgroup v1
	// backend cannot prove one and leaves it empty. It is never a write
	// target and never replaces journal identity verification.
	MemoryCgroupPath string
}

// FreezeState distinguishes the freeze request (cgroup.freeze) from the
// kernel-confirmed state (cgroup.events frozen). Both readings carry their own
// known flag; a missing or malformed file is unknown, never an observed false.
type FreezeState struct {
	RequestKnown  bool
	RequestFrozen bool
	EventsKnown   bool
	Frozen        bool
}

type cgroupOps interface {
	mode() cgroups.CGMode
	prepareRoot(root string, pidsMax int64) error
	list(root string) ([]string, error)
	create(name string, resources *specs.LinuxResources) error
	reset(name string) error
	setPidsLimit(name string, limit int64) error
	update(name string, resources *specs.LinuxResources) error
	stat(name string) (Stats, error)
	readFreeze(name string) (FreezeState, error)
	writeFreeze(name string, frozen bool) error
	writeMemoryLimits(name string, highBytes, maxBytes uint64) error
	identity(name string) (CgroupIdentity, error)
	newOOMWatcher() (oomWatcher, error)
	kill(name string) error
	delete(name string) error
}

// CgroupIdentity is the durable binding between a journal record and the
// physical cgroup directory it describes: the manager-relative path plus the
// inode and device of the directory, so a recycled path leased to a later
// sandbox can never satisfy an old record's identity check.
type CgroupIdentity struct {
	Path   string
	Inode  uint64
	Device uint64
}

var detectCgroupMode = cgroups.Mode

func newCgroupOps(memoryHighRatio float64, ioAccounting bool) (cgroupOps, error) {
	mode := detectCgroupMode()
	if ioAccounting && mode != cgroups.Unified {
		return nil, errors.New("cgroup_io_accounting requires cgroup v2")
	}
	switch mode {
	case cgroups.Unified:
		return &cgroupV2{mountpoint: cgroupMountpoint, memoryHighRatio: memoryHighRatio, ioAccounting: ioAccounting}, nil
	case cgroups.Legacy, cgroups.Hybrid:
		if memoryHighRatio > 0 {
			logrus.Warnf("memory_high_ratio %.2f configured but cgroup v1 has no memory.high; ignoring", memoryHighRatio)
		}
		return &cgroupV1{detectedMode: mode}, nil
	case cgroups.Unavailable:
		return nil, errors.New("cgroup filesystem is unavailable")
	default:
		return nil, fmt.Errorf("unsupported cgroup mode %d", mode)
	}
}

// MemoryHighBytes computes the cgroup v2 memory.high value for a sandbox
// memory limit: ceil(ratio * limit) rounded DOWN to a whole kernel page once
// the value reaches page size, always below the limit for a valid ratio in
// [0,1). Downward alignment is the conservative direction: the soft limit
// stays further below the hard limit and the shrink safety margin compares
// against a smaller budget. A zero ratio disables the soft limit (0 is
// returned). Writes, readback checks, and shrink safety margins all derive
// the value from here, so they can never disagree.
func MemoryHighBytes(limitBytes uint64, ratio float64) uint64 {
	if limitBytes == 0 || ratio <= 0 {
		return 0
	}
	high := uint64(math.Ceil(ratio * float64(limitBytes)))
	if page := uint64(os.Getpagesize()); page > 1 && high >= page {
		high -= high % page
	}
	if high >= limitBytes {
		high = limitBytes - 1
	}
	return high
}

func cgroupVersion(mode cgroups.CGMode) int {
	if mode == cgroups.Unified {
		return 2
	}
	return 1
}

func cgroupModeName(mode cgroups.CGMode) string {
	switch mode {
	case cgroups.Legacy:
		return "legacy"
	case cgroups.Hybrid:
		return "hybrid"
	case cgroups.Unified:
		return "unified"
	default:
		return "unavailable"
	}
}

func normalizeCgroupRoot(root string) (string, error) {
	cleaned := filepath.Clean("/" + strings.TrimPrefix(root, "/"))
	if cleaned == "/" || cleaned == "." {
		return "", errors.New("cgroup_root_name must name a non-root cgroup")
	}
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("invalid cgroup root %q", root)
	}
	return cleaned, nil
}

func belongsToRoot(name, root string) bool {
	cleaned := filepath.Clean(name)
	return cleaned != root && filepath.Dir(cleaned) == root
}

func sandboxResources(resource *runtime.LinuxSandboxResources) *specs.LinuxResources {
	if resource == nil {
		return &specs.LinuxResources{}
	}

	result := &specs.LinuxResources{}
	if resource.CpuShares > 0 || resource.CpuQuota > 0 || resource.CpuPeriod > 0 {
		result.CPU = &specs.LinuxCPU{}
		if resource.CpuShares > 0 {
			result.CPU.Shares = &resource.CpuShares
		}
		if resource.CpuQuota > 0 {
			result.CPU.Quota = &resource.CpuQuota
		}
		if resource.CpuPeriod > 0 {
			result.CPU.Period = &resource.CpuPeriod
		}
	}
	if resource.MemoryLimitInBytes > 0 {
		result.Memory = &specs.LinuxMemory{
			Limit: &resource.MemoryLimitInBytes,
		}
	}
	return result
}

func usecToNS(value uint64) uint64 {
	if value > math.MaxUint64/1000 {
		return math.MaxUint64
	}
	return value * 1000
}
