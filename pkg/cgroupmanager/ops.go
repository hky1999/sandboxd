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
	"path/filepath"
	"strings"
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

// Stats is the version-neutral subset of cgroup accounting exposed by
// sandboxd. All CPU values are nanoseconds and all memory values are bytes.
type Stats struct {
	CPUUsageNanos       uint64
	CPUUserNanos        uint64
	CPUKernelNanos      uint64
	MemoryUsageBytes    uint64
	MemoryLimitBytes    uint64
	MemoryMaxUsageBytes uint64
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
	newOOMWatcher() (oomWatcher, error)
	kill(name string) error
	delete(name string) error
}

var detectCgroupMode = cgroups.Mode

func newCgroupOps(memoryHighRatio float64) (cgroupOps, error) {
	switch mode := detectCgroupMode(); mode {
	case cgroups.Unified:
		return &cgroupV2{mountpoint: cgroupMountpoint, memoryHighRatio: memoryHighRatio}, nil
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
// memory limit: ceil(ratio * limit), always below the limit for a valid
// ratio in [0,1). A zero ratio disables the soft limit (0 is returned).
func MemoryHighBytes(limitBytes uint64, ratio float64) uint64 {
	if limitBytes == 0 || ratio <= 0 {
		return 0
	}
	high := uint64(math.Ceil(ratio * float64(limitBytes)))
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
