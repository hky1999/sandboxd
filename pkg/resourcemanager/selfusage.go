// Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
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

package resourcemanager

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// selfUsage reads the physical resource usage of the cgroup that contains
// sandboxd itself (on the scheduler node pod that is the whole node pod:
// proxies plus every sandbox). This is the "physical usage" input the
// usage-aware admission needs; pod requests are reservations, not usage.
type selfUsage struct {
	mu sync.Mutex

	// cgroup v2 unified root of the current process; empty when unavailable.
	unifiedRoot string
	// last cpu.stat usage read (microseconds) and its wall clock, used to
	// normalize a usage delta into cores.
	lastCPUUsec int64
	lastAt      time.Time
}

func newSelfUsage() *selfUsage {
	return &selfUsage{unifiedRoot: detectUnifiedRoot()}
}

func detectUnifiedRoot() string {
	// /proc/self/cgroup lists "0::/path" on cgroup v2.
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) == 3 && fields[0] == "0" && fields[1] == "" {
			return filepath.Join("/sys/fs/cgroup", fields[2])
		}
	}
	// Fall back to the v2 mount root itself.
	if st, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil && !st.IsDir() {
		return "/sys/fs/cgroup"
	}
	return ""
}

// MemoryUsage returns the current memory.usage-in-bytes of the containing
// cgroup. An error means UNKNOWN, never zero-by-accident.
func (s *selfUsage) MemoryUsage() (int64, error) {
	if s.unifiedRoot == "" {
		return 0, errNoSelfCgroup
	}
	return readInt64File(filepath.Join(s.unifiedRoot, "memory.current"))
}

// CPUUsageCores returns normalized CPU usage in cores computed from the
// cpu.stat usage_usec delta since the previous successful call. The first
// call after start has no window and reports an error so callers treat the
// sample as unknown instead of silently reporting zero.
func (s *selfUsage) CPUUsageCores() (float64, error) {
	if s.unifiedRoot == "" {
		return 0, errNoSelfCgroup
	}
	usec, err := readCPUStatUsec(s.unifiedRoot)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastAt.IsZero() {
		elapsed := now.Sub(s.lastAt).Seconds()
		if elapsed > 0.5 && usec >= s.lastCPUUsec {
			cores := float64(usec-s.lastCPUUsec) / 1e6 / elapsed
			s.lastCPUUsec, s.lastAt = usec, now
			return cores, nil
		}
	}
	s.lastCPUUsec, s.lastAt = usec, now
	return 0, errNoCPUWindow
}

func readCPUStatUsec(root string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(root, "cpu.stat"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == "usage_usec" {
			return strconv.ParseInt(fields[1], 10, 64)
		}
	}
	return 0, errNoCPUStat
}

type usageError string

func (e usageError) Error() string { return string(e) }

const (
	errNoSelfCgroup = usageError("self cgroup v2 root not detected")
	errNoCPUStat    = usageError("cpu.stat usage_usec not found")
	errNoCPUWindow  = usageError("no measurement window yet")
)
