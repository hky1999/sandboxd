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

// selfUsage reads the physical resource usage of the cgroup DOMAIN that the
// scheduler's budget covers: the pod's cgroup-namespace root (the mount
// point /sys/fs/cgroup inside the node pod), which contains the system
// services AND every /akernel/<id> sandbox. Reading the daemon's own
// service cgroup instead missed all sandbox memory (verified: sandboxes at
// /akernel/* are siblings of system.slice, not children of
// system.slice/sandboxd.service). Capacity comes from the same root's
// memory.max so usage and capacity share one physical domain.
type selfUsage struct {
	mu sync.Mutex

	// cgroup v2 unified root of the pod's cgroup namespace; empty when
	// unavailable (unknown samples, never zero-by-accident).
	unifiedRoot string
	// last cpu.stat usage read (microseconds) and its wall clock, used to
	// normalize a usage delta into cores.
	lastCPUUsec int64
	lastAt      time.Time
}

func newSelfUsage() *selfUsage {
	return &selfUsage{unifiedRoot: detectUnifiedRoot()}
}

// detectUnifiedRoot returns the pod's cgroup-namespace root. On the node pod
// every schedulable cgroup (system.slice, init.scope and /akernel/*) lives
// below /sys/fs/cgroup, so the mount point itself is the budget domain; the
// daemon's own /proc/self/cgroup path would only cover its service slice.
func detectUnifiedRoot() string {
	if st, err := os.Stat(filepath.Join(rootMount, "cgroup.controllers")); err == nil && !st.IsDir() {
		return rootMount
	}
	if _, err := os.Stat(filepath.Join(rootMount, "memory.max")); err == nil {
		return rootMount
	}
	return ""
}

const rootMount = "/sys/fs/cgroup"

// DomainCPUMilli returns the domain's cpu.max normalized to millicores
// through its own period ("quota period" -> quota*1000/period). Zero with
// nil error means unlimited; an error means unreadable (both conservative).
func (s *selfUsage) DomainCPUMilli() (int64, error) {
	if s.unifiedRoot == "" {
		return 0, errNoSelfCgroup
	}
	data, err := os.ReadFile(filepath.Join(s.unifiedRoot, "cpu.max"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 2 || fields[0] == "max" {
		return 0, nil
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, nil
	}
	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period <= 0 {
		return 0, nil
	}
	return quota * 1000 / period, nil
}

// DomainCapacityBytes returns the memory.max of the budget domain root, or
// an error when the domain is unlimited or unreadable. An unlimited domain
// ("max") has no finite capacity: callers must NOT fall back to the host
// allocatable, because sibling node pods would each claim the whole host.
func (s *selfUsage) DomainCapacityBytes() (int64, error) {
	if s.unifiedRoot == "" {
		return 0, errNoSelfCgroup
	}
	data, err := os.ReadFile(filepath.Join(s.unifiedRoot, "memory.max"))
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0, errUnlimitedDomain
	}
	raw, err := strconv.ParseInt(value, 10, 64)
	if err != nil || raw <= 0 {
		return 0, errUnlimitedDomain
	}
	return raw, nil
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
	errNoSelfCgroup    = usageError("self cgroup v2 root not detected")
	errNoCPUStat       = usageError("cpu.stat usage_usec not found")
	errNoCPUWindow     = usageError("no measurement window yet")
	errUnlimitedDomain = usageError("budget domain memory.max is unlimited")
)
