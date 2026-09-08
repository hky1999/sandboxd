// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A missing or malformed counter file is unknown, never an observed zero.
// Read the kernel files explicitly: a partially populated library struct does
// not distinguish absent fields from legitimate zero pressure.
func readPressureCounters(path string, required ...string) (map[string]uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	const maxBytes = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil, false
	}
	values := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 2 {
			return nil, false
		}
		if _, duplicate := values[parts[0]]; duplicate {
			return nil, false
		}
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, false
		}
		values[parts[0]] = value
	}
	for _, key := range required {
		if _, ok := values[key]; !ok {
			return nil, false
		}
	}
	return values, true
}

func readV2PressureStats(groupPath string) Stats {
	var result Stats
	if values, ok := readPressureCounters(filepath.Join(groupPath, "cpu.stat"),
		"nr_periods", "nr_throttled", "throttled_usec"); ok {
		result.CPUPressureKnown = true
		result.CPUPeriods = values["nr_periods"]
		result.CPUThrottledPeriods = values["nr_throttled"]
		result.CPUThrottledNanos = usecToNS(values["throttled_usec"])
	}
	if values, ok := readPressureCounters(filepath.Join(groupPath, "memory.events"),
		"high", "oom", "oom_kill"); ok {
		result.MemoryPressureKnown = true
		result.MemoryHighEvents = values["high"]
		result.MemoryOOMEvents = values["oom"]
		result.MemoryOOMKillEvents = values["oom_kill"]
	}
	result.Frozen, result.FrozenKnown = readFrozenState(filepath.Join(groupPath, "cgroup.events"))
	return result
}

// readFrozenState reads the frozen value from cgroup.events. The kernel only
// ever writes 0 or 1: any other value is a malformed or foreign source and
// must stay unknown instead of masquerading as an unfrozen reading.
func readFrozenState(path string) (frozen, known bool) {
	values, ok := readPressureCounters(path, "frozen")
	if !ok {
		return false, false
	}
	switch values["frozen"] {
	case 0:
		return false, true
	case 1:
		return true, true
	default:
		return false, false
	}
}
