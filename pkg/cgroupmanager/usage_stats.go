// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// maxUsageFileBytes bounds a single-value cgroup counter read: anything
// larger is not a kernel counter file and is unknown.
const maxUsageFileBytes = 4096

// readUsageFile reads at most maxUsageFileBytes from a single-value kernel
// file and returns its trimmed contents. A missing, unreadable, or oversized
// file is unknown, never an observed zero.
func readUsageFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUsageFileBytes+1))
	if err != nil || len(data) > maxUsageFileBytes {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// parseUsageCounter accepts exactly a non-empty run of decimal digits —
// including a lone "0" — with no sign, radix prefix, or trailing junk, and
// no uint64 overflow.
func parseUsageCounter(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// readUsageCounter reads a single-value cgroup v2 counter such as
// memory.current or memory.peak under the strict rules of parseUsageCounter.
// The "max" sentinel is not a counter reading and is unknown here.
func readUsageCounter(path string) (uint64, bool) {
	value, ok := readUsageFile(path)
	if !ok {
		return 0, false
	}
	return parseUsageCounter(value)
}

// readUsageLimit reads a cgroup v2 limit such as memory.max: the same strict
// decimal rules as readUsageCounter, plus the kernel's "max" sentinel, which
// is a known reading of unlimited (MaxUint64).
func readUsageLimit(path string) (uint64, bool) {
	value, ok := readUsageFile(path)
	if !ok {
		return 0, false
	}
	if value == "max" {
		return math.MaxUint64, true
	}
	return parseUsageCounter(value)
}

// readV2CPUUsageUsec reads cpu.stat's usage_usec through the same strict
// key/value parser as the pressure counters, so a missing file, missing key,
// malformed line, or duplicate usage_usec is unknown. The usec value must
// also convert to nanoseconds without overflow.
func readV2CPUUsageUsec(path string) (uint64, bool) {
	values, ok := readPressureCounters(path, "usage_usec")
	if !ok {
		return 0, false
	}
	usage := values["usage_usec"]
	if usage > math.MaxUint64/1000 {
		return 0, false
	}
	return usage, true
}
