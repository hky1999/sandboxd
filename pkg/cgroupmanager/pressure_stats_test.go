// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPressureCountersRejectUnknownAndMalformedSamples(t *testing.T) {
	for name, input := range map[string]string{
		"missing": "", "partial": "high 0\noom 0\n", "negative": "high -1\noom 0\noom_kill 0\n",
		"duplicate": "high 0\nhigh 1\noom 0\noom_kill 0\n", "overflow": "high 18446744073709551616\noom 0\noom_kill 0\n",
		"malformed": "high 1 extra\noom 0\noom_kill 0\n", "too large": strings.Repeat(" ", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "memory.events")
			if name != "missing" {
				require.NoError(t, os.WriteFile(path, []byte(input), 0600))
			}
			_, known := readPressureCounters(path, "high", "oom", "oom_kill")
			require.False(t, known)
		})
	}
}

func TestPressureStatsPreserveZeroAndCumulativeValues(t *testing.T) {
	path := t.TempDir()
	writeTestFile(t, filepath.Join(path, "cpu.stat"), "usage_usec 99\nnr_periods 20\nnr_throttled 3\nthrottled_usec 17\n")
	writeTestFile(t, filepath.Join(path, "memory.events"), "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	stats := readV2PressureStats(path)
	require.True(t, stats.CPUPressureKnown)
	require.Equal(t, uint64(20), stats.CPUPeriods)
	require.Equal(t, uint64(3), stats.CPUThrottledPeriods)
	require.Equal(t, uint64(17000), stats.CPUThrottledNanos)
	require.True(t, stats.MemoryPressureKnown)
	require.Zero(t, stats.MemoryHighEvents)
	writeTestFile(t, filepath.Join(path, "memory.events"), "high 9\noom 2\noom_kill 1\n")
	stats = readV2PressureStats(path)
	require.Equal(t, uint64(9), stats.MemoryHighEvents)
	require.Equal(t, uint64(2), stats.MemoryOOMEvents)
	require.Equal(t, uint64(1), stats.MemoryOOMKillEvents)
	require.NoError(t, os.Remove(filepath.Join(path, "cpu.stat")))
	stats = readV2PressureStats(path)
	require.False(t, stats.CPUPressureKnown)
	require.True(t, stats.MemoryPressureKnown)
}
