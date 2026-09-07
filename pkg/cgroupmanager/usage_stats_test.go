// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeUsageFixture(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "counter")
	require.NoError(t, os.WriteFile(path, []byte(text), 0600))
	return path
}

func TestReadUsageCounterTreatsOnlyExactDecimalsAsKnown(t *testing.T) {
	for name, tc := range map[string]struct {
		text  string
		value uint64
		known bool
	}{
		"observed zero":   {text: "0", value: 0, known: true},
		"decimal":         {text: "4096", value: 4096, known: true},
		"newline wrapped": {text: " 123\n", value: 123, known: true},
		"max uint64":      {text: "18446744073709551615", value: math.MaxUint64, known: true},
		"overflow":        {text: "18446744073709551616", known: false},
		"empty":           {text: "", known: false},
		"whitespace only": {text: " \n\t", known: false},
		"max sentinel":    {text: "max", known: false},
		"plus signed":     {text: "+1", known: false},
		"negative":        {text: "-1", known: false},
		"trailing junk":   {text: "12x", known: false},
		"embedded space":  {text: "1 2", known: false},
		"hex":             {text: "0x10", known: false},
		"float":           {text: "1.5", known: false},
		"underscored":     {text: "1_000", known: false},
	} {
		t.Run(name, func(t *testing.T) {
			value, known := readUsageCounter(writeUsageFixture(t, tc.text))
			require.Equal(t, tc.known, known)
			require.Equal(t, tc.value, value)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		_, known := readUsageCounter(filepath.Join(t.TempDir(), "absent"))
		require.False(t, known)
	})
	t.Run("oversized file", func(t *testing.T) {
		path := writeUsageFixture(t, strings.Repeat("1", maxUsageFileBytes+1))
		_, known := readUsageCounter(path)
		require.False(t, known)
	})
}

func TestReadUsageLimitAcceptsOnlyMaxSentinelAndDecimals(t *testing.T) {
	for name, tc := range map[string]struct {
		text  string
		value uint64
		known bool
	}{
		"unlimited":    {text: "max", value: math.MaxUint64, known: true},
		"zero":         {text: "0", value: 0, known: true},
		"finite":       {text: "8192", value: 8192, known: true},
		"cased max":    {text: "MAX", known: false},
		"max with arg": {text: "max 0", known: false},
		"negative":     {text: "-8192", known: false},
		"overflow":     {text: "18446744073709551616", known: false},
	} {
		t.Run(name, func(t *testing.T) {
			value, known := readUsageLimit(writeUsageFixture(t, tc.text))
			require.Equal(t, tc.known, known)
			require.Equal(t, tc.value, value)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		_, known := readUsageLimit(filepath.Join(t.TempDir(), "absent"))
		require.False(t, known)
	})
}

func TestReadV2CPUUsageUsecSharesStrictCounterRules(t *testing.T) {
	read := func(text string) (uint64, bool) {
		return readV2CPUUsageUsec(writeUsageFixture(t, text))
	}
	usage, known := read("usage_usec 123\nuser_usec 80\nsystem_usec 43\n")
	require.True(t, known)
	require.Equal(t, uint64(123), usage)

	for name, text := range map[string]string{
		"missing key":     "user_usec 80\nsystem_usec 43\n",
		"duplicate usage": "usage_usec 5\nusage_usec 6\n",
		"malformed line":  "usage_usec 5 extra\n",
		"signed value":    "usage_usec -5\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, known := read(text)
			require.False(t, known)
		})
	}
	// The boundary converts exactly; anything larger cannot become nanoseconds.
	usage, known = read(fmt.Sprintf("usage_usec %d\n", math.MaxUint64/1000))
	require.True(t, known)
	require.Equal(t, uint64(math.MaxUint64/1000), usage)
	_, known = read(fmt.Sprintf("usage_usec %d\n", math.MaxUint64/1000+1))
	require.False(t, known)
	_, known = readV2CPUUsageUsec(filepath.Join(t.TempDir(), "absent"))
	require.False(t, known)
}

func TestV2StatKnownFlagsTrackStrictDirectReads(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	writeTestFile(t, filepath.Join(groupPath, "cgroup.controllers"), "cpu memory")
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 123\nuser_usec 80\nsystem_usec 43\n")
	writeTestFile(t, filepath.Join(groupPath, "cpu.max"), "max 100000")
	writeTestFile(t, filepath.Join(groupPath, "memory.stat"), "anon 100\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.current"), "4096")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "max")
	writeTestFile(t, filepath.Join(groupPath, "memory.peak"), "0")
	writeTestFile(t, filepath.Join(groupPath, "memory.events"), "oom_kill 0\n")

	ops := &cgroupV2{mountpoint: mountpoint}
	stats, err := ops.stat(name)
	require.NoError(t, err)
	// A measured zero peak stays a known zero; it must not fall back to usage.
	require.True(t, stats.CPUUsageKnown)
	require.Equal(t, uint64(123000), stats.CPUUsageNanos)
	require.True(t, stats.MemoryUsageKnown)
	require.Equal(t, uint64(4096), stats.MemoryUsageBytes)
	require.True(t, stats.MemoryLimitKnown)
	require.Equal(t, uint64(math.MaxUint64), stats.MemoryLimitBytes)
	require.True(t, stats.MemoryPeakKnown)
	require.Zero(t, stats.MemoryMaxUsageBytes)

	// Without memory.peak the numeric keeps the legacy current-usage fallback
	// for old consumers, but the flag reports the peak unknown. The other
	// flags must move independently.
	require.NoError(t, os.Remove(filepath.Join(groupPath, "memory.peak")))
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.False(t, stats.MemoryPeakKnown)
	require.Equal(t, stats.MemoryUsageBytes, stats.MemoryMaxUsageBytes)
	require.True(t, stats.CPUUsageKnown)
	require.True(t, stats.MemoryUsageKnown)
	require.True(t, stats.MemoryLimitKnown)

	// A usage_usec too large for the nanosecond conversion is unknown even
	// though the legacy number stays at its clamped value.
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 18446744073709551615\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.peak"), "8192")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.False(t, stats.CPUUsageKnown)
	require.Equal(t, uint64(math.MaxUint64), stats.CPUUsageNanos)
	require.True(t, stats.MemoryPeakKnown)
	require.Equal(t, uint64(8192), stats.MemoryMaxUsageBytes)

	// A missing memory.current leaves usage unknown while the other sources
	// stay proven.
	require.NoError(t, os.Remove(filepath.Join(groupPath, "memory.current")))
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.False(t, stats.MemoryUsageKnown)
	require.True(t, stats.MemoryLimitKnown)
	require.True(t, stats.MemoryPeakKnown)
}
