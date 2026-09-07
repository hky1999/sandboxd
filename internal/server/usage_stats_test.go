// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// The Stats response must forward the cgroup backend's source-validity flags
// verbatim: a backend that proves its kernel files reports them true, and one
// that cannot (or a zero-valued legacy reading) reports them false without the
// server manufacturing validity.
func TestStatsMapsSourceValidityFlags(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	require.NoError(t, h.sandboxManager.StoreMetadata("stats-flags", &runtime.SandboxMetadata{
		ID:             "stats-flags",
		RuntimeHandler: "runsc",
		ResourceFacts:  map[string]string{config.ResourceNameCgroup: "/sandbox/lease"},
	}))
	h.cgroupMgr = &resizeCgroups{stats: cgroupmanager.Stats{
		CPUUsageNanos: 123000, CPUUsageKnown: true,
		MemoryUsageBytes: 4096, MemoryUsageKnown: true,
		MemoryLimitBytes: 1 << 30, MemoryLimitKnown: true,
		MemoryMaxUsageBytes: 8192, MemoryPeakKnown: true,
	}}
	response, err := h.Stats(context.Background(), &runtime.StatsRequest{ID: "stats-flags"})
	require.NoError(t, err)
	require.True(t, response.CpuUsageKnown)
	require.True(t, response.MemoryUsageKnown)
	require.True(t, response.MemoryLimitKnown)
	require.True(t, response.MemoryPeakKnown)
	require.Equal(t, uint64(8192), response.MemoryMaxUsageBytes)

	// A backend that proved nothing — the cgroup v1 shape and the pre-flag
	// zero value — must surface unknown, not defaults turned known.
	h.cgroupMgr = &resizeCgroups{stats: cgroupmanager.Stats{
		CPUUsageNanos: 123000, MemoryMaxUsageBytes: 8192,
	}}
	response, err = h.Stats(context.Background(), &runtime.StatsRequest{ID: "stats-flags"})
	require.NoError(t, err)
	require.False(t, response.CpuUsageKnown)
	require.False(t, response.MemoryUsageKnown)
	require.False(t, response.MemoryLimitKnown)
	require.False(t, response.MemoryPeakKnown)
	require.Equal(t, uint64(8192), response.MemoryMaxUsageBytes)
}
