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

package server

import (
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestMemoryLimitConfigAndDistillReserve(t *testing.T) {
	var cfg config.Config
	require.NoError(t, toml.Unmarshal([]byte(`
[plugin.resource]
cgroup_cache_size = 1
[plugin.resource.memory_limit]
enabled = true
system_reserve = "512MiB"
control_reserve = "auto"
other_reserve = "256MiB"
safety_buffer = "512MiB"
runtime_headroom = "134217735"
[plugin.image]
cgroup_memory_limit = "256MiB"
`), &cfg))
	require.True(t, cfg.MemoryLimit.Enabled)
	require.Equal(t, "512MiB", cfg.MemoryLimit.SystemReserve)
	require.Equal(t, "auto", cfg.MemoryLimit.ControlReserve)
	require.Equal(t, "256MiB", cfg.MemoryLimit.OtherReserve)
	require.Equal(t, "512MiB", cfg.MemoryLimit.SafetyBuffer)
	require.Equal(t, "134217735", cfg.MemoryLimit.RuntimeHeadroom)
	reserve, err := memoryLimitDistillReserve(cfg)
	require.NoError(t, err)
	require.Equal(t, []int64{256 << 20}, reserve)

	for _, value := range []string{"", "0", "-1", "max", "invalid", "9223372036854775807GiB"} {
		invalid := cfg
		invalid.CgroupMemoryLimit = value
		_, err := memoryLimitDistillReserve(invalid)
		require.Error(t, err, value)
	}
	disabledCgroup := cfg
	disabledCgroup.DisableCgroup = true
	_, err = memoryLimitDistillReserve(disabledCgroup)
	require.Error(t, err)
	disabledCache := cfg
	disabledCache.CgroupCacheSize = 0
	_, err = memoryLimitDistillReserve(disabledCache)
	require.Error(t, err)
	cfg.MemoryLimit.Enabled = false
	cfg.CgroupMemoryLimit = "invalid"
	reserve, err = memoryLimitDistillReserve(cfg)
	require.NoError(t, err, "disabled policy must not validate unused reserves")
	require.Nil(t, reserve)
}
