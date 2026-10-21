// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckpointSyncAndBackgroundRestoreDecode(t *testing.T) {
	var cfg Config
	err := toml.Unmarshal([]byte(`
[runtime]
[runtime.checkpoint_sync]
sync_output = true
[runtime.runsc]
background_restore = true
`), &cfg.PluginConfig)
	require.NoError(t, err)
	assert.True(t, cfg.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput,
		"runtime.checkpoint_sync.sync_output must decode")
	assert.True(t, cfg.PluginConfig.RuntimeConfig.Runsc.BackgroundRestore,
		"runtime.runsc.background_restore must decode")
}

func TestCheckpointSyncDefaultsPreserveLocalContract(t *testing.T) {
	var cfg Config
	err := toml.Unmarshal([]byte(""), &cfg.PluginConfig)
	require.NoError(t, err)
	assert.False(t, cfg.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput,
		"defaults must not force writeback for local recovery points")
	assert.False(t, cfg.PluginConfig.RuntimeConfig.Runsc.BackgroundRestore,
		"defaults must keep synchronous restores")
}
