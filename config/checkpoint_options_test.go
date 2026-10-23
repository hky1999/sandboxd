// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestCheckpointOptionsDefaultOff(t *testing.T) {
	cfg := DefaultConfig()
	require.False(t, cfg.RuntimeConfig.Runsc.BackgroundRestore)
	require.False(t, cfg.RuntimeConfig.CheckpointSync.SyncOutput)
}

func TestCheckpointOptionsTOML(t *testing.T) {
	for _, background := range []bool{false, true} {
		for _, syncOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("background=%t/sync=%t", background, syncOutput), func(t *testing.T) {
				cfg := DefaultConfig()
				input := fmt.Sprintf("[plugin.runtime.runsc]\nbackground_restore=%t\n[plugin.runtime.checkpoint_sync]\nsync_output=%t\n", background, syncOutput)
				require.NoError(t, toml.Unmarshal([]byte(input), &cfg))
				require.Equal(t, background, cfg.RuntimeConfig.Runsc.BackgroundRestore)
				require.Equal(t, syncOutput, cfg.RuntimeConfig.CheckpointSync.SyncOutput)
			})
		}
	}
}
