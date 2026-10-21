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

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCheckpointSyncOutputBarrierFailsPublicationOnUnsyncableEntry(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput = true
	storeRunningSandbox(t, service, "sbox-sync", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	// The runtime handler "succeeds" but leaves an entry the durability walk
	// must refuse: a READY acknowledgement may never cover such output.
	handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
		if err := os.WriteFile(filepath.Join(cfg.Directory, "checkpoint.img"), []byte("image"), 0600); err != nil {
			return err
		}
		return os.Symlink("nowhere", filepath.Join(cfg.Directory, "dangling"))
	}

	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-sync",
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
	})
	require.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.NoDirExists(t, directory, "failed barrier must clean the output directory")
}

func TestCheckpointSyncOutputBarrierPassesCleanOutput(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput = true
	storeRunningSandbox(t, service, "sbox-sync-ok", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-sync-ok",
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.FileExists(t, filepath.Join(directory, "checkpoint.img"))
}

func TestCheckpointWithoutSyncKeepsHistoricalLocalContract(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	require.False(t, service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput,
		"the default must not force writeback for local recovery points")
	storeRunningSandbox(t, service, "sbox-local", "runsc")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID:             "sbox-local",
		CheckpointDir:  directory,
		TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
}
