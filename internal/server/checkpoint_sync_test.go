// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

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

func TestCheckpointSyncOutputRejectsUnsupportedEntry(t *testing.T) {
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
		return os.Symlink("missing", filepath.Join(cfg.Directory, "checkpoint.img"))
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput = true
	storeRunningSandbox(t, service, "sbox-sync-failure", "runsc")
	directory := filepath.Join(t.TempDir(), "capture")
	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID: "sbox-sync-failure", CheckpointDir: directory, TimeoutSeconds: 5, LeaveRunning: true,
	})
	require.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.ErrorContains(t, err, "output persistence barrier failed")
	assert.NoDirExists(t, directory)
	assert.Zero(t, handler.deleteCalls)
}

func TestCheckpointSyncOutputAcceptsNestedOutput(t *testing.T) {
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
		if err := os.Mkdir(filepath.Join(cfg.Directory, "memory"), 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(cfg.Directory, "memory", "pages.img"), []byte("pages"), 0600)
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput = true
	storeRunningSandbox(t, service, "sbox-sync-ok", "runsc")
	directory := filepath.Join(t.TempDir(), "capture")
	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID: "sbox-sync-ok", CheckpointDir: directory, TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.FileExists(t, filepath.Join(directory, "memory", "pages.img"))
}

func TestCheckpointSyncOutputPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
		err := os.WriteFile(filepath.Join(cfg.Directory, "checkpoint.img"), []byte("image"), 0600)
		cancel()
		return err
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput = true
	storeRunningSandbox(t, service, "sbox-sync-cancel", "runsc")
	directory := filepath.Join(t.TempDir(), "capture")
	response, err := service.Checkpoint(ctx, &runtime.CheckpointRequest{
		ID: "sbox-sync-cancel", CheckpointDir: directory, TimeoutSeconds: 5,
	})
	require.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, codes.Canceled, status.Code(err))
	assert.NoDirExists(t, directory)
	assert.Zero(t, handler.deleteCalls)
}

func TestCheckpointWithoutSyncKeepsExistingContract(t *testing.T) {
	handler := newCheckpointTestHandler()
	handler.checkpointFn = func(_ context.Context, cfg svc.CheckpointConfig) error {
		return os.Symlink("missing", filepath.Join(cfg.Directory, "opaque-runtime-entry"))
	}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	require.False(t, service.config.PluginConfig.RuntimeConfig.CheckpointSync.SyncOutput)
	storeRunningSandbox(t, service, "sbox-no-sync", "runsc")
	directory := filepath.Join(t.TempDir(), "capture")
	response, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID: "sbox-no-sync", CheckpointDir: directory, TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.DirExists(t, directory)
}
