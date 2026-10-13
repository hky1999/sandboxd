// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

func TestStartupPreservesIncompatibleMetadata(t *testing.T) {
	for _, bucket := range []string{config.CgroupBucket, config.BridgeIpBucket} {
		t.Run(bucket, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metadata.db")
			db := store.NewStoreImp(path)
			require.NoError(t, db.StoreRaw(bucket, []byte{0x0b, 0x0a, 0x05}))
			require.NoError(t, db.StoreRaw("unsettled-owner", []byte(`{"generation":"original","pending":true}`)))
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Error(t, resetMetadataIfResourceStateIncompatible(path))
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestStartupPreservesStateWithoutMatchingHostStamp(t *testing.T) {
	for _, stamp := range []string{"missing", "foreign", "directory"} {
		t.Run(stamp, func(t *testing.T) {
			base := t.TempDir()
			storeDir, rootDir, imageDir := filepath.Join(base, "store"), filepath.Join(base, "root"), filepath.Join(base, "images")
			files := []string{filepath.Join(storeDir, "metadata.db"), filepath.Join(rootDir, "containers", "original.state"), filepath.Join(imageDir, "mount_records.db")}
			for _, path := range files {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
				require.NoError(t, os.WriteFile(path, []byte("original unsettled state"), 0600))
			}
			stampPath := filepath.Join(storeDir, ".pod_host")
			if stamp == "foreign" {
				require.NoError(t, os.WriteFile(stampPath, []byte("another-original-owner"), 0600))
			} else if stamp == "directory" {
				require.NoError(t, os.Mkdir(stampPath, 0700))
			}
			require.Error(t, resetStateIfPodChanged(storeDir, rootDir, imageDir))
			for _, path := range files {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, "original unsettled state", string(data))
			}
			if stamp == "missing" {
				_, err := os.Lstat(stampPath)
				require.True(t, os.IsNotExist(err))
			} else if stamp == "foreign" {
				data, err := os.ReadFile(stampPath)
				require.NoError(t, err)
				require.Equal(t, "another-original-owner", string(data))
			}
		})
	}
}

func TestStartupInitializesOnlyEmptyStateAndPreservesSameHost(t *testing.T) {
	base := t.TempDir()
	storeDir, rootDir, imageDir := filepath.Join(base, "store"), filepath.Join(base, "root"), filepath.Join(base, "images")
	require.NoError(t, resetStateIfPodChanged(storeDir, rootDir, imageDir))
	host, err := os.Hostname()
	require.NoError(t, err)
	stamp, err := os.ReadFile(filepath.Join(storeDir, ".pod_host"))
	require.NoError(t, err)
	require.Equal(t, host, string(stamp))
	path := filepath.Join(rootDir, "scheduler-retirements", "original.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte("pending original retirement"), 0600))
	require.NoError(t, resetStateIfPodChanged(storeDir, rootDir, imageDir))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "pending original retirement", string(data))
}

func TestStartupRejectsMissingStampWithRootOrImageState(t *testing.T) {
	for _, location := range []string{"root", "images"} {
		t.Run(location, func(t *testing.T) {
			base := t.TempDir()
			storeDir, rootDir, imageDir := filepath.Join(base, "store"), filepath.Join(base, "root"), filepath.Join(base, "images")
			path := filepath.Join(base, location, "original.json")
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
			require.NoError(t, os.WriteFile(path, []byte("original owner"), 0600))
			require.Error(t, resetStateIfPodChanged(storeDir, rootDir, imageDir))
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "original owner", string(data))
		})
	}
}
