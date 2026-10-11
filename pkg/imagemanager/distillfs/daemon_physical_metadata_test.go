// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonPhysicalMetadataPrivatePublication(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.meta.Env = []string{"TEST_PRIVATE_VALUE=fixture-only"}
	require.NoError(t, mock.saveMeta())
	info, err := os.Stat(mock.savedPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestDaemonPhysicalMetadataDoesNotFollowReplacementSymlink(t *testing.T) {
	root := t.TempDir()
	mock := newMockDaemon(root)
	neighbor := filepath.Join(root, "neighbor")
	original := []byte("neighbor metadata")
	require.NoError(t, os.WriteFile(neighbor, original, 0600))
	require.NoError(t, os.Symlink(neighbor, mock.savedPath))
	require.Error(t, mock.saveMeta())
	current, err := os.ReadFile(neighbor)
	require.NoError(t, err)
	require.Equal(t, original, current)
}

func TestDaemonPhysicalMetadataReplacementIsNotOverwritten(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	require.NoError(t, mock.saveMeta())
	replacement := []byte(`{"id":"different-original-owner"}`)
	require.NoError(t, os.WriteFile(mock.savedPath, replacement, 0600))
	mock.meta.Env = []string{"TEST_NEW_VALUE=fixture-only"}
	require.Error(t, mock.saveMeta())
	current, err := os.ReadFile(mock.savedPath)
	require.NoError(t, err)
	require.Equal(t, replacement, current)
}

func TestDaemonPhysicalMetadataInvalidRecordsStopBeforeRecovery(t *testing.T) {
	for _, mode := range []string{"duplicate identity", "unknown field", "trailing object"} {
		t.Run(mode, func(t *testing.T) {
			mock := newMockDaemon(t.TempDir())
			require.NoError(t, mock.applyConfig())
			original, err := json.Marshal(mock.meta)
			require.NoError(t, err)
			switch mode {
			case "duplicate identity":
				original = bytes.Replace(original, []byte(`"id":"test-daemon"`), []byte(`"id":"original","id":"test-daemon"`), 1)
			case "unknown field":
				original = append(original[:len(original)-1], []byte(`,"foreign_owner":"neighbor"}`)...)
			default:
				original = append(original, []byte(` {"id":"neighbor"}`)...)
			}
			require.NoError(t, os.WriteFile(mock.savedPath, original, 0600))
			loaded := &Daemon{ctx: context.Background(), binPath: mock.binPath}
			require.Error(t, loaded.LoadExisted(mock.savedPath))
			current, err := os.ReadFile(mock.savedPath)
			require.NoError(t, err)
			require.Equal(t, original, current)
			require.False(t, loaded.watcherActive.Load())
		})
	}
}

func TestDaemonPhysicalMetadataCorruptionCannotDisappearFromManager(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "daemon_configs")
	require.NoError(t, os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "original.json")
	original := []byte(`{"id":"original",broken`)
	require.NoError(t, os.WriteFile(path, original, 0600))
	mgr := &manager{ctx: context.Background(), root: root, daemons: map[string]*Daemon{}, recovered: map[string]bool{}}
	require.Error(t, mgr.loadExistedDaemons(), "a broken source record cannot turn into an empty known inventory")
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, current)
}
