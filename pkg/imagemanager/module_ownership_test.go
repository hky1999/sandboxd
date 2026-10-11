// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package imagemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/stretchr/testify/require"
)

// Empty local configuration and inventory keep this construction free of
// registry calls, physical mounts, daemon processes, and cgroup changes.
func ownershipModuleConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0600))
		return p
	}
	return Config{Root: t.TempDir(), DisableCgroup: true, OSSTemplate: file("oss.json"), NydusTemplate: file("nydus.json"), OSSAuthsPath: file("objects.json"), RegistryAuthsPath: file("registry.json")}
}

func TestImageManagerOwnershipModuleRejectsDuplicateAndReopensAfterStop(t *testing.T) {
	cfg := ownershipModuleConfig(t)
	first, err := NewModule(cfg)
	require.NoError(t, err)
	t.Cleanup(first.Stop)
	second, err := NewModule(cfg)
	require.Error(t, err)
	require.Nil(t, second)
	require.NoError(t, first.StopWithContext(context.Background()))
	require.False(t, first.Healthy())
	second, err = NewModule(cfg)
	require.NoError(t, err)
	t.Cleanup(second.Stop)
	_, err = first.Service().MountOCI(&api.OCIMountRequest{ImageURL: "private.example/original"})
	require.ErrorContains(t, err, "closing")
}

func TestImageManagerOwnershipModuleTimeoutRetainsRootForActiveWork(t *testing.T) {
	cfg := ownershipModuleConfig(t)
	m, err := NewModule(cfg)
	require.NoError(t, err)
	t.Cleanup(m.Stop)
	release, err := m.owner.RetainOwnership()
	require.NoError(t, err)
	t.Cleanup(release)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, m.StopWithContext(ctx), context.DeadlineExceeded)
	require.False(t, m.Healthy())
	replacement, err := NewModule(cfg)
	require.Error(t, err)
	require.Nil(t, replacement)
	release()
	require.NoError(t, m.StopWithContext(context.Background()))
	replacement, err = NewModule(cfg)
	require.NoError(t, err)
	t.Cleanup(replacement.Stop)
}

func TestImageManagerOwnershipModuleConstructorFailureReleasesRoot(t *testing.T) {
	cfg := ownershipModuleConfig(t)
	// A directory at the database path makes worker construction fail after
	// both backend managers have been constructed.
	db := filepath.Join(cfg.Root, "mount_records.db")
	require.NoError(t, os.Mkdir(db, 0700))
	m, err := NewModule(cfg)
	require.Error(t, err)
	require.Nil(t, m)
	require.NoError(t, os.Remove(db))
	m, err = NewModule(cfg)
	require.NoError(t, err)
	t.Cleanup(m.Stop)
}
