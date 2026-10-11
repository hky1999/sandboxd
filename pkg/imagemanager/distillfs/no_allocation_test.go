// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonMountOperationNoAllocationInventoryRejectsUnindexedEffects(t *testing.T) {
	for _, entry := range []string{"allocations/orphan", "mnt/orphan", "daemons/orphan", "image_metas/orphan"} {
		t.Run(entry, func(t *testing.T) {
			cfg := ownershipManagerConfig(t)
			m := ownedManager(t, cfg)
			require.NoError(t, m.ConfirmNoPreparation(preparationOwner()))
			path := filepath.Join(cfg.Root, entry)
			require.NoError(t, os.MkdirAll(path, 0700))
			require.Error(t, m.ConfirmNoPreparation(preparationOwner()))
			require.DirExists(t, path, "checking inventory must never remove an unknown allocation")
		})
	}
}

func TestDaemonMountOperationNoAllocationInventoryKeepsOriginalAndAllowsKnownNeighbor(t *testing.T) {
	cfg := ownershipManagerConfig(t)
	m := ownedManager(t, cfg)
	neighbor := PreparationOwner{OperationID: strings.Repeat("e", 64), RequestFingerprint: strings.Repeat("f", 64)}
	id := strings.Repeat("a", 64)
	require.NoError(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "neighbor.erofs"}, neighbor, func(string, string) error { return nil }))
	info, err := m.FindPreparation(neighbor)
	require.NoError(t, err)
	require.NoError(t, m.ConfirmNoPreparation(preparationOwner()), "a proven unrelated preparation cannot block empty original ownership")
	require.Error(t, m.ConfirmNoPreparation(neighbor))
	changed := neighbor
	changed.RequestFingerprint = strings.Repeat("b", 64)
	require.Error(t, m.ConfirmNoPreparation(changed), "the same operation with another fingerprint remains unresolved")
	require.DirExists(t, filepath.Dir(info.Target))
	require.NoError(t, m.Close(context.Background()))
	m = ownedManager(t, cfg)
	require.NoError(t, m.ConfirmNoPreparation(preparationOwner()))
	require.Error(t, m.ConfirmNoPreparation(neighbor), "recovery must preserve original ownership")
}

func TestDaemonMountOperationNoAllocationInventoryRejectsLegacyBusyAndSymlink(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		m := ownedManager(t, ownershipManagerConfig(t))
		require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: strings.Repeat("a", 64), Name: "legacy.erofs"}))
		require.Error(t, m.ConfirmNoPreparation(preparationOwner()))
	})
	t.Run("busy", func(t *testing.T) {
		m := ownedManager(t, ownershipManagerConfig(t))
		owner := preparationOwner()
		id := strings.Repeat("a", 64)
		require.NoError(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}, owner, func(string, string) error { return nil }))
		d := m.GetDaemon(id)
		d.physicalMu.Lock()
		err := m.ConfirmNoPreparation(owner)
		d.physicalMu.Unlock()
		require.ErrorContains(t, err, "currently active")
	})
	t.Run("symlink", func(t *testing.T) {
		cfg := ownershipManagerConfig(t)
		m := ownedManager(t, cfg)
		foreign := t.TempDir()
		require.NoError(t, os.Symlink(foreign, filepath.Join(cfg.Root, "allocations", "foreign")))
		require.Error(t, m.ConfirmNoPreparation(preparationOwner()))
		require.DirExists(t, foreign)
	})
}

func TestDaemonMountOperationNoAllocationInventoryRejectsUnindexedMetadata(t *testing.T) {
	cfg := ownershipManagerConfig(t)
	m := ownedManager(t, cfg)
	file := filepath.Join(cfg.Root, "daemon_configs", "unindexed.json")
	require.NoError(t, os.WriteFile(file, []byte(`{}`), 0600))
	require.Error(t, m.ConfirmNoPreparation(preparationOwner()), "an unindexed native owner must prevent a no-allocation proof")
	require.FileExists(t, file)
}

func TestDaemonMountOperationNoAllocationInventoryRejectsChangedAndMissingMetadata(t *testing.T) {
	cfg := ownershipManagerConfig(t)
	m := ownedManager(t, cfg)
	neighbor := PreparationOwner{OperationID: strings.Repeat("e", 64), RequestFingerprint: strings.Repeat("f", 64)}
	id := strings.Repeat("a", 64)
	require.NoError(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "neighbor.erofs"}, neighbor, func(string, string) error { return nil }))
	path := filepath.Join(cfg.Root, "daemon_configs", id+".json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0600))
	require.Error(t, m.ConfirmNoPreparation(preparationOwner()))
	require.NoError(t, os.Remove(path))
	require.Error(t, m.ConfirmNoPreparation(preparationOwner()))
	require.NoError(t, os.WriteFile(path, raw, 0600))
	require.NoError(t, m.ConfirmNoPreparation(preparationOwner()))
}
