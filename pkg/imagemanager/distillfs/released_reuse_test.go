// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0
package distillfs

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func retiredPreparationForReuse(t *testing.T) (*manager, *Daemon, *DaemonCreateOpt, string) {
	t.Helper()
	m := ownedManager(t, ownershipManagerConfig(t))
	opts := &DaemonCreateOpt{ID: strings.Repeat("e", 64), Name: "original.erofs"}
	require.NoError(t, m.PrepareDaemon(opts, preparationOwner(), func(string, string) error { return nil }))
	d := m.GetDaemon(opts.ID)
	generation := d.originalPreparation().Generation
	require.NoError(t, d.UnmountIfPhysicalGeneration(generation))
	return m, d, opts, generation
}
func TestRetiredPreparationNewOwnerGetsDifferentAllocation(t *testing.T) {
	m, old, opts, generation := retiredPreparationForReuse(t)
	owner := PreparationOwner{OperationID: strings.Repeat("1", 64), RequestFingerprint: strings.Repeat("2", 64)}
	bound := ""
	require.NoError(t, m.PrepareDaemon(opts, owner, func(g, target string) error { bound = g; return nil }))
	current := m.GetDaemon(opts.ID)
	require.NotSame(t, old, current)
	require.NotEqual(t, generation, bound)
	require.Equal(t, bound, current.originalPreparation().Generation)
	require.NotEqual(t, old.meta.MountPoint, current.meta.MountPoint)
	before, err := os.ReadFile(current.savedPath)
	require.NoError(t, err)
	_, err = old.MountWithPhysicalGeneration()
	require.Error(t, err)
	require.Error(t, old.persistDaemonMetadata())
	require.NoError(t, old.UnmountIfPhysicalGeneration(generation))
	phase, err := old.InspectPhysicalGeneration(generation)
	require.NoError(t, err)
	require.Equal(t, "released", phase)
	after, err := os.ReadFile(current.savedPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
func TestUnresolvedPreparationCannotBeReplacedByNewProducer(t *testing.T) {
	m := ownedManager(t, ownershipManagerConfig(t))
	opts := &DaemonCreateOpt{ID: strings.Repeat("a", 64), Name: "original.erofs"}
	require.NoError(t, m.PrepareDaemon(opts, preparationOwner(), func(string, string) error { return nil }))
	old := m.GetDaemon(opts.ID)
	before, err := os.ReadFile(old.savedPath)
	require.NoError(t, err)
	called := false
	require.Error(t, m.PrepareDaemon(opts, PreparationOwner{OperationID: strings.Repeat("1", 64), RequestFingerprint: strings.Repeat("2", 64)}, func(string, string) error { called = true; return nil }))
	require.False(t, called)
	require.Same(t, old, m.GetDaemon(opts.ID))
	after, err := os.ReadFile(old.savedPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
func TestRetiredPreparationForeignDirectoryBlocksReplacement(t *testing.T) {
	m, old, opts, _ := retiredPreparationForReuse(t)
	directory := old.originalPreparation().Directory
	require.NoError(t, os.Mkdir(directory, 0700))
	marker := filepath.Join(directory, "foreign")
	require.NoError(t, os.WriteFile(marker, []byte("preserve"), 0600))
	called := false
	require.Error(t, m.PrepareDaemon(opts, PreparationOwner{OperationID: strings.Repeat("1", 64), RequestFingerprint: strings.Repeat("2", 64)}, func(string, string) error { called = true; return nil }))
	require.False(t, called)
	require.Same(t, old, m.GetDaemon(opts.ID))
	data, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(data))
	require.NoError(t, os.Rename(directory, directory+"-foreign-preserved"))
}
func TestRetiredAllocationReplacementPreservesAnotherSource(t *testing.T) {
	m, _, opts, _ := retiredPreparationForReuse(t)
	peer := &DaemonCreateOpt{ID: strings.Repeat("f", 64), Name: "peer.erofs"}
	require.NoError(t, m.PrepareDaemon(peer, PreparationOwner{OperationID: strings.Repeat("3", 64), RequestFingerprint: strings.Repeat("4", 64)}, func(string, string) error { return nil }))
	neighbor := m.GetDaemon(peer.ID)
	before, err := os.ReadFile(neighbor.savedPath)
	require.NoError(t, err)
	require.NoError(t, m.PrepareDaemon(opts, PreparationOwner{OperationID: strings.Repeat("1", 64), RequestFingerprint: strings.Repeat("2", 64)}, func(string, string) error { return nil }))
	require.Same(t, neighbor, m.GetDaemon(peer.ID))
	after, err := os.ReadFile(neighbor.savedPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
