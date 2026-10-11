// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestMountGenerationSamePathReplacementStopsBeforeBackend(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	replacement := *original
	replacement.PhysicalGeneration = strings.Repeat("b", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, &replacement))
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration}))
	require.Zero(t, lookups, "a changed physical generation must be rejected before backend dispatch")
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, &replacement, got)
}

func TestMountGenerationPublicationCannotOverwriteOriginalRoute(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	replacement := *original
	replacement.PhysicalGeneration = strings.Repeat("b", 64)
	require.Error(t, w.mountStore.Publish(original.ImageURL, &replacement))
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.NoError(t, w.mountStore.Publish(original.ImageURL, original))
}

func TestMountGenerationManagedRequestRequiresPersistentRouteBeforeDispatch(t *testing.T) {
	w := mustNewHttpWorker(t, newMockManager())
	_, err := w.MountOCI(&OCIMountRequest{ImageURL: "registry.example/original:tag", RequirePhysicalGeneration: true})
	require.ErrorContains(t, err, "persistent route")
}

func TestMountGenerationCompletionSurvivesDatabaseReopen(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	require.NoError(t, w.mountStore.DeleteIfRecord(original.ImageURL, original))
	replacement := *original
	replacement.PhysicalGeneration = strings.Repeat("b", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, &replacement))
	path := w.mountStore.db.Path()
	require.NoError(t, w.mountStore.Close())
	var err error
	w.mountStore, err = OpenMountStore(path)
	require.NoError(t, err)
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	resp, err := w.MountOCI(&OCIMountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration})
	require.NoError(t, err)
	require.True(t, resp.Released)
	require.Equal(t, original.PhysicalGeneration, resp.PhysicalGeneration)
	require.NoError(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration}))
	require.Zero(t, lookups)
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, &replacement, got)
}

func TestMountGenerationCompletedGenerationCannotBeRepublished(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	require.NoError(t, w.mountStore.DeleteIfRecord(original.ImageURL, original))
	require.Error(t, w.recordMountGeneration(original.ImageURL, original.MountType, original.NydusImageURL, original.MountPoint, original.PhysicalGeneration))
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestMountGenerationCompletionCorruptionCannotAuthorizeReplay(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	require.NoError(t, w.mountStore.DeleteIfRecord(original.ImageURL, original))
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(mountCompletionsBucket)
		key := mountCompletionKey(original.ImageURL, original.PhysicalGeneration)
		raw := bytes.Replace(b.Get(key), []byte(original.MountPoint), []byte("/corrupted/mount"), 1)
		return b.Put(key, raw)
	}))
	require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration}))
}

func TestMountGenerationDuplicateRouteFieldsCannotBeAdopted(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(mountRecordsBucket)
		raw := bytes.Replace(b.Get([]byte(original.ImageURL)), []byte(`"physical_generation":`), []byte(`"physical_generation":"`+original.PhysicalGeneration+`","physical_generation":`), 1)
		return b.Put([]byte(original.ImageURL), raw)
	}))
	_, err := w.mountStore.Get(original.ImageURL)
	require.Error(t, err, "ambiguous journal fields must fail before any backend query")
	require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration}))
}

func TestMountGenerationManagedOCIStopsBeforeUnsupportedFallback(t *testing.T) {
	w, _ := routingRetentionWorker(t)
	require.NotPanics(t, func() {
		_, err := w.MountOCI(&OCIMountRequest{ImageURL: "registry.example/unsupported:tag", RequirePhysicalGeneration: true})
		require.ErrorContains(t, err, "ownership is not supported")
	})
}

func TestMountGenerationInvalidSelectorStopsBeforeBackend(t *testing.T) {
	w, original := routingRetentionWorker(t)
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	for _, generation := range []string{"short", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		_, err := w.MountOCI(&OCIMountRequest{ImageURL: original.ImageURL, PhysicalGeneration: generation})
		require.Error(t, err)
		require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: generation}))
	}
	require.Zero(t, lookups)
}

func TestMountGenerationOversizedRouteIsNotPublished(t *testing.T) {
	store, err := OpenMountStore(filepath.Join(t.TempDir(), "mounts.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	record := &MountRecord{ImageURL: "registry.example/large:tag", MountType: "nydus", NydusImageURL: strings.Repeat("x", mountRecordLimit), MountPoint: "/original", PhysicalGeneration: strings.Repeat("a", 64)}
	require.Error(t, store.Put(record.ImageURL, record))
	got, err := store.Get(record.ImageURL)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestMountGenerationMissingCallerCannotAdoptRoute(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL}))
	require.Zero(t, lookups)
}

func TestMountGenerationCompletedReplayDoesNotTouchReplacement(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.PhysicalGeneration = strings.Repeat("a", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	// The backend completed; only its matching route can publish that result.
	require.NoError(t, w.mountStore.DeleteIfRecord(original.ImageURL, original))
	replacement := *original
	replacement.PhysicalGeneration = strings.Repeat("b", 64)
	require.NoError(t, w.mountStore.Put(original.ImageURL, &replacement))
	lookups := 0
	w.mgr.(*mockManager).getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	require.NoError(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL, PhysicalGeneration: original.PhysicalGeneration}))
	require.Zero(t, lookups)
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, &replacement, got)
}
