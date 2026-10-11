// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
	"github.com/stretchr/testify/require"
)

func routingRetentionWorker(t *testing.T) (*HttpWorker, *MountRecord) {
	t.Helper()
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: newMockManager(), OCIManager: &oci.Manager{}, DBPath: filepath.Join(t.TempDir(), "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	record := &MountRecord{ImageURL: "registry.example/root:tag", MountType: "nydus", NydusImageURL: "registry.example/root:tag-nydus", MountPoint: "/original/mount"}
	require.NoError(t, w.mountStore.Put(record.ImageURL, record))
	return w, record
}

func TestMountRoutingUnmountFailureKeepsOriginalRecord(t *testing.T) {
	w, original := routingRetentionWorker(t)
	for i := 0; i < 2; i++ {
		require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL}), "missing daemon is not confirmed cleanup")
		got, err := w.mountStore.Get(original.ImageURL)
		require.NoError(t, err)
		require.Equal(t, original, got, "failed unmount must retain the original backend route for retry")
	}
}

func TestMountRoutingReadErrorNeverFallsBack(t *testing.T) {
	w, original := routingRetentionWorker(t)
	mgr := w.mgr.(*mockManager)
	lookups := 0
	mgr.getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	w.nydusClient = &nydus.RegistryClient{}
	require.NoError(t, w.mountStore.Close())
	var err error
	require.NotPanics(t, func() { err = w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL}) }, "unreadable route must stop before any backend lookup")
	require.Error(t, err)
	require.Zero(t, lookups, "a read error does not authorize switching backend")
}

func TestMountRoutingUnknownTypePreservesRecord(t *testing.T) {
	w, original := routingRetentionWorker(t)
	original.MountType = "unknown-backend"
	require.NoError(t, w.mountStore.Put(original.ImageURL, original))
	var err error
	require.NotPanics(t, func() { err = w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL}) })
	require.Error(t, err, "unknown route is not an OCI route")
	got, readErr := w.mountStore.Get(original.ImageURL)
	require.NoError(t, readErr)
	require.Equal(t, original, got)
}

func TestMountRoutingPublicationFailureReturnsErrorAndKeepsOriginal(t *testing.T) {
	w, original := routingRetentionWorker(t)
	require.Error(t, w.recordMount(original.ImageURL, "oci", "", "/replacement/mount"))
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.NoError(t, w.mountStore.Close())
	require.Error(t, w.recordMount("registry.example/other:tag", "oci", "", "/new/mount"))
}

func TestMountRoutingConditionalRemovalProtectsReplacement(t *testing.T) {
	w, original := routingRetentionWorker(t)
	replacement := *original
	replacement.MountPoint = "/replacement/mount"
	require.NoError(t, w.mountStore.Put(original.ImageURL, &replacement))
	require.Error(t, w.mountStore.DeleteIfRecord(original.ImageURL, original))
	got, err := w.mountStore.Get(original.ImageURL)
	require.NoError(t, err)
	require.Equal(t, &replacement, got)
	require.NoError(t, w.mountStore.DeleteIfRecord(original.ImageURL, &replacement))
	require.Error(t, w.mountStore.DeleteIfRecord(original.ImageURL, &replacement), "missing route is unknown, not a completed replay")
}

func TestMountRoutingMissingPersistentRouteNeverFallsBack(t *testing.T) {
	w, original := routingRetentionWorker(t)
	require.NoError(t, w.mountStore.Delete(original.ImageURL))
	mgr := w.mgr.(*mockManager)
	lookups := 0
	mgr.getDaemonFunc = func(string) *distillfs.Daemon { lookups++; return nil }
	w.nydusClient = &nydus.RegistryClient{}
	require.Error(t, w.UnmountOCI(&OCIUmountRequest{ImageURL: original.ImageURL}))
	require.Zero(t, lookups)
}

func TestMountRoutingSerializesSameSourceWithoutBlockingNeighbor(t *testing.T) {
	w := mustNewHttpWorker(t, newMockManager())
	unlock := w.acquireMountRouteLock("original")
	acquired := make(chan struct{})
	done := make(chan struct{})
	go func() { release := w.acquireMountRouteLock("original"); close(acquired); release(); close(done) }()
	// Wait until the second caller has joined the original source's queue.
	deadline := time.Now().Add(time.Second)
	for {
		w.routeLocksMu.Lock()
		refs := w.routeLocks["original"].refs
		w.routeLocksMu.Unlock()
		if refs == 2 {
			break
		}
		require.True(t, time.Now().Before(deadline))
		time.Sleep(time.Millisecond)
	}
	select {
	case <-acquired:
		t.Fatal("same source entered before original publication finished")
	default:
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); release := w.acquireMountRouteLock("neighbor"); release() }()
	wg.Wait()
	unlock()
	<-done
	w.routeLocksMu.Lock()
	require.Empty(t, w.routeLocks)
	w.routeLocksMu.Unlock()
}
