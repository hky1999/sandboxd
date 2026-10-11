// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/stretchr/testify/require"
)

// This fixture creates empty local configuration and databases. No registry,
// mount, cgroup, or physical daemon operation is performed.
func workerOwnershipManager(t *testing.T) (distillfs.Manager, *distillfs.ManagerConfig) {
	t.Helper()
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0600))
		return p
	}
	cfg := &distillfs.ManagerConfig{Root: t.TempDir(), DisableCgroup: true, OSSCfgPath: file("oss.json"), NydusCfgPath: file("nydus.json"), OSSAuthsPath: file("objects.json"), RegistryAuthsPath: file("registry.json")}
	m, err := distillfs.NewManager(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background())) })
	return m, cfg
}

func TestImageManagerOwnershipWorkerDatabaseRetainsRootUntilClose(t *testing.T) {
	m, cfg := workerOwnershipManager(t)
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: filepath.Join(cfg.Root, "mounts.db")})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, m.(distillfs.ManagerLifecycle).Close(ctx), context.DeadlineExceeded)
	_, err = distillfs.NewManager(cfg)
	require.Error(t, err, "the open worker database still owns the root")
	require.NoError(t, w.CloseWithContext(context.Background()))
	require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background()))
	replacement, err := distillfs.NewManager(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, replacement.(distillfs.ManagerLifecycle).Close(context.Background())) })
}

func TestImageManagerOwnershipWorkerCloseDrainsOriginalRequest(t *testing.T) {
	mock := newMockManager()
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	mock.cleanupDaemonFunc = func(string) error { close(entered); <-proceed; return nil }
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: mock, DBPath: filepath.Join(t.TempDir(), "mounts.db")})
	require.NoError(t, err)
	finished := make(chan error, 1)
	go func() { finished <- w.CleanupDaemon(&CleanupDaemonRequest{DaemonID: "original"}) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original request did not enter its backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, w.CloseWithContext(ctx), context.DeadlineExceeded)
	_, err = w.mountStore.Get("private-check")
	require.NoError(t, err, "the database must stay open until the old request exits")
	_, err = w.QueryMountOperation(&MountOperationQuery{})
	require.ErrorContains(t, err, "closing")
	unblock.Do(func() { close(proceed) })
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("original request did not finish")
	}
	require.NoError(t, w.CloseWithContext(context.Background()))
	_, err = w.mountStore.Get("private-check")
	require.Error(t, err)
}

func TestImageManagerOwnershipWorkerRejectsEveryClosedEntry(t *testing.T) {
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: newMockManager()})
	require.NoError(t, err)
	w.Close()
	calls := []struct {
		name string
		call func() error
	}{
		{"mount_oss", func() error { _, err := w.MountOSS(nil); return err }},
		{"unmount_oss", func() error { _, err := w.UnmountOSS(nil); return err }},
		{"mount_nydus", func() error { _, err := w.MountNydus(nil); return err }},
		{"unmount_nydus", func() error { _, err := w.UnmountNydus(nil); return err }},
		{"mount_oci", func() error { _, err := w.MountOCI(nil); return err }},
		{"unmount_oci", func() error { return w.UnmountOCI(nil) }},
		{"query", func() error { _, err := w.QueryMountOperation(nil); return err }},
		{"process", func() error { _, err := w.ImageProcess(""); return err }},
		{"cleanup", func() error { return w.CleanupDaemon(nil) }},
		{"list_daemons", func() error { _, err := w.ListDaemons(); return err }},
		{"list_images", func() error { _, err := w.ListMountedOCIImages(); return err }},
		{"list_details", func() error { _, err := w.ListMountedOCIDetails(); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) { require.ErrorContains(t, c.call(), "closing") })
	}
}

func TestImageManagerOwnershipWorkerRejectedOwnerCannotCreateDatabase(t *testing.T) {
	m, cfg := workerOwnershipManager(t)
	require.NoError(t, m.(distillfs.ManagerLifecycle).Close(context.Background()))
	db := filepath.Join(cfg.Root, "must-not-create.db")
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: m, DBPath: db})
	require.Error(t, err)
	require.Nil(t, w)
	require.NoFileExists(t, db)
}

func TestImageManagerOwnershipWorkerBackendErrorReleasesAdmission(t *testing.T) {
	mock := newMockManager()
	mock.cleanupDaemonFunc = func(string) error { return fmt.Errorf("controlled backend failure") }
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: mock})
	require.NoError(t, err)
	require.Error(t, w.CleanupDaemon(&CleanupDaemonRequest{DaemonID: "original"}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, w.CloseWithContext(ctx))
}
