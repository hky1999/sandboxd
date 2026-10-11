// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Manager construction here disables cgroups and has no daemons to recover.
// No filesystem is mounted and no physical daemon or sandbox is started.
func ownershipManagerConfig(t *testing.T) *ManagerConfig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	configDir := t.TempDir()
	return &ManagerConfig{
		Context: ctx, Root: t.TempDir(), DisableCgroup: true,
		OSSCfgPath:        createTestConfigFile(t, configDir, "oss.json", BackendConfig{BackendType: "oss", Oss: &OssConfig{}}),
		NydusCfgPath:      createTestConfigFile(t, configDir, "nydus.json", BackendConfig{BackendType: "registry", Registry: &RegistryConfig{}}),
		OSSAuthsPath:      createTestOSSAuthsFile(t, configDir),
		RegistryAuthsPath: createTestRegistryAuthsFile(t, configDir),
	}
}

func TestDaemonMountOperationManagerSecondOwnerRejectedBeforePreparation(t *testing.T) {
	config := ownershipManagerConfig(t)
	first, err := NewManager(config)
	require.NoError(t, err)
	require.NotNil(t, first)
	second, err := NewManager(config)
	require.Error(t, err, "two independent owners must not recover or write one image-manager root")
	require.Nil(t, second)
}

func TestDaemonMountOperationManagerDuplicatePreservesPendingFiles(t *testing.T) {
	config := ownershipManagerConfig(t)
	_, err := NewManager(config)
	require.NoError(t, err)
	marker := filepath.Join(config.Root, daemonLogStagingDir, "original-pending-file")
	require.NoError(t, os.WriteFile(marker, []byte("original owner still holds this file"), 0600))
	_, _ = NewManager(config)
	raw, err := os.ReadFile(marker)
	require.NoError(t, err, "a duplicate constructor must fail before preparing or deleting original files")
	require.Equal(t, "original owner still holds this file", string(raw))
}

func ownedManager(t *testing.T, config *ManagerConfig) *manager {
	t.Helper()
	m, err := NewManager(config)
	require.NoError(t, err)
	owned := m.(*manager)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, owned.Close(ctx))
	})
	return owned
}

func TestDaemonMountOperationManagerCloseTimeoutRetainsOriginalOwner(t *testing.T) {
	config := ownershipManagerConfig(t)
	first := ownedManager(t, config)
	release, err := first.RetainOwnership()
	require.NoError(t, err)
	t.Cleanup(release)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, first.Close(ctx), context.DeadlineExceeded)
	second, err := NewManager(config)
	require.Error(t, err)
	require.Nil(t, second)
	require.Error(t, first.CreateDaemon(&DaemonCreateOpt{ID: "late-allocation"}))
	require.NoDirExists(t, filepath.Join(config.Root, "daemons", "late-allocation"))
	release()
	release() // An admitted operation can release only once.
	require.NoError(t, first.Close(context.Background()))
	_ = ownedManager(t, config)
	require.Error(t, first.CreateDaemon(&DaemonCreateOpt{ID: "old-owner-allocation"}))
}

func TestDaemonMountOperationManagerCloseStopsLateOriginalDispatch(t *testing.T) {
	config := ownershipManagerConfig(t)
	first := ownedManager(t, config)
	d, marker := lateDispatchFixture(t)
	d.ownership = first.ownership
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	finished := make(chan error, 1)
	go func() {
		timing, ctx := StartTimedOperation(context.Background(), "blocked-owner-dispatch", d.meta.ID)
		defer timing.End()
		finished <- d.initializeDaemonWithBinding(ctx, timing, func(string, string) error {
			close(entered)
			<-proceed
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original initializer did not reach its binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, first.Close(ctx), context.DeadlineExceeded)
	_, err := NewManager(config)
	require.Error(t, err, "the blocked original initializer still owns the root")
	unblock.Do(func() { close(proceed) })
	select {
	case err := <-finished:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("original initializer did not stop")
	}
	require.NoFileExists(t, marker)
	require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed, "rejecting an old owner is not a Start syscall result")
	require.NoError(t, first.Close(context.Background()))
	_ = ownedManager(t, config)
}

func TestDaemonMountOperationManagerCloseDeadlineDoesNotWaitForDispatchLock(t *testing.T) {
	config := ownershipManagerConfig(t)
	first := ownedManager(t, config)
	release, err := first.RetainOwnership()
	require.NoError(t, err)
	t.Cleanup(release)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	finished := make(chan error, 1)
	go func() {
		invoked, err := first.ownership.dispatch(func() error { close(entered); <-proceed; return nil })
		if !invoked && err == nil {
			err = fmt.Errorf("controlled dispatch did not run")
		}
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("controlled dispatch did not hold the owner lock")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, first.Close(ctx), context.DeadlineExceeded)
	_, err = NewManager(config)
	require.Error(t, err)
	unblock.Do(func() { close(proceed) })
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("controlled dispatch did not finish")
	}
	release()
	require.NoError(t, first.Close(context.Background()))
	_ = ownedManager(t, config)
}

func TestDaemonMountOperationManagerReadinessWaitRetainsOriginalOwner(t *testing.T) {
	config := ownershipManagerConfig(t)
	first := ownedManager(t, config)
	d := newMockDaemon(t.TempDir()).Daemon
	d.ownership = first.ownership
	d.watcherActive.Store(true) // Skip initialization and any process dispatch.
	d.stopChan = make(chan struct{})
	d.setState(DaemonStateMounting)
	entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, unblock sync.Once
	previous := statfsFunc
	statfsFunc = func(string, *unix.Statfs_t) error {
		enteredOnce.Do(func() { close(entered) })
		<-proceed
		return fmt.Errorf("controlled unreadiness")
	}
	t.Cleanup(func() {
		unblock.Do(func() { close(proceed) })
		close(d.stopChan)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("original readiness wait did not exit")
		}
		statfsFunc = previous
	})
	go func() { defer close(done); d.startDaemonProcess() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("readiness wait did not enter its controlled observation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, first.Close(ctx), context.DeadlineExceeded)
	_, err := NewManager(config)
	require.Error(t, err, "post-initialization readiness still owns the root")
	unblock.Do(func() { close(proceed) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closing owner did not stop readiness wait")
	}
	require.NoError(t, first.Close(context.Background()))
	_ = ownedManager(t, config)
}

func TestDaemonMountOperationManagerParentCancellationRetainsActiveRoot(t *testing.T) {
	config := ownershipManagerConfig(t)
	ctx, cancel := context.WithCancel(config.Context)
	t.Cleanup(cancel)
	config.Context = ctx
	first := ownedManager(t, config)
	release, err := first.RetainOwnership()
	require.NoError(t, err)
	t.Cleanup(release)
	cancel()
	select {
	case <-first.ownership.closing:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled parent did not close admission")
	}
	config.Context = context.Background()
	_, err = NewManager(config)
	require.ErrorContains(t, err, "already has an owner")
	release()
	require.NoError(t, first.Close(context.Background()))
	_ = ownedManager(t, config)
}

func TestDaemonMountOperationManagerChangedPathsRejectOriginalWriter(t *testing.T) {
	for _, changed := range []string{"root", "lock", "private_parent"} {
		t.Run(changed, func(t *testing.T) {
			config := ownershipManagerConfig(t)
			if changed == "private_parent" {
				parent := filepath.Join(t.TempDir(), "private")
				require.NoError(t, os.Mkdir(parent, 0700))
				config.Root = filepath.Join(parent, "root")
				require.NoError(t, os.Mkdir(config.Root, 0770))
				require.NoError(t, os.Chmod(config.Root, 0770))
			}
			first := ownedManager(t, config)
			switch changed {
			case "root":
				require.NoError(t, os.Rename(config.Root, config.Root+"-original"))
				require.NoError(t, os.Mkdir(config.Root, 0700))
			case "lock":
				lock := filepath.Join(config.Root, managerOwnerLockName)
				require.NoError(t, os.Rename(lock, lock+"-original"))
				require.NoError(t, os.WriteFile(lock, nil, 0600))
			case "private_parent":
				require.NoError(t, os.Chmod(filepath.Dir(config.Root), 0755))
			}
			require.Error(t, first.CreateDaemon(&DaemonCreateOpt{ID: "foreign-root-write"}))
			called := false
			invoked, err := first.ownership.dispatch(func() error { called = true; return nil })
			require.Error(t, err)
			require.False(t, invoked)
			require.False(t, called)
			require.NoDirExists(t, filepath.Join(config.Root, "daemons", "foreign-root-write"))
		})
	}
}

func TestDaemonMountOperationManagerInvalidLockRejectedBeforePreparation(t *testing.T) {
	for _, invalid := range []string{"symlink", "hardlink", "permissions", "nonempty"} {
		t.Run(invalid, func(t *testing.T) {
			config := ownershipManagerConfig(t)
			staging := filepath.Join(config.Root, daemonLogStagingDir)
			require.NoError(t, os.Mkdir(staging, 0700))
			marker := filepath.Join(staging, "original")
			require.NoError(t, os.WriteFile(marker, []byte("preserve"), 0600))
			lock := filepath.Join(config.Root, managerOwnerLockName)
			switch invalid {
			case "symlink", "hardlink":
				foreign := filepath.Join(t.TempDir(), "foreign-lock")
				require.NoError(t, os.WriteFile(foreign, nil, 0600))
				if invalid == "symlink" {
					require.NoError(t, os.Symlink(foreign, lock))
				} else {
					require.NoError(t, os.Link(foreign, lock))
				}
			case "permissions":
				require.NoError(t, os.WriteFile(lock, nil, 0600))
				require.NoError(t, os.Chmod(lock, 0644))
			case "nonempty":
				require.NoError(t, os.WriteFile(lock, []byte("foreign lock contents"), 0600))
			}
			m, err := NewManager(config)
			require.Error(t, err)
			require.Nil(t, m)
			raw, err := os.ReadFile(marker)
			require.NoError(t, err)
			require.Equal(t, "preserve", string(raw))
		})
	}
}

func TestDaemonMountOperationManagerSharedWritableRootIsRejected(t *testing.T) {
	config := ownershipManagerConfig(t)
	parent := t.TempDir()
	require.NoError(t, os.Chmod(parent, 0755))
	config.Root = filepath.Join(parent, "shared-root")
	require.NoError(t, os.Mkdir(config.Root, 0770))
	require.NoError(t, os.Chmod(config.Root, 0770))
	m, err := NewManager(config)
	require.ErrorContains(t, err, "private parent")
	require.Nil(t, m)
	require.NoDirExists(t, filepath.Join(config.Root, "daemons"))
}

func TestDaemonMountOperationManagerConstructorFailureAllowsRetry(t *testing.T) {
	config := ownershipManagerConfig(t)
	valid := config.OSSCfgPath
	config.OSSCfgPath = ""
	m, err := NewManager(config)
	require.Error(t, err)
	require.Nil(t, m)
	config.OSSCfgPath = valid
	_ = ownedManager(t, config)
}

func TestDaemonMountOperationManagerOtherRootsRemainIndependent(t *testing.T) {
	_ = ownedManager(t, ownershipManagerConfig(t))
	_ = ownedManager(t, ownershipManagerConfig(t))
}

// The subprocess touches only the test-owned root; it starts no daemon.
func TestImageManagerOwnershipProcessHelper(t *testing.T) {
	root := os.Getenv("AKERNEL_TEST_MANAGER_OWNER_ROOT")
	if root == "" {
		t.Skip("private subprocess helper")
	}
	dir := os.Getenv("AKERNEL_TEST_MANAGER_OWNER_CONFIG")
	m, err := NewManager(&ManagerConfig{Root: root, DisableCgroup: true, OSSCfgPath: filepath.Join(dir, "oss.json"), NydusCfgPath: filepath.Join(dir, "nydus.json"), OSSAuthsPath: filepath.Join(dir, "oss_auths.json"), RegistryAuthsPath: filepath.Join(dir, "registry_auths.json")})
	if os.Getenv("AKERNEL_TEST_MANAGER_OWNER_EXPECT") == "reject" {
		require.Error(t, err)
		require.Nil(t, m)
		return
	}
	require.NoError(t, err)
	require.NoError(t, m.(ManagerLifecycle).Close(context.Background()))
}

func TestDaemonMountOperationManagerOwnershipAcrossProcesses(t *testing.T) {
	config := ownershipManagerConfig(t)
	first := ownedManager(t, config)
	run := func(expected string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestImageManagerOwnershipProcessHelper$", "-test.v")
		command.Env = append(os.Environ(), "AKERNEL_TEST_MANAGER_OWNER_ROOT="+config.Root, "AKERNEL_TEST_MANAGER_OWNER_CONFIG="+filepath.Dir(config.OSSCfgPath), "AKERNEL_TEST_MANAGER_OWNER_EXPECT="+expected)
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
		require.True(t, strings.Contains(string(output), "--- PASS: TestImageManagerOwnershipProcessHelper"), "%s", output)
	}
	run("reject")
	require.NoError(t, first.Close(context.Background()))
	run("accept")
}
