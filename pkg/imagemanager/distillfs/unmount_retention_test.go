// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDaemonUnmountCleanupErrorKeepsPIDAndBlocksReuse(t *testing.T) {
	root := t.TempDir()
	mock := newMockDaemon(root)
	mock.mockIsAlive = func() bool { return false }
	blocked := filepath.Join(root, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("file blocks mount directory"), 0600))
	mock.meta.MountPoint = filepath.Join(blocked, "mount")
	original := []byte("invalid-test-pid")
	require.NoError(t, os.WriteFile(mock.meta.PidFilePath, original, 0600))
	require.Error(t, mock.Unmount(), "mount inspection failure must be returned")
	current, err := os.ReadFile(mock.meta.PidFilePath)
	require.NoError(t, err)
	require.Equal(t, original, current)
	require.Error(t, mock.Mount(), "unconfirmed release must not start another daemon")
	require.NoError(t, os.Remove(blocked))
	require.NoError(t, os.MkdirAll(mock.meta.MountPoint, 0700))
	require.NoError(t, mock.Unmount(), "same owner may retry the failed cleanup")
	_, err = os.Stat(mock.meta.PidFilePath)
	require.True(t, os.IsNotExist(err))
	require.Equal(t, DaemonStateStopped, mock.getState())
}

func TestDaemonUnmountAliveWithUnknownPIDRetainsOwnership(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.mockIsAlive = func() bool { return true }
	original := []byte("invalid-test-pid")
	require.NoError(t, os.WriteFile(mock.meta.PidFilePath, original, 0600))
	require.Error(t, mock.Unmount(), "alive observation without an actionable PID remains unknown")
	current, err := os.ReadFile(mock.meta.PidFilePath)
	require.NoError(t, err)
	require.Equal(t, original, current)
	require.Error(t, mock.Mount())
	mock.mockIsAlive = func() bool { return false }
	require.NoError(t, mock.Unmount())
}

func TestDaemonUnmountPIDRemovalErrorRetainsPendingState(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.mockIsAlive = func() bool { return false }
	require.NoError(t, os.Mkdir(mock.meta.PidFilePath, 0700))
	child := filepath.Join(mock.meta.PidFilePath, "retained")
	require.NoError(t, os.WriteFile(child, []byte("owned metadata"), 0600))
	require.Error(t, mock.Unmount(), "failed PID cleanup must not be reported as complete")
	require.NotEqual(t, DaemonStateStopped, mock.getState())
	require.Error(t, mock.Mount())
	require.NoError(t, os.Remove(child))
	require.NoError(t, mock.Unmount())
	require.Equal(t, DaemonStateStopped, mock.getState())
}

func TestDaemonUnmountPhysicalReadbackFailureKeepsPID(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "still mounted", true: "readback unknown"}[unknown], func(t *testing.T) {
			mock := newMockDaemon(t.TempDir())
			mock.mockIsAlive = func() bool { return false }
			original := []byte("invalid-test-pid")
			require.NoError(t, os.WriteFile(mock.meta.PidFilePath, original, 0600))
			probes, calls := 0, 0
			mock.mountPresentFunc = func(string) (bool, error) {
				probes++
				if unknown && probes > 1 {
					return false, errors.New("readback unavailable")
				}
				return true, nil
			}
			mock.unmountTargetFunc = func(string, int) error { calls++; return nil }
			require.Error(t, mock.Unmount())
			current, err := os.ReadFile(mock.meta.PidFilePath)
			require.NoError(t, err)
			require.Equal(t, original, current)
			require.Error(t, mock.Mount())
			require.Equal(t, 1, calls)
			mock.mountPresentFunc = func(string) (bool, error) { return true, nil }
			require.Error(t, mock.Unmount(), "do not unmount a newly observed target after the original syscall succeeded")
			require.Equal(t, 1, calls)
			mock.mountPresentFunc = func(string) (bool, error) { return false, nil }
			require.NoError(t, mock.Unmount())
			require.Equal(t, 1, calls, "retry confirms absence instead of a second unmount")
		})
	}
}

func TestDaemonUnmountInitializationKeepsOriginalAttempt(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.mockIsAlive = func() bool { return false }
	mock.setState(DaemonStateMounting)
	original := []byte("invalid-test-pid")
	require.NoError(t, os.WriteFile(mock.meta.PidFilePath, original, 0600))
	probes := 0
	mock.mountPresentFunc = func(string) (bool, error) { probes++; return false, nil }
	require.Error(t, mock.Unmount())
	current, err := os.ReadFile(mock.meta.PidFilePath)
	require.NoError(t, err)
	require.Equal(t, original, current)
	require.Zero(t, probes)
	require.Error(t, mock.Mount())
	mock.setState(DaemonStateStopped)
	require.NoError(t, mock.Unmount())
}

func TestDaemonCleanupAndGarbageCollectionPreserveUnconfirmedMount(t *testing.T) {
	for _, mode := range []string{"explicit cleanup", "expired cleanup", "failed mount cleanup"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			mock := newMockDaemon(root)
			mock.mockIsAlive = func() bool { return false }
			original := []byte("original daemon metadata")
			require.NoError(t, os.WriteFile(mock.savedPath, original, 0600))
			mock.mountPresentFunc = func(string) (bool, error) { return false, errors.New("original mount observation unavailable") }
			mgr := newTestManager(map[string]*Daemon{mock.meta.ID: mock.Daemon})
			mgr.root = root
			switch mode {
			case "explicit cleanup":
				require.Error(t, mgr.CleanupDaemon(mock.meta.ID))
			case "expired cleanup":
				mock.expiredAt = 0
				mgr.gcDaemons()
			case "failed mount cleanup":
				mock.expiredAt = 0
				mock.mountFailed.Store(true)
				mgr.gcDaemons()
			}
			require.Contains(t, mgr.daemons, mock.meta.ID)
			current, err := os.ReadFile(mock.savedPath)
			require.NoError(t, err)
			require.Equal(t, original, current)
			mock.mountPresentFunc = func(string) (bool, error) { return false, nil }
			require.NoError(t, mock.Unmount())
			require.NoError(t, mgr.CleanupDaemon(mock.meta.ID))
			require.NotContains(t, mgr.daemons, mock.meta.ID)
		})
	}
}

func TestDaemonUnmountStopObservationTimeoutKeepsPID(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.mockIsAlive = func() bool { return false }
	mock.stopChan = make(chan struct{})
	mock.unmountTimeout = 5 * time.Millisecond
	original := []byte("invalid-test-pid")
	require.NoError(t, os.WriteFile(mock.meta.PidFilePath, original, 0600))
	probes := 0
	mock.mountPresentFunc = func(string) (bool, error) { probes++; return false, nil }
	require.Error(t, mock.Unmount())
	current, err := os.ReadFile(mock.meta.PidFilePath)
	require.NoError(t, err)
	require.Equal(t, original, current)
	require.Zero(t, probes)
	require.Error(t, mock.Mount())
	close(mock.stopChan)
	require.NoError(t, mock.Unmount())
}
