// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func privateTransitionClient(t *testing.T) *Client {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	return NewClient("/unused/runsc", root)
}

type transitionWriteBoundary struct {
	*os.File
	beforeWrite func()
	syncError   error
}

func (f *transitionWriteBoundary) WriteAt(value []byte, offset int64) (int, error) {
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	return f.File.WriteAt(value, offset)
}

func (f *transitionWriteBoundary) Sync() error {
	if f.syncError != nil {
		return f.syncError
	}
	return f.File.Sync()
}

func TestRunningTransitionReplacementAtWriteCannotRedirectOriginalHandle(t *testing.T) {
	for _, kind := range []string{"state", "root"} {
		t.Run(kind, func(t *testing.T) {
			client := privateTransitionClient(t)
			path := client.stateFilePath("original")
			original := []byte(`{"id":"original","status":"created","owner":"original"}`)
			foreign := []byte(`{"id":"original","status":"created","owner":"replacement"}`)
			require.NoError(t, os.WriteFile(path, original, 0600))
			g, err := client.beginStateTransition(context.Background(), "original", false)
			require.NoError(t, err)
			defer g.close()
			file := g.stateFile.(*os.File)
			g.stateFile = &transitionWriteBoundary{File: file, beforeWrite: func() {
				if kind == "state" {
					require.NoError(t, os.Rename(path, path+".saved"))
				} else {
					require.NoError(t, os.Rename(client.RootDir, filepath.Join(t.TempDir(), "old-root")))
					require.NoError(t, os.Mkdir(client.RootDir, 0700))
				}
				require.NoError(t, os.WriteFile(path, foreign, 0600))
			}}
			require.Error(t, g.markRunning(context.Background()))
			out, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, foreign, out)
		})
	}
}

func TestRunningTransitionPersistenceFailureKeepsOriginalEffectUnconfirmed(t *testing.T) {
	client := privateTransitionClient(t)
	path := client.stateFilePath("original")
	data := []byte(`{"id":"original","status":"created","opaque":9007199254740993}`)
	require.NoError(t, os.WriteFile(path, data, 0600))
	g, err := client.beginStateTransition(context.Background(), "original", false)
	require.NoError(t, err)
	defer g.close()
	failure := errors.New("injected original file persistence failure")
	g.stateFile = &transitionWriteBoundary{File: g.stateFile.(*os.File), syncError: failure}
	require.ErrorIs(t, g.markRunning(context.Background()), failure)
	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, bytes.Replace(data, []byte(`"created"`), []byte(`"running"`), 1), out)
}

func TestManagedTransitionRejectsMissingAndUnsafeOriginalLock(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "hardlink", "fifo", "writable"} {
		t.Run(kind, func(t *testing.T) {
			client, args := managedTransitionFixture(t)
			lock := strings.TrimSuffix(client.stateFilePath(args.ID), ".state") + ".lock"
			data, err := os.ReadFile(client.stateFilePath(args.ID))
			require.NoError(t, err)
			switch kind {
			case "missing":
				require.NoError(t, os.Remove(lock))
			case "symlink":
				require.NoError(t, os.Rename(lock, lock+".foreign"))
				require.NoError(t, os.Symlink(lock+".foreign", lock))
			case "hardlink":
				require.NoError(t, os.Link(lock, lock+".alias"))
			case "fifo":
				require.NoError(t, os.Remove(lock))
				require.NoError(t, unix.Mkfifo(lock, 0600))
			case "writable":
				require.NoError(t, os.Chmod(lock, 0660))
			}
			_, _, err = client.beginStartTransition(context.Background(), args)
			require.Error(t, err)
			out, err := os.ReadFile(client.stateFilePath(args.ID))
			require.NoError(t, err)
			require.Equal(t, data, out)
		})
	}
}

type transitionControl struct{ closed bool }

func (c *transitionControl) Call(string, any, any) error { return nil }
func (c *transitionControl) Close() error                { c.closed = true; return nil }

func bindTransitionSocket(t *testing.T, root, name string) {
	t.Helper()
	directory, err := os.Open(root)
	require.NoError(t, err)
	defer directory.Close()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	require.NoError(t, unix.Bind(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/%s", directory.Fd(), name)}))
	require.NoError(t, unix.Listen(fd, 1))
}

func TestTransitionConnectRefusesPeerSocketAndReplacementDuringDial(t *testing.T) {
	for _, kind := range []string{"peer", "socket", "state"} {
		t.Run(kind, func(t *testing.T) {
			client := privateTransitionClient(t)
			statePath := client.stateFilePath("original")
			data := []byte(`{"id":"original","status":"created"}`)
			require.NoError(t, os.WriteFile(statePath, data, 0600))
			bindTransitionSocket(t, client.RootDir, "runsc-original.sock")
			g, err := client.beginStateTransition(context.Background(), "original", false)
			require.NoError(t, err)
			defer g.close()
			conn := &transitionControl{}
			called := false
			client.connectControl = func(path string) (controlRPC, error) {
				called = true
				require.True(t, strings.HasPrefix(path, "/proc/self/fd/"))
				if kind == "socket" {
					require.NoError(t, os.Remove(filepath.Join(client.RootDir, "runsc-original.sock")))
					bindTransitionSocket(t, client.RootDir, "runsc-original.sock")
				} else {
					require.NoError(t, os.Rename(statePath, statePath+".saved"))
					require.NoError(t, os.WriteFile(statePath, data, 0600))
				}
				return conn, nil
			}
			path := filepath.Join(client.RootDir, "runsc-original.sock")
			if kind == "peer" {
				path = filepath.Join(client.RootDir, "runsc-peer.sock")
			}
			_, err = g.connect(context.Background(), path)
			require.Error(t, err)
			if kind == "peer" {
				require.False(t, called)
			} else {
				require.True(t, called)
				require.True(t, conn.closed)
			}
		})
	}
}

func TestRunningStatePreservesExactOpaqueIntegerIdentity(t *testing.T) {
	client := privateTransitionClient(t)
	id := "original"
	data := []byte(`{"id":"original","status":"created","opaque":{"inode":18446744073709551615,"revision":9007199254740993}}`)
	require.NoError(t, os.WriteFile(client.stateFilePath(id), data, 0600))
	require.NoError(t, client.markStateRunning(id))
	out, err := os.ReadFile(client.stateFilePath(id))
	require.NoError(t, err)
	require.Contains(t, string(out), "18446744073709551615")
	require.Contains(t, string(out), "9007199254740993")
}

func TestRunningStateRefusesSymlinkWithoutChangingForeignFile(t *testing.T) {
	client := privateTransitionClient(t)
	id := "original"
	foreign := filepath.Join(t.TempDir(), "foreign.state")
	data := []byte(`{"id":"original","status":"created","foreign":true}`)
	require.NoError(t, os.WriteFile(foreign, data, 0600))
	require.NoError(t, os.Symlink(foreign, client.stateFilePath(id)))
	require.Error(t, client.markStateRunning(id))
	out, err := os.ReadFile(foreign)
	require.NoError(t, err)
	require.Equal(t, data, out)
	_, err = os.Readlink(client.stateFilePath(id))
	require.NoError(t, err, "the foreign state alias must remain untouched")
}

func TestRunningStateWaitsForOriginalGVisorLifecycleLock(t *testing.T) {
	client := privateTransitionClient(t)
	id := "original"
	data := []byte(`{"id":"original","status":"created"}`)
	require.NoError(t, os.WriteFile(client.stateFilePath(id), data, 0600))
	lockPath := strings.TrimSuffix(client.stateFilePath(id), ".state") + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0640)
	require.NoError(t, err)
	defer lock.Close()
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	done := make(chan error, 1)
	go func() { done <- client.markStateRunning(id) }()
	completedEarly := false
	select {
	case err := <-done:
		completedEarly = true
		t.Errorf("state mutation ignored the original gVisor lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	out, err := os.ReadFile(client.stateFilePath(id))
	require.NoError(t, err)
	if !completedEarly {
		require.Equal(t, data, out)
	}
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_UN))
	if !completedEarly {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("state update did not finish after the original lock was released")
		}
	}
}

func TestRunningStateChangesOnlyRootStatusBytes(t *testing.T) {
	client := privateTransitionClient(t)
	data := []byte("{\n  \"opaque\" : {\"status\":\"created\",\"epoch\":18446744073709551615},\n  \"id\":\"original\",\n  \"status\" : \"created\"\n}\n")
	require.NoError(t, os.WriteFile(client.stateFilePath("original"), data, 0640))
	require.NoError(t, client.markStateRunning("original"))
	out, err := os.ReadFile(client.stateFilePath("original"))
	require.NoError(t, err)
	require.Equal(t, bytes.Replace(data, []byte(`"status" : "created"`), []byte(`"status" : "running"`), 1), out)
}

func TestRunningTransitionRefusesStateReplacementWithEqualBytes(t *testing.T) {
	client := privateTransitionClient(t)
	path := client.stateFilePath("original")
	data := []byte(`{"id":"original","status":"created"}`)
	require.NoError(t, os.WriteFile(path, data, 0600))
	g, err := client.beginStateTransition(context.Background(), "original", false)
	require.NoError(t, err)
	defer g.close()
	original := filepath.Join(client.RootDir, "original-saved.state")
	require.NoError(t, os.Rename(path, original))
	require.NoError(t, os.WriteFile(path, data, 0600))
	require.Error(t, g.markRunning(context.Background()))
	for _, p := range []string{path, original} {
		out, err := os.ReadFile(p)
		require.NoError(t, err)
		require.Equal(t, data, out)
	}
}

func TestRunningTransitionRefusesRootAndLockReplacement(t *testing.T) {
	for _, kind := range []string{"root", "lock"} {
		t.Run(kind, func(t *testing.T) {
			client := privateTransitionClient(t)
			path := client.stateFilePath("original")
			data := []byte(`{"id":"original","status":"created"}`)
			require.NoError(t, os.WriteFile(path, data, 0600))
			g, err := client.beginStateTransition(context.Background(), "original", false)
			require.NoError(t, err)
			defer g.close()
			if kind == "root" {
				old := filepath.Join(t.TempDir(), "saved-original-root")
				require.NoError(t, os.Rename(client.RootDir, old))
				require.NoError(t, os.Mkdir(client.RootDir, 0700))
				require.NoError(t, os.WriteFile(path, data, 0600))
			} else {
				name := strings.TrimSuffix(path, ".state") + ".lock"
				require.NoError(t, os.Rename(name, name+".saved"))
				require.NoError(t, os.WriteFile(name, nil, 0640))
			}
			require.Error(t, g.markRunning(context.Background()))
			out, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, data, out)
		})
	}
}

func TestRunningTransitionLockWaitHonorsDeadlineAndKeepsOriginalOwner(t *testing.T) {
	client := privateTransitionClient(t)
	path := client.stateFilePath("original")
	data := []byte(`{"id":"original","status":"created"}`)
	require.NoError(t, os.WriteFile(path, data, 0600))
	lock, err := os.OpenFile(strings.TrimSuffix(path, ".state")+".lock", os.O_RDWR|os.O_CREATE, 0640)
	require.NoError(t, err)
	defer lock.Close()
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = client.beginStateTransition(ctx, "original", false)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, out)
	other, err := os.OpenFile(lock.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	defer other.Close()
	require.ErrorIs(t, unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB), unix.EWOULDBLOCK)
}

func managedTransitionFixture(t *testing.T) (*Client, StartArgs) {
	t.Helper()
	client, args, _ := managedGenerationClient(t)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), generationStateBytes(t, args.ID, args.ResourceGeneration, args.BundleDir), 0600))
	require.NoError(t, os.WriteFile(strings.TrimSuffix(client.stateFilePath(args.ID), ".state")+".lock", nil, 0640))
	return client, args
}

func TestManagedTransitionRefusesChangedBundleAndPreservesState(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			client, args := managedTransitionFixture(t)
			g, _, err := client.beginStartTransition(context.Background(), args)
			require.NoError(t, err)
			defer g.close()
			data, err := os.ReadFile(client.stateFilePath(args.ID))
			require.NoError(t, err)
			path := filepath.Join(args.BundleDir, "config.json")
			config, err := os.ReadFile(path)
			require.NoError(t, err)
			if kind == "file" {
				require.NoError(t, os.Rename(path, path+".saved"))
			} else {
				require.NoError(t, os.Rename(args.BundleDir, filepath.Join(t.TempDir(), "original-bundle")))
				require.NoError(t, os.Mkdir(args.BundleDir, 0700))
			}
			require.NoError(t, os.WriteFile(path, config, 0600))
			require.Error(t, g.markRunning(context.Background()))
			out, err := os.ReadFile(client.stateFilePath(args.ID))
			require.NoError(t, err)
			require.Equal(t, data, out)
		})
	}
}
