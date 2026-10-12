// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Ordinary files and controlled identity only. These unit checks never clone
// into a real cgroup, signal a process, or turn a saved intent into retirement.
func managedLaunchFixture(t *testing.T) (*Client, *managedLaunchRecord) {
	t.Helper()
	client := NewClient("/controlled/runsc", t.TempDir())
	require.NoError(t, os.Chmod(client.RootDir, 0700))
	return client, &managedLaunchRecord{Version: 1, SandboxID: "original", ResourceGeneration: "generation-original",
		OperationID: uuid.NewString(), Revision: 1, DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli(),
		ArgumentsSHA256: strings.Repeat("a", 64), Stage: "dispatching", CloneIntoCgroup: true,
		Cgroup: &managedLaunchCgroup{Path: "/owned/original", Device: 1, Inode: 2,
			BootID: "controlled-unit-boot", CgroupNamespaceInode: 3, MountNamespaceInode: 4}}
}

func TestManagedLaunchImmutableIntentSurvivesClientReopen(t *testing.T) {
	client, record := managedLaunchFixture(t)
	require.NoError(t, client.publishManagedLaunch(context.Background(), record))
	path := filepath.Join(client.RootDir, managedLaunchDirectory, record.SandboxID+".json")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	var saved managedLaunchRecord
	require.NoError(t, json.Unmarshal(before, &saved))
	require.Equal(t, record, &saved)
	reopened := NewClient(client.Binary, client.RootDir)
	replacement := *record
	replacement.ResourceGeneration = "generation-replacement"
	replacement.OperationID = uuid.NewString()
	require.Error(t, reopened.publishManagedLaunch(context.Background(), &replacement))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	var stat unix.Stat_t
	require.NoError(t, unix.Lstat(path, &stat))
	require.EqualValues(t, 1, stat.Nlink)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 2, "only original intent and its private lock should remain")
}

func TestManagedLaunchMalformedOrExpiredIntentCannotPublish(t *testing.T) {
	for _, change := range []string{"wrong-version", "missing-operation", "expired", "unbound-directory", "missing-namespace", "traversing-id", "not-cloned"} {
		t.Run(change, func(t *testing.T) {
			client, record := managedLaunchFixture(t)
			switch change {
			case "wrong-version":
				record.Version = 2
			case "missing-operation":
				record.OperationID = ""
			case "expired":
				record.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
			case "unbound-directory":
				record.Cgroup.Inode = 0
			case "missing-namespace":
				record.Cgroup.MountNamespaceInode = 0
			case "traversing-id":
				record.SandboxID = "../foreign"
			case "not-cloned":
				record.CloneIntoCgroup = false
			}
			require.Error(t, client.publishManagedLaunch(context.Background(), record))
			require.NoDirExists(t, filepath.Join(client.RootDir, managedLaunchDirectory))
		})
	}
}

func TestManagedLaunchForeignJournalAndLockCannotAuthorizeDispatch(t *testing.T) {
	for _, change := range []string{"directory-symlink", "lock-fifo", "lock-symlink", "lock-hardlink", "lock-held"} {
		t.Run(change, func(t *testing.T) {
			client, record := managedLaunchFixture(t)
			dir := filepath.Join(client.RootDir, managedLaunchDirectory)
			if change == "directory-symlink" {
				require.NoError(t, os.Symlink(t.TempDir(), dir))
			} else {
				require.NoError(t, os.Mkdir(dir, 0700))
				lock := filepath.Join(dir, ".lock")
				switch change {
				case "lock-fifo":
					require.NoError(t, unix.Mkfifo(lock, 0600))
				case "lock-symlink", "lock-hardlink":
					foreign := filepath.Join(t.TempDir(), "foreign-lock")
					require.NoError(t, os.WriteFile(foreign, []byte("original"), 0600))
					if change == "lock-symlink" {
						require.NoError(t, os.Symlink(foreign, lock))
					} else {
						require.NoError(t, os.Link(foreign, lock))
					}
				case "lock-held":
					file, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0600)
					require.NoError(t, err)
					defer file.Close()
					require.NoError(t, unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB))
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			require.Error(t, client.publishManagedLaunch(ctx, record))
			require.NoFileExists(t, filepath.Join(dir, record.SandboxID+".json"))
		})
	}
}

func TestManagedLaunchPinsOriginalDescriptorBeforeCommandStart(t *testing.T) {
	client, record := managedLaunchFixture(t)
	originalPath := t.TempDir()
	original, err := os.Open(originalPath)
	require.NoError(t, err)
	client.openLaunchCgroup = func(string) (*os.File, *managedLaunchCgroup, error) { return original, record.Cgroup, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, client.Binary, "create", record.SandboxID)
	group, err := client.bindManagedLaunch(ctx, StartArgs{ID: record.SandboxID, ResourceGeneration: record.ResourceGeneration, CgroupPath: record.Cgroup.Path}, cmd)
	require.NoError(t, err)
	defer group.Close()
	require.Nil(t, cmd.Process, "this is a configuration check, not a kernel clone")
	require.True(t, cmd.SysProcAttr.UseCgroupFD)
	require.Equal(t, int(original.Fd()), cmd.SysProcAttr.CgroupFD)
	require.FileExists(t, filepath.Join(client.RootDir, managedLaunchDirectory, record.SandboxID+".json"))
	before, err := group.Stat()
	require.NoError(t, err)
	require.NoError(t, os.Rename(originalPath, originalPath+"-original"))
	require.NoError(t, os.Mkdir(originalPath, 0700))
	after, err := group.Stat()
	require.NoError(t, err)
	replacement, err := os.Stat(originalPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after))
	require.False(t, os.SameFile(after, replacement), "descriptor must not follow replacement path")
}
