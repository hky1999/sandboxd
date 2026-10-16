// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const managedLaunchLimit = 65536
const managedLaunchDirectory = ".scheduler-launches"

// This is an original kernel-directory reference, not a process birth,
// retirement receipt, or permission to signal an arbitrary cgroup member.
type managedLaunchCgroup struct {
	Path                 string `json:"path"`
	Device               uint64 `json:"device"`
	Inode                uint64 `json:"inode"`
	BootID               string `json:"boot_id"`
	CgroupNamespaceDev   uint64 `json:"cgroup_namespace_device"`
	CgroupNamespaceInode uint64 `json:"cgroup_namespace_inode"`
	MountNamespaceDev    uint64 `json:"mount_namespace_device"`
	MountNamespaceInode  uint64 `json:"mount_namespace_inode"`
}

type managedLaunchRecord struct {
	Version            int                  `json:"version"`
	SandboxID          string               `json:"sandbox_id"`
	ResourceGeneration string               `json:"resource_generation"`
	OperationID        string               `json:"operation_id"`
	Revision           uint64               `json:"revision"`
	DeadlineUnixMs     int64                `json:"deadline_unix_ms"`
	ArgumentsSHA256    string               `json:"arguments_sha256"`
	Stage              string               `json:"stage"`
	CloneIntoCgroup    bool                 `json:"clone_into_cgroup"`
	Cgroup             *managedLaunchCgroup `json:"cgroup"`
}

func validLaunchCgroupPath(path string) bool {
	return path != "" && path != "/" && path != "." && len(path) < 4096 &&
		filepath.Clean(path) == path && !strings.HasPrefix(path, "../") &&
		!strings.ContainsAny(path, "\x00\r\n")
}

func openOriginalLaunchCgroup(path string) (*os.File, *managedLaunchCgroup, error) {
	if !validLaunchCgroupPath(path) {
		return nil, nil, errors.New("launch cgroup path is not an exact non-root directory")
	}
	root, err := unix.Open("/sys/fs/cgroup", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, strings.TrimPrefix(path, "/"), &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open original launch cgroup: %w", err)
	}
	group := os.NewFile(uintptr(fd), "original managed launch cgroup")
	ok := false
	defer func() {
		if !ok && group != nil {
			group.Close()
		}
	}()
	var source unix.Stat_t
	var filesystem unix.Statfs_t
	if err := unix.Fstat(fd, &source); err != nil {
		return nil, nil, err
	}
	if err := unix.Fstatfs(fd, &filesystem); err != nil || filesystem.Type != unix.CGROUP2_SUPER_MAGIC ||
		source.Mode&unix.S_IFMT != unix.S_IFDIR || source.Uid != uint32(os.Geteuid()) || source.Mode&0022 != 0 {
		return nil, nil, errors.New("original launch directory is not a private owned cgroup v2 directory")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 128 || strings.TrimSpace(string(boot)) == "" {
		return nil, nil, errors.New("launch boot identity is unavailable")
	}
	var cgroupNS, mountNS unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/cgroup", &cgroupNS); err != nil {
		return nil, nil, err
	}
	if err := unix.Stat("/proc/thread-self/ns/mnt", &mountNS); err != nil {
		return nil, nil, err
	}
	ok = true
	return group, &managedLaunchCgroup{Path: path, Device: source.Dev, Inode: source.Ino,
		BootID: strings.TrimSpace(string(boot)), CgroupNamespaceDev: cgroupNS.Dev,
		CgroupNamespaceInode: cgroupNS.Ino, MountNamespaceDev: mountNS.Dev, MountNamespaceInode: mountNS.Ino}, nil
}

// bindManagedLaunch publishes one immutable dispatch intent before cmd.Start.
// The pinned descriptor is consumed by clone3; unsupported kernels must return
// an error, never fall back to exec followed by a numeric PID migration.
func (c *Client) bindManagedLaunch(ctx context.Context, args StartArgs, cmd *exec.Cmd) (*os.File, error) {
	if args.ResourceGeneration == "" || args.CgroupPath == "" {
		return nil, nil
	}
	if !validLaunchCgroupPath(args.CgroupPath) || !runtimeInventoryID(args.ID) || !runtimeInventoryID(args.ResourceGeneration) {
		return nil, errors.New("original managed launch binding is invalid")
	}
	open := c.openLaunchCgroup
	if open == nil {
		open = openOriginalLaunchCgroup
	}
	group, identity, err := open(args.CgroupPath)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok && group != nil {
			group.Close()
		}
	}()
	deadline, known := ctx.Deadline()
	if !known || group == nil || identity == nil || identity.Path != args.CgroupPath || identity.Inode == 0 ||
		identity.BootID == "" || identity.CgroupNamespaceInode == 0 || identity.MountNamespaceInode == 0 {
		return nil, errors.New("original launch directory identity or deadline is missing")
	}
	arguments, err := json.Marshal(cmd.Args)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(arguments)
	record := &managedLaunchRecord{Version: 1, SandboxID: args.ID, ResourceGeneration: args.ResourceGeneration,
		OperationID: uuid.NewString(), Revision: 1, DeadlineUnixMs: deadline.UnixMilli(),
		ArgumentsSHA256: hex.EncodeToString(digest[:]), Stage: "dispatching", CloneIntoCgroup: true, Cgroup: identity}
	if err := c.publishManagedLaunch(ctx, record); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
	ok = true
	return group, nil
}

func (c *Client) publishManagedLaunch(ctx context.Context, record *managedLaunchRecord) error {
	if record == nil || record.Version != 1 || !runtimeInventoryID(record.SandboxID) ||
		!runtimeInventoryID(record.ResourceGeneration) || record.Revision != 1 || record.Stage != "dispatching" ||
		!record.CloneIntoCgroup || !nativeDigest(record.ArgumentsSHA256) || record.DeadlineUnixMs <= time.Now().UnixMilli() ||
		record.Cgroup == nil || !validLaunchCgroupPath(record.Cgroup.Path) || record.Cgroup.Inode == 0 ||
		record.Cgroup.BootID == "" || record.Cgroup.CgroupNamespaceInode == 0 || record.Cgroup.MountNamespaceInode == 0 {
		return errors.New("managed launch intent is incomplete or expired")
	}
	if _, err := uuid.Parse(record.OperationID); err != nil {
		return errors.New("managed launch operation ID is invalid")
	}
	root, original, err := openRuntimeIdentityDirectory(c.RootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := unix.Mkdirat(int(root.Fd()), managedLaunchDirectory, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(int(root.Fd()), managedLaunchDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "original managed launch journal")
	defer directory.Close()
	var source unix.Stat_t
	if err := unix.Fstat(fd, &source); err != nil || source.Uid != uint32(os.Geteuid()) || source.Mode&0077 != 0 {
		return errors.New("managed launch journal is not privately owned")
	}
	lockFD, err := unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	var lockSource unix.Stat_t
	if err := unix.Fstat(lockFD, &lockSource); err != nil || lockSource.Mode&unix.S_IFMT != unix.S_IFREG ||
		lockSource.Uid != uint32(os.Geteuid()) || lockSource.Mode&0077 != 0 || lockSource.Nlink != 1 {
		return errors.New("original managed launch lock is not private regular data")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		} else if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	entries, err := directory.ReadDir(managedLaunchLimit + 2)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) >= managedLaunchLimit+1 {
		return errors.New("managed launch journal is full; unresolved ownership is retained")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.DeadlineUnixMs <= time.Now().UnixMilli() {
			return errors.New("managed launch deadline expired before publication")
		}
		if err := verifyRuntimeIdentityDirectory(c.RootDir, original); err != nil {
			return err
		}
		var current, held unix.Stat_t
		if err := unix.Fstatat(int(root.Fd()), managedLaunchDirectory, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			current.Dev != source.Dev || current.Ino != source.Ino || current.Mode != source.Mode || current.Uid != source.Uid {
			return errors.New("original managed launch journal directory changed")
		}
		if err := unix.Fstat(lockFD, &held); err != nil || !sameRuntimeInventoryStat(lockSource, held) {
			return errors.New("original managed launch lock changed")
		}
		if err := unix.Fstatat(fd, ".lock", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameRuntimeInventoryStat(held, current) {
			return errors.New("original managed launch lock was replaced")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	retiredName := "retired-" + managedLaunchKey(record.SandboxID, record.ResourceGeneration) + ".json"
	var archived unix.Stat_t
	if err := unix.Fstatat(fd, retiredName, &archived, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("managed launch generation was already archived or its history is unknown")
	}
	receipt, _, err := c.readLaunchRetirement(ctx, record.SandboxID, record.ResourceGeneration)
	if err != nil {
		return err
	}
	if receipt != nil {
		return errors.New("managed launch generation already has a retirement intent")
	}
	name := record.SandboxID + ".json"
	previous, err := privateManagedLaunchJSON(directory, name, managedLaunchRecordBytes)
	replace := false
	if err == nil {
		var old managedLaunchRecord
		if err := decodeManagedLaunchJSON(previous, &old); err != nil {
			return err
		}
		if old.Version != 1 || old.SandboxID != record.SandboxID || !runtimeInventoryID(old.ResourceGeneration) ||
			old.ResourceGeneration == record.ResourceGeneration || old.Revision != 1 || old.Stage != "dispatching" ||
			!old.CloneIntoCgroup || !nativeDigest(old.ArgumentsSHA256) || old.Cgroup == nil ||
			!validLaunchCgroupPath(old.Cgroup.Path) || old.Cgroup.Inode == 0 || old.Cgroup.BootID == "" ||
			old.Cgroup.CgroupNamespaceInode == 0 || old.Cgroup.MountNamespaceInode == 0 || old.DeadlineUnixMs <= 0 {
			return errors.New("managed launch original owner is incomplete or unchanged")
		}
		if _, err := uuid.Parse(old.OperationID); err != nil {
			return errors.New("managed launch original operation is invalid")
		}
		if err := c.archiveRetiredManagedLaunch(ctx, directory, root, &old, previous, check); err != nil {
			return err
		}
		replace = true
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return c.writeManagedLaunchJSON(directory, root, name, data, replace, check)
}
