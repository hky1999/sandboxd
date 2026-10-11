// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const managerOwnerLockName = ".scheduler-image-manager.lock"

// ManagerLifecycle keeps shutdown separate from the legacy Manager interface.
// A timed-out close retains its flock until every admitted operation exits.
type ManagerLifecycle interface {
	RetainOwnership() (func(), error)
	StopAccepting()
	Close(context.Context) error
}

type managerOwnership struct {
	mu             sync.Mutex
	ctx            context.Context
	root           string
	session        string
	directory      *os.File
	lock           *os.File
	directoryStat  unix.Stat_t
	privateParent  *unix.Stat_t
	lockStat       unix.Stat_t
	active         int
	closeRequested atomic.Bool
	closing        chan struct{}
	done           chan struct{}
	closeErr       error
}

func openManagerOwnership(ctx context.Context, root string) (*managerOwnership, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("image-manager root is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve image-manager root")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("prepare image-manager owner root: %w", err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open image-manager owner root: %w", err)
	}
	o := &managerOwnership{ctx: ctx, root: root, directory: os.NewFile(uintptr(fd), root), closing: make(chan struct{}), done: make(chan struct{})}
	ok := false
	defer func() {
		if !ok {
			if o.lock != nil {
				_ = o.lock.Close()
			}
			_ = o.directory.Close()
		}
	}()
	if err := unix.Fstat(fd, &o.directoryStat); err != nil || o.directoryStat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("image-manager owner root is not privately writable by this owner")
	}
	if o.directoryStat.Mode&0022 != 0 {
		// Go's TempDir children can inherit group-write permissions. They are
		// still private when the original immediate parent denies traversal.
		var parent unix.Stat_t
		if err := unix.Lstat(filepath.Dir(root), &parent); err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Mode&0077 != 0 || parent.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("image-manager owner root lacks a private parent")
		}
		o.privateParent = &parent
	}
	lockFD, err := unix.Openat(fd, managerOwnerLockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open image-manager owner lock: %w", err)
	}
	o.lock = os.NewFile(uintptr(lockFD), managerOwnerLockName)
	if err := unix.Fstat(lockFD, &o.lockStat); err != nil || o.lockStat.Mode&unix.S_IFMT != unix.S_IFREG || o.lockStat.Mode&07777 != 0600 || o.lockStat.Uid != uint32(os.Geteuid()) || o.lockStat.Nlink != 1 || o.lockStat.Size != 0 {
		return nil, fmt.Errorf("image-manager owner lock identity is invalid")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("image-manager root already has an owner: %w", err)
	}
	if err := o.verifyPathsLocked(); err != nil {
		return nil, err
	}
	if err := o.lock.Sync(); err != nil {
		return nil, fmt.Errorf("sync image-manager owner lock: %w", err)
	}
	if err := o.directory.Sync(); err != nil {
		return nil, fmt.Errorf("sync image-manager owner directory: %w", err)
	}
	var session [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		return nil, fmt.Errorf("allocate original image-manager session: %w", err)
	}
	o.session = hex.EncodeToString(session[:])
	ok = true
	return o, nil
}

func (o *managerOwnership) verifyPathsLocked() error {
	var directory, lock unix.Stat_t
	if o.privateParent != nil {
		var parent unix.Stat_t
		if err := unix.Lstat(filepath.Dir(o.root), &parent); err != nil || parent.Dev != o.privateParent.Dev || parent.Ino != o.privateParent.Ino || parent.Mode != o.privateParent.Mode || parent.Uid != o.privateParent.Uid {
			return fmt.Errorf("original private image-manager parent changed")
		}
	}
	if err := unix.Lstat(o.root, &directory); err != nil || directory.Dev != o.directoryStat.Dev || directory.Ino != o.directoryStat.Ino || directory.Mode != o.directoryStat.Mode || directory.Uid != o.directoryStat.Uid {
		return fmt.Errorf("original image-manager root changed or is unavailable")
	}
	if err := unix.Fstatat(int(o.directory.Fd()), managerOwnerLockName, &lock, unix.AT_SYMLINK_NOFOLLOW); err != nil || lock.Dev != o.lockStat.Dev || lock.Ino != o.lockStat.Ino || lock.Mode != o.lockStat.Mode || lock.Uid != o.lockStat.Uid || lock.Nlink != 1 || lock.Size != 0 {
		return fmt.Errorf("original image-manager owner lock changed or is unavailable")
	}
	return nil
}

func (o *managerOwnership) acquire() (func(), error) {
	if o == nil {
		return func() {}, nil // Private, unmanaged test fixtures have no owner.
	}
	if o.closeRequested.Load() || o.ctx.Err() != nil {
		return nil, fmt.Errorf("image-manager owner is closing")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closeRequested.Load() || o.ctx.Err() != nil {
		return nil, fmt.Errorf("image-manager owner is closing")
	}
	if err := o.verifyPathsLocked(); err != nil {
		return nil, err
	}
	o.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			defer o.mu.Unlock()
			o.active--
			o.finishCloseLocked()
		})
	}, nil
}

// The existing operation holds an admission lease. Close cannot release flock
// while this critical section or any previously admitted work still runs.
func (o *managerOwnership) dispatch(command func() error) (bool, error) {
	if o == nil {
		return true, command()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closeRequested.Load() || o.ctx.Err() != nil {
		return false, fmt.Errorf("image-manager owner cannot dispatch after close")
	}
	if err := o.verifyPathsLocked(); err != nil {
		return false, err
	}
	return true, command()
}

func (o *managerOwnership) requestClose() {
	if o == nil || !o.closeRequested.CompareAndSwap(false, true) {
		return
	}
	close(o.closing)
	// Do not make the caller's deadline wait for an in-progress Start syscall.
	go func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.finishCloseLocked()
	}()
}

func (o *managerOwnership) closingSignal() <-chan struct{} {
	if o == nil {
		return nil
	}
	return o.closing
}

func (o *managerOwnership) finishCloseLocked() {
	if !o.closeRequested.Load() || o.active != 0 {
		return
	}
	select {
	case <-o.done:
		return
	default:
	}
	if err := o.lock.Close(); err != nil {
		o.closeErr = fmt.Errorf("close image-manager owner lock: %w", err)
	}
	if err := o.directory.Close(); err != nil && o.closeErr == nil {
		o.closeErr = fmt.Errorf("close image-manager owner directory: %w", err)
	}
	close(o.done)
}

func (mgr *manager) RetainOwnership() (func(), error) {
	return mgr.ownership.acquire()
}

func (mgr *manager) StopAccepting() {
	if mgr.ownership == nil {
		return
	}
	mgr.ownership.requestClose()
	if mgr.cancel != nil {
		mgr.cancel()
	}
}

func (mgr *manager) Close(ctx context.Context) error {
	if mgr.ownership == nil {
		return nil
	}
	mgr.StopAccepting()
	select {
	case <-mgr.ownership.done:
		return mgr.ownership.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (mgr *manager) commandContext() context.Context {
	if mgr.ctx == nil {
		return context.Background()
	}
	return mgr.ctx
}
