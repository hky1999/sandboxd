// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The producer's .lock file serializes this entire transition with native
// start/restore/deletion. Held directory descriptors prevent path replacement
// from redirecting the final state write into a different runtime root.
type runtimeStateTransition struct {
	id                 string
	client             *Client
	directory          *os.File
	rootIdentity       unix.Stat_t
	lock               *os.File
	lockIdentity       unix.Stat_t
	stateName          string
	stateData          []byte
	stateIdentity      unix.Stat_t
	stateFile          originalRuntimeStateFile
	bundle             *os.File
	bundlePath         string
	bundleIdentity     unix.Stat_t
	bundleData         []byte
	bundleFileIdentity unix.Stat_t
}

type originalRuntimeStateFile interface {
	Fd() uintptr
	WriteAt([]byte, int64) (int, error)
	Sync() error
	Close() error
}

func privateRuntimeSnapshot(directory *os.File, name string) ([]byte, unix.Stat_t, error) {
	var before, after unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, before, err
	}
	data, err := readPrivateRuntimeJSON(directory, name)
	if err != nil {
		return nil, before, err
	}
	if err := unix.Fstatat(int(directory.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameRuntimeInventoryStat(before, after) {
		return nil, before, errors.New("original runtime data changed while capturing the transition")
	}
	return data, before, nil
}

func (c *Client) beginStateTransition(ctx context.Context, id string, managed bool) (*runtimeStateTransition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !runtimeInventoryID(id) || !filepath.IsAbs(c.RootDir) || filepath.Clean(c.RootDir) != c.RootDir {
		return nil, errors.New("runtime transition requires an exact original root and full ID")
	}
	directory, identity, err := openRuntimeIdentityDirectory(c.RootDir)
	if err != nil {
		return nil, err
	}
	g := &runtimeStateTransition{id: id, client: c, directory: directory, rootIdentity: identity,
		stateName: filepath.Base(c.stateFilePath(id))}
	complete := false
	defer func() {
		if !complete {
			g.close()
		}
	}()
	g.stateData, g.stateIdentity, err = privateRuntimeSnapshot(directory, g.stateName)
	if err != nil {
		return nil, err
	}
	var owner struct{ ID, Status string }
	if err := json.Unmarshal(g.stateData, &owner); err != nil || owner.ID != id || owner.Status != "created" {
		return nil, errors.New("runtime transition source is not the original created state")
	}
	stateFD, err := unix.Openat(int(directory.Fd()), g.stateName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	g.stateFile = os.NewFile(uintptr(stateFD), g.stateName)
	var stateHeld unix.Stat_t
	if err := unix.Fstat(stateFD, &stateHeld); err != nil || !sameRuntimeInventoryStat(stateHeld, g.stateIdentity) {
		return nil, errors.New("original runtime state changed before its handle was acquired")
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if !managed {
		flags |= unix.O_CREAT
	}
	name := strings.TrimSuffix(g.stateName, ".state") + ".lock"
	fd, err := unix.Openat(int(directory.Fd()), name, flags, 0640)
	if err != nil {
		return nil, fmt.Errorf("open original runtime lifecycle lock: %w", err)
	}
	g.lock = os.NewFile(uintptr(fd), name)
	if err := unix.Fstat(fd, &g.lockIdentity); err != nil || g.lockIdentity.Mode&unix.S_IFMT != unix.S_IFREG ||
		g.lockIdentity.Mode&0022 != 0 || g.lockIdentity.Uid != uint32(os.Geteuid()) || g.lockIdentity.Nlink != 1 {
		return nil, errors.New("runtime lifecycle lock is not the original private regular file")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return nil, bounded.Err()
		case <-timer.C:
		}
	}
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	complete = true
	return g, nil
}

func (g *runtimeStateTransition) close() {
	if g.bundle != nil {
		_ = g.bundle.Close()
	}
	if g.lock != nil {
		_ = g.lock.Close()
	}
	if g.stateFile != nil {
		_ = g.stateFile.Close()
	}
	if g.directory != nil {
		_ = g.directory.Close()
	}
}

func (g *runtimeStateTransition) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyRuntimeIdentityDirectory(g.client.RootDir, g.rootIdentity); err != nil {
		return err
	}
	var held, current unix.Stat_t
	if err := unix.Fstat(int(g.lock.Fd()), &held); err != nil {
		return err
	}
	if err := unix.Fstatat(int(g.directory.Fd()), g.lock.Name(), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!sameRuntimeInventoryStat(g.lockIdentity, held) || !sameRuntimeInventoryStat(held, current) {
		return errors.New("original runtime lifecycle lock was replaced")
	}
	data, stat, err := privateRuntimeSnapshot(g.directory, g.stateName)
	if err != nil || !bytes.Equal(data, g.stateData) || !sameRuntimeInventoryStat(stat, g.stateIdentity) {
		return errors.New("original runtime state changed during the transition")
	}
	if err := unix.Fstat(int(g.stateFile.Fd()), &held); err != nil || !sameRuntimeInventoryStat(held, g.stateIdentity) {
		return errors.New("original runtime state handle no longer matches the transition")
	}
	if g.bundle != nil {
		if err := verifyRuntimeIdentityDirectory(g.bundlePath, g.bundleIdentity); err != nil {
			return err
		}
		data, stat, err = privateRuntimeSnapshot(g.bundle, "config.json")
		if err != nil || !bytes.Equal(data, g.bundleData) || !sameRuntimeInventoryStat(stat, g.bundleFileIdentity) {
			return errors.New("original runtime bundle changed during the transition")
		}
	}
	return ctx.Err()
}

func (c *Client) beginStartTransition(ctx context.Context, args StartArgs) (*runtimeStateTransition, *containerState, error) {
	// Preserve early generation rejection, before even opening a lifecycle lock.
	if _, err := c.loadStartState(args); err != nil {
		return nil, nil, err
	}
	g, err := c.beginStateTransition(ctx, args.ID, args.ResourceGeneration != "")
	if err != nil {
		return nil, nil, err
	}
	complete := false
	defer func() {
		if !complete {
			g.close()
		}
	}()
	state, err := decodeNativeState(g.stateData, args.ID)
	if err != nil {
		return nil, nil, err
	}
	if args.ResourceGeneration != "" {
		if err := validateStartState(state, args); err != nil {
			return nil, nil, err
		}
		if !filepath.IsAbs(args.BundleDir) || filepath.Clean(args.BundleDir) != args.BundleDir {
			return nil, nil, errors.New("original runtime bundle path is not exact and absolute")
		}
		g.bundlePath = args.BundleDir
		g.bundle, g.bundleIdentity, err = openRuntimeIdentityDirectory(args.BundleDir)
		if err != nil {
			return nil, nil, err
		}
		g.bundleData, g.bundleFileIdentity, err = privateRuntimeSnapshot(g.bundle, "config.json")
		if err != nil {
			return nil, nil, err
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(g.bundleData, &spec); err != nil || spec.Annotations[runtimeResourceGenerationAnnotation] != args.ResourceGeneration {
			return nil, nil, errors.New("original runtime bundle generation changed")
		}
	}
	if err := g.check(ctx); err != nil {
		return nil, nil, err
	}
	complete = true
	return g, state, nil
}

func (g *runtimeStateTransition) connect(ctx context.Context, path string) (controlRPC, error) {
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != g.client.RootDir || filepath.Base(path) != "runsc-"+g.id+".sock" {
		return nil, errors.New("control socket is outside the original runtime directory")
	}
	name := filepath.Base(path)
	var before, after unix.Stat_t
	if err := unix.Fstatat(int(g.directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("original runtime control endpoint is not a socket")
	}
	conn, err := g.client.connectControl(fmt.Sprintf("/proc/self/fd/%d/%s", g.directory.Fd(), name))
	if err != nil {
		return nil, err
	}
	if err := unix.Fstatat(int(g.directory.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameRuntimeInventoryStat(before, after) {
		_ = conn.Close()
		return nil, errors.New("original runtime control socket was replaced while connecting")
	}
	if err := g.check(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (g *runtimeStateTransition) markRunning(ctx context.Context) error {
	if err := g.check(ctx); err != nil {
		return err
	}
	offset, err := createdStatusOffset(g.stateData)
	if err != nil {
		return err
	}
	// Both native status strings have the same length. Write only that field to
	// the held original inode: even a noncooperating path replacement between
	// verification and this write cannot redirect it into a foreign state file.
	// Every other byte, including opaque future identity fields, stays exact.
	value := []byte(`"running"`)
	if _, err := g.stateFile.WriteAt(value, offset); err != nil {
		return err
	}
	if err := g.stateFile.Sync(); err != nil {
		return err
	}
	if err := g.directory.Sync(); err != nil {
		return err
	}
	data := bytes.Clone(g.stateData)
	copy(data[offset:], value)
	g.stateData = data
	if err := unix.Fstat(int(g.stateFile.Fd()), &g.stateIdentity); err != nil {
		return err
	}
	// A partial write or failed persistence/readback is unconfirmed; do not
	// roll an already-started runtime back or clean another incarnation.
	return g.check(ctx)
}

func createdStatusOffset(data []byte) (int64, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return 0, errors.New("runtime state is not an object")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return 0, err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return 0, err
		}
		if token == "status" {
			end := decoder.InputOffset()
			start := end - int64(len(value))
			if !bytes.Equal(value, []byte(`"created"`)) || start < 0 || end > int64(len(data)) || !bytes.Equal(data[start:end], value) {
				return 0, errors.New("runtime status is not the original native created token")
			}
			return start, nil
		}
	}
	return 0, errors.New("runtime state has no original status token")
}
