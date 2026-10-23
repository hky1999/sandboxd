// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

const writableOwnerFile = ".sandboxd-owner"

// A held directory descriptor anchors host operations to the accepted mount.
// Canonical names are used only for persisted state and VMM drive symlinks.
// The VMM retains its disk FD while running; an operator must drain instances
// before moving/remounting this directory or changing its node configuration.
type firecrackerWritableRoot struct {
	path    string
	dir     *os.File
	mountID int
}

func openFirecrackerWritableRoot(path, filesystem string) (*firecrackerWritableRoot, error) {
	if path == "" && filesystem == "" {
		return nil, nil
	}
	if path == "" || filesystem == "" || !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return nil, errors.New("Firecracker writable_storage_dir requires an absolute non-root path and writable_storage_filesystem")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve writable storage: %w", err)
	}
	if canonical != filepath.Clean(path) {
		return nil, errors.New("Firecracker writable storage must not contain symlinks")
	}
	dir, err := openWritableDirectory(path)
	if err != nil {
		return nil, err
	}
	root := &firecrackerWritableRoot{path: canonical, dir: dir}
	accepted := false
	defer func() {
		if !accepted {
			dir.Close()
		}
	}()
	id, err := writableMountID(dir)
	if err != nil {
		return nil, err
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return nil, err
	}
	for _, mount := range mounts {
		if mount.ID == id && mount.FSType == filesystem {
			root.mountID = id
			accepted = true
			return root, nil
		}
	}
	return nil, fmt.Errorf("Firecracker writable storage is not mounted as %q", filesystem)
}

func openWritableDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func writableMountID(dir *os.File) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", dir.Fd()))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, errors.New("writable directory has no mount identity")
}

func (root *firecrackerWritableRoot) verify() error {
	current, err := openWritableDirectory(root.path)
	if err != nil {
		return fmt.Errorf("open configured writable storage: %w", err)
	}
	defer current.Close()
	currentInfo, err := current.Stat()
	if err != nil {
		return err
	}
	acceptedInfo, err := root.dir.Stat()
	if err != nil {
		return err
	}
	id, err := writableMountID(current)
	if err != nil {
		return err
	}
	if id != root.mountID || !os.SameFile(currentInfo, acceptedInfo) {
		return errors.New("Firecracker writable storage mount or directory was replaced")
	}
	return nil
}

func (root *firecrackerWritableRoot) anchoredPath() string {
	// mkfs.ext4 runs in a subprocess with CLOEXEC descriptors. Refer to this
	// daemon's proc entry rather than that subprocess's /proc/self/fd.
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), root.dir.Fd())
}

func (root *firecrackerWritableRoot) component(id, owner string) (string, error) {
	decoded, err := hex.DecodeString(owner)
	if !config.IsValidSandboxID(id) || err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != owner {
		return "", errors.New("invalid Firecracker writable directory ownership")
	}
	return id + "-" + owner, nil
}

func (root *firecrackerWritableRoot) create(id string) (string, error) {
	if err := root.verify(); err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	owner := hex.EncodeToString(nonce[:])
	component, err := root.component(id, owner)
	if err != nil {
		return "", err
	}
	if err := unix.Mkdirat(int(root.dir.Fd()), component, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(root.anchoredPath(), component)
	// This directory was created exclusively by this invocation. Cleanup on
	// failure never touches a pre-existing directory or another generation.
	marker := filepath.Join(path, writableOwnerFile)
	if err := os.WriteFile(marker, []byte(owner+"\n"), 0600); err != nil {
		return "", errors.Join(err, os.Remove(marker), os.Remove(path))
	}
	file, err := os.Open(marker)
	if err != nil {
		return "", errors.Join(err, os.Remove(marker), os.Remove(path))
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return "", errors.Join(err, os.Remove(marker), os.Remove(path))
	}
	dir, err := openWritableDirectory(path)
	if err != nil {
		return "", errors.Join(err, os.Remove(marker), os.Remove(path))
	}
	err = errors.Join(dir.Sync(), dir.Close(), root.dir.Sync())
	if err != nil {
		return "", errors.Join(err, os.Remove(marker), os.Remove(path))
	}
	return owner, nil
}

// openOwned returns a held instance directory after checking mount identity
// and the persistent ownership marker. Callers close it after their operation.
func (root *firecrackerWritableRoot) openOwned(id, owner string) (*os.File, error) {
	if err := root.verify(); err != nil {
		return nil, err
	}
	component, err := root.component(id, owner)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(root.dir.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), component)
	markerFD, err := unix.Openat(fd, writableOwnerFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		dir.Close()
		return nil, err
	}
	marker := os.NewFile(uintptr(markerFD), writableOwnerFile)
	info, statErr := marker.Stat()
	data, readErr := io.ReadAll(io.LimitReader(marker, 65))
	closeErr := marker.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || string(data) != owner+"\n" {
		dir.Close()
		return nil, errors.Join(errors.New("Firecracker writable directory ownership marker mismatch"), statErr, readErr, closeErr)
	}
	return dir, nil
}

func writableFDOverlay(dir *os.File) string {
	return fmt.Sprintf("/proc/%d/fd/%d/overlay.ext4", os.Getpid(), dir.Fd())
}

func (handler *Handler) writableOverlay(state firecrackerPersistedState) (string, *os.File, error) {
	if state.WritableOwner == "" {
		return state.OverlayPath, nil, nil
	}
	if handler.writableRoot == nil {
		return "", nil, errors.New("Firecracker state requires configured writable storage")
	}
	dir, err := handler.writableRoot.openOwned(state.ID, state.WritableOwner)
	if err != nil {
		return "", nil, err
	}
	return writableFDOverlay(dir), dir, nil
}

func (root *firecrackerWritableRoot) overlayPath(id, owner string) (string, error) {
	component, err := root.component(id, owner)
	if err != nil {
		return "", err
	}
	return filepath.Join(root.path, component, "overlay.ext4"), nil
}

func (root *firecrackerWritableRoot) cleanup(id, owner string) error {
	if err := root.verify(); err != nil {
		return err
	}
	dir, err := root.openOwned(id, owner)
	if errors.Is(err, os.ErrNotExist) {
		// Only a missing instance directory is idempotent. A missing marker
		// inside an existing directory is an ownership failure.
		component, componentErr := root.component(id, owner)
		if componentErr != nil {
			return componentErr
		}
		var stat unix.Stat_t
		if statErr := unix.Fstatat(int(root.dir.Fd()), component, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(statErr, unix.ENOENT) {
			return nil
		}
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "overlay.ext4" && entry.Name() != writableOwnerFile {
			return errors.New("unexpected file in Firecracker writable directory; retaining it")
		}
	}
	if err := unix.Unlinkat(int(dir.Fd()), "overlay.ext4", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := unix.Unlinkat(int(dir.Fd()), writableOwnerFile, 0); err != nil {
		return err
	}
	component, _ := root.component(id, owner)
	if err := unix.Unlinkat(int(root.dir.Fd()), component, unix.AT_REMOVEDIR); err != nil {
		// Preserve retry evidence if an unexpected concurrent entry prevented
		// removal after the marker was unlinked.
		return errors.Join(err, os.WriteFile(filepath.Join(fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), dir.Fd()), writableOwnerFile), []byte(owner+"\n"), 0600))
	}
	return root.dir.Sync()
}

func (handler *Handler) prepareWritableOverlay(id, localDir string) (ioPath, canonical, owner string, err error) {
	if handler.writableRoot == nil {
		path := filepath.Join(localDir, "overlay.ext4")
		return path, path, "", nil
	}
	owner, err = handler.writableRoot.create(id)
	if err != nil {
		return "", "", "", err
	}
	component, _ := handler.writableRoot.component(id, owner)
	canonical, _ = handler.writableRoot.overlayPath(id, owner)
	return filepath.Join(handler.writableRoot.anchoredPath(), component, "overlay.ext4"), canonical, owner, nil
}

func (handler *Handler) cleanupWritableOverlay(id, owner string) error {
	if owner == "" {
		return nil
	}
	if handler.writableRoot == nil {
		return errors.New("cannot clean Firecracker writable storage without its configured root")
	}
	return handler.writableRoot.cleanup(id, owner)
}

func (handler *Handler) writableProcessesRunning(state firecrackerPersistedState) bool {
	return firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) ||
		(state.VirtioFS != nil && firecrackerVirtioFSProcessMatches(state.VirtioFS, handler.virtiofsdPath))
}

// stopInstance is best-effort. An abort must retain its state and storage if
// the process still matches after stopping, just as explicit Delete does.
func (handler *Handler) preserveRunningWritable(instance *firecrackerInstance) error {
	state := instance.snapshot()
	if state.WritableOwner == "" || !handler.writableProcessesRunning(state) {
		return nil
	}
	return errors.Join(fmt.Errorf("Firecracker processes for %s still hold writable storage; retaining abort state", state.ID), handler.persistInstance(instance))
}
