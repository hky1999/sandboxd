// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// Keep the same held-directory/mount identity contract as Firecracker's
// writable root. runsc owns anonymous files, so no second directory catalog or
// managed cleanup is needed here. Drain instances before remounting this root.
type runscWritableRoot struct {
	path    string
	dir     *os.File
	mountID int
	device  uint64
}

func openRunscWritableRoot(path, filesystem string) (*runscWritableRoot, error) {
	if path == "" && filesystem == "" {
		return nil, nil
	}
	if path == "" || filesystem == "" || !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return nil, errors.New("runsc writable_storage_dir requires an absolute non-root path and writable_storage_filesystem")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve writable storage: %w", err)
	}
	if canonical != filepath.Clean(path) {
		return nil, errors.New("runsc writable storage must not contain symlinks")
	}
	dir, err := openRunscWritableDirectory(path)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			dir.Close()
		}
	}()
	id, err := runscWritableMountID(fmt.Sprintf("/proc/self/fdinfo/%d", dir.Fd()))
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return nil, err
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return nil, err
	}
	for _, mount := range mounts {
		if mount.ID == id && mount.FSType == filesystem {
			accepted = true
			return &runscWritableRoot{path: canonical, dir: dir, mountID: id, device: uint64(stat.Dev)}, nil
		}
	}
	return nil, fmt.Errorf("runsc writable storage is not mounted as %q", filesystem)
}

func openRunscWritableDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func runscWritableMountID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, errors.New("writable file has no mount identity")
}

func (root *runscWritableRoot) verify() error {
	current, err := openRunscWritableDirectory(root.path)
	if err != nil {
		return err
	}
	defer current.Close()
	a, err := root.dir.Stat()
	if err != nil {
		return err
	}
	b, err := current.Stat()
	if err != nil {
		return err
	}
	id, err := runscWritableMountID(fmt.Sprintf("/proc/self/fdinfo/%d", current.Fd()))
	if err != nil {
		return err
	}
	if id != root.mountID || !os.SameFile(a, b) {
		return errors.New("runsc writable storage mount or directory was replaced")
	}
	return nil
}

func (c *Client) verifyCreatedFilestores(args StartArgs) error {
	state, err := c.loadState(args.ID)
	if err != nil {
		return err
	}
	if state.ID != args.ID || state.Sandbox.ID != args.ID {
		return errors.New("created runsc state identity mismatch")
	}
	return c.Options.writableRoot.verifyProcessFilestores(state.Sandbox.Pid, args.FilestoreAdoptDir)
}

func runscProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("invalid runsc PID")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("invalid runsc process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", errors.New("runsc process is not alive")
	}
	return fields[19], nil
}

// Check actual Sentry descriptors after create and before starting user code.
// The parent-mount flag is not itself proof of where runsc opened its files.
// Restore's non-consuming copies live beside the immutable artifact; accept
// that known directory on the same volume, without consuming the input files.
func (root *runscWritableRoot) verifyProcessFilestores(pid int, adoptDir string) error {
	if err := root.verify(); err != nil {
		return err
	}
	identity, err := runscProcessIdentity(pid)
	if err != nil {
		return err
	}
	allowed := map[string]int{root.path: root.mountID}
	if adoptDir != "" {
		dir, err := openRunscWritableDirectory(adoptDir)
		if err != nil {
			return err
		}
		defer dir.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
			return err
		}
		id, err := runscWritableMountID(fmt.Sprintf("/proc/self/fdinfo/%d", dir.Fd()))
		if err != nil {
			return err
		}
		if uint64(stat.Dev) != root.device {
			return errors.New("adopted filestore is on another filesystem")
		}
		allowed[filepath.Clean(adoptDir)] = id
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		path := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
		target, err := os.Readlink(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		target = strings.TrimSuffix(target, " (deleted)")
		if !strings.HasPrefix(filepath.Base(target), "runsc-filestore-") {
			continue
		}
		expected, ok := allowed[filepath.Dir(target)]
		if !ok {
			return errors.New("runsc opened a private filestore outside its configured directories")
		}
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			return err
		}
		id, err := runscWritableMountID(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Dev) != root.device || id != expected {
			return errors.New("runsc private filestore filesystem does not match its accepted mount")
		}
		count++
	}
	if count == 0 {
		return errors.New("created runsc has no verified private filestore descriptor")
	}
	final, err := runscProcessIdentity(pid)
	if err != nil {
		return err
	}
	if final != identity {
		return errors.New("runsc process identity changed during filestore validation")
	}
	return root.verify()
}
