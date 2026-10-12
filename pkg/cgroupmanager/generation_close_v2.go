// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type v2GenerationDirectory struct {
	mountpoint              string
	root, parent, directory *os.File
	identity, parentID      CgroupIdentity
	scope                   generationLeaseScope
}

func originalCgroupDirectory(fd int, path string) (CgroupIdentity, error) {
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return CgroupIdentity{}, err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return CgroupIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.CGROUP2_SUPER_MAGIC ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
		return CgroupIdentity{}, errors.New("original cgroup directory is not a private owned cgroup v2 object")
	}
	return CgroupIdentity{Path: path, Device: stat.Dev, Inode: stat.Ino}, nil
}

func openCgroupDirectoryAt(fd int, name string) (*os.File, error) {
	child, err := unix.Openat2(fd, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(child), name), nil
}

func (o *cgroupV2) openGenerationDirectory(identity CgroupIdentity, scope generationLeaseScope, expectedParent *CgroupIdentity, allowMissing bool) (generationDirectory, error) {
	if identity.Path == "/" || !filepath.IsAbs(identity.Path) || filepath.Clean(identity.Path) != identity.Path || identity.Device == 0 || identity.Inode == 0 {
		return nil, errors.New("original cgroup directory identity is invalid")
	}
	current, err := currentGenerationLeaseScope()
	if err != nil || current != scope {
		return nil, errors.New("original cgroup directory scope changed")
	}
	rootFD, err := unix.Open(o.mountpoint, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	d := &v2GenerationDirectory{mountpoint: o.mountpoint, root: os.NewFile(uintptr(rootFD), o.mountpoint), identity: identity, scope: scope}
	good := false
	defer func() {
		if !good {
			_ = d.close()
		}
	}()
	rootID, err := originalCgroupDirectory(rootFD, "/")
	if err != nil || rootID.Device != scope.MountRootDevice || rootID.Inode != scope.MountRootInode {
		return nil, errors.Join(errors.New("original cgroup mount root differs"), err)
	}
	parentPath := filepath.Dir(identity.Path)
	if parentPath == "/" {
		return nil, errors.New("generation close requires a private non-root parent")
	}
	d.parent, err = openCgroupDirectoryAt(rootFD, strings.TrimPrefix(parentPath, "/"))
	if err != nil {
		return nil, err
	}
	d.parentID, err = originalCgroupDirectory(int(d.parent.Fd()), parentPath)
	if err != nil || (expectedParent != nil && d.parentID != *expectedParent) {
		return nil, errors.Join(errors.New("original cgroup parent differs"), err)
	}
	d.directory, err = openCgroupDirectoryAt(int(d.parent.Fd()), filepath.Base(identity.Path))
	if errors.Is(err, unix.ENOENT) && allowMissing && expectedParent != nil {
		// Only a persisted original-parent intent may authorize this branch.
		good = true
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	actual, err := originalCgroupDirectory(int(d.directory.Fd()), identity.Path)
	if err != nil || actual != identity {
		return nil, errors.Join(errors.New("original cgroup leaf replaced"), err)
	}
	good = true
	return d, nil
}

func (d *v2GenerationDirectory) parentIdentity() CgroupIdentity { return d.parentID }

func (d *v2GenerationDirectory) verifyParent() error {
	current, err := currentGenerationLeaseScope()
	if err != nil || current != d.scope {
		return errors.New("original cgroup scope changed during close")
	}
	// Reopen the current mount entry; a retained root FD alone cannot prove
	// that the currently mounted source is still the original one.
	fd, err := unix.Open(d.mountpoint, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	root, err := originalCgroupDirectory(fd, "/")
	if err != nil || root.Device != d.scope.MountRootDevice || root.Inode != d.scope.MountRootInode {
		return errors.New("original cgroup mount entry changed during close")
	}
	parent, err := openCgroupDirectoryAt(fd, strings.TrimPrefix(d.parentID.Path, "/"))
	if err != nil {
		return err
	}
	defer parent.Close()
	actual, err := originalCgroupDirectory(int(parent.Fd()), d.parentID.Path)
	if err != nil || actual != d.parentID {
		return errors.New("original cgroup parent entry changed during close")
	}
	return nil
}

func (d *v2GenerationDirectory) verify() error {
	if err := d.verifyParent(); err != nil {
		return err
	}
	if d.directory == nil {
		return errors.New("original cgroup leaf is already absent")
	}
	leaf, err := openCgroupDirectoryAt(int(d.parent.Fd()), filepath.Base(d.identity.Path))
	if err != nil {
		return err
	}
	defer leaf.Close()
	actual, err := originalCgroupDirectory(int(leaf.Fd()), d.identity.Path)
	if err != nil || actual != d.identity {
		return errors.New("original cgroup entry replaced during close")
	}
	return nil
}

func (d *v2GenerationDirectory) control(name string, flags int) (*os.File, error) {
	if d.directory == nil {
		return nil, unix.ENOENT
	}
	fd, err := unix.Openat2(int(d.directory.Fd()), name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (d *v2GenerationDirectory) read(name string) (string, error) {
	file, err := d.control(name, unix.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1048577))
	if err != nil || len(data) > 1048576 {
		return "", errors.Join(errors.New("original cgroup control read failed or exceeded its bound"), err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (d *v2GenerationDirectory) absent() (bool, error) {
	if err := d.verifyParent(); err != nil {
		return false, err
	}
	if d.directory != nil {
		for _, name := range []string{"cgroup.procs", "cgroup.events"} {
			file, err := d.control(name, unix.O_RDONLY)
			if err == nil {
				_ = file.Close()
				return false, nil
			}
			if !errors.Is(err, unix.ENOENT) {
				return false, err
			}
		}
	}
	leaf, err := openCgroupDirectoryAt(int(d.parent.Fd()), filepath.Base(d.identity.Path))
	if leaf != nil {
		_ = leaf.Close()
	}
	if !errors.Is(err, unix.ENOENT) {
		return false, errors.Join(errors.New("original closed cgroup name is present or unverifiable"), err)
	}
	return true, nil
}

func (d *v2GenerationDirectory) empty() (bool, error) {
	procs, err := d.read("cgroup.procs")
	if err != nil {
		return false, err
	}
	for _, field := range strings.Fields(procs) {
		pid, err := strconv.ParseUint(field, 10, 64)
		if err != nil || validateCgroupProcesses([]uint64{pid}) != nil {
			return false, errors.New("unsafe or unknown original cgroup member")
		}
	}
	events, err := d.read("cgroup.events")
	if err != nil {
		return false, err
	}
	seen := false
	populated := ""
	for _, line := range strings.Split(events, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "populated" {
			if seen || len(fields) != 2 || (fields[1] != "0" && fields[1] != "1") {
				return false, errors.New("original cgroup populated fact is malformed")
			}
			seen, populated = true, fields[1]
		}
	}
	if !seen {
		return false, errors.New("original cgroup populated fact is missing")
	}
	return procs == "" && populated == "0", nil
}

func (d *v2GenerationDirectory) noChildren() error {
	file, err := openCgroupDirectoryAt(int(d.directory.Fd()), ".")
	if err != nil {
		return err
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("original cgroup has unsupported child groups; close retained")
		}
	}
	return nil
}

func (d *v2GenerationDirectory) drain(ctx context.Context) error {
	if err := d.verify(); err != nil {
		return err
	}
	if err := d.noChildren(); err != nil {
		return err
	}
	self, err := os.ReadFile("/proc/thread-self/cgroup")
	if err != nil {
		return err
	}
	fields := strings.Split(strings.TrimSpace(string(self)), "::")
	if len(fields) != 2 || fields[0] != "0" || fields[1] == d.identity.Path || strings.HasPrefix(fields[1], d.identity.Path+"/") {
		return errors.New("cgroup close observer is not proven outside the original group")
	}
	frozen, err := d.read("cgroup.freeze")
	if err != nil || frozen != "0" {
		return errors.New("cgroup close cannot release a foreign or unknown freeze")
	}
	kind, err := d.read("cgroup.type")
	if err != nil || kind != "domain" {
		return errors.New("cgroup close requires a domain leaf")
	}
	empty, err := d.empty()
	if err != nil {
		return err
	}
	if !empty {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.verify(); err != nil {
			return err
		}
		kill, err := d.control("cgroup.kill", unix.O_WRONLY)
		if err != nil {
			return err
		}
		_, writeErr := kill.Write([]byte("1"))
		closeErr := kill.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
	}
	// cgroup.kill is allowed only on this permanently closing lease. Even if
	// interrupted, the pool cannot reuse a group whose kill sequence changed.
	bounded, cancel := context.WithTimeout(ctx, cgroupDrainTimeout)
	defer cancel()
	for {
		if err := d.verify(); err != nil {
			return err
		}
		empty, err := d.empty()
		if err != nil {
			return err
		}
		if empty {
			return nil
		}
		select {
		case <-bounded.Done():
			return bounded.Err()
		case <-time.After(cgroupDrainPoll):
		}
	}
}

func (d *v2GenerationDirectory) remove() error {
	if err := d.verify(); err != nil {
		return err
	}
	if err := d.noChildren(); err != nil {
		return err
	}
	empty, err := d.empty()
	if err != nil || !empty {
		return errors.Join(errors.New("original cgroup is not proven empty"), err)
	}
	if err := d.verify(); err != nil {
		return err
	}
	// Linux has no inode-conditional rmdir. The manager owns this private
	// parent and serializes lease reuse; an uncoordinated privileged rmdir
	// racing this syscall remains outside that ownership contract.
	return unix.Unlinkat(int(d.parent.Fd()), filepath.Base(d.identity.Path), unix.AT_REMOVEDIR)
}

func (d *v2GenerationDirectory) proof() (*ClosedGenerationCgroup, error) {
	proof := &ClosedGenerationCgroup{Identity: d.identity, ParentIdentity: d.parentID}
	for _, entry := range []struct {
		original *os.File
		target   **os.File
	}{{d.directory, &proof.Directory}, {d.parent, &proof.Parent}} {
		if entry.original == nil {
			continue
		}
		fd, err := unix.FcntlInt(entry.original.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			_ = proof.Close()
			return nil, err
		}
		*entry.target = os.NewFile(uintptr(fd), entry.original.Name())
	}
	return proof, nil
}

func (d *v2GenerationDirectory) close() error {
	var errs []error
	for _, file := range []*os.File{d.directory, d.parent, d.root} {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	return errors.Join(errs...)
}
