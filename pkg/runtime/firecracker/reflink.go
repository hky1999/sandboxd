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
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ioctlFICLONE clones an entire file into the destination file descriptor
// via copy-on-write reflinks on filesystems that support them (XFS, Btrfs).
const ioctlFICLONE = 0x40049409

// cloneFileIoctl is the raw reflink entry point, replaceable in tests to
// exercise the fallback path on reflink-capable filesystems.
var cloneFileIoctl = func(destination, source *os.File) error {
	// The ioctl takes the source file descriptor as its argument.
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		destination.Fd(),
		uintptr(ioctlFICLONE),
		uintptr(source.Fd()),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// cloneFile creates dst as a copy of src, preferring a copy-on-write reflink
// (FICLONE) so that unchanged extents are shared and the copy costs O(changed)
// disk space instead of O(file). Reflink support is an optimization, never a
// correctness requirement: on any filesystem or kernel that rejects the ioctl
// the function falls back to a full copy and reports reflinked=false. The
// destination is fsynced before the call returns.
func cloneFile(sourcePath, destinationPath string) (reflinked bool, retErr error) {
	return cloneFileOpts(sourcePath, destinationPath, true)
}

// cloneFileNoSync is cloneFile without the destination fsync, for callers
// that intentionally leave the clone in the page cache. Syncing inside the
// clone is not free: an fsync on the destination can wait behind unrelated
// dirty writeback on the same filesystem, which is exactly the checkpoint
// latency this variant exists to avoid.
func cloneFileNoSync(sourcePath, destinationPath string) (reflinked bool, retErr error) {
	return cloneFileOpts(sourcePath, destinationPath, false)
}

func cloneFileOpts(
	sourcePath, destinationPath string, sync bool,
) (reflinked bool, retErr error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return false, fmt.Errorf("open reflink source %s: %w", sourcePath, err)
	}
	defer source.Close()

	destination, err := os.OpenFile(
		destinationPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return false, fmt.Errorf("create reflink destination %s: %w", destinationPath, err)
	}
	defer func() {
		if sync {
			retErr = errors.Join(retErr, destination.Sync())
		}
		retErr = errors.Join(retErr, destination.Close())
	}()

	if err := cloneFileIoctl(destination, source); err == nil {
		return true, nil
	} else if !isReflinkUnsupported(err) {
		return false, fmt.Errorf("reflink %s to %s: %w", sourcePath, destinationPath, err)
	}

	// Filesystem-level reflink unavailable: degrade to a full copy. The
	// destination was created empty, so rewind it defensively before copying.
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("rewind reflink fallback destination: %w", err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		return false, fmt.Errorf("copy %s to %s after missing reflink support: %w",
			sourcePath, destinationPath, err)
	}
	return false, nil
}

// isReflinkUnsupported reports whether the ioctl error means "reflinks are
// not available here" rather than a real I/O or permission failure. EINVAL
// covers non-regular or same-file sources on some kernels, ENOTTY covers
// filesystems without the ioctl at all, EPERM covers immutable or
// swap-backed inodes, EXDEV covers cross-filesystem clones.
func isReflinkUnsupported(err error) bool {
	for _, candidate := range []error{
		syscall.EOPNOTSUPP,
		syscall.ENOTSUP,
		syscall.EINVAL,
		syscall.ENOTTY,
		syscall.EPERM,
		syscall.EXDEV,
	} {
		if errors.Is(err, candidate) {
			return true
		}
	}
	return false
}
