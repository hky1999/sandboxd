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

package checkpointchunks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// BackingProof binds a locally managed memory artifact to verified expected
// content. It has no exported fields or serialization. Timestamp checks alone
// cannot detect writes within one filesystem clock tick, so Open and Check
// revalidate content as well. Consumers must keep artifacts immutable while
// cloning: this is not a lock against concurrent writers.
type BackingProof struct {
	dir      string
	digest   string
	mode     string
	memory   backingIdentity
	sidecar  backingIdentity
	verified bool
}

type backingIdentity struct {
	dev, ino     uint64
	size         int64
	mode         uint32
	mtime, ctime syscall.Timespec
}

func backingID(info os.FileInfo) (backingIdentity, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return backingIdentity{}, fmt.Errorf("backing is not a regular Linux file")
	}
	return backingIdentity{dev: uint64(st.Dev), ino: st.Ino, size: st.Size, mode: st.Mode, mtime: st.Mtim, ctime: st.Ctim}, nil
}
func identityAt(path string) (backingIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return backingIdentity{}, err
	}
	return backingID(info)
}
func rejectMaterialized(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, ".materialized"))
	if err == nil {
		return fmt.Errorf("materialized remote placeholder is not a local complete backing")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func openMemory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "memory")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func normalizeDigestMode(mode string) string {
	if mode == "" {
		return FileDigestSha256
	}
	return mode
}

// VerifyMemoryBacking binds the sidecar and actual bytes to the digest/mode
// expected by the caller's outer checkpoint manifest. Holes are allowed only
// when their zero bytes match that expected content. The .materialized marker
// always forbids a local proof, even for preallocated or all-zero placeholders.
func VerifyMemoryBacking(ctx context.Context, dir, expectedDigest, expectedMode string) (*BackingProof, error) {
	proof, f, err := verifyAndOpenMemoryBacking(ctx, dir, expectedDigest, expectedMode)
	if f != nil {
		f.Close()
	}
	return proof, err
}

// OpenVerifiedMemoryBacking returns the same descriptor whose complete contents
// were just verified. Immediate consumers avoid closing it and rescanning via
// BackingProof.Open. The caller owns the fd and must keep the managed artifact
// immutable while serving it; this is not a lock against concurrent writes.
func OpenVerifiedMemoryBacking(ctx context.Context, dir, expectedDigest, expectedMode string) (*os.File, error) {
	_, f, err := verifyAndOpenMemoryBacking(ctx, dir, expectedDigest, expectedMode)
	return f, err
}

func verifyAndOpenMemoryBacking(ctx context.Context, dir, expectedDigest, expectedMode string) (*BackingProof, *os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !validDigest(expectedDigest) {
		return nil, nil, fmt.Errorf("invalid expected memory digest")
	}
	expectedMode = normalizeDigestMode(expectedMode)
	if expectedMode != FileDigestChunks && expectedMode != FileDigestSha256 {
		return nil, nil, fmt.Errorf("invalid expected digest mode %q", expectedMode)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, err
	}
	if err = rejectMaterialized(dir); err != nil {
		return nil, nil, err
	}
	sidecar, err := identityAt(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, nil, err
	}
	m, err := Load(dir)
	if err != nil {
		return nil, nil, err
	}
	if m.File != "memory" || m.FileDigest != expectedDigest || normalizeDigestMode(m.FileDigestMode) != expectedMode {
		return nil, nil, fmt.Errorf("memory sidecar does not match expected file/digest/mode")
	}
	f, err := openMemory(dir)
	if err != nil {
		return nil, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	id, err := backingID(info)
	if err != nil {
		return nil, nil, err
	}
	if id.size != m.FileSize {
		return nil, nil, fmt.Errorf("memory backing size %d does not match manifest %d", id.size, m.FileSize)
	}
	proof := &BackingProof{dir: dir, digest: expectedDigest, mode: expectedMode, memory: id, sidecar: sidecar, verified: true}
	if err = proof.Check(ctx, f); err != nil {
		return nil, nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	keep = true
	return proof, f, nil
}

// Check validates the actual opened source fd and its current pathname against
// the verified identities. Neither the source nor sidecar may have changed.
func (p *BackingProof) Check(ctx context.Context, f *os.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || !p.verified || f == nil {
		return fmt.Errorf("no verified backing proof")
	}
	if err := rejectMaterialized(p.dir); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	id, err := backingID(info)
	if err != nil {
		return err
	}
	pathID, err := identityAt(filepath.Join(p.dir, "memory"))
	if err != nil {
		return err
	}
	sidecar, err := identityAt(filepath.Join(p.dir, ManifestName))
	if err != nil {
		return err
	}
	if id != p.memory || pathID != p.memory || sidecar != p.sidecar {
		return fmt.Errorf("verified memory backing or sidecar changed")
	}
	m, err := Load(p.dir)
	if err != nil {
		return err
	}
	if m.File != "memory" || m.FileSize != p.memory.size || m.FileDigest != p.digest || normalizeDigestMode(m.FileDigestMode) != p.mode {
		return fmt.Errorf("verified sidecar no longer matches expected content")
	}
	section := io.NewSectionReader(f, 0, p.memory.size)
	var reader io.Reader = section
	if p.mode == FileDigestChunks {
		// dup would share f's offset. Open independently and bind the query
		// descriptor to the same identity before using its extent answers.
		extents, err := openMemory(p.dir)
		if err != nil {
			return err
		}
		defer extents.Close()
		info, err := extents.Stat()
		if err != nil {
			return err
		}
		extentID, err := backingID(info)
		if err != nil {
			return err
		}
		if extentID != p.memory {
			return fmt.Errorf("extent descriptor does not match verified backing")
		}
		reader = &memoryHoleReader{SectionReader: section, seekData: func(offset int64) (int64, error) {
			return unix.Seek(int(extents.Fd()), offset, unix.SEEK_DATA)
		}}
	}
	if err = verifyContents(ctx, reader, m); err != nil {
		return err
	}
	// Recheck the actual fd and pathname after the scan. Content checking
	// closes same-tick writes before validation; immutable ownership is still
	// required to exclude mutations during clone/copy itself.
	after, err := f.Stat()
	if err != nil {
		return err
	}
	afterID, err := backingID(after)
	if err != nil {
		return err
	}
	pathAfter, err := identityAt(filepath.Join(p.dir, "memory"))
	if err != nil {
		return err
	}
	sidecarAfter, err := identityAt(filepath.Join(p.dir, ManifestName))
	if err != nil {
		return err
	}
	if afterID != p.memory || pathAfter != p.memory || sidecarAfter != p.sidecar {
		return fmt.Errorf("backing changed during content verification")
	}
	if err = rejectMaterialized(p.dir); err != nil {
		return err
	}
	return ctx.Err()
}

// Open returns a read-only descriptor checked against this proof. The caller
// owns it and must Check it again after a clone/copy before adopting the result.
func (p *BackingProof) Open(ctx context.Context) (*os.File, error) {
	if p == nil || !p.verified {
		return nil, fmt.Errorf("no verified backing proof")
	}
	f, err := openMemory(p.dir)
	if err != nil {
		return nil, err
	}
	if err = p.Check(ctx, f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// memoryHoleReader is private to verified backing checks. Its extent state is
// rebuilt for each check, and the file must remain immutable during that check.
// Only verifyContents' expected-zero, chunks-mode branch may skip these bytes.
type memoryHoleReader struct {
	*io.SectionReader
	seekData    func(int64) (int64, error)
	nextData    int64
	unsupported bool
}

func (r *memoryHoleReader) skipZeroHole(length int64) (bool, error) {
	if r.unsupported {
		return false, nil
	}
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}
	if length <= 0 || offset < 0 || length > r.Size()-offset {
		return false, fmt.Errorf("invalid hole verification range at %d length %d", offset, length)
	}
	end := offset + length
	if r.nextData < end {
		start, err := r.seekData(offset)
		switch {
		case errors.Is(err, unix.ENXIO):
			r.nextData = r.Size()
		case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.ENOSYS):
			r.unsupported = true
			return false, nil
		case err != nil:
			return false, fmt.Errorf("query verified memory extent: %w", err)
		default:
			if start < offset || start >= r.Size() {
				return false, fmt.Errorf("invalid data offset %d at %d", start, offset)
			}
			r.nextData = start
		}
	}
	if r.nextData < end {
		return false, nil
	}
	_, err = r.Seek(length, io.SeekCurrent)
	return err == nil, err
}
