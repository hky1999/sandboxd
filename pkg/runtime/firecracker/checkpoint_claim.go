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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

const (
	// firecrackerCheckpointClaimVersion is the schema version of
	// firecrackerCheckpointClaim.
	firecrackerCheckpointClaimVersion = 1
	// firecrackerCheckpointClaimMaxBytes bounds one claim read. The claim is a
	// fixed set of short identity strings; anything larger is corruption, and
	// the bound is checked by fstat before a single byte is buffered.
	firecrackerCheckpointClaimMaxBytes = 8 << 10
)

// Narrow test seams over the claim durability calls. Production defaults are
// the plain fsyncs; tests substitute counting wrappers that still perform the
// real sync so the observable ordering — the claim file and the containing
// directory are synced before an acquisition returns success — can be proven
// without time polling. They are plain variables, not exported API.
var (
	firecrackerClaimSyncFile = func(f *os.File) error { return f.Sync() }
	firecrackerClaimSyncDir  = func(f *os.File) error { return f.Sync() }
	// firecrackerClaimDirectoryOpenedHook runs right after the output
	// directory descriptor is opened and fstat'd, before any claim decision:
	// the deterministic injection window for a directory replaced or deleted
	// underneath the acquisition. Nil in production.
	firecrackerClaimDirectoryOpenedHook func(canonical string)
	// firecrackerClaimPostCreateHook runs right after a NEW claim file was
	// created and synced, before the post-create rescan: the deterministic
	// injection window for a concurrent foreign entry landing in the claimed
	// directory. Nil in production.
	firecrackerClaimPostCreateHook func(canonical string)
)

// firecrackerCheckpointClaimName is the fixed claim file name inside the
// caller-owned checkpoint output directory. It deliberately equals
// checkpointroot.ClaimFileName — the shared root derivation excludes exactly
// this name from the logical content root, so the claim is source-directory
// ownership metadata and never artifact content.
func firecrackerCheckpointClaimName() string {
	return checkpointroot.ClaimFileName
}

// firecrackerCheckpointClaim is the persistent exclusive-ownership record of
// one identified checkpoint operation over the caller-owned output directory.
// It binds the exact admission identity — sandbox, operation, request digest,
// source generation — to the directory's canonical path and birth identity
// (filesystem device and inode, the statx stx_dev/stx_ino pair), so a later
// reconciliation can prove the directory still is the one this operation
// claimed, and a competing operation over the same path is refused from the
// binding rather than from timing.
//
// The claim is a tombstone, not a lease: it survives success, abort, and
// acknowledgment, and only an explicit deletion of the whole checkpoint
// directory clears it. It is never part of the manifest or the content root,
// never published, and never required on a restore target.
type firecrackerCheckpointClaim struct {
	Version          int    `json:"version"`
	SandboxID        string `json:"sandbox_id"`
	OperationID      string `json:"operation_id"`
	RequestDigest    string `json:"request_digest"`
	SourceGeneration string `json:"source_generation"`
	Directory        string `json:"directory"`
	DirectoryDev     uint64 `json:"directory_dev"`
	DirectoryInode   uint64 `json:"directory_inode"`
}

// validateFirecrackerCheckpointClaim accepts only a complete, self-consistent
// claim. Unknown versions are rejected, never reinterpreted; the binding
// fields must be nonempty; the digest must be the strict lowercase hex shape
// every operation binding carries; and the directory identity must be a
// canonical absolute non-root path with a complete birth identity.
func validateFirecrackerCheckpointClaim(claim firecrackerCheckpointClaim) error {
	if claim.Version != firecrackerCheckpointClaimVersion {
		return fmt.Errorf(
			"unsupported checkpoint directory claim version %d", claim.Version,
		)
	}
	for _, field := range []struct{ name, value string }{
		{"sandbox id", claim.SandboxID},
		{"operation id", claim.OperationID},
		{"source generation", claim.SourceGeneration},
		{"directory", claim.Directory},
	} {
		if field.value == "" {
			return fmt.Errorf("checkpoint directory claim carries no %s", field.name)
		}
	}
	if len(claim.RequestDigest) != checkpointroot.DigestHexLen {
		return fmt.Errorf(
			"checkpoint directory claim request digest is not %d hex characters",
			checkpointroot.DigestHexLen,
		)
	}
	for i := 0; i < len(claim.RequestDigest); i++ {
		c := claim.RequestDigest[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New(
				"checkpoint directory claim request digest is not lowercase hex",
			)
		}
	}
	if canonical := filepath.Clean(claim.Directory); !filepath.IsAbs(canonical) ||
		canonical != claim.Directory || canonical == string(filepath.Separator) {
		return fmt.Errorf(
			"checkpoint directory claim directory %q is not an absolute non-root canonical path",
			claim.Directory,
		)
	}
	if claim.DirectoryDev == 0 || claim.DirectoryInode == 0 {
		return fmt.Errorf(
			"checkpoint directory claim carries no complete directory identity (dev=%d inode=%d)",
			claim.DirectoryDev, claim.DirectoryInode,
		)
	}
	return nil
}

// openFirecrackerClaimDirFD opens an existing canonical output directory by
// walking every pathname component without following symbolic links. It never
// creates a missing leaf.
func openFirecrackerClaimDirFD(
	canonical string,
) (*os.File, uint64, uint64, error) {
	return openFirecrackerClaimDirAnchored(canonical, false)
}

// openFirecrackerClaimFileAt opens the claim file relative to the open
// directory descriptor without following a symlink. The read flavor adds
// O_NONBLOCK so a FIFO or device left at the claim name cannot block the open
// — the fstat that follows refuses it before any read. perm is the creation
// mode and is ignored unless flags carry O_CREAT.
func openFirecrackerClaimFileAt(dir *os.File, flags int, perm uint32) (*os.File, error) {
	fd, err := unix.Openat(
		int(dir.Fd()), firecrackerCheckpointClaimName(),
		flags|unix.O_CLOEXEC, perm,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), firecrackerCheckpointClaimName()), nil
}

// readFirecrackerCheckpointClaimAt reads and strictly validates the claim of
// the directory an open descriptor anchors: the claim file is opened through
// that descriptor with O_NOFOLLOW, fstat'd as the very same object the bytes
// are then read from — no Lstat/open pair a swap could race — size-bounded
// before a byte is buffered, and decoded under DisallowUnknownFields with no
// trailing content. A claim that fails any of these checks proves nothing
// about ownership; the caller fails closed and never repairs or replaces it.
func readFirecrackerCheckpointClaimAt(
	dir *os.File,
) (firecrackerCheckpointClaim, error) {
	canonical := dir.Name()
	file, err := openFirecrackerClaimFileAt(
		dir, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0,
	)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return firecrackerCheckpointClaim{}, fmt.Errorf(
				"Firecracker checkpoint directory claim in %s is a symbolic link; a link is refused, never resolved: %w",
				canonical, errord.ErrFailedPrecondition,
			)
		}
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"open Firecracker checkpoint directory claim in %s: %w", canonical, err,
		)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"inspect Firecracker checkpoint directory claim in %s: %w", canonical, err,
		)
	}
	if !info.Mode().IsRegular() {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"Firecracker checkpoint directory claim in %s is not a regular file: %w",
			canonical, errord.ErrFailedPrecondition,
		)
	}
	if info.Size() <= 0 || info.Size() > firecrackerCheckpointClaimMaxBytes {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"Firecracker checkpoint directory claim in %s is %d bytes, outside the bounded regular-file shape: %w",
			canonical, info.Size(), errord.ErrFailedPrecondition,
		)
	}
	raw, err := io.ReadAll(io.LimitReader(file, firecrackerCheckpointClaimMaxBytes+1))
	if err != nil {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"read Firecracker checkpoint directory claim in %s: %w", canonical, err,
		)
	}
	if len(raw) > firecrackerCheckpointClaimMaxBytes {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"Firecracker checkpoint directory claim in %s exceeded its size bound while reading: %w",
			canonical, errord.ErrFailedPrecondition,
		)
	}
	return decodeFirecrackerCheckpointClaim(canonical, raw)
}

// decodeFirecrackerCheckpointClaim applies the strict JSON shape: no unknown
// fields, no trailing content, and the complete validated binding.
func decodeFirecrackerCheckpointClaim(
	canonical string, raw []byte,
) (firecrackerCheckpointClaim, error) {
	var claim firecrackerCheckpointClaim
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claim); err != nil {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"decode Firecracker checkpoint directory claim in %s: %w; a partial or malformed claim proves no ownership: %w",
			canonical, err, errord.ErrFailedPrecondition,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"Firecracker checkpoint directory claim in %s carries trailing content: %w",
			canonical, errord.ErrFailedPrecondition,
		)
	}
	if err := validateFirecrackerCheckpointClaim(claim); err != nil {
		return firecrackerCheckpointClaim{}, fmt.Errorf(
			"Firecracker checkpoint directory claim in %s is unusable: %w: %w",
			canonical, err, errord.ErrFailedPrecondition,
		)
	}
	return claim, nil
}

// readFirecrackerCheckpointClaim opens the directory itself with
// O_DIRECTORY|O_NOFOLLOW and reads its claim through that descriptor — the
// path-based form of readFirecrackerCheckpointClaimAt for callers holding
// only the recorded directory path.
func readFirecrackerCheckpointClaim(
	directory string,
) (firecrackerCheckpointClaim, error) {
	dir, _, _, err := openFirecrackerClaimDirFD(filepath.Clean(directory))
	if err != nil {
		return firecrackerCheckpointClaim{}, err
	}
	defer dir.Close()
	return readFirecrackerCheckpointClaimAt(dir)
}

// verifyFirecrackerClaimPathIdentity proves the canonical pathname still
// resolves to the exact directory the acquisition's descriptor was anchored
// to. A directory removed or replaced underneath the acquisition — including
// between the descriptor open and this check — fails closed: the claim the
// acquisition wrote lives in the descriptor's directory, and a different
// object at the pathname must never be reported as claimed.
func verifyFirecrackerClaimPathIdentity(canonical string, dev, inode uint64) error {
	dir, gotDev, gotInode, err := openFirecrackerClaimDirFD(canonical)
	if err != nil {
		return fmt.Errorf(
			"Firecracker checkpoint output %s can no longer be opened through its symlink-free path after claiming it: %w; refusing fail-closed: %w",
			canonical, err, errord.ErrFailedPrecondition,
		)
	}
	dir.Close()
	if gotDev != dev || gotInode != inode {
		return fmt.Errorf(
			"Firecracker checkpoint output %s was replaced while it was being claimed (claimed dev=%d inode=%d, path now carries dev=%d inode=%d); a replaced output directory is never reported as claimed: %w",
			canonical, dev, inode, gotDev, gotInode, errord.ErrFailedPrecondition,
		)
	}
	return nil
}

// openFirecrackerClaimDirAnchored opens the canonical checkpoint output
// directory through a descriptor-anchored walk: starting from a descriptor on
// / itself, EVERY component is opened with openat(2) carrying
// O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, so no step of the acquisition resolves a
// pathname through the kernel's symlink-following lookup. An intermediate
// symbolic link — present from the start or swapped in while the acquisition
// runs — can therefore neither redirect the walk nor receive a created leaf;
// it is refused fail-closed by name. A missing FINAL component is the one
// creation: it is mkdirat(2)'d relative to the walked parent descriptor, and
// that same parent descriptor is fsynced, so the reservation entry is durable
// exactly where it was created — never in a pathname-derived parent a swapped
// intermediate component could point elsewhere. Missing intermediate
// components are refusals (the service contract requires the parent to
// already exist); a racing creator's EEXIST is fine, because the shared open
// and the exclusivity of the claim decide ownership. The returned descriptor
// anchors the leaf, and its own fstat supplies the birth identity the claim
// records. createLeaf controls whether the final component may be created;
// reads and witness verification always pass false.
func openFirecrackerClaimDirAnchored(
	canonical string,
	createLeaf bool,
) (*os.File, uint64, uint64, error) {
	if filepath.Clean(canonical) != canonical || !filepath.IsAbs(canonical) ||
		canonical == string(filepath.Separator) {
		return nil, 0, 0, fmt.Errorf(
			"checkpoint output %q is not an absolute non-root canonical directory path", canonical,
		)
	}
	components := strings.Split(
		strings.TrimPrefix(canonical, string(filepath.Separator)),
		string(filepath.Separator),
	)
	if len(components) == 0 || components[0] == "" {
		return nil, 0, 0, fmt.Errorf(
			"checkpoint output %q is not an absolute non-root canonical directory path", canonical,
		)
	}
	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return nil, 0, 0, fmt.Errorf(
			"open the filesystem root to walk to Firecracker checkpoint output %s: %w", canonical, err,
		)
	}
	parent := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	// fail closes the walked-so-far descriptor and formats the refusal.
	fail := func(format string, args ...any) (*os.File, uint64, uint64, error) {
		parent.Close()
		return nil, 0, 0, fmt.Errorf(format, args...)
	}
	for index, component := range components {
		fd, openErr := unix.Openat(
			int(parent.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if openErr != nil && errors.Is(openErr, unix.ENOENT) &&
			createLeaf && index == len(components)-1 {
			// A fresh leaf is the one creation, relative to the walked
			// parent descriptor.
			if mkErr := unix.Mkdirat(int(parent.Fd()), component, 0700); mkErr != nil &&
				!errors.Is(mkErr, unix.EEXIST) {
				return fail("reserve Firecracker checkpoint output %s: %w", canonical, mkErr)
			}
			// The reservation entry itself must survive a crash for the
			// recorded directory identity to stay meaningful: sync the parent
			// DESCRIPTOR the entry was created in, never a path.
			if syncErr := firecrackerClaimSyncDir(parent); syncErr != nil {
				return fail("sync Firecracker checkpoint output reservation %s: %w", canonical, syncErr)
			}
			fd, openErr = unix.Openat(
				int(parent.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
			)
		}
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				// O_NOFOLLOW on a symlink reports ELOOP, but paired with
				// O_DIRECTORY some filesystems report ENOTDIR instead;
				// classify through a no-follow fstatat relative to the walked
				// parent so the refusal names the actual shape.
				var stat unix.Stat_t
				if statErr := unix.Fstatat(
					int(parent.Fd()), component, &stat, unix.AT_SYMLINK_NOFOLLOW,
				); statErr == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFLNK {
					return fail(
						"Firecracker checkpoint output component %s of %s is a symbolic link; a link is refused, never resolved: %w",
						component, canonical, errord.ErrFailedPrecondition,
					)
				}
				return fail(
					"Firecracker checkpoint output component %s of %s is not a directory: %w",
					component, canonical, errord.ErrFailedPrecondition,
				)
			}
			return fail(
				"open Firecracker checkpoint output component %s of %s: %w",
				component, canonical, openErr,
			)
		}
		opened := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), component))
		parent.Close()
		parent = opened
	}
	info, statErr := parent.Stat()
	if statErr != nil {
		return fail("inspect Firecracker checkpoint output %s: %w", canonical, statErr)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(
			"Firecracker checkpoint output %s carries no unix directory identity", canonical,
		)
	}
	return parent, uint64(stat.Dev), stat.Ino, nil
}

// claimFirecrackerCheckpointDirectory acquires the persistent exclusive claim
// on the caller-owned output directory of an identified operation, replacing
// the weaker emptiness-only reservation. The directory is reached through the
// descriptor-anchored component walk (openFirecrackerClaimDirAnchored) — no
// intermediate symlink is ever resolved, and a missing leaf is created
// relative to the walked parent — and is then opened as that one descriptor,
// to which every claim operation — the pre-scan, the creation, the read, the
// syncs, the post-create rescan — is anchored; the descriptor's fstat
// supplies the birth identity the claim records, and the pathname is
// re-verified against the same identity before success, so a replaced or
// deleted directory fails closed instead of being claimed against a stale
// name. A NEW claim is created at its final component with
// O_CREATE|O_EXCL|O_NOFOLLOW — never a rename over a competitor — written in
// full, fsynced, closed, and the directory fsynced, so the claim is durable
// before the caller persists the runtime intent or runs any layout, guest
// flush, pause, or snapshot side effect.
//
// Exactly one binding owns a directory: a concurrent operation with a
// different binding loses the O_EXCL race and finds a foreign claim, which is
// refused. An existing claim admits only an idempotent re-entry of the SAME
// binding — every field, including the directory birth identity taken from
// the descriptor — so a retried operation continues against its own claim
// while layout components keep their own O_EXCL exclusivity; the re-entry
// re-establishes durability by syncing the already-written claim and the
// directory, never by rewriting or replacing the file, because the previous
// acquisition may have died between its write and an ambiguous final fsync.
// A corrupt, half-written, drifted, or foreign claim fails closed: nothing is
// deleted, repaired, or overwritten, and the operator must reconcile the
// directory explicitly. A new claim is never established in a directory that
// already holds non-claim entries — checked before the creation AND rescanned
// through the descriptor after it, so a foreign entry racing the creation
// leaves the tombstone in place and fails the acquisition. Clearing the
// tombstone requires deleting the whole checkpoint directory.
func claimFirecrackerCheckpointDirectory(
	directory string,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
) (dev, inode uint64, err error) {
	canonical := filepath.Clean(directory)
	if !filepath.IsAbs(canonical) || canonical == "." || canonical == string(filepath.Separator) {
		return 0, 0, fmt.Errorf(
			"checkpoint output %q is not an absolute non-root canonical directory path", directory,
		)
	}
	dir, dev, inode, err := openFirecrackerClaimDirAnchored(canonical, true)
	if err != nil {
		return 0, 0, err
	}
	defer dir.Close()
	if firecrackerClaimDirectoryOpenedHook != nil {
		firecrackerClaimDirectoryOpenedHook(canonical)
	}
	expected := firecrackerCheckpointClaim{
		Version:          firecrackerCheckpointClaimVersion,
		SandboxID:        sandboxID,
		OperationID:      binding.OperationID,
		RequestDigest:    binding.RequestDigest,
		SourceGeneration: binding.SourceGeneration,
		Directory:        canonical,
		DirectoryDev:     dev,
		DirectoryInode:   inode,
	}
	if err := validateFirecrackerCheckpointClaim(expected); err != nil {
		return 0, 0, fmt.Errorf(
			"invalid Firecracker checkpoint directory claim binding for %s: %w: %w",
			canonical, err, errord.ErrInvalidArgument,
		)
	}
	claimed, stray, err := scanFirecrackerClaimEntries(dir, canonical)
	if err != nil {
		return 0, 0, err
	}
	if claimed {
		// Idempotent re-entry only: the existing claim must be the exact
		// binding this call carries, verified against the descriptor's
		// identity. Nothing is written, replaced, or removed.
		if err := reenterFirecrackerCheckpointClaim(dir, canonical, expected); err != nil {
			return 0, 0, err
		}
	} else {
		if stray > 0 {
			return 0, 0, fmt.Errorf(
				"Firecracker checkpoint output %s is not an empty reserved directory (%d non-claim entries); a directory holding artifacts or foreign files is never claimed: %w",
				canonical, stray, errord.ErrFailedPrecondition,
			)
		}
		if err := createFirecrackerCheckpointClaim(dir, canonical, expected); err != nil {
			return 0, 0, err
		}
	}
	// The pathname must still resolve to the exact directory the descriptor
	// anchored to — the last check of the acquisition, after every write.
	if err := verifyFirecrackerClaimPathIdentity(canonical, dev, inode); err != nil {
		return 0, 0, err
	}
	return dev, inode, nil
}

// scanFirecrackerClaimEntries reads the directory through the open descriptor
// and reports whether the claim is present and how many non-claim entries
// exist beside it. The descriptor is a shared cursor, so every scan rewinds
// to the start first; a directory whose entries can no longer be enumerated —
// for example one unlinked while the acquisition holds it — is a fail-closed
// refusal, never a silent empty scan.
func scanFirecrackerClaimEntries(
	dir *os.File, canonical string,
) (claimed bool, stray int, err error) {
	if _, seekErr := dir.Seek(0, 0); seekErr != nil {
		return false, 0, fmt.Errorf(
			"inspect Firecracker checkpoint output %s: %w; refusing fail-closed: %w",
			canonical, seekErr, errord.ErrFailedPrecondition,
		)
	}
	entries, readErr := dir.ReadDir(-1)
	if readErr != nil {
		return false, 0, fmt.Errorf(
			"inspect Firecracker checkpoint output %s: %w; refusing fail-closed: %w",
			canonical, readErr, errord.ErrFailedPrecondition,
		)
	}
	for _, entry := range entries {
		if entry.Name() == firecrackerCheckpointClaimName() {
			claimed = true
			continue
		}
		stray++
	}
	return claimed, stray, nil
}

// createFirecrackerCheckpointClaim creates a NEW claim through the open
// directory descriptor with O_CREATE|O_EXCL|O_NOFOLLOW, writes the complete
// record, fsyncs the file, closes it, fsyncs the directory, and then rescans
// the directory: a foreign entry that raced the creation is never silently
// adopted — the acquisition fails closed and the claim stays as the
// directory's tombstone. A crash before the fsyncs can leave a partial claim,
// and that shape fails closed on every later read.
func createFirecrackerCheckpointClaim(
	dir *os.File,
	canonical string,
	expected firecrackerCheckpointClaim,
) error {
	encoded, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf(
			"encode Firecracker checkpoint directory claim for %s: %w", canonical, err,
		)
	}
	if len(encoded) > firecrackerCheckpointClaimMaxBytes {
		return fmt.Errorf(
			"Firecracker checkpoint directory claim for %s exceeds its size bound", canonical,
		)
	}
	file, err := openFirecrackerClaimFileAt(
		dir, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0600,
	)
	if err != nil {
		if os.IsExist(err) {
			// A concurrent claimant won the empty directory; only the exact
			// same binding may re-enter it.
			return reenterFirecrackerCheckpointClaim(dir, canonical, expected)
		}
		return fmt.Errorf(
			"claim Firecracker checkpoint output %s: %w", canonical, err,
		)
	}
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = fmt.Errorf(
			"short write: %d of %d bytes", written, len(encoded),
		)
	}
	if writeErr == nil {
		writeErr = firecrackerClaimSyncFile(file)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf(
			"write Firecracker checkpoint directory claim for %s: %w", canonical, writeErr,
		)
	}
	if closeErr != nil {
		return fmt.Errorf(
			"close Firecracker checkpoint directory claim for %s: %w", canonical, closeErr,
		)
	}
	if firecrackerClaimPostCreateHook != nil {
		firecrackerClaimPostCreateHook(canonical)
	}
	// The creation is durable; prove no foreign entry raced it. The claim
	// itself stays as the tombstone either way.
	if _, stray, rescanErr := scanFirecrackerClaimEntries(dir, canonical); rescanErr != nil {
		return rescanErr
	} else if stray > 0 {
		return fmt.Errorf(
			"Firecracker checkpoint output %s gained %d non-claim entries while it was being claimed; the claim tombstone is left in place and the directory must be reconciled explicitly: %w",
			canonical, stray, errord.ErrFailedPrecondition,
		)
	}
	if err := firecrackerClaimSyncDir(dir); err != nil {
		return fmt.Errorf(
			"sync Firecracker checkpoint output %s after claiming it: %w", canonical, err,
		)
	}
	return nil
}

// reenterFirecrackerCheckpointClaim validates an already-present claim for
// idempotent re-entry: it must read strictly and equal the expected binding
// field for field, directory birth identity included. Anything else — a
// foreign operation, a different sandbox, a drifted field, a corrupt or
// half-written record — is refused fail-closed without touching the file. An
// exact match then re-establishes durability by syncing the claim file and
// the directory as they are: the previous acquisition may have died after its
// write but before an ambiguous final fsync, and the re-entry must not report
// success on durability it has not itself established. The file is never
// rewritten, replaced, or removed.
func reenterFirecrackerCheckpointClaim(
	dir *os.File,
	canonical string,
	expected firecrackerCheckpointClaim,
) error {
	claim, err := readFirecrackerCheckpointClaimAt(dir)
	if err != nil {
		return fmt.Errorf(
			"Firecracker checkpoint output %s already holds a claim that cannot be verified: %w; refusing fail-closed and leaving the directory untouched",
			canonical, err,
		)
	}
	if claim != expected {
		return fmt.Errorf(
			"Firecracker checkpoint output %s is already claimed by sandbox %s operation %s (request %s, generation %s, dev=%d inode=%d); a different binding never re-enters it: %w",
			canonical, claim.SandboxID, claim.OperationID, claim.RequestDigest,
			claim.SourceGeneration, claim.DirectoryDev, claim.DirectoryInode,
			errord.ErrFailedPrecondition,
		)
	}
	syncFile, err := openFirecrackerClaimFileAt(dir, unix.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf(
			"sync Firecracker checkpoint directory claim in %s: %w; the binding matches but its durability cannot be re-established",
			canonical, err,
		)
	}
	syncErr := firecrackerClaimSyncFile(syncFile)
	closeErr := syncFile.Close()
	if syncErr != nil {
		return fmt.Errorf(
			"sync Firecracker checkpoint directory claim in %s: %w", canonical, syncErr,
		)
	}
	if closeErr != nil {
		return fmt.Errorf(
			"close Firecracker checkpoint directory claim in %s: %w", canonical, closeErr,
		)
	}
	if err := firecrackerClaimSyncDir(dir); err != nil {
		return fmt.Errorf(
			"sync Firecracker checkpoint output %s on re-entry: %w", canonical, err,
		)
	}
	return nil
}

// verifyFirecrackerCheckpointDirectoryClaim proves a version-3 (or later)
// witness record still describes the exact claim it was admitted under. The
// recorded directory is opened with O_DIRECTORY|O_NOFOLLOW and fstat'd — the
// descriptor's birth identity must equal the record's before anything is
// read — and the claim read through that descriptor must bind the same
// sandbox, operation, request digest, source generation, canonical directory,
// and directory birth identity. Version-1/2 records predate the claim
// protocol and verify nothing here — their recovery, abort, and
// acknowledgment paths keep their original directory semantics unchanged. A
// missing, corrupt, or drifted claim fails closed: the reconciliation never
// deletes, repairs, or overwrites the file.
func verifyFirecrackerCheckpointDirectoryClaim(
	sandboxID string,
	record firecrackerCheckpointOperationRecord,
) error {
	if record.Version < firecrackerCheckpointOperationRecordVersion3 {
		return nil
	}
	canonical := filepath.Clean(record.Directory)
	dir, dev, inode, err := openFirecrackerClaimDirFD(canonical)
	if err != nil {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s whose ownership claim cannot be verified: %w; refusing to reconcile the claim-bound record: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
	defer dir.Close()
	if dev != record.DirectoryDev || inode != record.DirectoryInode {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s (dev=%d inode=%d) but it now carries (dev=%d inode=%d); a replaced output directory is never reconciled: %w",
			record.OperationID, sandboxID, record.Directory, record.DirectoryDev,
			record.DirectoryInode, dev, inode, errord.ErrFailedPrecondition,
		)
	}
	claim, err := readFirecrackerCheckpointClaimAt(dir)
	if err != nil {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s whose ownership claim cannot be verified: %w; refusing to reconcile the claim-bound record: %w",
			record.OperationID, sandboxID, record.Directory, err, errord.ErrFailedPrecondition,
		)
	}
	if claim.SandboxID != sandboxID ||
		claim.OperationID != record.OperationID ||
		claim.RequestDigest != record.RequestDigest ||
		claim.SourceGeneration != record.SourceGeneration ||
		claim.Directory != record.Directory ||
		claim.DirectoryDev != record.DirectoryDev ||
		claim.DirectoryInode != record.DirectoryInode {
		return fmt.Errorf(
			"checkpoint operation %s of Firecracker sandbox %s records directory %s (dev=%d inode=%d) that is now claimed by sandbox %s operation %s (request %s, generation %s, dev=%d inode=%d); a claim that no longer binds this exact operation is never reconciled: %w",
			record.OperationID, sandboxID, record.Directory, record.DirectoryDev,
			record.DirectoryInode, claim.SandboxID, claim.OperationID,
			claim.RequestDigest, claim.SourceGeneration, claim.DirectoryDev,
			claim.DirectoryInode, errord.ErrFailedPrecondition,
		)
	}
	return nil
}
