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

package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

const (
	ImageName    = "checkpoint.img"
	ManifestName = "manifest.json"
	// FsArtifactDirName is the subdirectory inside a checkpoint directory
	// that holds a paired writable-layer (runsc fscheckpoint) artifact.
	FsArtifactDirName = "fs"
	maxManifestBytes  = 64 * 1024
)

// DeleteIdentity binds cleanup to one committed checkpoint artifact. Callers
// must obtain these fields from the durable manifest/CheckpointResponse.
type DeleteIdentity struct {
	CheckpointID string
	SourceID     string
	ImageSize    int64
	ImageSHA256  string
}

// CleanupStaging removes checkpoint directories left before the atomic
// publish rename. Committed directories never use this reserved prefix.
func CleanupStaging(root string) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return classifyIOError(fmt.Errorf("scan checkpoint staging directories: %w", err))
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || name == "" || name[0] != '.' || !strings.Contains(name, ".staging-") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			return classifyIOError(fmt.Errorf("remove checkpoint staging directory %q: %w", name, err))
		}
		removed = true
	}
	if removed {
		return classifyIOError(syncPath(root))
	}
	return nil
}

// PublishAt atomically publishes checkpoint.img and manifest.json in a
// caller-owned directory by renaming one fully synced staging directory.
func PublishAt(directory string, source SourceIdentity, build func(string) error) (Fact, error) {
	if build == nil {
		return Fact{}, fmt.Errorf("checkpoint builder is nil: %w", errord.ErrInvalidArgument)
	}
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil || cleaned == string(filepath.Separator) {
		return Fact{}, fmt.Errorf("resolve checkpoint directory: %w", errord.ErrInvalidArgument)
	}
	if existing, inspectErr := InspectAt(cleaned, source.CheckpointID); inspectErr == nil {
		return MatchSource(existing, source)
	}
	parent := filepath.Dir(cleaned)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return Fact{}, classifyIOError(fmt.Errorf("create checkpoint parent: %w", err))
	}
	if _, err := os.Lstat(cleaned); err == nil {
		return Fact{}, fmt.Errorf("checkpoint directory is incomplete: %w", errord.ErrFailedPrecondition)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Fact{}, classifyIOError(err)
	}
	if err := validateSourceIdentity(source.CheckpointID, source); err != nil {
		return Fact{}, err
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(cleaned)+".staging-")
	if err != nil {
		return Fact{}, classifyIOError(err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(staging)
		}
	}()
	stagingImage := filepath.Join(staging, ImageName)
	if err := build(stagingImage); err != nil {
		return Fact{}, err
	}
	imageSize, imageDigest, err := inspectImage(stagingImage)
	if err != nil {
		return Fact{}, err
	}
	manifest := Manifest{Version: manifestVersion, CheckpointID: source.CheckpointID,
		SourceID: source.SourceID, Runtime: source.Runtime, RootfsSHA256: source.RootfsSHA256,
		LeaveRunning: source.LeaveRunning, IncludeFilesystem: source.IncludeFilesystem,
		ImageSHA256: imageDigest, ImageSize: imageSize}
	if source.IncludeFilesystem {
		fsDir := filepath.Join(staging, FsArtifactDirName)
		fsSize, fsDigest, fsErr := inspectFsImage(fsDir)
		if fsErr != nil {
			return Fact{}, fsErr
		}
		manifest.FsImageSize = fsSize
		manifest.FsImageSHA256 = fsDigest
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Fact{}, err
	}
	stagingManifest := filepath.Join(staging, ManifestName)
	if err := os.WriteFile(stagingManifest, append(data, '\n'), 0600); err != nil {
		return Fact{}, classifyIOError(err)
	}
	syncTargets := []string{stagingImage, stagingManifest, staging}
	if source.IncludeFilesystem {
		syncTargets = append(syncTargets, filepath.Join(staging, FsArtifactDirName))
	}
	for _, path := range syncTargets {
		if err := syncPath(path); err != nil {
			return Fact{}, classifyIOError(err)
		}
	}
	if err := os.Rename(staging, cleaned); err != nil {
		if existing, inspectErr := InspectAt(cleaned, source.CheckpointID); inspectErr == nil {
			return MatchSource(existing, source)
		}
		return Fact{}, classifyIOError(fmt.Errorf("publish checkpoint artifact: %w", err))
	}
	cleanup = false
	if err := syncPath(parent); err != nil {
		return Fact{}, classifyIOError(err)
	}
	return InspectAt(cleaned, source.CheckpointID)
}

func InspectAt(directory, checkpointID string) (Fact, error) {
	paths := Paths{Dir: directory, Image: filepath.Join(directory, ImageName), Manifest: filepath.Join(directory, ManifestName)}
	manifest, err := readManifest(paths.Manifest)
	if err != nil {
		return Fact{}, err
	}
	if err := validateManifest(checkpointID, manifest); err != nil {
		return Fact{}, err
	}
	size, digest, err := inspectImage(paths.Image)
	if err != nil || size != manifest.ImageSize || digest != manifest.ImageSHA256 {
		return Fact{}, fmt.Errorf("checkpoint image integrity differs from manifest: %w", errord.ErrFailedPrecondition)
	}
	if manifest.IncludeFilesystem {
		fsSize, fsDigest, fsErr := inspectFsImage(filepath.Join(directory, FsArtifactDirName))
		if fsErr != nil || fsSize != manifest.FsImageSize || fsDigest != manifest.FsImageSHA256 {
			return Fact{}, fmt.Errorf("filesystem checkpoint integrity differs from manifest: %w", errord.ErrFailedPrecondition)
		}
	}
	return Fact{Paths: paths, Manifest: manifest}, nil
}

// DeleteAt removes an exact committed artifact. A missing directory is an
// idempotent success; an incomplete or mismatched artifact is never removed.
func DeleteAt(directory string, expected DeleteIdentity) error {
	if expected.CheckpointID == "" || expected.SourceID == "" || expected.ImageSize <= 0 ||
		len(expected.ImageSHA256) != sha256.Size*2 {
		return fmt.Errorf("checkpoint delete identity is incomplete: %w", errord.ErrInvalidArgument)
	}
	if _, err := hex.DecodeString(expected.ImageSHA256); err != nil {
		return fmt.Errorf("checkpoint delete digest is invalid: %w", errord.ErrInvalidArgument)
	}
	cleaned, err := filepath.Abs(filepath.Clean(directory))
	if err != nil || cleaned == string(filepath.Separator) {
		return fmt.Errorf("resolve checkpoint delete directory: %w", errord.ErrInvalidArgument)
	}
	trash := filepath.Join(filepath.Dir(cleaned), "."+filepath.Base(cleaned)+".deleting-"+expected.ImageSHA256)
	if _, err := os.Lstat(cleaned); errors.Is(err, fs.ErrNotExist) {
		return deleteIsolatedAt(trash, expected)
	} else if err != nil {
		return classifyIOError(fmt.Errorf("inspect checkpoint delete directory: %w", err))
	}
	fact, err := InspectAt(cleaned, expected.CheckpointID)
	if err != nil {
		return err
	}
	if fact.Manifest.SourceID != expected.SourceID || fact.Manifest.ImageSize != expected.ImageSize ||
		!strings.EqualFold(fact.Manifest.ImageSHA256, expected.ImageSHA256) {
		return fmt.Errorf("checkpoint delete identity differs from committed artifact: %w",
			errord.ErrFailedPrecondition)
	}
	parent := filepath.Dir(cleaned)
	if err := os.Rename(cleaned, trash); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return deleteIsolatedAt(trash, expected)
		}
		return classifyIOError(fmt.Errorf("isolate checkpoint artifact for delete: %w", err))
	}
	if err := syncPath(parent); err != nil {
		return classifyIOError(fmt.Errorf("persist checkpoint artifact isolation: %w", err))
	}
	return deleteIsolatedAt(trash, expected)
}

func deleteIsolatedAt(trash string, expected DeleteIdentity) error {
	if _, err := os.Lstat(trash); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return classifyIOError(fmt.Errorf("inspect isolated checkpoint artifact: %w", err))
	}
	fact, err := InspectAt(trash, expected.CheckpointID)
	if err != nil || fact.Manifest.SourceID != expected.SourceID ||
		fact.Manifest.ImageSize != expected.ImageSize ||
		!strings.EqualFold(fact.Manifest.ImageSHA256, expected.ImageSHA256) {
		return fmt.Errorf("isolated checkpoint delete identity differs from committed artifact: %w",
			errord.ErrFailedPrecondition)
	}
	if err := os.RemoveAll(trash); err != nil {
		return classifyIOError(fmt.Errorf("remove checkpoint artifact: %w", err))
	}
	if err := syncPath(filepath.Dir(trash)); err != nil {
		return classifyIOError(fmt.Errorf("persist checkpoint artifact delete: %w", err))
	}
	return nil
}

// MatchSource verifies that a committed artifact belongs to the exact source
// and physical checkpoint mode requested by a replay.
func MatchSource(fact Fact, source SourceIdentity) (Fact, error) {
	if fact.Manifest.sourceIdentity() != source {
		return Fact{}, fmt.Errorf("checkpoint ID already belongs to a different source: %w",
			errord.ErrFailedPrecondition)
	}
	return fact, nil
}

func validateSourceIdentity(checkpointID string, source SourceIdentity) error {
	if source.CheckpointID != checkpointID || source.SourceID == "" || source.Runtime == "" {
		return fmt.Errorf("checkpoint source identity is incomplete: %w", errord.ErrInvalidArgument)
	}
	if len(source.RootfsSHA256) != sha256.Size*2 {
		return fmt.Errorf("checkpoint rootfs digest is invalid: %w", errord.ErrInvalidArgument)
	}
	if _, err := hex.DecodeString(source.RootfsSHA256); err != nil {
		return fmt.Errorf("checkpoint rootfs digest is invalid: %w", errord.ErrInvalidArgument)
	}
	return nil
}

func validateManifest(checkpointID string, manifest Manifest) error {
	if manifest.Version != manifestVersion || manifest.CheckpointID != checkpointID ||
		manifest.SourceID == "" || manifest.Runtime == "" || manifest.ImageSize <= 0 {
		return fmt.Errorf("checkpoint manifest identity is invalid: %w", errord.ErrFailedPrecondition)
	}
	if len(manifest.RootfsSHA256) != sha256.Size*2 || len(manifest.ImageSHA256) != sha256.Size*2 {
		return fmt.Errorf("checkpoint manifest digest is invalid: %w", errord.ErrFailedPrecondition)
	}
	if _, err := hex.DecodeString(manifest.RootfsSHA256); err != nil {
		return fmt.Errorf("checkpoint rootfs digest is invalid: %w", errord.ErrFailedPrecondition)
	}
	if _, err := hex.DecodeString(manifest.ImageSHA256); err != nil {
		return fmt.Errorf("checkpoint image digest is invalid: %w", errord.ErrFailedPrecondition)
	}
	if manifest.IncludeFilesystem {
		if manifest.FsImageSize <= 0 || len(manifest.FsImageSHA256) != sha256.Size*2 {
			return fmt.Errorf("filesystem checkpoint manifest digest is invalid: %w",
				errord.ErrFailedPrecondition)
		}
		if _, err := hex.DecodeString(manifest.FsImageSHA256); err != nil {
			return fmt.Errorf("filesystem checkpoint digest is invalid: %w",
				errord.ErrFailedPrecondition)
		}
	}
	return nil
}

// inspectFsImage hashes the writable-layer artifact directory in a
// deterministic order: sorted regular file names, then their sizes and
// contents. The returned size is the sum of the regular file sizes.
func inspectFsImage(dir string) (int64, string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return 0, "", fmt.Errorf("inspect filesystem checkpoint: %w", errord.ErrFailedPrecondition)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, "", fmt.Errorf("filesystem checkpoint must be a real directory: %w",
			errord.ErrFailedPrecondition)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, "", classifyIOError(fmt.Errorf("scan filesystem checkpoint: %w", err))
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	hash := sha256.New()
	var size int64
	for _, name := range names {
		path := filepath.Join(dir, name)
		entryInfo, err := os.Lstat(path)
		if err != nil || !entryInfo.Mode().IsRegular() {
			return 0, "", fmt.Errorf("filesystem checkpoint entry %q is not a regular file: %w",
				name, errord.ErrFailedPrecondition)
		}
		hash.Write([]byte(name))
		if _, err := hash.Write([]byte(fmt.Sprintf(":%d:", entryInfo.Size()))); err != nil {
			return 0, "", err
		}
		file, err := os.Open(path)
		if err != nil {
			return 0, "", classifyIOError(fmt.Errorf("open filesystem checkpoint entry: %w", err))
		}
		written, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return 0, "", classifyIOError(fmt.Errorf("hash filesystem checkpoint entry: %w", copyErr))
		}
		if closeErr != nil {
			return 0, "", classifyIOError(closeErr)
		}
		if written != entryInfo.Size() {
			return 0, "", fmt.Errorf("filesystem checkpoint entry %q changed while reading: %w",
				name, errord.ErrFailedPrecondition)
		}
		size += written
	}
	if size <= 0 {
		return 0, "", fmt.Errorf("filesystem checkpoint is empty: %w", errord.ErrFailedPrecondition)
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func readManifest(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect checkpoint manifest: %w", errord.ErrFailedPrecondition)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return Manifest{}, fmt.Errorf("checkpoint manifest is not a bounded regular file: %w",
			errord.ErrFailedPrecondition)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, classifyIOError(fmt.Errorf("read checkpoint manifest: %w", err))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode checkpoint manifest: %w", errord.ErrFailedPrecondition)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("checkpoint manifest has trailing data: %w", errord.ErrFailedPrecondition)
	}
	return nil
}

// FsArtifactPath returns the writable-layer artifact directory recorded by
// the committed manifest in directory, or "" when the checkpoint has none.
// It verifies presence only; full content verification happens in InspectAt.
func FsArtifactPath(directory string) (string, error) {
	manifest, err := readManifest(filepath.Join(directory, ManifestName))
	if err != nil {
		return "", err
	}
	if !manifest.IncludeFilesystem {
		return "", nil
	}
	path := filepath.Join(directory, FsArtifactDirName)
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("filesystem checkpoint artifact is missing: %w",
			errord.ErrFailedPrecondition)
	}
	return path, nil
}

func inspectImage(path string) (int64, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, "", fmt.Errorf("inspect checkpoint image: %w", errord.ErrFailedPrecondition)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return 0, "", fmt.Errorf("checkpoint image must be a non-empty regular file: %w",
			errord.ErrFailedPrecondition)
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", classifyIOError(fmt.Errorf("open checkpoint image: %w", err))
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return 0, "", classifyIOError(fmt.Errorf("hash checkpoint image: %w", err))
	}
	if written != info.Size() {
		return 0, "", fmt.Errorf("checkpoint image changed while reading: %w",
			errord.ErrFailedPrecondition)
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func syncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func classifyIOError(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return fmt.Errorf("%v: %w", err, errord.ErrResourceExhausted)
	}
	return err
}
