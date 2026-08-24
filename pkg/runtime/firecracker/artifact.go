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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	firecrackerCheckpointManifestName = "manifest.json"
	firecrackerCheckpointVersion2     = 2
)

// Snapshot types recorded in a v2 manifest; the strings match the Firecracker
// API SnapshotCreateParams values.
const (
	firecrackerSnapshotTypeFull        = "Full"
	firecrackerSnapshotTypeIncremental = "Incremental"
	firecrackerSnapshotTypeSoftDirty   = "SoftDirty"
)

// firecrackerCheckpointManifest describes the contents of a v2 checkpoint
// directory. It is written last so that its presence marks a self-consistent
// artifact: a restore never sees a half-written checkpoint.
type firecrackerCheckpointManifest struct {
	Version      int               `json:"version"`
	SnapshotType string            `json:"snapshot_type"`
	MemorySize   int64             `json:"memory_size"`
	BaseMemory   string            `json:"base_memory,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	Digests      map[string]string `json:"digests"`
}

type firecrackerCheckpointLayout int

const (
	// firecrackerCheckpointLayoutV1Archive is the legacy single-file
	// checkpoint.img tar (optionally gzipped) archive.
	firecrackerCheckpointLayoutV1Archive firecrackerCheckpointLayout = iota + 1
	// firecrackerCheckpointLayoutV2Directory is the uncompressed directory
	// layout whose memory file is a plain file that Firecracker patches in
	// place; the directory holds a manifest.json instead of an archive.
	firecrackerCheckpointLayoutV2Directory
)

// firecrackerCheckpointArtifact is the opened view of a caller-owned
// checkpoint directory, regardless of layout version.
type firecrackerCheckpointArtifact struct {
	Layout firecrackerCheckpointLayout
	// Manifest is set for v2 directories only.
	Manifest *firecrackerCheckpointManifest
	// Files holds the in-directory component paths for v2 directories only.
	Files firecrackerCheckpointFiles
}

// prepareFirecrackerCheckpointV2 lays out a caller-owned directory for a v2
// checkpoint before Firecracker is asked to snapshot into it. The memory file
// is either a reflink clone of the previous generation's memory (which
// Firecracker then patches in place) or, without lineage, a freshly
// preallocated zero file that receives the first dirty window. A directory
// that already holds a complete checkpoint is rejected instead of rewritten.
func prepareFirecrackerCheckpointV2(
	dir, baseMemoryPath string,
	memorySize int64,
) (files firecrackerCheckpointFiles, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return files, fmt.Errorf("create Firecracker checkpoint directory: %w", err)
	}
	manifestErr := checkFirecrackerCheckpointDirVacant(dir)
	if manifestErr != nil {
		return files, manifestErr
	}
	files = firecrackerCheckpointFiles{
		State:   filepath.Join(dir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
	}

	if baseMemoryPath == "" {
		memory, err := os.OpenFile(
			files.Memory,
			os.O_CREATE|os.O_EXCL|os.O_WRONLY,
			0600,
		)
		if err != nil {
			return files, fmt.Errorf("create Firecracker checkpoint memory: %w", err)
		}
		defer func() {
			retErr = errors.Join(retErr, memory.Sync(), memory.Close())
		}()
		// A sparse zero file: reads see zeroes without allocating extents,
		// and the pages the snapshot writes out become the only real
		// disk usage of the first window.
		if err := memory.Truncate(memorySize); err != nil {
			return files, fmt.Errorf("preallocate Firecracker checkpoint memory: %w", err)
		}
		return files, nil
	}

	if _, err := cloneFile(baseMemoryPath, files.Memory); err != nil {
		return files, err
	}
	return files, nil
}

// checkFirecrackerCheckpointDirVacant rejects a directory that already
// contains the manifest of a complete checkpoint. Individual components are
// protected by O_EXCL at creation time instead.
func checkFirecrackerCheckpointDirVacant(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, firecrackerCheckpointManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Firecracker checkpoint directory: %w", err)
	}
	return fmt.Errorf(
		"Firecracker checkpoint directory %s already contains a complete checkpoint",
		dir,
	)
}

// finalizeFirecrackerCheckpointV2 seals a v2 checkpoint after Firecracker has
// written its components: it records the component digests and lands the
// manifest last, fsynced, so the directory becomes self-consistent in one
// step. The manifest is created with O_EXCL; finalizing an already sealed
// directory is an error.
func finalizeFirecrackerCheckpointV2(
	ctx context.Context,
	files firecrackerCheckpointFiles,
	manifest *firecrackerCheckpointManifest,
) (retErr error) {
	manifest.Version = firecrackerCheckpointVersion2
	manifest.CreatedAt = time.Now().UTC()
	manifest.Digests = make(map[string]string, 3)
	for _, component := range firecrackerCheckpointComponents(files) {
		digest, err := digestFirecrackerCheckpointComponent(ctx, component.name, component.path)
		if err != nil {
			return err
		}
		manifest.Digests[component.name] = digest
	}

	manifestPath := filepath.Join(
		filepath.Dir(files.State),
		firecrackerCheckpointManifestName,
	)
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Firecracker checkpoint manifest: %w", err)
	}
	onDisk, err := os.OpenFile(
		manifestPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create Firecracker checkpoint manifest: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, onDisk.Sync(), onDisk.Close())
	}()
	if _, err := onDisk.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write Firecracker checkpoint manifest: %w", err)
	}
	return syncFirecrackerCheckpointDir(filepath.Dir(manifestPath))
}

// openFirecrackerCheckpoint inspects a caller-owned checkpoint directory and
// reports its layout: v1 single-file archives keep working unchanged, v2
// directories must carry a well-formed manifest and all components.
func openFirecrackerCheckpoint(dir string) (*firecrackerCheckpointArtifact, error) {
	imageInfo, err := os.Lstat(filepath.Join(dir, checkpointImageName))
	if err == nil {
		if !imageInfo.Mode().IsRegular() || imageInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("Firecracker checkpoint archive is not a regular file")
		}
		return &firecrackerCheckpointArtifact{
			Layout: firecrackerCheckpointLayoutV1Archive,
		}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Firecracker checkpoint directory: %w", err)
	}

	manifest, err := readFirecrackerCheckpointManifest(dir)
	if err != nil {
		return nil, err
	}
	artifact := &firecrackerCheckpointArtifact{
		Layout:   firecrackerCheckpointLayoutV2Directory,
		Manifest: manifest,
		Files: firecrackerCheckpointFiles{
			State:   filepath.Join(dir, firecrackerCheckpointStateName),
			Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
			Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
		},
	}
	for _, component := range firecrackerCheckpointComponents(artifact.Files) {
		info, err := os.Lstat(component.path)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect Firecracker checkpoint component %s: %w",
				component.name, err,
			)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() <= 0 || info.Size() > firecrackerCheckpointMaxComponent {
			return nil, fmt.Errorf(
				"Firecracker checkpoint component %s is not a bounded regular file",
				component.name,
			)
		}
	}
	memoryInfo, err := os.Lstat(artifact.Files.Memory)
	if err != nil {
		return nil, fmt.Errorf("inspect Firecracker checkpoint memory: %w", err)
	}
	if memoryInfo.Size() != artifact.Manifest.MemorySize {
		return nil, fmt.Errorf(
			"Firecracker checkpoint memory is %d bytes, manifest expects %d",
			memoryInfo.Size(), artifact.Manifest.MemorySize,
		)
	}
	return artifact, nil
}

// readFirecrackerCheckpointManifest parses and validates the manifest of a v2
// checkpoint directory.
func readFirecrackerCheckpointManifest(dir string) (*firecrackerCheckpointManifest, error) {
	path := filepath.Join(dir, firecrackerCheckpointManifestName)
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Firecracker checkpoint manifest: %w", err)
	}
	var manifest firecrackerCheckpointManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return nil, fmt.Errorf("decode Firecracker checkpoint manifest: %w", err)
	}
	if manifest.Version != firecrackerCheckpointVersion2 {
		return nil, fmt.Errorf(
			"unsupported Firecracker checkpoint manifest version %d",
			manifest.Version,
		)
	}
	switch manifest.SnapshotType {
	case firecrackerSnapshotTypeFull,
		firecrackerSnapshotTypeIncremental,
		firecrackerSnapshotTypeSoftDirty:
	default:
		return nil, fmt.Errorf(
			"invalid Firecracker checkpoint snapshot type %q",
			manifest.SnapshotType,
		)
	}
	if manifest.MemorySize <= 0 || manifest.MemorySize > firecrackerCheckpointMaxComponent {
		return nil, fmt.Errorf(
			"Firecracker checkpoint manifest has unbounded memory size %d",
			manifest.MemorySize,
		)
	}
	return &manifest, nil
}

// verifyFirecrackerCheckpointDigests recomputes component digests and compares
// them against the manifest. verifyMemory can be skipped for large memory
// files where a full pass costs seconds per GiB.
func verifyFirecrackerCheckpointDigests(
	ctx context.Context,
	artifact *firecrackerCheckpointArtifact,
	verifyMemory bool,
) error {
	for _, component := range firecrackerCheckpointComponents(artifact.Files) {
		if component.name == firecrackerCheckpointMemoryName && !verifyMemory {
			continue
		}
		digest, err := digestFirecrackerCheckpointComponent(
			ctx,
			component.name,
			component.path,
		)
		if err != nil {
			return err
		}
		if digest != artifact.Manifest.Digests[component.name] {
			return fmt.Errorf(
				"Firecracker checkpoint component %s digest mismatch: manifest %s, on disk %s",
				component.name, artifact.Manifest.Digests[component.name], digest,
			)
		}
	}
	return nil
}

func firecrackerCheckpointComponents(
	files firecrackerCheckpointFiles,
) []struct{ name, path string } {
	return []struct{ name, path string }{
		{name: firecrackerCheckpointStateName, path: files.State},
		{name: firecrackerCheckpointMemoryName, path: files.Memory},
		{name: firecrackerCheckpointOverlayName, path: files.Overlay},
	}
}

func digestFirecrackerCheckpointComponent(
	ctx context.Context,
	name, path string,
) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Firecracker checkpoint component %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > firecrackerCheckpointMaxComponent {
		return "", fmt.Errorf(
			"Firecracker checkpoint component %s is not a bounded regular file",
			name,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Firecracker checkpoint component %s: %w", name, err)
	}
	defer file.Close()
	hash := sha256.New()
	written, err := copyFirecrackerCheckpoint(ctx, hash, file)
	if err != nil {
		return "", fmt.Errorf("digest Firecracker checkpoint component %s: %w", name, err)
	}
	if written != info.Size() {
		return "", fmt.Errorf(
			"Firecracker checkpoint component %s changed while reading",
			name,
		)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func syncFirecrackerCheckpointDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open Firecracker checkpoint directory: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("fsync Firecracker checkpoint directory: %w", err)
	}
	return nil
}
