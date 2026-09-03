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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealV2ArtifactFixture writes a complete, sealed v2 checkpoint directory with
// a 1 MiB memory image and returns its opened artifact view.
func sealV2ArtifactFixture(t *testing.T, dir string) *firecrackerCheckpointArtifact {
	t.Helper()
	sealV2ArtifactFixtureMemSize(t, dir, 1<<20)
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open sealed v2 checkpoint: %v", err)
	}
	return artifact
}

func TestInstantiateCheckpointV2UsesArtifactInPlace(t *testing.T) {
	root := t.TempDir()
	artifact := sealV2ArtifactFixture(t, filepath.Join(root, "gen1"))
	overlayCopy := filepath.Join(root, "storage", "overlay.ext4")
	if err := os.Mkdir(filepath.Dir(overlayCopy), 0700); err != nil {
		t.Fatalf("create storage dir: %v", err)
	}

	files, memorySize, err := instantiateFirecrackerCheckpoint(
		context.Background(),
		artifact,
		&checkpointDigestCache{},
		filepath.Join(root, "gen1"),
		filepath.Join(root, "state"),
		overlayCopy,
	)
	if err != nil {
		t.Fatalf("instantiate v2 checkpoint: %v", err)
	}
	// State and memory are used directly from the caller-owned artifact; only
	// the writable layer is instantiated into sandbox-owned storage.
	if files.State != artifact.Files.State || files.Memory != artifact.Files.Memory {
		t.Fatalf("v2 restore copies components: %+v", files)
	}
	if memorySize != 1<<20 {
		t.Fatalf("memory size %d, want %d", memorySize, 1<<20)
	}
	if _, err := os.Lstat(files.State); err != nil {
		t.Fatalf("artifact state vanished: %v", err)
	}
	overlayContent, err := os.ReadFile(overlayCopy)
	if err != nil {
		t.Fatalf("read instantiated overlay: %v", err)
	}
	artifactOverlay, err := os.ReadFile(artifact.Files.Overlay)
	if err != nil {
		t.Fatalf("read artifact overlay: %v", err)
	}
	if string(overlayContent) != string(artifactOverlay) {
		t.Fatal("instantiated overlay diverged from the artifact")
	}
	// The writable layer is a private copy: mutating it must not leak into the
	// caller-owned checkpoint.
	writeArtifactComponent(t, overlayCopy, 16<<10)
	after, err := os.ReadFile(artifact.Files.Overlay)
	if err != nil {
		t.Fatalf("re-read artifact overlay: %v", err)
	}
	if string(after) != string(artifactOverlay) {
		t.Fatal("writable-layer writes leaked into the checkpoint artifact")
	}
}

func TestInstantiateCheckpointV2RejectsTamperedArtifact(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "gen1")
	artifact := sealV2ArtifactFixture(t, dir)
	writeArtifactComponent(t, artifact.Files.State, 16<<10)

	_, _, err := instantiateFirecrackerCheckpoint(
		context.Background(),
		artifact,
		&checkpointDigestCache{},
		dir,
		filepath.Join(root, "state"),
		filepath.Join(root, "overlay"),
	)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered artifact passed verification: %v", err)
	}
}

func TestInstantiateCheckpointV1ArchiveExtracts(t *testing.T) {
	root := t.TempDir()
	source := firecrackerCheckpointFiles{
		State:   filepath.Join(root, "source-state"),
		Memory:  filepath.Join(root, "source-memory"),
		Overlay: filepath.Join(root, "source-overlay"),
	}
	writeArtifactComponent(t, source.State, 8<<10)
	writeArtifactComponent(t, source.Memory, 1<<20)
	writeArtifactComponent(t, source.Overlay, 32<<10)
	archiveDir := filepath.Join(root, "v1-artifact")
	if err := os.Mkdir(archiveDir, 0700); err != nil {
		t.Fatalf("create v1 artifact dir: %v", err)
	}
	if err := createFirecrackerCheckpointArchive(
		context.Background(), filepath.Join(archiveDir, checkpointImageName), false, source,
	); err != nil {
		t.Fatalf("create v1 archive: %v", err)
	}
	artifact, err := openFirecrackerCheckpoint(archiveDir)
	if err != nil {
		t.Fatalf("open v1 checkpoint: %v", err)
	}

	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	overlayPath := filepath.Join(root, "overlay")
	files, memorySize, err := instantiateFirecrackerCheckpoint(
		context.Background(), artifact, &checkpointDigestCache{}, archiveDir, stateDir, overlayPath,
	)
	if err != nil {
		t.Fatalf("instantiate v1 checkpoint: %v", err)
	}
	if files.State != filepath.Join(stateDir, firecrackerCheckpointStateName) ||
		files.Memory != filepath.Join(stateDir, firecrackerCheckpointMemoryName) {
		t.Fatalf("v1 restore did not extract into the state dir: %+v", files)
	}
	if memorySize != 1<<20 {
		t.Fatalf("memory size %d, want %d", memorySize, 1<<20)
	}
	for _, path := range []string{files.State, files.Memory, overlayPath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("v1 component %s missing after extraction: %v", path, err)
		}
	}
}

func TestInstantiateCheckpointRejectsUnalignedMemory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "gen1")
	sealV2ArtifactFixtureMemSize(t, dir, 64<<10)
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open v2 checkpoint: %v", err)
	}
	_, _, err = instantiateFirecrackerCheckpoint(
		context.Background(),
		artifact,
		&checkpointDigestCache{},
		dir,
		filepath.Join(root, "state"),
		filepath.Join(root, "overlay"),
	)
	if err == nil || !strings.Contains(err.Error(), "not MiB-aligned") {
		t.Fatalf("sub-MiB memory accepted: %v", err)
	}
}

// sealV2ArtifactFixtureMemSize seals a v2 checkpoint whose manifest records an
// arbitrary memory size, for negative validation paths.
func sealV2ArtifactFixtureMemSize(t *testing.T, dir string, memorySize int64) firecrackerCheckpointFiles {
	t.Helper()
	files, err := prepareFirecrackerCheckpointV2(dir, "", memorySize)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	writeArtifactComponent(t, files.State, 8<<10)
	writeArtifactComponent(t, files.Memory, int(memorySize))
	writeArtifactComponent(t, files.Overlay, 32<<10)
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeSoftDirty,
		MemorySize:   memorySize,
	}); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	return files
}
