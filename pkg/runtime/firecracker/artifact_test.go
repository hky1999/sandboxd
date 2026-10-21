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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
)

func writeArtifactComponent(t *testing.T, path string, size int) {
	t.Helper()
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write artifact component %s: %v", path, err)
	}
}

func sealArtifactFixture(t *testing.T, dir string) firecrackerCheckpointFiles {
	t.Helper()
	files, err := prepareFirecrackerCheckpointV2(dir, "", 64<<10)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	writeArtifactComponent(t, files.State, 8<<10)
	writeArtifactComponent(t, files.Overlay, 32<<10)
	return files
}

func TestPrepareCheckpointV2PreallocatesZeroMemory(t *testing.T) {
	dir := t.TempDir()
	files, err := prepareFirecrackerCheckpointV2(dir, "", 128<<10)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	info, err := os.Lstat(files.Memory)
	if err != nil {
		t.Fatalf("stat prepared memory: %v", err)
	}
	if info.Size() != 128<<10 {
		t.Fatalf("prepared memory is %d bytes, want %d", info.Size(), 128<<10)
	}
	content, err := os.ReadFile(files.Memory)
	if err != nil {
		t.Fatalf("read prepared memory: %v", err)
	}
	for _, b := range content {
		if b != 0 {
			t.Fatal("prepared memory is not zero-filled")
		}
	}
}

func TestPrepareCheckpointV2FullDiscoversMemorySize(t *testing.T) {
	dir := t.TempDir()
	// Full snapshots pass no size: Firecracker writes the memory file itself
	// and the manifest learns the size from disk.
	files, err := prepareFirecrackerCheckpointV2(dir, "", 0)
	if err != nil {
		t.Fatalf("prepare v2 full checkpoint: %v", err)
	}
	if _, err := os.Lstat(files.Memory); !os.IsNotExist(err) {
		t.Fatalf("full layout preallocated memory: %v", err)
	}
	writeArtifactComponent(t, files.State, 4<<10)
	writeArtifactComponent(t, files.Memory, 96<<10)
	writeArtifactComponent(t, files.Overlay, 32<<10)
	manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatalf("finalize v2 full checkpoint: %v", err)
	}
	if manifest.MemorySize != 96<<10 {
		t.Fatalf("manifest memory size %d, want %d", manifest.MemorySize, 96<<10)
	}
	if _, err := openFirecrackerCheckpoint(dir); err != nil {
		t.Fatalf("open sealed full checkpoint: %v", err)
	}
}

func TestPrepareCheckpointV2ClonesBaseMemory(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base-memory")
	writeArtifactComponent(t, base, 64<<10)

	files, err := prepareFirecrackerCheckpointV2(filepath.Join(dir, "gen1"), base, 64<<10)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint with base: %v", err)
	}
	baseContent, err := os.ReadFile(base)
	if err != nil {
		t.Fatalf("read base memory: %v", err)
	}
	cloneContent, err := os.ReadFile(files.Memory)
	if err != nil {
		t.Fatalf("read cloned memory: %v", err)
	}
	if string(baseContent) != string(cloneContent) {
		t.Fatal("cloned memory diverged from base")
	}
}

func TestPrepareCheckpointV2RejectsSealedDirectory(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeSoftDirty,
			MemorySize:   64 << 10,
		},
	); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}

	if _, err := prepareFirecrackerCheckpointV2(dir, "", 64<<10); err == nil {
		t.Fatal("prepare v2 checkpoint into a sealed directory succeeded")
	}
}

func TestPrepareCheckpointV2RejectsV1ArchiveDirectory(t *testing.T) {
	dir := t.TempDir()
	writeArtifactComponent(t, filepath.Join(dir, checkpointImageName), 4096)
	if _, err := prepareFirecrackerCheckpointV2(dir, "", 64<<10); err == nil {
		t.Fatal("prepare v2 checkpoint over a legacy archive succeeded")
	}
}

func TestFinalizeCheckpointV2ManifestIsSealedOnce(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeSoftDirty,
		MemorySize:   64 << 10,
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	if manifest.Version != firecrackerCheckpointVersion2 {
		t.Fatalf("manifest version %d, want %d",
			manifest.Version, firecrackerCheckpointVersion2)
	}
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeSoftDirty,
			MemorySize:   64 << 10,
		},
	); err == nil {
		t.Fatal("finalize v2 checkpoint over an existing manifest succeeded")
	}
}

func TestOpenCheckpointSniffsLayouts(t *testing.T) {
	dir := t.TempDir()

	if _, err := openFirecrackerCheckpoint(dir); err == nil {
		t.Fatal("opened an empty checkpoint directory")
	}

	archiveDir := filepath.Join(dir, "v1")
	if err := os.MkdirAll(archiveDir, 0700); err != nil {
		t.Fatalf("create v1 dir: %v", err)
	}
	writeArtifactComponent(t, filepath.Join(archiveDir, checkpointImageName), 4096)
	artifact, err := openFirecrackerCheckpoint(archiveDir)
	if err != nil {
		t.Fatalf("open v1 checkpoint: %v", err)
	}
	if artifact.Layout != firecrackerCheckpointLayoutV1Archive {
		t.Fatalf("layout %v, want v1 archive", artifact.Layout)
	}
	if artifact.Manifest != nil {
		t.Fatal("v1 artifact carries a manifest")
	}
}

func TestOpenCheckpointV2AndVerifyDigests(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeIncremental,
			MemorySize:   64 << 10,
			BaseMemory:   "gen0/memory",
		},
	); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}

	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open v2 checkpoint: %v", err)
	}
	if artifact.Layout != firecrackerCheckpointLayoutV2Directory {
		t.Fatalf("layout %v, want v2 directory", artifact.Layout)
	}
	if artifact.Manifest.BaseMemory != "gen0/memory" {
		t.Fatalf("base memory lineage %q lost", artifact.Manifest.BaseMemory)
	}
	if err := verifyArtifactDigests(context.Background(), artifact); err != nil {
		t.Fatalf("verify untouched artifact digests: %v", err)
	}
	if artifact.Manifest.Digests[firecrackerCheckpointMemoryName] == "" {
		t.Fatal("memory lacks the portable content proof")
	}
	if artifact.Manifest.Digests[firecrackerCheckpointOverlayName] == "" {
		t.Fatal("overlay lacks the portable content proof")
	}

	// Every payload is covered, even a same-size change to memory or overlay.
	for _, component := range firecrackerCheckpointComponents(artifact.Files) {
		original, err := os.ReadFile(component.path)
		if err != nil {
			t.Fatal(err)
		}
		changed := append([]byte(nil), original...)
		changed[0] ^= 1
		if err := os.WriteFile(component.path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyArtifactDigests(context.Background(), artifact); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("tampered %s not detected: %v", component.name, err)
		}
		if err := os.WriteFile(component.path, original, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// verifyArtifactDigests runs the digest verification through a fresh cache,
// mirroring the restore path.
func verifyArtifactDigests(
	ctx context.Context, artifact *firecrackerCheckpointArtifact,
) error {
	var cache checkpointDigestCache
	return cache.verifyFirecrackerCheckpointDigests(ctx, artifact)
}

func TestVerifyCheckpointDigestsMemoized(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeIncremental,
			MemorySize:   64 << 10,
		},
	); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open v2 checkpoint: %v", err)
	}

	var cache checkpointDigestCache
	for i := 0; i < 3; i++ {
		if err := cache.verifyFirecrackerCheckpointDigests(
			context.Background(), artifact,
		); err != nil {
			t.Fatalf("verify artifact digests (round %d): %v", i, err)
		}
	}
	// Every recorded component is hashed once; later rounds hit the cache.
	components := len(firecrackerCheckpointComponents(artifact.Files))
	if cache.hashes != components {
		t.Fatalf("component hashes = %d, want %d", cache.hashes, components)
	}

	// A same-stat rewrite is invisible by design (documented tradeoff), but
	// a content change that moves the mtime must re-hash and fail. The sleep
	// clears the filesystem's timestamp granularity.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(artifact.Files.State, make([]byte, 8<<10), 0600); err != nil {
		t.Fatalf("rewrite artifact state: %v", err)
	}
	if err := cache.verifyFirecrackerCheckpointDigests(
		context.Background(), artifact,
	); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("stale cache entry survived an mtime change: %v", err)
	}
	if cache.hashes != components+1 {
		t.Fatalf("component hashes after invalidation = %d, want %d", cache.hashes, components+1)
	}
}

func TestOpenCheckpointV2RejectsBadManifests(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
	}{
		{
			name:     "wrong version",
			manifest: `{"version":1,"snapshot_type":"Full","memory_size":1024}`,
		},
		{
			name:     "unknown snapshot type",
			manifest: `{"version":2,"snapshot_type":"Lazy","memory_size":1024}`,
		},
		{
			name:     "unbounded memory size",
			manifest: `{"version":2,"snapshot_type":"Full","memory_size":0}`,
		},
		{
			name:     "malformed json",
			manifest: `{`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(
				filepath.Join(dir, firecrackerCheckpointManifestName),
				[]byte(tc.manifest), 0600,
			); err != nil {
				t.Fatalf("write manifest fixture: %v", err)
			}
			if _, err := openFirecrackerCheckpoint(dir); err == nil {
				t.Fatal("opened a checkpoint directory with an invalid manifest")
			}
		})
	}
}

func TestOpenCheckpointV2RejectsMissingComponent(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeSoftDirty,
			MemorySize:   64 << 10,
		},
	); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	if err := os.Remove(files.State); err != nil {
		t.Fatalf("remove vmstate component: %v", err)
	}
	if _, err := openFirecrackerCheckpoint(dir); err == nil {
		t.Fatal("opened a v2 checkpoint with a missing component")
	}
}

func TestFinalizeCheckpointV2CoversLargeComponentDigests(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   64 << 10,
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	if manifest.Digests[firecrackerCheckpointOverlayName] == "" {
		t.Fatal("Full generation lacks the overlay content digest")
	}
	if manifest.Digests[firecrackerCheckpointMemoryName] == "" {
		t.Fatal("Full generation lacks the guest memory content digest")
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointStateName]; !recorded {
		t.Fatal("Full generation lost the vmstate digest")
	}
	// New full generations satisfy both the legacy and identified consumers.
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open Full v2 checkpoint: %v", err)
	}
	var cache checkpointDigestCache
	if err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
		t.Fatalf("verify Full artifact digests: %v", err)
	}
	if _, err := checkpointroot.Bind(dir); err != nil {
		t.Fatalf("new Full checkpoint is not content-bound: %v", err)
	}

	// An explicit historical fixture keeps the old unpinned local behavior.
	// It must not be mistaken for an admissible identified restore artifact.
	delete(manifest.Digests, firecrackerCheckpointMemoryName)
	delete(manifest.Digests, firecrackerCheckpointOverlayName)
	legacy, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, firecrackerCheckpointManifestName), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open historical unpinned fixture: %v", err)
	}
	if err := verifyArtifactDigests(context.Background(), old); err != nil {
		t.Fatalf("legacy digest compatibility: %v", err)
	}
	if _, err := checkpointroot.Bind(dir); !errors.Is(err, checkpointroot.ErrUnverifiable) {
		t.Fatalf("historical fixture without proof became an admissible restore: %v", err)
	}
}

func TestCheckpointV2CarriesVirtioFSState(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	files.VirtioFSState = filepath.Join(dir, firecrackerCheckpointVirtioFSName)
	writeArtifactComponent(t, files.VirtioFSState, 4<<10)
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeSoftDirty,
		MemorySize:   64 << 10,
		VirtioFS:     true,
	}
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		manifest,
	); err != nil {
		t.Fatalf("finalize virtio-fs checkpoint: %v", err)
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointVirtioFSName]; !recorded {
		t.Fatal("virtio-fs state digest was not recorded")
	}
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open virtio-fs checkpoint: %v", err)
	}
	if !artifact.Manifest.VirtioFS || artifact.Files.VirtioFSState != files.VirtioFSState {
		t.Fatalf("virtio-fs artifact = %+v", artifact)
	}
	var cache checkpointDigestCache
	if err := cache.verifyFirecrackerCheckpointDigests(
		context.Background(),
		artifact,
	); err != nil {
		t.Fatalf("verify virtio-fs checkpoint: %v", err)
	}
	if err := os.WriteFile(files.VirtioFSState, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cache.verifyFirecrackerCheckpointDigests(
		context.Background(),
		artifact,
	); err == nil {
		t.Fatal("accepted changed virtio-fs state")
	}
}

func TestFinalizeCheckpointV2RejectsVirtioFSMismatch(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	if err := finalizeFirecrackerCheckpointV2(
		context.Background(),
		files,
		&firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeFull,
			MemorySize:   64 << 10,
			VirtioFS:     true,
		},
	); err == nil {
		t.Fatal("sealed a virtio-fs manifest without device state")
	}
}

// Phase69 tests use only private dependency parameters and task-local temporary
// files. No daemon, mount, VM, cgroup, or mutable global test hook is required.
func phase69Files(t *testing.T, virtioFS bool) firecrackerCheckpointFiles {
	t.Helper()
	files := sealArtifactFixture(t, t.TempDir())
	if virtioFS {
		files.VirtioFSState = filepath.Join(filepath.Dir(files.State), firecrackerCheckpointVirtioFSName)
		writeArtifactComponent(t, files.VirtioFSState, 4<<10)
	}
	return files
}

func phase69Artifact(t *testing.T, virtioFS bool) *firecrackerCheckpointArtifact {
	t.Helper()
	files := phase69Files(t, virtioFS)
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   64 << 10,
		VirtioFS:     virtioFS,
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
		t.Fatal(err)
	}
	artifact, err := openFirecrackerCheckpoint(filepath.Dir(files.State))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func phase69Receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("Phase69 worker failed to join before test deadline")
		var zero T
		return zero
	}
}

func TestPhase69SealMatchesOriginalDigester(t *testing.T) {
	for _, virtioFS := range []bool{false, true} {
		t.Run(fmt.Sprintf("virtiofs=%t", virtioFS), func(t *testing.T) {
			files := phase69Files(t, virtioFS)
			expected := make(map[string]string)
			for _, component := range firecrackerCheckpointComponents(files) {
				digest, err := digestFirecrackerCheckpointComponent(context.Background(), component.name, component.path)
				if err != nil {
					t.Fatal(err)
				}
				expected[component.name] = digest
			}
			manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull, VirtioFS: virtioFS}
			if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Digests) != len(expected) || manifest.MemorySize != 64<<10 {
				t.Fatalf("manifest changed: %#v", manifest)
			}
			for name, digest := range expected {
				if manifest.Digests[name] != digest {
					t.Fatalf("digest %s changed", name)
				}
			}
			if err := verifyArtifactDigests(context.Background(), &firecrackerCheckpointArtifact{Layout: firecrackerCheckpointLayoutV2Directory, Files: files, Manifest: manifest}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPhase69EachComponentDamageRejected(t *testing.T) {
	for _, virtioFS := range []bool{false, true} {
		components := firecrackerCheckpointComponents(phase69Files(t, virtioFS))
		for index, original := range components {
			for _, damage := range []string{"tamper", "missing", "symlink", "truncate"} {
				t.Run(fmt.Sprintf("%t/%s/%s", virtioFS, original.name, damage), func(t *testing.T) {
					artifact := phase69Artifact(t, virtioFS)
					component := firecrackerCheckpointComponents(artifact.Files)[index]
					switch damage {
					case "tamper":
						body, err := os.ReadFile(component.path)
						if err != nil {
							t.Fatal(err)
						}
						body[len(body)/2] ^= 0xff
						if err := os.WriteFile(component.path, body, 0600); err != nil {
							t.Fatal(err)
						}
					case "missing":
						if err := os.Remove(component.path); err != nil {
							t.Fatal(err)
						}
					case "symlink":
						target := component.path + ".payload"
						if err := os.Rename(component.path, target); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(target, component.path); err != nil {
							t.Fatal(err)
						}
					case "truncate":
						if err := os.Truncate(component.path, 0); err != nil {
							t.Fatal(err)
						}
					}
					err := verifyArtifactDigests(context.Background(), artifact)
					if err == nil || !strings.Contains(err.Error(), component.name) {
						t.Fatalf("damage accepted or wrong component: %v", err)
					}
				})
			}
		}
	}
}

func TestPhase69SealReadErrorsNeverPublishManifest(t *testing.T) {
	sentinel := errors.New("injected component read failure")
	for _, virtioFS := range []bool{false, true} {
		components := firecrackerCheckpointComponents(phase69Files(t, virtioFS))
		for _, target := range components {
			t.Run(fmt.Sprintf("%t/%s", virtioFS, target.name), func(t *testing.T) {
				files := phase69Files(t, virtioFS)
				var finished atomic.Int32
				digester := func(ctx context.Context, name, path string) (string, error) {
					defer finished.Add(1)
					if name == target.name {
						return "", sentinel
					}
					return digestFirecrackerCheckpointComponent(ctx, name, path)
				}
				manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull, VirtioFS: virtioFS}
				err := finalizeFirecrackerCheckpointV2WithDigester(context.Background(), files, manifest, digester)
				if !errors.Is(err, sentinel) {
					t.Fatalf("original error lost: %v", err)
				}
				if int(finished.Load()) != len(components) {
					t.Fatal("returned before joining every component")
				}
				if _, err := os.Lstat(filepath.Join(filepath.Dir(files.State), firecrackerCheckpointManifestName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed seal published manifest: %v", err)
				}
			})
		}
	}
}

func TestPhase69VerifyReadErrorAndMismatchPrefix(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch=%t", mismatch), func(t *testing.T) {
			artifact := phase69Artifact(t, false)
			components := firecrackerCheckpointComponents(artifact.Files)
			cache := &checkpointDigestCache{}
			sentinel := errors.New("injected verify read failure")
			var called atomic.Int32
			digester := func(ctx context.Context, name, path string) (string, error) {
				called.Add(1)
				if name == components[1].name {
					if mismatch {
						return "actual-but-not-manifest", nil
					}
					return "", sentinel
				}
				return digestFirecrackerCheckpointComponent(ctx, name, path)
			}
			err := cache.verifyFirecrackerCheckpointDigestsWithDigester(context.Background(), artifact, digester)
			if mismatch {
				if err == nil || !strings.Contains(err.Error(), components[1].name+" digest mismatch:") {
					t.Fatalf("mismatch error changed: %v", err)
				}
			} else if !errors.Is(err, sentinel) {
				t.Fatalf("read error lost: %v", err)
			}
			want := 1
			if mismatch {
				want = 2
			}
			if cache.hashes != want || len(cache.entries) != want {
				t.Fatalf("legacy prefix cache changed: hashes=%d entries=%d", cache.hashes, len(cache.entries))
			}
			if _, exists := cache.entries[components[2].path]; exists {
				t.Fatal("later speculative digest committed")
			}
			if called.Load() != int32(len(components)) {
				t.Fatal("cold workers not joined")
			}
			if mismatch {
				before := called.Load()
				if err := cache.verifyFirecrackerCheckpointDigestsWithDigester(context.Background(), artifact, digester); err == nil {
					t.Fatal("cached bad digest was accepted")
				}
				if cache.hashes != 2 || called.Load() != before {
					t.Fatal("mismatching digest did not remain memoized")
				}
			}
		})
	}
}

func TestPhase69CapacityRolloverUsesLegacyOrder(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch=%t", mismatch), func(t *testing.T) {
			artifact := phase69Artifact(t, false)
			components := firecrackerCheckpointComponents(artifact.Files)
			cache := &checkpointDigestCache{entries: make(map[string]cachedCheckpointDigest)}
			for i := 0; i < checkpointDigestCacheMaxEntries-1; i++ {
				cache.entries[fmt.Sprintf("old/%d", i)] = cachedCheckpointDigest{}
			}
			if mismatch {
				artifact.Manifest.Digests[components[1].name] = "different"
			}
			err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact)
			if mismatch && err == nil {
				t.Fatal("expected mismatch")
			}
			if !mismatch && err != nil {
				t.Fatal(err)
			}
			wantHashes, wantEntries := 3, 2
			if mismatch {
				wantHashes, wantEntries = 2, 1
			}
			if cache.hashes != wantHashes || len(cache.entries) != wantEntries {
				t.Fatalf("rollover changed: hashes=%d entries=%d", cache.hashes, len(cache.entries))
			}
			if _, exists := cache.entries[components[0].path]; exists {
				t.Fatal("pre-clear component unexpectedly retained")
			}
			if _, exists := cache.entries[components[1].path]; !exists {
				t.Fatal("post-clear component missing")
			}
		})
	}
}

func TestPhase69ConcurrentWarmCacheAndMtimeInvalidation(t *testing.T) {
	artifact := phase69Artifact(t, true)
	cache := &checkpointDigestCache{}
	var reads atomic.Int32
	digester := func(ctx context.Context, name, path string) (string, error) {
		reads.Add(1)
		return digestFirecrackerCheckpointComponent(ctx, name, path)
	}
	results := make(chan error, 8)
	for i := 0; i < cap(results); i++ {
		go func() {
			results <- cache.verifyFirecrackerCheckpointDigestsWithDigester(context.Background(), artifact, digester)
		}()
	}
	for i := 0; i < cap(results); i++ {
		if err := phase69Receive(t, results); err != nil {
			t.Fatal(err)
		}
	}
	count := len(firecrackerCheckpointComponents(artifact.Files))
	if reads.Load() != int32(count) || cache.hashes != count {
		t.Fatalf("cache miss duplicated: reads=%d remembered=%d", reads.Load(), cache.hashes)
	}
	info, err := os.Stat(artifact.Files.State)
	if err != nil {
		t.Fatal(err)
	}
	later := info.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(artifact.Files.State, later, later); err != nil {
		t.Fatal(err)
	}
	if err := cache.verifyFirecrackerCheckpointDigestsWithDigester(context.Background(), artifact, digester); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != int32(count+1) || cache.hashes != count+1 {
		t.Fatal("mtime invalidation changed")
	}
}

func TestPhase69SharedBudgetAcrossConcurrentSealAndVerify(t *testing.T) {
	if cap(firecrackerCheckpointDigestSlots) != 2 || len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatal("unexpected shared budget")
	}
	artifact := phase69Artifact(t, true)
	files := phase69Files(t, false)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	entered := make(chan struct{}, 16)
	var active, maximum atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	digester := func(ctx context.Context, name, path string) (string, error) {
		now := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); now > old && !maximum.CompareAndSwap(old, now); old = maximum.Load() {
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		return digestFirecrackerCheckpointComponent(ctx, name, path)
	}
	done := make(chan error, 2)
	go func() {
		done <- finalizeFirecrackerCheckpointV2WithDigester(ctx, files, &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}, digester)
	}()
	go func() {
		done <- (&checkpointDigestCache{}).verifyFirecrackerCheckpointDigestsWithDigester(ctx, artifact, digester)
	}()
	phase69Receive(t, entered)
	phase69Receive(t, entered)
	if active.Load() != 2 || len(firecrackerCheckpointDigestSlots) != 2 {
		t.Fatal("budget not held before I/O")
	}
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < 2; i++ {
		if err := phase69Receive(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if maximum.Load() != 2 || active.Load() != 0 || len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatalf("budget/worker leak: max=%d active=%d slots=%d", maximum.Load(), active.Load(), len(firecrackerCheckpointDigestSlots))
	}
}

func TestPhase69CancellationBeforeStartAndWhileQueued(t *testing.T) {
	files := phase69Files(t, false)
	components := firecrackerCheckpointComponents(files)
	var calls atomic.Int32
	unused := func(context.Context, string, string) (string, error) { calls.Add(1); return "", nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := firecrackerCheckpointDigestBatch(ctx, components, unused)
	for _, result := range results {
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", result.err)
		}
	}
	if calls.Load() != 0 || len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatal("canceled work opened or leaked budget")
	}
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	entered := make(chan struct{}, 2)
	held := make(chan []firecrackerCheckpointDigestResult, 1)
	blocked := func(context.Context, string, string) (string, error) {
		entered <- struct{}{}
		<-release
		return "done", nil
	}
	go func() { held <- firecrackerCheckpointDigestBatch(context.Background(), components[:2], blocked) }()
	phase69Receive(t, entered)
	phase69Receive(t, entered)
	queuedCtx, queuedCancel := context.WithCancel(context.Background())
	queued := make(chan []firecrackerCheckpointDigestResult, 1)
	go func() { queued <- firecrackerCheckpointDigestBatch(queuedCtx, components[2:], unused) }()
	queuedCancel()
	for _, result := range phase69Receive(t, queued) {
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("queued cancellation lost: %v", result.err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("queued canceled callback ran")
	}
	once.Do(func() { close(release) })
	phase69Receive(t, held)
	if len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatal("budget leaked after cancel")
	}
}

func TestPhase69OrdinaryErrorDoesNotCancelAndStillJoins(t *testing.T) {
	files := phase69Files(t, false)
	components := firecrackerCheckpointComponents(files)
	sentinel := errors.New("ordinary component error")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	entered := make(chan struct{}, len(components))
	var finished atomic.Int32
	digester := func(ctx context.Context, name, path string) (string, error) {
		defer finished.Add(1)
		if name == components[0].name {
			return "", sentinel
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return digestFirecrackerCheckpointComponent(ctx, name, path)
	}
	done := make(chan error, 1)
	manifest := &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}
	go func() { done <- finalizeFirecrackerCheckpointV2WithDigester(ctx, files, manifest, digester) }()
	phase69Receive(t, entered)
	select {
	case <-done:
		t.Fatal("returned without joining blocked sibling")
	default:
	}
	if ctx.Err() != nil {
		t.Fatal("ordinary error canceled external context")
	}
	once.Do(func() { close(release) })
	if err := phase69Receive(t, done); !errors.Is(err, sentinel) {
		t.Fatalf("canonical error lost: %v", err)
	}
	if finished.Load() != int32(len(components)) || len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatal("workers not joined")
	}
}

func TestPhase69SealCanceledAndManifestExclusiveError(t *testing.T) {
	files := phase69Files(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finalizeFirecrackerCheckpointV2(ctx, files, &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel changed: %v", err)
	}
	path := filepath.Join(filepath.Dir(files.State), firecrackerCheckpointManifestName)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled seal published manifest: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{SnapshotType: firecrackerSnapshotTypeFull})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("O_EXCL error changed: %v", err)
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		t.Fatal("preexisting manifest path was overwritten")
	}
}

func TestPhase69OriginalDigesterFDAndWorkerLifetime(t *testing.T) {
	files := phase69Files(t, true)
	components := firecrackerCheckpointComponents(files)
	firecrackerCheckpointDigestBatch(context.Background(), components, digestFirecrackerCheckpointComponent)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("Linux fd inventory unavailable: %v", err)
	}
	for i := 0; i < 12; i++ {
		for _, result := range firecrackerCheckpointDigestBatch(context.Background(), components, digestFirecrackerCheckpointComponent) {
			if result.err != nil {
				t.Fatal(result.err)
			}
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || len(firecrackerCheckpointDigestSlots) != 0 {
		t.Fatalf("owned fd/budget leak: before=%d after=%d slots=%d", len(before), len(after), len(firecrackerCheckpointDigestSlots))
	}
}
