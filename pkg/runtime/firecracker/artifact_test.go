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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
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
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest, true); err != nil {
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
		true,
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
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest, true); err != nil {
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
		true,
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
		true,
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
	if digest, recorded := artifact.Manifest.Digests[firecrackerCheckpointMemoryName]; !recorded || digest == "" {
		t.Fatal("memory digest missing despite digest_memory default policy")
	}
	if _, recorded := artifact.Manifest.Digests[firecrackerCheckpointOverlayName]; recorded {
		t.Fatal("overlay digest was computed despite the synchronous-cost policy")
	}

	// The overlay carries no digest by design: changing it must not fail
	// verification. Memory is digested: tampering with it must fail
	// verification just like VM state (the corrupted-transfer guard), so
	// that check runs last to keep the undigested-overlay leg meaningful.
	writeArtifactComponent(t, artifact.Files.Overlay, 16<<10)
	if err := verifyArtifactDigests(context.Background(), artifact); err != nil {
		t.Fatalf("undigested overlay component failed verification: %v", err)
	}
	writeArtifactComponent(t, artifact.Files.Memory, 16<<10)
	if err := verifyArtifactDigests(
		context.Background(), artifact,
	); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered memory not detected: %v", err)
	}
	writeArtifactComponent(t, artifact.Files.State, 16<<10)
	if err := verifyArtifactDigests(
		context.Background(), artifact,
	); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered component not detected: %v", err)
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
		true,
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
	// vmstate and memory are hashed exactly once; the undigested overlay
	// is never hashed. Later rounds hit the cache.
	if cache.hashes != 2 {
		t.Fatalf("component hashes = %d, want 2", cache.hashes)
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
	if cache.hashes != 3 {
		t.Fatalf("component hashes after invalidation = %d, want 3", cache.hashes)
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
		true,
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

func TestFinalizeCheckpointV2DigestPolicy(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   64 << 10,
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest, true); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointOverlayName]; recorded {
		t.Fatal("Full generation digested the overlay")
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointMemoryName]; !recorded {
		t.Fatal("Full generation skipped guest memory despite digest_memory")
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointStateName]; !recorded {
		t.Fatal("Full generation lost the vmstate digest")
	}
	// A manifest without an overlay digest must still open and verify.
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open Full v2 checkpoint: %v", err)
	}
	var cache checkpointDigestCache
	if err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
		t.Fatalf("verify Full artifact digests: %v", err)
	}

	// With the knob off the memory digest is simply absent and the
	// artifact still opens and verifies (pre-knob manifests behave the
	// same way).
	dir = t.TempDir()
	files = sealArtifactFixture(t, dir)
	manifest = &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   64 << 10,
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest, false); err != nil {
		t.Fatalf("finalize v2 checkpoint (digest off): %v", err)
	}
	if _, recorded := manifest.Digests[firecrackerCheckpointMemoryName]; recorded {
		t.Fatal("Full generation digested guest memory despite digest_memory=false")
	}
	artifact, err = openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open Full v2 checkpoint (digest off): %v", err)
	}
	cache = checkpointDigestCache{}
	if err := cache.verifyFirecrackerCheckpointDigests(context.Background(), artifact); err != nil {
		t.Fatalf("verify Full artifact digests (digest off): %v", err)
	}
}

func TestFinalizeMemoryDigestMatchesPlainHashAndScansChunks(t *testing.T) {
	dir := t.TempDir()
	files := sealArtifactFixture(t, dir)
	// 2.5 chunks of non-trivial data.
	data := make([]byte, int64(2*checkpointchunks.DefaultChunkBytes)+131072)
	for i := range data {
		data[i] = byte(i*31 + 5)
	}
	if err := os.WriteFile(files.Memory, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   int64(len(data)),
	}
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, manifest, true); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	plain := sha256.Sum256(data)
	if got := manifest.Digests[firecrackerCheckpointMemoryName]; got != hex.EncodeToString(plain[:]) {
		t.Fatalf("dual-hash digest %s != plain sha256 %s", got, hex.EncodeToString(plain[:]))
	}
	// The sidecar must equal what the standalone Compute produces.
	scan, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatalf("load sidecar: %v", err)
	}
	if scan.ChunkCount != 3 || scan.FileDigest != hex.EncodeToString(plain[:]) {
		t.Fatalf("sidecar = %+v", scan)
	}
	reference, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reference.Entries) != len(scan.Entries) {
		t.Fatalf("entry count %d != %d", len(scan.Entries), len(reference.Entries))
	}
	if err := checkpointchunks.Verify(context.Background(), dir); err != nil {
		t.Fatalf("sidecar verify: %v", err)
	}
}
