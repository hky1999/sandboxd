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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// sealOverlaySidecarArtifact seals a chunks-mode v2 checkpoint through the
// real generator with a sparse overlay (a data island, a full hole chunk,
// and a short data tail), then reopens it the way a restore would.
func sealOverlaySidecarArtifact(t *testing.T, dir string) *firecrackerCheckpointArtifact {
	t.Helper()
	const memorySize = 1 << 20
	files, err := prepareFirecrackerCheckpointV2(dir, "", memorySize)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	writeArtifactComponent(t, files.State, 8<<10)
	writeArtifactComponent(t, files.Memory, memorySize)
	writeSparseOverlay(t, files.Overlay, 2*checkpointchunks.DefaultChunkBytes+8192)
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{
		SnapshotType:     firecrackerSnapshotTypeFull,
		MemorySize:       memorySize,
		MemoryDigestMode: checkpointchunks.FileDigestChunks,
	}, true, nil); err != nil {
		t.Fatalf("finalize chunks-mode v2 checkpoint: %v", err)
	}
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("open sealed v2 checkpoint: %v", err)
	}
	return artifact
}

// writeSparseOverlay lays down a truncated file with data only at the head
// and tail, leaving the middle chunk a hole like a real sealed ext4 layer.
func writeSparseOverlay(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create overlay fixture: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate overlay fixture: %v", err)
	}
	island := make([]byte, 8192)
	for i := range island {
		island[i] = byte(i%251 + 1)
	}
	if _, err := f.WriteAt(island, 0); err != nil {
		t.Fatalf("write overlay head island: %v", err)
	}
	tail := make([]byte, 100)
	for i := range tail {
		tail[i] = byte(i%249 + 2)
	}
	if _, err := f.WriteAt(tail, size-100); err != nil {
		t.Fatalf("write overlay tail island: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close overlay fixture: %v", err)
	}
}

// flipOverlayByte rewrites one byte in place, keeping the file size — the
// same-size swap the manifest's digest loop cannot see.
func flipOverlayByte(t *testing.T, path string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open overlay for flip: %v", err)
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], offset); err != nil {
		t.Fatalf("read overlay byte at %d: %v", offset, err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], offset); err != nil {
		t.Fatalf("write overlay byte at %d: %v", offset, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close overlay after flip: %v", err)
	}
}

func overlaySidecarPath(dir string) string {
	return filepath.Join(dir, checkpointchunks.SidecarName(firecrackerCheckpointOverlayName))
}

func mutateOverlaySidecar(
	t *testing.T, dir string, mutate func(m *checkpointchunks.Manifest),
) {
	t.Helper()
	m, err := checkpointchunks.LoadNamed(dir, checkpointchunks.SidecarName(firecrackerCheckpointOverlayName))
	if err != nil {
		t.Fatalf("load overlay sidecar: %v", err)
	}
	mutate(m)
	if err := checkpointchunks.WriteNamed(
		dir, checkpointchunks.SidecarName(firecrackerCheckpointOverlayName), m,
	); err != nil {
		t.Fatalf("rewrite overlay sidecar: %v", err)
	}
}

// blankManifestMemoryMode rewrites the sealed manifest on disk into the
// pre-chunks shape (no memory digest recorded, no digest mode) and reopens
// the artifact, so the overlay sidecar is the only content authority left.
func blankManifestMemoryMode(t *testing.T, dir string) *firecrackerCheckpointArtifact {
	t.Helper()
	path := filepath.Join(dir, firecrackerCheckpointManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sealed manifest: %v", err)
	}
	var manifest firecrackerCheckpointManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode sealed manifest: %v", err)
	}
	manifest.MemoryDigestMode = ""
	delete(manifest.Digests, firecrackerCheckpointMemoryName)
	encoded, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		t.Fatalf("encode relaxed manifest: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		t.Fatalf("write relaxed manifest: %v", err)
	}
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatalf("reopen relaxed checkpoint: %v", err)
	}
	return artifact
}

// TestVerifyCheckpointOverlaySidecarContents drives the restore-side digest
// verification entry over real sealed chunks-mode artifacts: the overlay's
// actual bytes are checked whenever its sidecar exists, and a missing
// sidecar keeps the legacy undigested-overlay semantics.
func TestVerifyCheckpointOverlaySidecarContents(t *testing.T) {
	const chunk = checkpointchunks.DefaultChunkBytes
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact
		wantErr string // empty expects verification to pass
	}{
		{
			name: "sealed artifact verifies",
		},
		{
			name: "same-size flip in data chunk",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				flipOverlayByte(t, artifact.Files.Overlay, 100)
				return nil
			},
			wantErr: "digest mismatch",
		},
		{
			name: "same-size flip in hole chunk",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				flipOverlayByte(t, artifact.Files.Overlay, chunk+4096)
				return nil
			},
			wantErr: "digest mismatch",
		},
		{
			name: "same-size flip with preserved mtime",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				info, err := os.Lstat(artifact.Files.Overlay)
				if err != nil {
					t.Fatalf("stat overlay before flip: %v", err)
				}
				flipOverlayByte(t, artifact.Files.Overlay, 200)
				// Content, not the stat identity, must drive the decision.
				if err := os.Chtimes(artifact.Files.Overlay, info.ModTime(), info.ModTime()); err != nil {
					t.Fatalf("restore overlay mtime: %v", err)
				}
				return nil
			},
			wantErr: "digest mismatch",
		},
		{
			name: "sidecar root does not bind entries",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.FileDigest = strings.Repeat("ab", 32)
				})
				return nil
			},
			wantErr: "does not bind",
		},
		{
			name: "sidecar entry swapped with consistent root",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.Entries[1].Digest = m.Entries[0].Digest
					m.FileDigest = checkpointchunks.RootDigest(m.Entries)
				})
				return nil
			},
			wantErr: "digest mismatch",
		},
		{
			name: "sidecar file size disagrees with disk",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.FileSize++
				})
				return nil
			},
			wantErr: "chunk manifest expects",
		},
		{
			name: "sidecar tail breaks the grid bound",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.FileSize = m.Entries[len(m.Entries)-1].Offset + int64(m.ChunkBytes) + 1
				})
				return nil
			},
			wantErr: "tail must be in",
		},
		{
			name: "sidecar entry offset breaks the grid",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.Entries[1].Offset++
				})
				return nil
			},
			wantErr: "grid",
		},
		{
			name: "sidecar describes another file",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.File = firecrackerCheckpointMemoryName
				})
				return nil
			},
			wantErr: "describes file",
		},
		{
			name: "sidecar digest mode is not chunks",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				mutateOverlaySidecar(t, dir, func(m *checkpointchunks.Manifest) {
					m.FileDigestMode = checkpointchunks.FileDigestSha256
				})
				return nil
			},
			wantErr: "digest mode",
		},
		{
			name: "no sidecar keeps legacy overlay semantics",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				if err := os.Remove(overlaySidecarPath(dir)); err != nil {
					t.Fatalf("remove overlay sidecar: %v", err)
				}
				flipOverlayByte(t, artifact.Files.Overlay, chunk+4096)
				return nil
			},
		},
		{
			name: "blank manifest mode still verifies the sidecar",
			mutate: func(t *testing.T, dir string, artifact *firecrackerCheckpointArtifact) *firecrackerCheckpointArtifact {
				relaxed := blankManifestMemoryMode(t, dir)
				flipOverlayByte(t, relaxed.Files.Overlay, chunk+4096)
				return relaxed
			},
			wantErr: "digest mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := sealOverlaySidecarArtifact(t, dir)
			if tc.mutate != nil {
				if replacement := tc.mutate(t, dir, artifact); replacement != nil {
					artifact = replacement
				}
			}
			err := verifyArtifactDigests(context.Background(), artifact)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify overlay sidecar artifact: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyCheckpointOverlaySidecarNonDefaultChunkBytes covers the fixed
// buffer streaming verifier for sidecars whose chunk size is not the seal
// default, including one whose chunk_bytes exceeds the whole file.
func TestVerifyCheckpointOverlaySidecarNonDefaultChunkBytes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		chunkBytes int
	}{
		{name: "finer than default", chunkBytes: checkpointchunks.DefaultChunkBytes / 2},
		{name: "coarser than the file", chunkBytes: 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := sealOverlaySidecarArtifact(t, dir)
			rewriteOverlaySidecarGranularity(t, dir, tc.chunkBytes)
			if err := verifyArtifactDigests(context.Background(), artifact); err != nil {
				t.Fatalf("verify non-default chunk size: %v", err)
			}
			flipOverlayByte(t, artifact.Files.Overlay, 100)
			err := verifyArtifactDigests(context.Background(), artifact)
			if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
				t.Fatalf("same-size flip at non-default chunk size: %v", err)
			}
		})
	}
}

// rewriteOverlaySidecarGranularity rebuilds the overlay sidecar at another
// chunk size from an independent sequential hash of the actual bytes.
func rewriteOverlaySidecarGranularity(t *testing.T, dir string, chunkBytes int) {
	t.Helper()
	path := filepath.Join(dir, firecrackerCheckpointOverlayName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read overlay for oracle: %v", err)
	}
	m := &checkpointchunks.Manifest{
		Version:    1,
		File:       firecrackerCheckpointOverlayName,
		FileSize:   int64(len(data)),
		ChunkBytes: chunkBytes,
	}
	for offset := 0; offset < len(data); offset += chunkBytes {
		sum := sha256.Sum256(data[offset : offset+min(chunkBytes, len(data)-offset)])
		m.Entries = append(m.Entries, checkpointchunks.Chunk{
			Offset: int64(offset),
			Digest: hex.EncodeToString(sum[:]),
		})
	}
	m.ChunkCount = len(m.Entries)
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := checkpointchunks.WriteNamed(
		dir, checkpointchunks.SidecarName(firecrackerCheckpointOverlayName), m,
	); err != nil {
		t.Fatalf("rewrite overlay sidecar: %v", err)
	}
}

// errAfterContext reports Canceled once its Err has been consulted a fixed
// number of times, cancelling a scan at a deterministic point.
type errAfterContext struct {
	context.Context
	mu     sync.Mutex
	remain int
}

func (c *errAfterContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remain > 0 {
		c.remain--
		return nil
	}
	return context.Canceled
}

func countScanFileChunksGoroutines(t *testing.T) int {
	t.Helper()
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	if n == len(buf) {
		t.Fatal("goroutine dump truncated")
	}
	count := 0
	for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(stack, "scanFileChunks.func") {
			count++
		}
	}
	return count
}

// TestVerifyCheckpointOverlaySidecarCancellation checks both a cancelled
// restore and one cancelled mid-scan, and that the scan's workers are joined
// on the failure exit. The manifest is relaxed to the pre-chunks shape so
// the overlay scan is the only context consumer in the path.
func TestVerifyCheckpointOverlaySidecarCancellation(t *testing.T) {
	dir := t.TempDir()
	sealOverlaySidecarArtifact(t, dir)
	artifact := blankManifestMemoryMode(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cache checkpointDigestCache
	if err := cache.verifyFirecrackerCheckpointDigests(ctx, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled verify error = %v", err)
	}

	before := countScanFileChunksGoroutines(t)
	cache = checkpointDigestCache{}
	err := cache.verifyFirecrackerCheckpointDigests(
		&errAfterContext{Context: context.Background(), remain: 1}, artifact,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-scan cancellation error = %v", err)
	}
	if after := countScanFileChunksGoroutines(t); after != before {
		t.Errorf("scan goroutines before=%d after=%d", before, after)
	}
}

// TestInstantiateCheckpointVerifiesOverlaySidecar runs the restore-side
// instantiation entry: an untouched artifact restores, and a same-size
// overlay swap is refused before the writable layer is cloned.
func TestInstantiateCheckpointVerifiesOverlaySidecar(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "gen1")
	artifact := sealOverlaySidecarArtifact(t, dir)
	overlayCopy := filepath.Join(root, "storage", "overlay.ext4")
	if err := os.Mkdir(filepath.Dir(overlayCopy), 0700); err != nil {
		t.Fatalf("create storage dir: %v", err)
	}

	if _, memorySize, err := instantiateFirecrackerCheckpoint(
		context.Background(), artifact, &checkpointDigestCache{},
		dir, filepath.Join(root, "state"), overlayCopy,
	); err != nil {
		t.Fatalf("instantiate chunks-mode checkpoint: %v", err)
	} else if memorySize != 1<<20 {
		t.Fatalf("memory size %d, want %d", memorySize, 1<<20)
	}

	if err := os.Remove(overlayCopy); err != nil {
		t.Fatalf("remove instantiated overlay: %v", err)
	}
	flipOverlayByte(t, artifact.Files.Overlay, checkpointchunks.DefaultChunkBytes+4096)
	_, _, err := instantiateFirecrackerCheckpoint(
		context.Background(), artifact, &checkpointDigestCache{},
		dir, filepath.Join(root, "state"), overlayCopy,
	)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("same-size overlay swap accepted by restore: %v", err)
	}
	if _, statErr := os.Lstat(overlayCopy); !os.IsNotExist(statErr) {
		t.Errorf("writable layer created despite failed verification: %v", statErr)
	}
}
