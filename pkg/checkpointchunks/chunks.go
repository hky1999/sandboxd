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

// Package checkpointchunks describes a Firecracker checkpoint's memory file
// as fixed-size content-addressed chunks. The chunk manifest is the unit of
// incremental distribution: a generation publishes only the chunks whose
// digests are new, a consumer fetches by digest, and every transfer is
// verifiable end to end. The manifest is a sidecar (chunks.json) written
// after the artifact is sealed; it never participates in the seal.
package checkpointchunks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// ManifestName is the sidecar file written next to the memory artifact.
const ManifestName = "chunks.json"

// DefaultChunkBytes matches the uffd handler's fetch granularity: large
// enough for bulk transfer efficiency, small enough that incremental
// generations re-publish little.
const DefaultChunkBytes = 256 << 10

// File digest modes. Sha256 is the plain sequential whole-file hash;
// Chunks derives the file digest as the sha256 of the concatenated chunk
// digests (offset order) — fully parallelizable, and equivalent for
// corruption detection because every chunk digest is checked on its own.
const (
	FileDigestSha256 = "sha256"
	FileDigestChunks = "chunks"
)

// Chunk is one content-addressed slice of the memory file.
type Chunk struct {
	Offset int64  `json:"offset"`
	Digest string `json:"digest"`
}

// Manifest is the chunk description of one memory file.
type Manifest struct {
	Version    int    `json:"version"`
	File       string `json:"file"`
	FileSize   int64  `json:"file_size"`
	FileDigest string `json:"file_digest"`
	// FileDigestMode names how FileDigest was derived: "sha256"
	// (sequential whole-file hash, the default for pre-existing sidecars)
	// or "chunks" (sha256 over the concatenated chunk digests).
	FileDigestMode string                   `json:"file_digest_mode,omitempty"`
	ChunkBytes     int                      `json:"chunk_bytes"`
	ChunkCount     int                      `json:"chunk_count"`
	Entries        []Chunk                  `json:"entries"`
	Packs          map[string]PackReference `json:"packs,omitempty"`
}

// RootDigest derives the "chunks"-mode file digest from ordered chunk
// digests: sha256 over their hex concatenation.
func RootDigest(entries []Chunk) string {
	h := sha256.New()
	for i := range entries {
		h.Write([]byte(entries[i].Digest))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ChunkBytesFromEnv returns the chunk size for standalone tools,
// overridable with CHUNK_BYTES for object-store backends where 1MiB
// objects halve the request count (the seal-side size stays fixed at
// DefaultChunkBytes so manifests never disagree with their artifacts).
func ChunkBytesFromEnv() int {
	if v := os.Getenv("CHUNK_BYTES"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n >= 4096 && n <= 4<<20 {
			return n
		}
	}
	return DefaultChunkBytes
}

// Compute chunks the checkpoint's memory file and writes the sidecar
// manifest next to it. The whole-file digest doubles as a cross-check: a
// consumer that fetches every chunk and re-hashes the concatenation must
// arrive at it. The memory file is read once, sequentially.
func Compute(ctx context.Context, dir string, chunkBytes int) (*Manifest, error) {
	if chunkBytes <= 0 {
		chunkBytes = DefaultChunkBytes
	}
	path := filepath.Join(dir, "memory")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open memory artifact: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	manifest := &Manifest{
		Version:    1,
		File:       "memory",
		FileSize:   info.Size(),
		ChunkBytes: chunkBytes,
	}
	fileHash := sha256.New()
	buf := make([]byte, chunkBytes)
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			chunkHash := sha256.New()
			chunkHash.Write(buf[:n])
			fileHash.Write(buf[:n])
			manifest.Entries = append(manifest.Entries, Chunk{
				Offset: offset,
				Digest: hex.EncodeToString(chunkHash.Sum(nil)),
			})
			offset += int64(n)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read memory artifact: %w", err)
		}
	}
	manifest.ChunkCount = len(manifest.Entries)
	manifest.FileDigest = hex.EncodeToString(fileHash.Sum(nil))
	manifest.FileDigestMode = FileDigestSha256

	if err := Write(dir, manifest); err != nil {
		return nil, fmt.Errorf("write chunk manifest: %w", err)
	}
	return manifest, nil
}

// Write stores the manifest as the sidecar file. The checkpoint finalize
// path uses it to persist chunk digests computed in its own single pass
// over the memory file (one-pass dual-hash); Compute is the standalone
// equivalent for artifacts that predate it.
func Write(dir string, manifest *Manifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestName), append(encoded, '\n'), 0o600)
}

// WriteNamed stores the manifest under an explicit sidecar file name,
// used for secondary scans (the overlay's overlay.ext4.chunks.json).
func WriteNamed(dir, name string, manifest *Manifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(encoded, '\n'), 0o600)
}

// LoadNamed reads a sidecar under an explicit file name (the overlay's
// overlay.ext4.chunks.json).
func LoadNamed(dir, name string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return decodeManifest(raw, false)
}

// SidecarName is the chunk sidecar file name for an artifact file.
func SidecarName(file string) string { return file + "." + ManifestName }

// Load reads the sidecar manifest from a checkpoint directory. A checkpoint
// without one predates chunked distribution.
func Load(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	return decodeManifest(raw, false)
}

// validateManifest enforces the structural invariants every consumer
// indexes on: positive chunk size, entries matching the declared count,
// offsets laid out as i*ChunkBytes, and a FileSize consistent with the
// final (possibly short) chunk. A manifest failing any of these would
// otherwise divide by zero, read out of bounds, or silently describe a
// different file (C6).
func validateManifest(manifest *Manifest) error {
	if manifest.ChunkBytes <= 0 {
		return fmt.Errorf("chunk manifest has non-positive chunk_bytes %d", manifest.ChunkBytes)
	}
	if manifest.ChunkCount != len(manifest.Entries) {
		return fmt.Errorf("chunk manifest declares %d chunks but carries %d entries",
			manifest.ChunkCount, len(manifest.Entries))
	}
	if manifest.File == "" {
		return fmt.Errorf("chunk manifest has an empty file name")
	}
	for i := range manifest.Entries {
		if want := int64(i) * int64(manifest.ChunkBytes); manifest.Entries[i].Offset != want {
			return fmt.Errorf("chunk manifest entry %d offset %d breaks the %d-byte grid (want %d)",
				i, manifest.Entries[i].Offset, manifest.ChunkBytes, want)
		}
	}
	if n := len(manifest.Entries); n > 0 {
		last := manifest.Entries[n-1].Offset
		if manifest.FileSize <= last || manifest.FileSize > last+int64(manifest.ChunkBytes) {
			return fmt.Errorf("chunk manifest file_size %d inconsistent with %d entries of %d bytes (tail must be in (%d, %d])",
				manifest.FileSize, n, manifest.ChunkBytes, last, last+int64(manifest.ChunkBytes))
		}
	} else if manifest.FileSize != 0 {
		return fmt.Errorf("chunk manifest with no entries must have file_size 0, got %d", manifest.FileSize)
	}
	return nil
}

// validDigest accepts exactly 64 lowercase ASCII hexadecimal bytes.
// Check bytes rather than runes: non-ASCII and malformed UTF-8 are invalid.
func validDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// zeroChunkDigestCache publishes initialization before hashing, so concurrent
// cold callers do not each allocate and hash the same all-zero chunk.
var zeroChunkDigestCache sync.Map

type zeroChunkDigestEntry struct {
	once   sync.Once
	digest string
}

// ZeroChunkDigest returns the sha256 of n zero bytes. Initialization uses a
// fixed scratch buffer; the hot path retains only one digest per length.
func ZeroChunkDigest(n int) string {
	if n < 0 {
		panic("negative zero chunk length")
	}
	value, ok := zeroChunkDigestCache.Load(n)
	if !ok {
		value, _ = zeroChunkDigestCache.LoadOrStore(n, &zeroChunkDigestEntry{})
	}
	entry := value.(*zeroChunkDigestEntry)
	entry.once.Do(func() {
		var block [32 << 10]byte
		hash := sha256.New()
		for left := n; left > 0; {
			count := min(left, len(block))
			hash.Write(block[:count])
			left -= count
		}
		entry.digest = hex.EncodeToString(hash.Sum(nil))
	})
	return entry.digest
}

// Verify re-hashes the memory file chunk by chunk against the manifest.
// It proves the sidecar still describes the artifact on disk.
func Verify(ctx context.Context, dir string) error {
	manifest, err := Load(dir)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dir, manifest.File))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, manifest.ChunkBytes)
	fileHash := sha256.New()
	for i, chunk := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(f, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if int64(n) != expectedChunkLen(manifest, i) {
			return fmt.Errorf("chunk %d short: %d bytes", i, n)
		}
		chunkHash := sha256.New()
		chunkHash.Write(buf[:n])
		fileHash.Write(buf[:n])
		if got := hex.EncodeToString(chunkHash.Sum(nil)); got != chunk.Digest {
			return fmt.Errorf("chunk %d (offset %d) digest mismatch: manifest %s on disk %s",
				i, chunk.Offset, chunk.Digest, got)
		}
	}
	switch manifest.FileDigestMode {
	case "", FileDigestSha256:
		if got := hex.EncodeToString(fileHash.Sum(nil)); got != manifest.FileDigest {
			return fmt.Errorf("file digest mismatch: manifest %s on disk %s", manifest.FileDigest, got)
		}
	case FileDigestChunks:
		// Every chunk digest was checked above; the root binds them in
		// order, so no second whole-file pass is needed.
		if got := RootDigest(manifest.Entries); got != manifest.FileDigest {
			return fmt.Errorf("chunk root digest mismatch: manifest %s on disk %s", manifest.FileDigest, got)
		}
	default:
		return fmt.Errorf("unknown file digest mode %q", manifest.FileDigestMode)
	}
	return nil
}

func expectedChunkLen(m *Manifest, i int) int64 {
	if last := m.ChunkBytes * (m.ChunkCount - 1); int64(i) == int64(m.ChunkCount-1) && m.ChunkCount > 0 {
		return m.FileSize - int64(last)
	}
	return int64(m.ChunkBytes)
}
