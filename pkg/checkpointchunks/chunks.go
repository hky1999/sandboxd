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
	"regexp"
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
	FileDigestMode string  `json:"file_digest_mode,omitempty"`
	ChunkBytes     int     `json:"chunk_bytes"`
	ChunkCount     int     `json:"chunk_count"`
	Entries        []Chunk `json:"entries"`
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

// Load reads the sidecar manifest from a checkpoint directory. A checkpoint
// without one predates chunked distribution.
func Load(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode chunk manifest: %w", err)
	}
	if manifest.Version != 1 {
		return nil, fmt.Errorf("unsupported chunk manifest version %d", manifest.Version)
	}
	// Digests are used as object keys (sliced and path-joined) by every
	// consumer: an empty or non-hex value would panic the slice at best and
	// path-traverse the store at worst. The write side already rejects
	// these; loading must be equally defensive (F2).
	for i, entry := range manifest.Entries {
		if !digestPattern.MatchString(entry.Digest) {
			return nil, fmt.Errorf("chunk manifest entry %d has invalid digest %q", i, entry.Digest)
		}
	}
	return &manifest, nil
}

// digestPattern is the strict shape of a sha256 hex digest, shared by the
// chunk store's object-key validation.
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
