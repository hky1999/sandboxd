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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// verifyFirecrackerCheckpointOverlayChunks verifies the writable layer's
// actual disk contents whenever its chunk sidecar
// (overlay.ext4.chunks.json) is present. The Firecracker manifest
// deliberately records no overlay digest, but an artifact carrying a sidecar
// has advertised chunk-level content for the overlay, and a restore must not
// ignore that advertisement just because the manifest has no field for it: a
// same-size replacement of the whole overlay would otherwise pass the
// manifest's digest loop unnoticed. A directory without the sidecar keeps
// the legacy semantics — the overlay is not content-verified at restore and
// its integrity rests on local immutability as before. This is content
// verification, not a defense against a writer that violates the
// immutable-artifact contract concurrently.
func (cache *checkpointDigestCache) verifyFirecrackerCheckpointOverlayChunks(
	ctx context.Context,
	artifact *firecrackerCheckpointArtifact,
) error {
	if artifact.Layout != firecrackerCheckpointLayoutV2Directory || artifact.Files.Overlay == "" {
		return nil
	}
	dir := filepath.Dir(artifact.Files.Overlay)
	sidecarName := checkpointchunks.SidecarName(firecrackerCheckpointOverlayName)
	info, err := os.Lstat(filepath.Join(dir, sidecarName))
	if errors.Is(err, os.ErrNotExist) {
		return nil // legacy artifact: no overlay content advertisement
	}
	if err != nil {
		return fmt.Errorf("inspect Firecracker checkpoint overlay chunk manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"Firecracker checkpoint overlay chunk manifest %s is not a regular file",
			sidecarName,
		)
	}
	// Bound concurrent overlay content scans per cache independently of the
	// memory scan gate: a materialized restore verifies its overlay without
	// queueing behind another restore's local memory verification.
	cache.overlayOnce.Do(func() { cache.overlayGate = make(chan struct{}, 1) })
	select {
	case cache.overlayGate <- struct{}{}:
		defer func() { <-cache.overlayGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	// Cancellation racing an available slot must not start a content scan.
	if err := ctx.Err(); err != nil {
		return err
	}
	if filepath.Base(artifact.Files.Overlay) != firecrackerCheckpointOverlayName {
		return fmt.Errorf("local overlay artifact must be named %s", firecrackerCheckpointOverlayName)
	}
	// LoadNamed is strict: a version-1 sidecar whose entry count, digest
	// shapes, offset grid, or tail size disagree with its own geometry is
	// rejected here, before any artifact byte is read.
	sidecar, err := checkpointchunks.LoadNamed(dir, sidecarName)
	if err != nil {
		return fmt.Errorf("load Firecracker checkpoint overlay chunk manifest: %w", err)
	}
	if sidecar.File != firecrackerCheckpointOverlayName {
		return fmt.Errorf(
			"overlay chunk manifest describes file %q, want %q",
			sidecar.File, firecrackerCheckpointOverlayName,
		)
	}
	if sidecar.FileDigestMode != checkpointchunks.FileDigestChunks {
		return fmt.Errorf(
			"overlay chunk manifest digest mode %q, want %q",
			sidecar.FileDigestMode, checkpointchunks.FileDigestChunks,
		)
	}
	if root := checkpointchunks.RootDigest(sidecar.Entries); root != sidecar.FileDigest {
		return fmt.Errorf(
			"overlay chunk manifest root %s does not bind its entries (%s)",
			sidecar.FileDigest, root,
		)
	}
	overlayInfo, err := os.Lstat(artifact.Files.Overlay)
	if err != nil {
		return fmt.Errorf(
			"inspect Firecracker checkpoint component %s: %w",
			firecrackerCheckpointOverlayName, err,
		)
	}
	if overlayInfo.Size() != sidecar.FileSize {
		return fmt.Errorf(
			"Firecracker checkpoint overlay is %d bytes, chunk manifest expects %d",
			overlayInfo.Size(), sidecar.FileSize,
		)
	}
	return verifyFirecrackerCheckpointOverlayContents(ctx, artifact.Files.Overlay, sidecar)
}

// verifyFirecrackerCheckpointOverlayContents hashes the overlay's actual
// bytes and compares every chunk digest with the sidecar. The default chunk
// size reuses the seal's sparse parallel scan: proven holes are not read,
// allocated zero chunks avoid repeated hashing, and the same worker pool
// bounds apply; any other granularity streams through one fixed buffer,
// because the sidecar's chunk_bytes is untrusted input and must never size
// an allocation.
func verifyFirecrackerCheckpointOverlayContents(
	ctx context.Context,
	path string,
	sidecar *checkpointchunks.Manifest,
) error {
	if sidecar.ChunkBytes == checkpointchunks.DefaultChunkBytes {
		scan, err := scanFileChunks(ctx, path, firecrackerCheckpointOverlayName, nil)
		if err != nil {
			return fmt.Errorf("scan Firecracker checkpoint overlay: %w", err)
		}
		if scan.ChunkCount != sidecar.ChunkCount {
			return fmt.Errorf(
				"Firecracker checkpoint overlay chunks into %d entries, chunk manifest declares %d",
				scan.ChunkCount, sidecar.ChunkCount,
			)
		}
		for i := range sidecar.Entries {
			if scan.Entries[i].Digest != sidecar.Entries[i].Digest {
				return fmt.Errorf(
					"Firecracker checkpoint overlay chunk %d (offset %d) digest mismatch: chunk manifest %s on disk %s",
					i, sidecar.Entries[i].Offset, sidecar.Entries[i].Digest, scan.Entries[i].Digest,
				)
			}
		}
		return nil
	}
	return verifyOverlayChunkStream(ctx, path, sidecar)
}

// overlayStreamBytes fixes the streaming verifier's read granularity
// independently of the sidecar's chunk_bytes.
const overlayStreamBytes = checkpointchunks.DefaultChunkBytes

// verifyOverlayChunkStream verifies a sidecar whose chunk size is not the
// seal default. Each chunk is hashed from one fixed buffer; whole chunks the
// filesystem proves are holes read as zeroes and only the matching zero
// digest can verify them, so an unchanged sparse overlay is not re-read.
func verifyOverlayChunkStream(
	ctx context.Context,
	path string,
	sidecar *checkpointchunks.Manifest,
) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf(
			"open Firecracker checkpoint component %s: %w",
			firecrackerCheckpointOverlayName, err,
		)
	}
	defer f.Close()
	buf := make([]byte, overlayStreamBytes)
	extents := chunkExtentReader{f: f}
	for i := range sidecar.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := sidecar.Entries[i]
		length := min(int64(sidecar.ChunkBytes), sidecar.FileSize-chunk.Offset)
		hasData, err := extents.hasData(chunk.Offset, chunk.Offset+length)
		if err != nil {
			return fmt.Errorf("query %s extents: %w", firecrackerCheckpointOverlayName, err)
		}
		var got string
		if !hasData {
			got = zeroChunkDigest(int(length))
		} else {
			hash := sha256.New()
			for remaining, offset := length, chunk.Offset; remaining > 0; {
				if err := ctx.Err(); err != nil {
					return err
				}
				n := min(int64(len(buf)), remaining)
				if _, err := f.ReadAt(buf[:n], offset); err != nil {
					return fmt.Errorf(
						"read Firecracker checkpoint overlay chunk %d: %w", i, err,
					)
				}
				hash.Write(buf[:n])
				offset += n
				remaining -= n
			}
			got = hex.EncodeToString(hash.Sum(nil))
		}
		if got != chunk.Digest {
			return fmt.Errorf(
				"Firecracker checkpoint overlay chunk %d (offset %d) digest mismatch: chunk manifest %s on disk %s",
				i, chunk.Offset, chunk.Digest, got,
			)
		}
	}
	return nil
}
