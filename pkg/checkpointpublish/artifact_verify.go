// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpointpublish

// Shared artifact-metadata extraction with MATERIALIZE-grade fail-closed
// verification. One implementation serves the pack-baseline loader and
// cn-gcsweep's live-set derivation, so a corrupted object that still decodes
// a reference-poorer sidecar can never make a consumer MISS live references
// (for the sweep that means deleting live objects) — the extraction chain is
// exactly as strict as materialization, never a third weaker copy.
//
// Bounds discipline: NOTHING is allocated by a declared size from an
// untrusted INDEX. In-memory metadata reads (INDEX, sidecars, legacy
// per-file objects, requested bundle parts) go through a fixed bound with
// one-byte-over truncation DETECTION; the bundle itself streams to a private
// temp file with an exact declared-length check and a whole-object sha256
// while copying — a legitimate bundle larger than the bound still verifies
// (only the SIDEcar slices it serves are bounded), and a hostile Bundle.Size
// cannot OOM the process.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// maxSidecarFetchBytes bounds every in-memory metadata read in this chain,
// and is EXACTLY checkpointchunks.MaxManifestBytes — the authority limit
// LoadTransport/LoadNamed enforce after materialization lands the file. A
// sidecar this chain accepts but LoadTransport would reject (say 33MiB)
// would not be "the same grade", so the two bounds are one constant. (The
// metadata chain never requests whole-file overlay objects; bundle parts
// are small files by design.)
const maxSidecarFetchBytes = checkpointchunks.MaxManifestBytes

// fetchBoundedKey GETs one metadata object fully inside the fixed bound,
// detecting (not truncating) an overlong body, and optionally verifies its
// sha256 against a trusted digest.
func fetchBoundedKey(ctx context.Context, store chunkstore.Keyed, key, wantDigest string) ([]byte, error) {
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxSidecarFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSidecarFetchBytes {
		return nil, fmt.Errorf("object %s exceeds the %d-byte metadata bound", key, maxSidecarFetchBytes)
	}
	if wantDigest != "" {
		if !checkpointchunks.ValidDigest(wantDigest) {
			return nil, fmt.Errorf("digest for %s is not a valid sha256 hex string", key)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != wantDigest {
			return nil, fmt.Errorf("object %s digest mismatch (index says %s)", key, wantDigest)
		}
	}
	return raw, nil
}

// FetchVerifiedIndex fetches, decodes and validates an artifact INDEX: a
// bounded read with truncation detection, the declared-bundle format check,
// and the IDENTITY check — the INDEX must name the artifact it was fetched
// under, or a stray/misplaced INDEX would define someone else's live set.
func FetchVerifiedIndex(ctx context.Context, store chunkstore.Keyed, id string) (*ArtifactIndex, error) {
	raw, err := fetchBoundedKey(ctx, store, ArtifactKey(id, IndexName), "")
	if err != nil {
		return nil, fmt.Errorf("fetch INDEX: %w", err)
	}
	var index ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("decode INDEX: %w", err)
	}
	if err := validateIndexBundle(&index); err != nil {
		return nil, fmt.Errorf("INDEX bundle: %w", err)
	}
	if index.CheckpointID != id {
		return nil, fmt.Errorf("INDEX names checkpoint %q, fetched under %q", index.CheckpointID, id)
	}
	// The memory root must be a well-formed digest HERE, so the closure
	// comparison downstream can never see an empty-vs-empty "agreement".
	if !checkpointchunks.ValidDigest(index.MemoryRoot) {
		return nil, fmt.Errorf("INDEX memory root %q is not a valid digest", index.MemoryRoot)
	}
	return &index, nil
}

// expectedArtifactFiles mirrors materialization's LOCAL expected file set
// (derived from the artifact shape, never trusted from the INDEX).
func expectedArtifactFiles(index *ArtifactIndex) []string {
	files := []string{"manifest.json", checkpointchunks.ManifestName, "vmstate"}
	if index.OverlayChunks {
		return append(files, OverlaySidecarName)
	}
	return append(files, "overlay.ext4")
}

// FetchVerifiedSidecars returns the requested artifact-set files' bytes with
// materialize-grade verification. names must be a subset of the artifact's
// expected file set. With a bundle, ONE GET streams the bundle to a private
// temp file (exact declared length + whole-object sha256), the part list is
// whitelist-checked against the expected set and Files digests with
// overflow-safe spans, and each requested part is read with its own digest
// check. Without a bundle, every requested per-file object is fetched
// bounded and digest-checked against Files.
func FetchVerifiedSidecars(ctx context.Context, store chunkstore.Keyed, id string, index *ArtifactIndex, names []string) (map[string][]byte, error) {
	expected := expectedArtifactFiles(index)
	expectedSet := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		expectedSet[name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := expectedSet[name]; !ok {
			return nil, fmt.Errorf("requested file %s is not part of this artifact's expected set", name)
		}
	}
	out := make(map[string][]byte, len(names))
	if index.Bundle == nil {
		for _, name := range names {
			want, ok := index.Files[name]
			if !ok || !checkpointchunks.ValidDigest(want) {
				return nil, fmt.Errorf("index has no valid digest for %s", name)
			}
			raw, err := fetchBoundedKey(ctx, store, ArtifactKey(id, name), want)
			if err != nil {
				return nil, fmt.Errorf("fetch %s: %w", name, err)
			}
			out[name] = raw
		}
		return out, nil
	}
	// Part whitelist FIRST (same rule as materialization): safe basenames,
	// every part among the expected files, part digests equal to the INDEX
	// Files digests, no duplicates, and EXACT set equality in both
	// directions between parts and the expected files.
	seen := make(map[string]struct{}, len(index.Bundle.Parts))
	for _, part := range index.Bundle.Parts {
		if part.Name == "" || part.Name == "." || part.Name == ".." || strings.ContainsAny(part.Name, "/\\\x00") {
			return nil, fmt.Errorf("bundle part name %q is not a safe basename", part.Name)
		}
		if _, ok := expectedSet[part.Name]; !ok {
			return nil, fmt.Errorf("bundle part %s is not among the artifact's expected files", part.Name)
		}
		want, ok := index.Files[part.Name]
		if !ok || !checkpointchunks.ValidDigest(want) {
			return nil, fmt.Errorf("bundle part %s has no valid index digest", part.Name)
		}
		if part.Digest != want {
			return nil, fmt.Errorf("bundle part %s digest %s disagrees with the index file digest", part.Name, part.Digest)
		}
		if _, dup := seen[part.Name]; dup {
			return nil, fmt.Errorf("bundle part %s listed twice", part.Name)
		}
		seen[part.Name] = struct{}{}
	}
	for name := range expectedSet {
		if _, covered := seen[name]; !covered {
			return nil, fmt.Errorf("expected file %s missing from the bundle parts", name)
		}
	}
	for name := range index.Files {
		if _, ok := expectedSet[name]; !ok {
			return nil, fmt.Errorf("index lists unexpected file %s", name)
		}
	}
	// ONE bundle GET: exact declared length + streaming whole-object digest
	// to a private temp file (never an allocation by declared size).
	bundlePath, err := fetchKeyToTempFile(ctx, store, ArtifactKey(id, BundleName), index.Bundle.Digest, index.Bundle.Size)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer os.Remove(bundlePath)
	bf, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer bf.Close()
	bfi, err := bf.Stat()
	if err != nil {
		return nil, err
	}
	if bfi.Size() != index.Bundle.Size {
		return nil, fmt.Errorf("bundle object is %d bytes, index declares %d", bfi.Size(), index.Bundle.Size)
	}
	partByName := make(map[string]BundlePart, len(index.Bundle.Parts))
	for _, part := range index.Bundle.Parts {
		// Subtraction-based bound: part.Offset+part.Length can overflow
		// int64 on a hostile INDEX; bfi.Size()-part.Offset cannot.
		if part.Length <= 0 || part.Offset < 8 || bfi.Size()-part.Offset < part.Length {
			return nil, fmt.Errorf("bundle part %s span out of range", part.Name)
		}
		partByName[part.Name] = part
	}
	for _, name := range names {
		part := partByName[name]
		if part.Length > maxSidecarFetchBytes {
			return nil, fmt.Errorf("bundle part %s (%d bytes) exceeds the %d-byte metadata bound", name, part.Length, maxSidecarFetchBytes)
		}
		body := make([]byte, part.Length)
		if _, err := io.ReadFull(io.NewSectionReader(bf, part.Offset, part.Length), body); err != nil {
			return nil, fmt.Errorf("bundle part %s read: %w", name, err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != index.Files[name] {
			return nil, fmt.Errorf("bundle part %s digest mismatch", name)
		}
		out[name] = body
	}
	return out, nil
}

// VerifySidecarIndexClosure enforces the three-authority closure for the
// memory sidecar: the sidecar a consumer extracted must be the one the INDEX
// advertised (root digest and chunk count), or the consumer would derive a
// live set (or a restore plan) from a different file than the checkpoint
// owns.
func VerifySidecarIndexClosure(m *checkpointchunks.Manifest, index *ArtifactIndex) error {
	// BOTH roots must be well-formed digests BEFORE any comparison: an
	// empty-vs-empty or garbage-vs-garbage "agreement" must never pass (and
	// formatting must never slice a short string into a panic).
	if !checkpointchunks.ValidDigest(m.FileDigest) {
		return fmt.Errorf("sidecar memory root %q is not a valid digest", m.FileDigest)
	}
	if !checkpointchunks.ValidDigest(index.MemoryRoot) {
		return fmt.Errorf("index memory root %q is not a valid digest", index.MemoryRoot)
	}
	if m.FileDigest != index.MemoryRoot || m.ChunkCount != index.ChunkCount {
		return fmt.Errorf("sidecar memory identity mismatch: sidecar root %q/%d chunks, index says %q/%d",
			m.FileDigest, m.ChunkCount, index.MemoryRoot, index.ChunkCount)
	}
	return nil
}
