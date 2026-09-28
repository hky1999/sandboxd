// Copyright (c) 2026 Ant Group Corporation.
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

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// ReconcilePublished converges a crash window the local state file cannot
// see: the remote INDEX committed (it is the last object a publication
// writes) but the daemon died before persisting "published". The
// reconciliation is BY ARTIFACT IDENTITY, not by presence alone: the remote
// INDEX must name this checkpoint and agree with the local chunk sidecar's
// memory root and chunk count, AND every dependency the INDEX references
// must actually be present in the store — a committed INDEX with a missing
// overlay chunk is NOT this artifact's remote_ready, because remote_ready
// means restorable from the store alone. Only when identity AND
// dependencies are proven does the local record converge to published —
// no re-scan, no re-upload, no new checkpoint. A missing or mismatched
// INDEX returns (false, nil) so the caller falls through to the ordinary
// idempotent publish (which re-puts only what the store lacks); a missing
// dependency likewise returns (false, nil) — the normal publish repairs
// the store. A transport error returns (false, err).
func ReconcilePublished(ctx context.Context, dir, id string, store chunkstore.Store, now func() time.Time) (bool, error) {
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		return false, nil // unkeyed stores cannot be probed; normal publish path
	}
	raw, err := fetchArtifactFile(ctx, keyed, id, IndexName)
	if err != nil {
		return false, nil // absent (or transiently unreadable) → normal publish
	}
	var index ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return false, fmt.Errorf("reconcile %s: decode remote INDEX: %w", id, err)
	}
	if index.CheckpointID != id {
		return false, fmt.Errorf("reconcile %s: remote INDEX names %q", id, index.CheckpointID)
	}
	if err := validateIndexBundle(&index); err != nil {
		return false, fmt.Errorf("reconcile %s: %w", id, err)
	}
	// Identity against the local sealed artifact: the sidecar's memory root
	// and geometry must be exactly what the remote INDEX advertises. A
	// mismatch means the remote INDEX belongs to a different generation
	// published under a reused ID — NOT this artifact's remote_ready.
	local, err := checkpointchunks.Load(dir)
	if err != nil {
		return false, fmt.Errorf("reconcile %s: load local sidecar: %w", id, err)
	}
	if local.FileDigest != index.MemoryRoot || local.ChunkCount != index.ChunkCount {
		return false, nil // different artifact identity: normal publish decides
	}
	// DEPENDENCY VERIFICATION: the INDEX is the commit point, but remote_ready
	// also requires the objects it references to be present. Dependencies are
	// derived from the REMOTE TRANSPORT SIDECAR (fetched from the artifact
	// bundle or per-file objects, then DecodeTransport'd) because only the
	// transport view carries the Compression and Packs fields that determine
	// the actual store representation. A concurrent sweep or an operator
	// deleting a chunk makes the artifact un-restorable even though the INDEX
	// exists — this artifact must NOT converge to published, and the normal
	// publish path (which re-puts only missing objects) is the repair.
	transport, err := fetchTransportSidecar(ctx, keyed, id, &index)
	if err != nil {
		return false, fmt.Errorf("reconcile %s: fetch transport sidecar: %w", id, err)
	}
	// The transport sidecar must bind to the same identity as the local
	// sealed sidecar — it names the same bytes in the same geometry.
	if transport.FileDigest != local.FileDigest || transport.ChunkCount != local.ChunkCount {
		return false, nil // transport mismatch: normal publish decides
	}
	// Artifact-set identity: the ID-named namespace's documented protection
	// is against checkpoint-ID REUSE — the normal publish path always
	// re-uploads the bundle/INDEX so a reused ID cannot keep serving a
	// previous generation's artifact set. Converging on memory identity
	// alone would defeat exactly that protection when a reused ID's new
	// generation happens to seal identical memory (paused-idle guests,
	// zero-memory artifacts) with a different vmstate or writable layer.
	// The remote INDEX's per-file digests must therefore ALSO match the
	// local files. The memory sidecar (chunks.json) is deliberately NOT
	// compared byte-for-byte — the remote copy is the transport view,
	// whose compression/pack representation legitimately differs.
	if !artifactSetIdentityMatches(ctx, dir, &index) {
		return false, nil // remote set describes another generation: normal publish re-commits
	}
	// Overlay dependencies from the remote overlay sidecar when the INDEX
	// says the writable layer ships as chunks.
	var overlayTransport *checkpointchunks.Manifest
	if index.OverlayChunks {
		overlayTransport, err = fetchOverlayTransportSidecar(ctx, keyed, id, &index)
		if err != nil {
			return false, fmt.Errorf("reconcile %s: fetch overlay sidecar: %w", id, err)
		}
	}
	deps := transportDependencies(transport, overlayTransport)
	for _, group := range deps {
		// Each group lists alternative store keys; at least one must be
		// present for the artifact to be restorable (zstd chunks are
		// restorable from either the .z object or the plain fallback).
		present := false
		for _, key := range group {
			ok, err := keyed.HasKey(ctx, key)
			if err != nil {
				return false, fmt.Errorf("reconcile %s: probe dependency %s: %w", id, key, err)
			}
			if ok {
				present = true
				break
			}
		}
		if !present {
			// The INDEX says published but a required object is gone
			// (sweep race, operator deletion). Fall through to the normal
			// idempotent publish, which re-puts missing objects and
			// recommits a fresh INDEX — the safe repair path.
			return false, nil
		}
	}
	// Identity proven AND every dependency present: converge the local
	// record to published. The committed INDEX is the protocol's
	// remote_ready point. A layout an earlier attempt decided MUST survive
	// the convergence — the next republish still owes this artifact the
	// same layout, and dropping the field here would silently release the
	// authority the state machine grants it.
	state := State{
		CheckpointID: id,
		Dir:          dir,
		State:        StatePublished,
		Store:        storeLabel(store),
		ChunksTotal:  local.ChunkCount,
		ChunksPut:    local.ChunkCount,
		ArtifactSet:  true,
	}
	if previous, serr := Status(dir); serr == nil && previous != nil {
		// The ID in the prior state may differ from this attempt's label
		// (republishing one directory under a new id is supported); only
		// the layout decision is carried forward, and an unknown layout
		// string is corruption — refuse so the normal-attempt path fails
		// closed on it instead of converging past it.
		if previous.Layout != "" && previous.Layout != layoutPlain && previous.Layout != layoutPack {
			return false, fmt.Errorf("reconcile %s: publish state carries unknown layout %q (corrupt state)", id, previous.Layout)
		}
		state.Layout = previous.Layout
	} else if serr != nil && !os.IsNotExist(serr) {
		// Same fail-closed rule as the publisher: an unreadable state is
		// never converged past. Return the error so the round reports the
		// artifact instead of silently publishing over it.
		return false, fmt.Errorf("reconcile %s: read publish state: %w", id, serr)
	}
	if now == nil {
		now = time.Now
	}
	state.StartedAt = now().UTC()
	state.PublishedAt = now().UTC()
	if err := writeState(state); err != nil {
		return false, fmt.Errorf("reconcile %s: persist published: %w", id, err)
	}
	return true, nil
}

// artifactSetIdentityMatches proves the remote INDEX describes THIS local
// artifact's non-memory files: every artifact-set file the INDEX must carry
// (manifest.json, vmstate, and the overlay sidecar when the INDEX says the
// writable layer ships as chunks, or the whole overlay file otherwise) has
// an entry in INDEX.Files whose digest equals the local file's sha256. A
// missing entry, an unreadable local file, or any mismatch means the remote
// set belongs to a different generation under this ID — false, and the
// caller falls through to the ordinary publish (which re-puts the ID-named
// objects and recommits a fresh INDEX, the existing ID-reuse repair). The
// memory sidecar is excluded on purpose: its remote form is the transport
// view (compression/pack fields), so its bytes legitimately differ.
func artifactSetIdentityMatches(ctx context.Context, dir string, index *ArtifactIndex) bool {
	type entry struct{ name, path string }
	expect := []entry{
		{"manifest.json", filepath.Join(dir, "manifest.json")},
		{"vmstate", filepath.Join(dir, "vmstate")},
	}
	if index.OverlayChunks {
		expect = append(expect, entry{OverlaySidecarName, filepath.Join(dir, OverlaySidecarName)})
	} else {
		expect = append(expect, entry{"overlay.ext4", filepath.Join(dir, "overlay.ext4")})
	}
	for _, e := range expect {
		want, recorded := index.Files[e.name]
		if !recorded {
			return false // INDEX predates the file or was forged; fall through
		}
		got, err := digestFile(ctx, e.path)
		if err != nil {
			return false // cannot prove identity; fall through to the publish path
		}
		if got != want {
			return false
		}
	}
	return true
}

// transportDependencies enumerates the store objects whose presence the
// artifact's restorability depends on, derived from the REMOTE TRANSPORT
// sidecar (the same view materialization readers use). It returns
// dependency GROUPS: each group lists alternative keys of which at least
// one must exist. Per unique entry digest:
//   - zero-chunk digests need no remote object (materialization
//     synthesizes them as sparse holes);
//   - Packs[digest] present → a singleton group with the pack object named
//     by ref.Key();
//   - Compression == zstd → the group {<aa>/<digest>.z, <aa>/<digest>}:
//     readers fall back from the compressed object to the plain one, so
//     either representation alone keeps the artifact restorable;
//   - otherwise the singleton group with the plain <aa>/<digest> key.
//
// Overlay chunks are enumerated from the overlay transport sidecar
// (they are never compressed or packed); zero overlay chunks are skipped
// consistently with materialization's sparse-hole synthesis.
func transportDependencies(memory, overlay *checkpointchunks.Manifest) [][]string {
	var deps [][]string
	appendMemory := func(m *checkpointchunks.Manifest) {
		if m == nil {
			return
		}
		seen := make(map[string]struct{}, len(m.Entries))
		for _, entry := range m.Entries {
			if _, dup := seen[entry.Digest]; dup {
				continue
			}
			seen[entry.Digest] = struct{}{}
			length := m.ChunkBytes
			if tail := int(m.FileSize - entry.Offset); tail < length {
				length = tail
			}
			if entry.Digest == checkpointchunks.ZeroChunkDigest(length) {
				continue // zero chunk: no remote object needed
			}
			if ref, packed := m.Packs[entry.Digest]; packed {
				if key, err := ref.Key(); err == nil {
					deps = append(deps, []string{key})
					continue
				}
			}
			if m.Compression == checkpointchunks.CompressionZstd {
				deps = append(deps, []string{
					chunkstore.CompressedKey(entry.Digest),
					chunkstore.PlainKey(entry.Digest),
				})
				continue
			}
			deps = append(deps, []string{chunkstore.PlainKey(entry.Digest)})
		}
	}
	appendMemory(memory)
	if overlay != nil {
		seen := make(map[string]struct{}, len(overlay.Entries))
		for _, entry := range overlay.Entries {
			if _, dup := seen[entry.Digest]; dup {
				continue
			}
			seen[entry.Digest] = struct{}{}
			length := overlay.ChunkBytes
			if tail := int(overlay.FileSize - entry.Offset); tail < length {
				length = tail
			}
			if entry.Digest == checkpointchunks.ZeroChunkDigest(length) {
				continue
			}
			deps = append(deps, []string{OverlayChunkKey(entry.Digest)})
		}
	}
	return deps
}

// fetchTransportSidecar retrieves the memory transport sidecar (the sealed
// chunks.json augmented with Compression/Packs) from the remote artifact
// set — extracted from the BUNDLE when present, or the per-file object
// otherwise — and DecodeTransports it. This is the same source
// materialization readers use.
func fetchTransportSidecar(ctx context.Context, keyed chunkstore.Keyed, id string, index *ArtifactIndex) (*checkpointchunks.Manifest, error) {
	raw, err := extractArtifactFile(ctx, keyed, id, index, checkpointchunks.ManifestName)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", checkpointchunks.ManifestName, err)
	}
	return checkpointchunks.DecodeTransport(raw)
}

// fetchOverlayTransportSidecar retrieves the overlay transport sidecar from
// the remote artifact set and DecodeTransports it.
func fetchOverlayTransportSidecar(ctx context.Context, keyed chunkstore.Keyed, id string, index *ArtifactIndex) (*checkpointchunks.Manifest, error) {
	raw, err := extractArtifactFile(ctx, keyed, id, index, OverlaySidecarName)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", OverlaySidecarName, err)
	}
	return checkpointchunks.DecodeTransport(raw)
}

// extractArtifactFile returns one artifact-set file's bytes — from the
// bundle when the INDEX advertises one, or the per-file object otherwise —
// under the SAME acceptance conditions Materialize applies before trusting
// those bytes: bundle size and whole-object digest against the INDEX, part
// span in range, part digest equal to the INDEX's Files entry, and (on the
// pre-bundle path) the per-file object's digest against Files. Reconcile
// deciding "published" on weaker checks than the reader's would let a
// tampered INDEX or bundle converge a local record for an artifact
// materialization would then reject.
func extractArtifactFile(ctx context.Context, keyed chunkstore.Keyed, id string, index *ArtifactIndex, name string) ([]byte, error) {
	want, recorded := index.Files[name]
	if !recorded {
		return nil, fmt.Errorf("index has no entry for %s", name)
	}
	if index.Bundle == nil {
		raw, err := fetchArtifactFile(ctx, keyed, id, name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("artifact %s digest mismatch: index %s object %s",
				name, want, hex.EncodeToString(sum[:]))
		}
		return raw, nil
	}
	bundle, err := fetchArtifactFile(ctx, keyed, id, BundleName)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	if int64(len(bundle)) != index.Bundle.Size {
		return nil, fmt.Errorf("bundle size %d, index says %d", len(bundle), index.Bundle.Size)
	}
	sum := sha256.Sum256(bundle)
	if hex.EncodeToString(sum[:]) != index.Bundle.Digest {
		return nil, fmt.Errorf("bundle digest mismatch: index %s fetched %s",
			index.Bundle.Digest, hex.EncodeToString(sum[:]))
	}
	for _, part := range index.Bundle.Parts {
		if part.Name != name {
			continue
		}
		// The part digest is recorded twice (BundlePart.Digest and
		// Files[name]); requiring BOTH to agree with the bytes closes a
		// forged-part-digest INDEX that Materialize's Files check alone
		// would still pass.
		if part.Digest != want {
			return nil, fmt.Errorf("bundle part %s digest %s disagrees with index files entry %s",
				name, part.Digest, want)
		}
		if part.Offset < 8 || part.Offset+part.Length > int64(len(bundle)) {
			return nil, fmt.Errorf("bundle part %s span out of range", name)
		}
		body := bundle[part.Offset : part.Offset+part.Length]
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("bundle part %s digest mismatch", name)
		}
		return body, nil
	}
	return nil, fmt.Errorf("bundle has no part %s", name)
}

// fetchArtifactFile fetches one artifact-set file from the bundle when the
// INDEX advertises one, or the per-file object otherwise. Reconciliation
// only needs the INDEX and the sidecars; the bundle span (if present) is
// validated against the recorded digest before any byte is trusted by
// materialization.
func fetchArtifactFile(ctx context.Context, keyed chunkstore.Keyed, id, name string) ([]byte, error) {
	raw, err := keyed.GetKey(ctx, ArtifactKey(id, name))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	return io.ReadAll(raw)
}

// storeLabel is the best-effort store name for state records.
func storeLabel(store chunkstore.Store) string {
	if s, ok := store.(interface{ String() string }); ok {
		return s.String()
	}
	return "store"
}
