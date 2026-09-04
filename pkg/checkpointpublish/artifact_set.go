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

package checkpointpublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// ArtifactNamespace is the key prefix under which a checkpoint's non-memory
// files live: artifacts/<id>/<file>. The INDEX object is the entry point a
// materializing node fetches first; it names every file's sha256 so nothing
// is trusted unverified.
const ArtifactNamespace = "artifacts"

// IndexName is the per-artifact entry-point object.
const IndexName = "INDEX.json"

// MaterializedMarker lands in a materialized checkpoint directory: restore
// paths read it to know the memory file is a sparse placeholder served by
// the chunk store, not local bytes to re-hash.
const MaterializedMarker = ".materialized"

// ArtifactIndex is the per-checkpoint manifest of everything except the
// memory bytes.
type ArtifactIndex struct {
	CheckpointID string `json:"checkpoint_id"`
	MemoryRoot   string `json:"memory_root"`
	ChunkCount   int    `json:"chunk_count"`
	// OverlayChunks marks that the writable layer ships as digest-keyed
	// chunk objects (overlay-chunks/<digest>) rather than one file object;
	// materialization reassembles it from the overlay sidecar.
	OverlayChunks bool              `json:"overlay_chunks,omitempty"`
	Files         map[string]string `json:"files"` // file name -> sha256
}

func ArtifactKey(id, name string) string {
	return ArtifactNamespace + "/" + id + "/" + name
}

// OverlaySidecarName is the chunk sidecar for the writable layer.
const OverlaySidecarName = "overlay.ext4.chunks.json"

// publishOverlayChunks ships the writable layer chunk-by-chunk when its
// sidecar exists (chunks-digest deployments): incremental generations put
// only their dirty chunks, and materialization reassembles by digest.
// Returns true when the chunked path was taken.
func publishOverlayChunks(
	ctx context.Context,
	checkpointDir, id string,
	store chunkstore.Keyed,
) (bool, error) {
	scan, err := checkpointchunks.LoadNamed(checkpointDir, OverlaySidecarName)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // legacy artifact: whole-file overlay object
		}
		return false, err
	}
	overlay, err := os.Open(filepath.Join(checkpointDir, scan.File))
	if err != nil {
		return false, err
	}
	defer overlay.Close()
	for _, entry := range scan.Entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if ok, err := store.HasKey(ctx, ArtifactKey(id, "overlay-chunks/"+entry.Digest)); err != nil {
			return false, err
		} else if ok {
			continue
		}
		want := scan.ChunkBytes
		if tail := int(scan.FileSize - entry.Offset); tail < want {
			want = tail
		}
		block := make([]byte, want)
		if _, err := overlay.ReadAt(block, entry.Offset); err != nil &&
			!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return false, fmt.Errorf("read overlay chunk at %d: %w", entry.Offset, err)
		}
		if err := store.PutKey(ctx, ArtifactKey(id, "overlay-chunks/"+entry.Digest),
			bytes.NewReader(block)); err != nil {
			return false, fmt.Errorf("put overlay chunk at %d: %w", entry.Offset, err)
		}
	}
	return true, nil
}

// publishArtifactSet uploads vmstate, overlay, manifest, chunk sidecar and
// the INDEX that binds them, skipping objects the store already holds.
func publishArtifactSet(
	ctx context.Context,
	checkpointDir, id string,
	store chunkstore.Keyed,
	state *State,
) error {
	// A directory carrying only a memory file (chunk-scan fixtures, or
	// callers publishing bare memory layers) publishes its chunks without
	// an artifact set; blind materialization is simply not advertised for
	// such objects.
	if _, err := os.Stat(filepath.Join(checkpointDir, "manifest.json")); os.IsNotExist(err) {
		return nil
	}
	chunks, err := checkpointchunks.Load(checkpointDir)
	if err != nil {
		return fmt.Errorf("load chunk sidecar for artifact set: %w", err)
	}
	index := ArtifactIndex{
		CheckpointID: id,
		MemoryRoot:   chunks.FileDigest,
		ChunkCount:   chunks.ChunkCount,
		Files:        make(map[string]string, 4),
	}
	overlayChunked, ocErr := publishOverlayChunks(ctx, checkpointDir, id, store)
	if ocErr != nil {
		return ocErr
	}
	index.OverlayChunks = overlayChunked
	files := []string{"manifest.json", checkpointchunks.ManifestName, "vmstate"}
	if overlayChunked {
		// The sidecar replaces the whole-file object for the writable
		// layer; it is small and digest-verified per chunk.
		files = append(files, OverlaySidecarName)
	} else {
		files = append(files, "overlay.ext4")
	}
	for _, name := range files {
		path := filepath.Join(checkpointDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("artifact set file %s missing", name)
		}
		digest, err := digestFile(ctx, path)
		if err != nil {
			return err
		}
		index.Files[name] = digest

		if ok, err := store.HasKey(ctx, ArtifactKey(id, name)); err != nil {
			return err
		} else if ok {
			continue // immutable content, already hosted
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = store.PutKey(ctx, ArtifactKey(id, name), f)
		f.Close()
		if err != nil {
			return fmt.Errorf("upload %s: %w", name, err)
		}
	}
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	if err := store.PutKey(ctx, ArtifactKey(id, IndexName),
		jsonReader(encoded)); err != nil {
		return fmt.Errorf("upload index: %w", err)
	}
	state.ArtifactSet = true
	return nil
}

// Materialize rebuilds a restorable checkpoint directory from the store on a
// node that never saw the source: every file is fetched by key and verified
// against the INDEX digest before landing; the memory file is created as a
// sparse placeholder of the recorded size with the marker written last so a
// partial materialization is never mistaken for a complete one.
func Materialize(ctx context.Context, targetDir, id string, store chunkstore.Keyed) error {
	indexRaw, err := fetchKey(ctx, store, ArtifactKey(id, IndexName))
	if err != nil {
		return fmt.Errorf("fetch artifact index: %w", err)
	}
	var index ArtifactIndex
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return fmt.Errorf("decode artifact index: %w", err)
	}
	if index.CheckpointID != id {
		return fmt.Errorf("index is for %q, requested %q", index.CheckpointID, id)
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return err
	}
	files := []string{"manifest.json", checkpointchunks.ManifestName, "vmstate"}
	if index.OverlayChunks {
		files = append(files, OverlaySidecarName)
	} else {
		files = append(files, "overlay.ext4")
	}
	for _, name := range files {
		want, recorded := index.Files[name]
		if !recorded {
			return fmt.Errorf("index has no entry for %s", name)
		}
		body, err := fetchKey(ctx, store, ArtifactKey(id, name))
		if err != nil {
			return fmt.Errorf("fetch %s: %w", name, err)
		}
		got := sha256.Sum256(body)
		if hex.EncodeToString(got[:]) != want {
			return fmt.Errorf("artifact %s digest mismatch: index %s fetched %s",
				name, want, hex.EncodeToString(got[:]))
		}
		if err := os.WriteFile(filepath.Join(targetDir, name), body, 0o600); err != nil {
			return err
		}
	}
	if index.OverlayChunks {
		if err := materializeOverlayChunks(ctx, targetDir, id, store, index); err != nil {
			return err
		}
	}

	// Sparse memory placeholder of the manifest's recorded size; the uffd
	// handler serves real bytes by digest from the chunk store.
	var manifest struct {
		MemorySize int64 `json:"memory_size"`
	}
	if raw, err := os.ReadFile(filepath.Join(targetDir, "manifest.json")); err == nil {
		if err := json.Unmarshal(raw, &manifest); err == nil && manifest.MemorySize > 0 {
			placeholder, err := os.OpenFile(
				filepath.Join(targetDir, "memory"), os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			if err := placeholder.Truncate(manifest.MemorySize); err != nil {
				placeholder.Close()
				return err
			}
			placeholder.Close()
		}
	}
	return os.WriteFile(filepath.Join(targetDir, MaterializedMarker), []byte(id+"\n"), 0o600)
}

// materializeOverlayChunks reassembles the writable layer from digest-keyed
// chunk objects, verifying every chunk against the sidecar before it lands.
func materializeOverlayChunks(
	ctx context.Context,
	targetDir, id string,
	store chunkstore.Keyed,
	index ArtifactIndex,
) error {
	scan, err := checkpointchunks.LoadNamed(targetDir, OverlaySidecarName)
	if err != nil {
		return fmt.Errorf("load overlay sidecar: %w", err)
	}
	overlay, err := os.OpenFile(filepath.Join(targetDir, "overlay.ext4"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer overlay.Close()
	for i, entry := range scan.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := fetchKey(ctx, store, ArtifactKey(id, "overlay-chunks/"+entry.Digest))
		if err != nil {
			return fmt.Errorf("fetch overlay chunk %d: %w", i, err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != entry.Digest {
			return fmt.Errorf("overlay chunk %d digest mismatch: sidecar %s fetched %s",
				i, entry.Digest, hex.EncodeToString(sum[:]))
		}
		if _, err := overlay.WriteAt(body, entry.Offset); err != nil {
			return err
		}
	}
	return overlay.Truncate(scan.FileSize)
}

func fetchKey(ctx context.Context, store chunkstore.Keyed, key string) ([]byte, error) {
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func jsonReader(b []byte) io.Reader {
	return newByteReader(b)
}

type byteReaderT struct{ b []byte }

func (r *byteReaderT) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func newByteReader(b []byte) io.Reader { return &byteReaderT{b: b} }

func digestFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
