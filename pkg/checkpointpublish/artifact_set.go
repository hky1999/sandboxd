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
	"sync"
	"sync/atomic"

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

// OverlayChunkKey is the store key for one overlay chunk. Overlay chunks
// live in a global content-addressed namespace — the key carries no
// checkpoint ID — so a digest held once serves every generation and node:
// unchanged blocks between generations are single Has hits instead of
// re-uploads (the cross-generation dedup the per-ID namespace could not
// express).
func OverlayChunkKey(digest string) string {
	return "overlay-chunks/" + digest[:2] + "/" + digest
}

// legacyOverlayChunkKey is the pre-global namespace (artifacts/<id>/...).
// Materialization still probes it so checkpoints published before the
// switch remain restorable.
func legacyOverlayChunkKey(id, digest string) string {
	return ArtifactKey(id, "overlay-chunks/"+digest)
}

// overlayWorkers bounds overlay publish/materialize concurrency.
const overlayWorkers = 8

// publishOverlayChunks ships the writable layer chunk-by-chunk when its
// sidecar exists (chunks-digest deployments): chunks are keyed by content
// in a global namespace, deduplicated within the run, and uploaded by a
// bounded worker pool. Returns true when the chunked path was taken.
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
	// P1: one job per unique digest — repeated blocks (zeros above all)
	// are served by whichever representative runs first.
	seen := make(map[string]struct{}, len(scan.Entries))
	type job struct {
		offset int64
		length int
		digest string
	}
	jobs := make([]job, 0, len(scan.Entries))
	for _, entry := range scan.Entries {
		if _, dup := seen[entry.Digest]; dup {
			continue
		}
		seen[entry.Digest] = struct{}{}
		want := scan.ChunkBytes
		if tail := int(scan.FileSize - entry.Offset); tail < want {
			want = tail
		}
		jobs = append(jobs, job{offset: entry.Offset, length: want, digest: entry.Digest})
	}
	var errMu sync.Mutex
	firstErr := error(nil)
	failed := atomic.Bool{}
	failJob := func(cause error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = cause
		}
		errMu.Unlock()
		failed.Store(true)
	}
	queue := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < overlayWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				if failed.Load() {
					continue // drain
				}
				key := OverlayChunkKey(j.digest)
				if ok, err := store.HasKey(ctx, key); err != nil {
					failJob(fmt.Errorf("has overlay chunk %s: %w", j.digest[:12], err))
					continue
				} else if ok {
					continue
				}
				block := make([]byte, j.length)
				if _, err := overlay.ReadAt(block, j.offset); err != nil &&
					!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					failJob(fmt.Errorf("read overlay chunk at %d: %w", j.offset, err))
					continue
				}
				if err := store.PutKey(ctx, key, bytes.NewReader(block)); err != nil {
					failJob(fmt.Errorf("put overlay chunk at %d: %w", j.offset, err))
					continue
				}
			}
		}()
	}
	for _, j := range jobs {
		if failed.Load() {
			break
		}
		if err := ctx.Err(); err != nil {
			failJob(err)
			break
		}
		queue <- j
	}
	close(queue)
	wg.Wait()
	if failed.Load() {
		errMu.Lock()
		cause := firstErr
		errMu.Unlock()
		return false, cause
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

		// Artifact-set files are named by checkpoint ID, not by content
		// digest: re-publishing the same ID after the local directory
		// was recreated (bench reruns, ID reuse) produces a different
		// manifest under the same key. The immutability skip is only
		// sound for digest-keyed objects, so these files always upload.
		// The one large file (overlay) ships as digest-keyed chunks
		// where the key IS the content hash and the skip stays correct.
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
// node that never saw the source. Every file is fetched by key and verified
// against the INDEX digest, and the INDEX's memory root is cross-checked
// against the chunk sidecar so the sidecar provably belongs to this
// checkpoint (not merely to itself). The whole rebuild lands in a staging
// directory and is committed by a single rename: a crash leaves either
// nothing or a complete artifact, never a half-materialized directory the
// catalog could mistake for sealed (the manifest also lands inside staging,
// before the commit). A non-empty target directory is refused rather than
// overwritten — an in-use generation must never be mutated under a live
// restorer.
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
	// Refuse to clobber a live target before doing any work.
	if entries, err := os.ReadDir(targetDir); err == nil && len(entries) > 0 {
		return fmt.Errorf("target %s is not empty; refusing to overwrite an in-use generation", targetDir)
	}
	parent := filepath.Dir(targetDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(targetDir)+".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	commit := func() error {
		if err := os.Rename(staging, targetDir); err != nil {
			return err
		}
		return nil
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
		if err := os.WriteFile(filepath.Join(staging, name), body, 0o600); err != nil {
			return err
		}
	}
	// Closure check: the memory root advertised by the INDEX must be the
	// root the sidecar actually derives, otherwise the sidecar describes a
	// different file than the checkpoint claims to own.
	if index.OverlayChunks || index.MemoryRoot != "" {
		if sidecar, err := checkpointchunks.Load(staging); err == nil {
			switch sidecar.FileDigestMode {
			case checkpointchunks.FileDigestChunks, "":
				if root := checkpointchunks.RootDigest(sidecar.Entries); root != index.MemoryRoot {
					return fmt.Errorf("index memory root %s does not match sidecar root %s",
						index.MemoryRoot, root)
				}
			}
		} else {
			return fmt.Errorf("verify sidecar against index: %w", err)
		}
	}
	if index.OverlayChunks {
		if err := materializeOverlayChunks(ctx, staging, id, store); err != nil {
			return err
		}
	}

	// Sparse memory placeholder of the manifest's recorded size; the uffd
	// handler serves real bytes by digest from the chunk store.
	var manifest struct {
		MemorySize int64 `json:"memory_size"`
	}
	if raw, err := os.ReadFile(filepath.Join(staging, "manifest.json")); err == nil {
		if err := json.Unmarshal(raw, &manifest); err == nil && manifest.MemorySize > 0 {
			placeholder, err := os.OpenFile(
				filepath.Join(staging, "memory"), os.O_CREATE|os.O_WRONLY, 0o600)
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
	if err := os.WriteFile(filepath.Join(staging, MaterializedMarker), []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	return commit()
}

// materializeOverlayChunks reassembles the writable layer from digest-keyed
// chunk objects: unique digests only, all-zero chunks synthesized as sparse
// holes (no GET, no write), bounded-concurrency GETs with per-run digest
// reuse, and legacy per-ID keys probed as fallback so checkpoints published
// before the global namespace remain restorable.
func materializeOverlayChunks(
	ctx context.Context,
	targetDir, id string,
	store chunkstore.Keyed,
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
	// Zero-chunk bypass: an all-zero chunk's digest is a constant per
	// length, and an unwritten region of the fresh file already reads as
	// zeros — skip both the GET and the write, keeping the layer sparse.
	zeroFull := checkpointchunks.ZeroChunkDigest(scan.ChunkBytes)
	zeroTail := ""
	if tail := scan.FileSize - int64(len(scan.Entries)-1)*int64(scan.ChunkBytes); tail > 0 && tail < int64(scan.ChunkBytes) {
		zeroTail = checkpointchunks.ZeroChunkDigest(int(tail))
	}
	// Unique-digest jobs with a shared body cache: repeated blocks are
	// fetched once and written to every offset that references them.
	seen := make(map[string][][]byte, len(scan.Entries))
	var order []string
	for _, entry := range scan.Entries {
		if entry.Digest == zeroFull || (zeroTail != "" && entry.Digest == zeroTail) {
			continue // sparse hole
		}
		if _, dup := seen[entry.Digest]; dup {
			continue
		}
		seen[entry.Digest] = nil
		order = append(order, entry.Digest)
	}
	var bodyMu sync.Mutex
	var errMu sync.Mutex
	firstErr := error(nil)
	failed := atomic.Bool{}
	failJob := func(cause error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = cause
		}
		errMu.Unlock()
		failed.Store(true)
	}
	fetchBody := func(digest string) ([]byte, bool) {
		bodyMu.Lock()
		cached, ok := seen[digest]
		bodyMu.Unlock()
		if ok && cached != nil {
			return cached[0], true
		}
		rc, err := store.GetKey(ctx, OverlayChunkKey(digest))
		if err != nil {
			// Legacy namespace fallback for artifacts published before
			// the global one.
			rc2, err2 := store.GetKey(ctx, legacyOverlayChunkKey(id, digest))
			if err2 != nil {
				failJob(fmt.Errorf("fetch overlay chunk %s: %v (legacy: %v)", digest[:12], err, err2))
				return nil, false
			}
			rc = rc2
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			failJob(fmt.Errorf("read overlay chunk %s: %w", digest[:12], err))
			return nil, false
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != digest {
			failJob(fmt.Errorf("overlay chunk digest mismatch: sidecar %s fetched %s",
				digest, hex.EncodeToString(sum[:])))
			return nil, false
		}
		bodyMu.Lock()
		seen[digest] = [][]byte{body}
		bodyMu.Unlock()
		return body, true
	}
	queue := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < overlayWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for digest := range queue {
				if failed.Load() {
					continue // drain
				}
				fetchBody(digest)
			}
		}()
	}
	for _, digest := range order {
		if failed.Load() {
			break
		}
		if err := ctx.Err(); err != nil {
			failJob(err)
			break
		}
		queue <- digest
	}
	close(queue)
	wg.Wait()
	if failed.Load() {
		errMu.Lock()
		cause := firstErr
		errMu.Unlock()
		return cause
	}
	// Writes are issued from one goroutine after all bodies are verified:
	// WriteAt ordering does not matter, but this keeps the failure mode a
	// clean all-or-nothing through staging + rename.
	for _, entry := range scan.Entries {
		if entry.Digest == zeroFull || (zeroTail != "" && entry.Digest == zeroTail) {
			continue
		}
		bodyMu.Lock()
		cached := seen[entry.Digest]
		bodyMu.Unlock()
		if len(cached) == 0 {
			return fmt.Errorf("internal: verified body for %s vanished", entry.Digest[:12])
		}
		if _, err := overlay.WriteAt(cached[0], entry.Offset); err != nil {
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
