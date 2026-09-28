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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
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
	// Bundle names a single object carrying all the small artifact-set
	// files concatenated with 8-byte big-endian length prefixes — one PUT
	// on publish, one GET on materialize. Parts keep per-file digests so
	// verification is unchanged; pre-bundle artifacts carry no field and
	// materialization falls back to per-file fetches.
	Bundle *BundleInfo `json:"bundle,omitempty"`
}

// BundleName is the bundle object's name inside the artifact namespace.
const BundleName = "BUNDLE"

// BundleInfo describes one concatenated small-file object.
type BundleInfo struct {
	Digest string       `json:"digest"` // sha256 of the whole bundle object
	Size   int64        `json:"size"`
	Parts  []BundlePart `json:"parts"`
}

// BundlePart locates one file inside the bundle.
type BundlePart struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Digest string `json:"digest"`
}

// validateIndexBundle guards the INDEX's BUNDLE descriptor (P1-E): a bundle
// with a zero-or-negative declared size is malformed — it would degenerate
// the bounded fetch into a zero-byte expectation — and its digest must be
// a valid content digest before anything streams it.
func validateIndexBundle(index *ArtifactIndex) error {
	if index.Bundle == nil {
		return nil
	}
	if index.Bundle.Size <= 0 {
		return fmt.Errorf("index bundle size %d must be > 0", index.Bundle.Size)
	}
	// Same ceiling the streaming fetchers enforce: a declared size near
	// MaxInt64 would overflow the declared+1 stream bound and disguise the
	// rejection as a bogus "short" read.
	if index.Bundle.Size > 1<<40 {
		return fmt.Errorf("index bundle size %d exceeds the %d-byte ceiling", index.Bundle.Size, int64(1<<40))
	}
	if !checkpointchunks.ValidDigest(index.Bundle.Digest) {
		return fmt.Errorf("index bundle digest %q is not a valid digest", index.Bundle.Digest)
	}
	return nil
}

// ValidateIndexBundle is the exported form for out-of-package INDEX
// consumers (cn-gcsweep) so every decode site applies the same rule.
func ValidateIndexBundle(index *ArtifactIndex) error { return validateIndexBundle(index) }

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

// defaultOverlayWorkers bounds overlay publish/materialize concurrency
// when the caller does not override it (Options.OverlayWorkers /
// MaterializeOptions.OverlayWorkers, 0 = this default).
const defaultOverlayWorkers = 8

func overlayWorkerCount(n int) int {
	if n <= 0 {
		return defaultOverlayWorkers
	}
	if n > 64 {
		return 64
	}
	return n
}

// publishOverlayChunks ships the writable layer chunk-by-chunk when its
// sidecar exists (chunks-digest deployments): chunks are keyed by content
// in a global namespace, deduplicated within the run, and uploaded by a
// bounded worker pool. Returns true when the chunked path was taken.
func publishOverlayChunks(
	ctx context.Context,
	checkpointDir, id string,
	store chunkstore.Keyed,
	overlayWorkers int,
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
	workers := overlayWorkerCount(overlayWorkers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				if failed.Load() {
					continue // drain
				}
				key := OverlayChunkKey(j.digest)
				claim := "" // this acquisition's handle; empty = no claim held
				if ok, err := store.HasKey(ctx, key); err != nil {
					failJob(fmt.Errorf("has overlay chunk %s: %w", j.digest[:12], err))
					continue
				} else if ok {
					// Sweep fence: a marked overlay block is scheduled for
					// collection once its mark ages past the sweep's grace,
					// and min-age cannot protect the reuse (the object is old
					// by construction). The local bytes are real (not a
					// hole), so refresh the object by re-uploading instead
					// of skipping — the digest re-check inside keeps the
					// global namespace poison-proof.
					body, fenced, err := gcFenceClaim(ctx, store, key)
					if err != nil {
						failJob(err)
						continue
					}
					if !fenced {
						continue
					}
					claim = body
				}
				putBlock := func() error {
					block := make([]byte, j.length)
					n, err := overlay.ReadAt(block, j.offset)
					if err != nil &&
						!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						return fmt.Errorf("read overlay chunk at %d: %w", j.offset, err)
					}
					if n != j.length {
						return fmt.Errorf("overlay chunk at %d short: %d bytes, want %d",
							j.offset, n, j.length)
					}
					// The object key is the content address shared by every
					// future generation: upload only bytes that actually hash
					// to it, or a corrupted local original would poison the
					// global namespace for all Has-hit readers (F9).
					sum := sha256.Sum256(block)
					if hex.EncodeToString(sum[:]) != j.digest {
						return fmt.Errorf("overlay chunk at %d content hashes to %s, sidecar claims %s — refusing to publish",
							j.offset, hex.EncodeToString(sum[:]), j.digest)
					}
					if err := store.PutKey(ctx, key, bytes.NewReader(block)); err != nil {
						return fmt.Errorf("put overlay chunk at %d: %w", j.offset, err)
					}
					return nil
				}
				err := putBlock()
				switch {
				case err == nil && claim != "":
					// Fenced re-upload complete: end this claim's protection.
					gcReleaseClaim(ctx, store, key, claim)
				case err == nil:
					// Fresh-upload guard: the key may carry a mark left by a
					// collector that just deleted the previous body; redo the
					// upload under the claim so the object provably exists
					// once the claim is released.
					err = gcGuardFreshUpload(ctx, store, key, putBlock)
				}
				if err != nil {
					if claim != "" {
						gcReleaseClaim(ctx, store, key, claim)
					}
					failJob(err)
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
// phases (optional) receives the attribution split: MetaWall spans entry
// through the BUNDLE PUT (overlay chunk PUTs + bundle assembly + bundle
// upload) and IndexWall the INDEX commit PUT.
func publishArtifactSetWithTransport(ctx context.Context, checkpointDir, id string, store chunkstore.Keyed, state *State, transport *checkpointchunks.Manifest, phases *PublishPhases, overlayWorkers int) error {
	metaStart := time.Now()
	defer func() {
		if phases != nil && phases.MetaWall == 0 {
			// Failed before the INDEX section: still record the stage wall
			// consumed so far.
			phases.MetaWall = time.Since(metaStart)
		}
	}()
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
	var transportRaw []byte
	if transport != nil {
		if err := checkpointchunks.ValidateTransport(transport); err != nil {
			return err
		}
		if transport.FileDigest != chunks.FileDigest || transport.FileSize != chunks.FileSize || transport.ChunkCount != chunks.ChunkCount {
			return fmt.Errorf("transport changed sealed memory identity")
		}
		transportRaw, err = json.MarshalIndent(transport, "", "  ")
		if err != nil {
			return err
		}
	}
	index := ArtifactIndex{
		CheckpointID: id,
		MemoryRoot:   chunks.FileDigest,
		ChunkCount:   chunks.ChunkCount,
		Files:        make(map[string]string, 4),
	}
	overlayChunked, ocErr := publishOverlayChunks(ctx, checkpointDir, id, store, overlayWorkers)
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
	// Artifact-set files ship as ONE bundle object (8-byte big-endian
	// length prefix per file): one PUT here and one GET at materialize
	// time, instead of one per file. The bundle keeps the ID-named
	// always-upload semantics that protect against checkpoint-ID reuse,
	// and every part carries its own digest so per-file verification is
	// unchanged. Pre-bundle artifacts carry per-file objects and no
	// index.Bundle; materialization falls back to per-file fetches.
	var bundle []byte
	info := &BundleInfo{}
	body := func(name string) ([]byte, error) {
		path := filepath.Join(checkpointDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("artifact set file %s missing", name)
		}
		if name == checkpointchunks.ManifestName && transportRaw != nil {
			return transportRaw, nil
		}
		return os.ReadFile(path)
	}
	for _, name := range files {
		raw, err := body(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		index.Files[name] = digest
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(len(raw)))
		part := BundlePart{Name: name, Offset: int64(len(bundle)) + 8, Length: int64(len(raw)), Digest: digest}
		bundle = append(bundle, prefix[:]...)
		bundle = append(bundle, raw...)
		info.Parts = append(info.Parts, part)
	}
	sum := sha256.Sum256(bundle)
	info.Digest = hex.EncodeToString(sum[:])
	info.Size = int64(len(bundle))
	index.Bundle = info
	if err := store.PutKey(ctx, ArtifactKey(id, BundleName), bytes.NewReader(bundle)); err != nil {
		return fmt.Errorf("upload bundle: %w", err)
	}
	if phases != nil {
		phases.MetaWall = time.Since(metaStart)
	}
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	indexStart := time.Now()
	err = store.PutKey(ctx, ArtifactKey(id, IndexName), jsonReader(encoded))
	if phases != nil {
		// Recorded BEFORE the error check: a failed commit keeps its stage
		// wall too, not only its request counters.
		phases.IndexWall = time.Since(indexStart)
	}
	if err != nil {
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
	return MaterializeWithOptions(ctx, targetDir, id, store, MaterializeOptions{})
}

// MaterializeOptions carries optional node-level services for
// materialization. Cache fronts overlay chunk GETs with the node's
// content-addressed cache: concurrent or repeat restores of overlapping
// artifacts stop re-downloading unchanged overlay blocks.
type MaterializeOptions struct {
	Cache *chunkcache.Manager
	// OverlayWorkers bounds the overlay chunk download pool; zero keeps the
	// package default (8).
	OverlayWorkers int
}

// MaterializeWithOptions is Materialize with node services. When a cache is
// configured, a restore pin protects the artifact's overlay chunk set for
// the duration of the rebuild (released on return; a crash drops the pin's
// flock with the process).
func MaterializeWithOptions(ctx context.Context, targetDir, id string, store chunkstore.Keyed, opts MaterializeOptions) error {
	if opts.OverlayWorkers < 0 || opts.OverlayWorkers > 64 {
		return fmt.Errorf("materialize overlay workers %d out of range [0,64]", opts.OverlayWorkers)
	}
	indexRaw, err := fetchKeyBounded(ctx, store, ArtifactKey(id, IndexName), maxIndexBytes)
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
	if err := validateIndexBundle(&index); err != nil {
		return fmt.Errorf("artifact %s: %w", id, err)
	}
	// Refuse to clobber a live target before doing any work.
	if entries, err := os.ReadDir(targetDir); err == nil && len(entries) > 0 {
		return fmt.Errorf("target %s is not empty; refusing to overwrite an in-use generation", targetDir)
	}
	parent := filepath.Dir(targetDir)
	// Keep staging on the target filesystem, independently of publication
	// state: .publish may be placed on a separate filesystem to isolate
	// control-state fsync from bulk snapshot writeback. The reserved nested
	// namespace keeps partial manifests out of catalog/publishd scans.
	stagingRoot := filepath.Join(parent, ".materialize")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(stagingRoot, "staging-")
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
	switch {
	case index.Bundle != nil:
		// One GET for every small file. The bundle streams to a staging
		// temp file (never an allocation by declared size — a hostile
		// INDEX cannot OOM us), is sha-verified as a whole, and each part
		// is then served via a SectionReader with its own digest check.
		// The streamed bundle file lives OUTSIDE staging (a sibling temp
		// dir under .materialize): only the SPLIT part files may land in
		// the final artifact — a stray BUNDLE object would ship with it
		// and break the operation-root verifier.
		bundleDir, berr := os.MkdirTemp(stagingRoot, "bundle-")
		if berr != nil {
			return berr
		}
		defer os.RemoveAll(bundleDir)
		bundlePath, err := fetchKeyToFile(ctx, store, ArtifactKey(id, BundleName), index.Bundle.Digest, index.Bundle.Size, bundleDir)
		if err != nil {
			return fmt.Errorf("fetch bundle: %w", err)
		}
		bundleFile, err := os.Open(bundlePath)
		if err != nil {
			return err
		}
		defer bundleFile.Close()
		bfi, err := bundleFile.Stat()
		if err != nil {
			return err
		}
		// Part whitelist FIRST: the parts must EXACTLY cover the LOCAL
		// expected file set (computed above from the artifact shape, not
		// trusted from the INDEX), every name a safe basename (a traversal
		// would escape staging), no duplicates, no extras, no omissions.
		expected := make(map[string]struct{}, len(files))
		for _, name := range files {
			expected[name] = struct{}{}
		}
		seenParts := make(map[string]struct{}, len(index.Bundle.Parts))
		for _, part := range index.Bundle.Parts {
			if part.Name == "" || part.Name == "." || part.Name == ".." || strings.ContainsAny(part.Name, "/\\\x00") {
				return fmt.Errorf("bundle part name %q is not a safe basename", part.Name)
			}
			if _, ok := expected[part.Name]; !ok {
				return fmt.Errorf("bundle part %s is not among the artifact's expected files", part.Name)
			}
			want, ok := index.Files[part.Name]
			if !ok || !checkpointchunks.ValidDigest(want) {
				return fmt.Errorf("bundle part %s has no valid index digest", part.Name)
			}
			if part.Digest != want {
				return fmt.Errorf("bundle part %s digest %s disagrees with the index file digest", part.Name, part.Digest)
			}
			if _, dup := seenParts[part.Name]; dup {
				return fmt.Errorf("bundle part %s listed twice", part.Name)
			}
			seenParts[part.Name] = struct{}{}
		}
		for name := range expected {
			if _, covered := seenParts[name]; !covered {
				return fmt.Errorf("expected file %s missing from the bundle parts", name)
			}
		}
		// EXACT set equality, both directions: index.Files may not carry
		// extra keys beyond the artifact's expected file set either.
		for name := range index.Files {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("index lists unexpected file %s", name)
			}
		}
		for _, part := range index.Bundle.Parts {
			want := index.Files[part.Name]
			// Subtraction-based bound: part.Offset+part.Length can overflow
			// int64 on a hostile INDEX; bfi.Size()-part.Offset cannot.
			// Zero/negative lengths are rejected outright.
			if part.Length <= 0 || part.Offset < 8 || bfi.Size()-part.Offset < part.Length {
				return fmt.Errorf("bundle part %s span out of range", part.Name)
			}
			// STREAM the part out (SectionReader -> temp file, hashing while
			// copying): memory is O(copy buffer), never O(part) — a
			// multi-hundred-MiB overlay part must not be allocated whole.
			if err := streamSectionToFile(ctx, bundleFile, part.Offset, part.Length, want, staging, part.Name); err != nil {
				return fmt.Errorf("bundle part %s: %w", part.Name, err)
			}
		}
	default:
		// Pre-bundle artifact: per-file objects under the ID namespace,
		// streamed to staging with digest verification — the whole-file
		// overlay object of legacy artifacts can be arbitrarily large and
		// must never be buffered in memory.
		for _, name := range files {
			want, recorded := index.Files[name]
			if !recorded {
				return fmt.Errorf("index has no entry for %s", name)
			}
			if _, err := fetchKeyToFile(ctx, store, ArtifactKey(id, name), want, -1, staging); err != nil {
				return fmt.Errorf("fetch %s: %w", name, err)
			}
		}
	}
	// Closure check (F5): three authorities must agree before the artifact
	// is committed — the chunk sidecar (what bytes exist per offset), the
	// INDEX (what the publisher advertised), and the Firecracker manifest
	// (what the runtime will actually restore). Any pairwise disagreement
	// means the sidecar describes a different file than this checkpoint
	// owns, and an unknown digest mode is rejected rather than waived.
	var fcManifest struct {
		MemorySize       int64             `json:"memory_size"`
		Digests          map[string]string `json:"digests"`
		MemoryDigestMode string            `json:"memory_digest_mode"`
	}
	if raw, err := os.ReadFile(filepath.Join(staging, "manifest.json")); err != nil {
		return fmt.Errorf("read Firecracker manifest for closure check: %w", err)
	} else if err := json.Unmarshal(raw, &fcManifest); err != nil {
		return fmt.Errorf("decode Firecracker manifest for closure check: %w", err)
	}
	sidecar, err := checkpointchunks.LoadTransport(staging)
	if err != nil {
		return fmt.Errorf("verify sidecar against index: %w", err)
	}
	switch sidecar.FileDigestMode {
	case checkpointchunks.FileDigestChunks:
		if root := checkpointchunks.RootDigest(sidecar.Entries); root != index.MemoryRoot {
			return fmt.Errorf("index memory root %s does not match sidecar root %s",
				index.MemoryRoot, root)
		}
	case checkpointchunks.FileDigestSha256:
		// Sequential-hash sidecars cannot be root-rederived without the
		// whole file, but the recorded digest must still agree with both
		// the INDEX and the Firecracker manifest below.
	default:
		return fmt.Errorf("sidecar carries unknown file digest mode %q", sidecar.FileDigestMode)
	}
	if index.MemoryRoot != "" && sidecar.FileDigest != index.MemoryRoot {
		return fmt.Errorf("index memory root %s does not match sidecar file digest %s",
			index.MemoryRoot, sidecar.FileDigest)
	}
	if index.ChunkCount != sidecar.ChunkCount {
		return fmt.Errorf("index chunk count %d does not match sidecar %d",
			index.ChunkCount, sidecar.ChunkCount)
	}
	if fcManifest.MemorySize != sidecar.FileSize {
		return fmt.Errorf("Firecracker manifest memory size %d does not match sidecar file size %d",
			fcManifest.MemorySize, sidecar.FileSize)
	}
	if fcDigest, ok := fcManifest.Digests["memory"]; ok && fcDigest != sidecar.FileDigest {
		return fmt.Errorf("Firecracker manifest memory digest %s does not match sidecar %s",
			fcDigest, sidecar.FileDigest)
	}
	if index.OverlayChunks {
		if opts.Cache != nil {
			// Restore pin: keep the overlay working set eviction-protected
			// while this rebuild runs (memory chunks are fetched lazily by
			// the uffd handler later, which holds its own runtime pin). With
			// eviction armed a failed pin is FATAL — continuing unpinned
			// would silently drop the pin gate (G); unarmed, the pin has
			// nothing to protect against and the failure is non-fatal.
			if scan, serr := checkpointchunks.LoadNamed(staging, OverlaySidecarName); serr == nil {
				release, perr := opts.Cache.PinContext(ctx, fmt.Sprintf("materialize-%s-%d", id, os.Getpid()), overlayPinDigests(scan))
				if err := restorePinDecision(opts.Cache, perr); err != nil {
					return err
				}
				if release != nil {
					defer release()
				}
			}
		}
		if err := materializeOverlayChunks(ctx, staging, id, store, opts.Cache, opts.OverlayWorkers); err != nil {
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

// MemoryVerification summarizes a full memory-transport walk.
type MemoryVerification struct {
	ChunksVerified int   `json:"chunks_verified"`
	ZeroSkipped    int   `json:"zero_skipped"`
	PacksRead      int   `json:"packs_read"`
	CompressedRead int   `json:"compressed_read"`
	PlainRead      int   `json:"plain_read"`
	BytesVerified  int64 `json:"bytes_verified"`
}

// VerifyMemoryTransport verifies a LOCAL transport sidecar against the
// store. The sidecar must already carry the encoding view (pack refs /
// compression marker): a sealed local sidecar describes only plain,
// unpacked publication, because publishers never rewrite it in compress or
// pack mode. Verifying a PUBLISHED artifact must use VerifyMemoryArtifact,
// which resolves the encoding view from the remote INDEX.

func VerifyMemoryTransport(ctx context.Context, dir string, store chunkstore.Keyed) (MemoryVerification, error) {
	var out MemoryVerification
	transport, err := checkpointchunks.LoadTransport(dir)
	if err != nil {
		return out, fmt.Errorf("load transport sidecar: %w", err)
	}
	return verifyTransportEntries(ctx, transport, store)
}

// VerifyMemoryArtifact verifies the memory transport of a PUBLISHED
// artifact: it resolves the transport sidecar from the remote INDEX (the
// publisher uploads its encoding view there — pack/compress markers never
// touch the sealed local sidecar), cross-checks the sidecar's memory
// identity against what the INDEX declares, then checks every chunk
// against the store exactly as a materializing consumer would read it.
func VerifyMemoryArtifact(ctx context.Context, id string, store chunkstore.Keyed) (MemoryVerification, error) {
	var out MemoryVerification
	index, sidecarRaw, err := resolveArtifactSidecar(ctx, id, store)
	if err != nil {
		return out, err
	}
	transport, err := checkpointchunks.DecodeTransport(sidecarRaw)
	if err != nil {
		return out, fmt.Errorf("decode transport sidecar: %w", err)
	}
	// Identity closure: the sidecar must describe EXACTLY the memory the
	// INDEX vouches for — root digest, chunk count and declared file size —
	// otherwise the verification only proves a self-consistent sidecar+chunk
	// set, not this artifact's memory.
	if transport.FileDigest != index.MemoryRoot {
		return out, fmt.Errorf("transport root %s disagrees with index memory root %s", transport.FileDigest, index.MemoryRoot)
	}
	if transport.ChunkCount != index.ChunkCount {
		return out, fmt.Errorf("transport chunk count %d disagrees with index %d", transport.ChunkCount, index.ChunkCount)
	}
	if index.ChunkCount != len(transport.Entries) {
		return out, fmt.Errorf("transport entries %d disagree with declared chunk count %d", len(transport.Entries), index.ChunkCount)
	}
	return verifyTransportEntries(ctx, transport, store)
}

// resolveArtifactSidecar validates the artifact INDEX (same rules
// materialize applies to the file set it consumes) and returns the
// digest-verified chunk sidecar bytes. Shared by Materialize and the
// verifier so the two resolvers cannot drift.
func resolveArtifactSidecar(ctx context.Context, id string, store chunkstore.Keyed) (*ArtifactIndex, []byte, error) {
	indexRaw, err := fetchKeyBounded(ctx, store, ArtifactKey(id, IndexName), maxIndexBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch artifact index: %w", err)
	}
	var index ArtifactIndex
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		return nil, nil, fmt.Errorf("decode artifact index: %w", err)
	}
	if index.CheckpointID != id {
		return nil, nil, fmt.Errorf("index is for %q, requested %q", index.CheckpointID, id)
	}
	if err := validateIndexBundle(&index); err != nil {
		return nil, nil, fmt.Errorf("artifact %s: %w", id, err)
	}
	want, recorded := index.Files[checkpointchunks.ManifestName]
	if !recorded || !checkpointchunks.ValidDigest(want) {
		return nil, nil, fmt.Errorf("index has no valid digest for the chunk sidecar")
	}
	var sidecarRaw []byte
	switch {
	case index.Bundle != nil:
		// Same whitelist discipline as materialize: every part a safe
		// basename, no duplicates, spans bounded by subtraction, part
		// digest equal to the index file digest — then extract the sidecar.
		seen := make(map[string]struct{}, len(index.Bundle.Parts))
		var sidecar *BundlePart
		for i := range index.Bundle.Parts {
			part := index.Bundle.Parts[i]
			if part.Name == "" || part.Name == "." || part.Name == ".." || strings.ContainsAny(part.Name, "/\\\x00") {
				return nil, nil, fmt.Errorf("bundle part name %q is not a safe basename", part.Name)
			}
			if _, dup := seen[part.Name]; dup {
				return nil, nil, fmt.Errorf("bundle part %s listed twice", part.Name)
			}
			seen[part.Name] = struct{}{}
			partWant, ok := index.Files[part.Name]
			if !ok || part.Digest != partWant {
				return nil, nil, fmt.Errorf("bundle part %s digest disagrees with the index file digest", part.Name)
			}
			if part.Name == checkpointchunks.ManifestName {
				sidecar = &index.Bundle.Parts[i]
			}
		}
		if sidecar == nil {
			return nil, nil, fmt.Errorf("bundle carries no chunk sidecar part")
		}
		bundlePath, err := fetchKeyToTempFile(ctx, store, ArtifactKey(id, BundleName), index.Bundle.Digest, index.Bundle.Size)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch bundle: %w", err)
		}
		defer os.Remove(bundlePath)
		bf, err := os.Open(bundlePath)
		if err != nil {
			return nil, nil, err
		}
		defer bf.Close()
		bfi, err := bf.Stat()
		if err != nil {
			return nil, nil, err
		}
		if sidecar.Length <= 0 || sidecar.Length > maxIndexBytes || sidecar.Offset < 8 || bfi.Size()-sidecar.Offset < sidecar.Length {
			return nil, nil, fmt.Errorf("chunk sidecar bundle span out of range")
		}
		body := make([]byte, sidecar.Length)
		if _, err := io.ReadFull(io.NewSectionReader(bf, sidecar.Offset, sidecar.Length), body); err != nil {
			return nil, nil, fmt.Errorf("read chunk sidecar part: %w", err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != want {
			return nil, nil, fmt.Errorf("chunk sidecar digest mismatch: index %s bundle %s", want, got)
		}
		sidecarRaw = body
	default:
		// Legacy per-file object: EXCLUSIVE temp dir (never a shared fixed
		// final name), declared-size bounded, digest verified, removed on
		// exit, and hard-capped at maxIndexBytes before buffering.
		tmpDir, derr := os.MkdirTemp("", "verify-sidecar-*")
		if derr != nil {
			return nil, nil, derr
		}
		defer os.RemoveAll(tmpDir)
		path, size, err := fetchKeyToFileAtMost(ctx, store, ArtifactKey(id, checkpointchunks.ManifestName), want, maxIndexBytes, tmpDir)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch chunk sidecar: %w", err)
		}
		if size > maxIndexBytes {
			return nil, nil, fmt.Errorf("chunk sidecar exceeds the %d-byte bound", maxIndexBytes)
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, nil, rerr
		}
		sidecarRaw = raw
	}
	return &index, sidecarRaw, nil
}

func verifyTransportEntries(ctx context.Context, transport *checkpointchunks.Manifest, store chunkstore.Keyed) (MemoryVerification, error) {
	var out MemoryVerification
	rangeReader, _ := store.(chunkstore.RangeReader)
	for i, entry := range transport.Entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		length := int64(min(int64(transport.ChunkBytes), transport.FileSize-entry.Offset))
		if length <= 0 {
			return out, fmt.Errorf("entry %d has non-positive length", i)
		}
		if entry.Digest == checkpointchunks.ZeroChunkDigest(int(length)) {
			out.ZeroSkipped++
			continue
		}
		var body []byte
		switch {
		case func() bool { _, ok := transport.Packs[entry.Digest]; return ok }():
			ref := transport.Packs[entry.Digest]
			if rangeReader == nil {
				return out, fmt.Errorf("store cannot range-read pack for %s", entry.Digest[:12])
			}
			key, err := ref.Key()
			if err != nil {
				return out, err
			}
			data, err := rangeReader.ReadKeyRange(ctx, key, chunkstore.ObjectRange{Offset: ref.Offset, Length: ref.Length, ObjectSize: ref.ObjectSize})
			if err != nil {
				return out, fmt.Errorf("fetch packed chunk %s: %w", entry.Digest[:12], err)
			}
			body = data
			out.PacksRead++
		case transport.Compression == checkpointchunks.CompressionZstd:
			rc, err := store.GetKey(ctx, chunkstore.CompressedKey(entry.Digest))
			if err == nil {
				compressed, rerr := chunkstore.ReadBounded(rc, chunkstore.MaxCompressedChunkBytes(length))
				rc.Close()
				if rerr != nil {
					return out, fmt.Errorf("read compressed chunk %s: %w", entry.Digest[:12], rerr)
				}
				plain, derr := chunkstore.DecompressChunkBody(compressed, int(length))
				if derr != nil {
					return out, fmt.Errorf("decompress chunk %s: %w", entry.Digest[:12], derr)
				}
				body = plain
				out.CompressedRead++
			} else if chunkstore.IsNotFound(err) {
				// Chunks shared with pre-compression generations keep their
				// plain objects — same fallback the consumer performs
				// (chunkstore.IsNotFound: local ENOENT and HTTP 404 alike).
				// Same bounded exact-length read as the default branch: an
				// overlong plain body is rejected, never buffered whole.
				rc, err2 := store.GetKey(ctx, entry.Digest[:2]+"/"+entry.Digest)
				if err2 != nil {
					return out, fmt.Errorf("fetch chunk %s: %w (compressed: %v)", entry.Digest[:12], err2, err)
				}
				raw, rerr := io.ReadAll(io.LimitReader(rc, length+1))
				rc.Close()
				if rerr != nil {
					return out, fmt.Errorf("read chunk %s: %w", entry.Digest[:12], rerr)
				}
				if int64(len(raw)) > length {
					return out, fmt.Errorf("chunk %s body longer than %d bytes", entry.Digest[:12], length)
				}
				body = raw
				out.PlainRead++
			} else {
				return out, fmt.Errorf("fetch compressed chunk %s: %w", entry.Digest[:12], err)
			}
		default:
			rc, err := store.GetKey(ctx, entry.Digest[:2]+"/"+entry.Digest)
			if err != nil {
				return out, fmt.Errorf("fetch chunk %s: %w", entry.Digest[:12], err)
			}
			// Bounded exact-length read: short AND overlong bodies are both
			// rejected (an unbounded ReadAll would buffer whatever the store
			// sends and only the length check below would notice).
			raw, rerr := io.ReadAll(io.LimitReader(rc, length+1))
			rc.Close()
			if rerr != nil {
				return out, fmt.Errorf("read chunk %s: %w", entry.Digest[:12], rerr)
			}
			if int64(len(raw)) > length {
				return out, fmt.Errorf("chunk %s body longer than %d bytes", entry.Digest[:12], length)
			}
			body = raw
			out.PlainRead++
		}
		if int64(len(body)) != length {
			return out, fmt.Errorf("chunk %s length %d, sidecar says %d", entry.Digest[:12], len(body), length)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != entry.Digest {
			return out, fmt.Errorf("chunk %s digest mismatch: sidecar %s fetched %s",
				entry.Digest[:12], entry.Digest[:12], hex.EncodeToString(sum[:]))
		}
		out.ChunksVerified++
		out.BytesVerified += length
	}
	if transport.FileDigestMode == checkpointchunks.FileDigestChunks {
		if root := checkpointchunks.RootDigest(transport.Entries); root != transport.FileDigest {
			return out, fmt.Errorf("transport root mismatch")
		}
	}
	return out, nil
}

// restorePinDecision encodes the pin gate (G): with eviction ARMED a
// failed restore pin is fatal — continuing unpinned would silently drop the
// pin gate; unarmed, the pin has nothing to protect against.
func restorePinDecision(cache *chunkcache.Manager, pinErr error) error {
	if pinErr == nil {
		return nil
	}
	if cache.WatermarksArmed() {
		return fmt.Errorf("restore pin (eviction armed): %w", pinErr)
	}
	return nil
}

// overlayPinDigests lists a sidecar's unique nonzero chunk digests — the
// entries that have store objects (and therefore cache entries) to protect.
func overlayPinDigests(scan *checkpointchunks.Manifest) []string {
	if scan == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(scan.Entries))
	digests := make([]string, 0, len(scan.Entries))
	for _, entry := range scan.Entries {
		length := int(min(int64(scan.ChunkBytes), scan.FileSize-entry.Offset))
		if length > 0 && entry.Digest == checkpointchunks.ZeroChunkDigest(length) {
			continue
		}
		if _, dup := seen[entry.Digest]; dup {
			continue
		}
		seen[entry.Digest] = struct{}{}
		digests = append(digests, entry.Digest)
	}
	return digests
}

// materializeOverlayChunks reassembles the writable layer from digest-keyed
// chunk objects: unique digests only, all-zero chunks synthesized as sparse
// holes (no GET, no write), bounded-concurrency GETs, and legacy per-ID keys
// probed as fallback so checkpoints published before the global namespace
// remain restorable. Each verified body is written straight to every
// referencing offset and released, so peak heap is bounded by
// overlayWorkers x chunk bytes rather than the total unique payload (F7).
// A non-nil node cache fronts every GET: the cache verifies and publishes
// atomically, so a repeated restore of the same blocks stays on-node.
func materializeOverlayChunks(
	ctx context.Context,
	targetDir, id string,
	store chunkstore.Keyed,
	cache *chunkcache.Manager,
	overlayWorkers int,
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
	// One job per unique digest, carrying every offset that references it:
	// a worker fetches, verifies, writes all references, and releases the
	// buffer before taking the next digest.
	type ref struct {
		offset int64
		length int
	}
	jobs := make(map[string][]ref, len(scan.Entries))
	order := make([]string, 0, len(scan.Entries))
	for _, entry := range scan.Entries {
		length := int(min(int64(scan.ChunkBytes), scan.FileSize-entry.Offset))
		// A zero digest proves only its own length, including a short tail.
		if entry.Digest == checkpointchunks.ZeroChunkDigest(length) {
			continue
		}
		refs := jobs[entry.Digest]
		if len(refs) == 0 {
			order = append(order, entry.Digest)
		} else if refs[0].length != length {
			return fmt.Errorf("overlay chunk %s referenced with inconsistent lengths %d and %d", entry.Digest, refs[0].length, length)
		}
		jobs[entry.Digest] = append(refs, ref{offset: entry.Offset, length: length})
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
	fetchBody := func(digest string) ([]byte, bool) {
		expected := jobs[digest][0].length
		download := func(c context.Context) ([]byte, error) {
			rc, err := store.GetKey(c, OverlayChunkKey(digest))
			if err != nil {
				// Legacy namespace fallback for artifacts published before
				// the global one — and ONLY for a genuinely absent global
				// key (P1-E): a permission, network, or transport error on
				// the global key must surface as-is, never be masked by a
				// second probe against the legacy namespace.
				if !chunkstore.IsNotFound(err) {
					return nil, fmt.Errorf("fetch overlay chunk %s: %w", digest[:12], err)
				}
				rc2, err2 := store.GetKey(c, legacyOverlayChunkKey(id, digest))
				if err2 != nil {
					return nil, fmt.Errorf("fetch overlay chunk %s: %w (legacy: %w)", digest[:12], err, err2)
				}
				rc = rc2
			}
			defer rc.Close()
			body, err := io.ReadAll(io.LimitReader(rc, int64(expected)+1))
			if err != nil {
				return nil, fmt.Errorf("read overlay chunk %s: %w", digest[:12], err)
			}
			if len(body) != expected {
				return nil, fmt.Errorf("overlay chunk %s length mismatch: expected %d got %d", digest, expected, len(body))
			}
			return body, nil
		}
		var body []byte
		var err error
		if cache != nil {
			// The cache verifies length+digest and publishes atomically;
			// its miss closure is the store download above. Repeated
			// restores of overlapping blocks stay on-node.
			body, err = cache.Fetch(ctx, digest, int64(expected), download)
		} else {
			body, err = download(ctx)
			if err == nil {
				sum := sha256.Sum256(body)
				if hex.EncodeToString(sum[:]) != digest {
					err = fmt.Errorf("overlay chunk digest mismatch: sidecar %s fetched %s",
						digest, hex.EncodeToString(sum[:]))
				}
			}
		}
		if err != nil {
			failJob(err)
			return nil, false
		}
		return body, true
	}
	queue := make(chan string)
	var wg sync.WaitGroup
	workers := overlayWorkerCount(overlayWorkers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for digest := range queue {
				if failed.Load() {
					continue // drain
				}
				body, ok := fetchBody(digest)
				if !ok {
					continue
				}
				for _, r := range jobs[digest] {
					if _, err := overlay.WriteAt(body[:r.length], r.offset); err != nil {
						failJob(fmt.Errorf("write overlay chunk at %d: %w", r.offset, err))
						break
					}
				}
				// body goes out of scope: the next job reuses the heap.
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
	return overlay.Truncate(scan.FileSize)
}

// copyWithContext copies with periodic context cancellation checks (the
// HTTP body itself may block indefinitely otherwise) and SHORT-WRITE
// detection: a Write that accepts fewer bytes than offered is an error,
// not a silent truncation.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			written += int64(wn)
			if werr != nil {
				return written, werr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
		}
		if rerr == io.EOF {
			return written, nil
		}
		if rerr != nil {
			return written, rerr
		}
	}
}

// streamSectionToFile copies [offset, offset+length) of f into
// <staging>/.part-<name>, hashing while copying, and renames to the final
// name only after the digest check — O(buffer) memory for any part size.
func streamSectionToFile(ctx context.Context, f *os.File, offset, length int64, wantDigest, staging, name string) error {
	tmp, err := os.CreateTemp(staging, ".part-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	final := filepath.Join(staging, name)
	fail := func(e error) error {
		tmp.Close()
		os.Remove(tmpName)
		return e
	}
	hash := sha256.New()
	section := io.NewSectionReader(f, offset, length)
	buf := make([]byte, 1<<20)
	written, cerr := copyWithContext(ctx, io.MultiWriter(tmp, hash), section, buf)
	if cerr != nil {
		return fail(cerr)
	}
	// Close the contract: a short copy is an error even though the temp
	// file is private.
	if written != length {
		return fail(fmt.Errorf("short copy: %d of %d bytes", written, length))
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != wantDigest {
		return fail(fmt.Errorf("digest mismatch: index %s extracted %s", wantDigest, got))
	}
	if serr := tmp.Sync(); serr != nil {
		return fail(serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpName)
		return cerr
	}
	return os.Rename(tmpName, final)
}

// maxIndexBytes bounds the INDEX object: it is a small manifest; anything
// larger is a hostile or corrupt store, not something to buffer whole.
// (Generic fetchKey stays UNBOUNDED for legitimate large objects; the
// INDEX call site uses fetchKeyBounded explicitly.)
const maxIndexBytes = 64 << 20

// fetchKeyToFile streams an object to <staging>/.fetch-<basename(key)> ,
// hashing while copying, and renames it to the FINAL name inside staging on
// success. declared == -1 means no declared-size cross-check (digest still
// binds the bytes). Memory use is O(buffer), never O(object): hostile or
// simply large objects cannot OOM the restore path.
func fetchKeyToFile(ctx context.Context, store chunkstore.Keyed, key, wantDigest string, declared int64, staging string) (string, error) {
	if !checkpointchunks.ValidDigest(wantDigest) {
		return "", fmt.Errorf("digest for %s is not a valid sha256 hex string", key)
	}
	if declared > 1<<40 {
		return "", fmt.Errorf("object %s declared size %d exceeds the %d-byte ceiling", key, declared, int64(1<<40))
	}
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	base := path.Base(strings.ReplaceAll(key, "\\", "/"))
	if base == "." || base == ".." || base == "/" || strings.ContainsAny(base, "\x00") {
		return "", fmt.Errorf("object key %q yields unsafe file name", key)
	}
	tmp, err := os.CreateTemp(staging, ".fetch-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	final := filepath.Join(staging, base)
	fail := func(e error) (string, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", e
	}
	hash := sha256.New()
	buf := make([]byte, 1<<20)
	// A declared size is a HARD STREAM BOUND: the copy reads at most
	// declared+1 bytes (one extra detects overlong bodies), so a hostile
	// INDEX cannot make an arbitrarily large object fill the staging disk
	// before the length check. declared < 0 keeps the historical unbounded
	// stream for legacy artifacts whose sizes were never declared.
	var src io.Reader = rc
	if declared >= 0 {
		src = io.LimitReader(rc, declared+1)
	}
	written, cerr := copyWithContext(ctx, io.MultiWriter(tmp, hash), src, buf)
	if cerr != nil {
		return fail(cerr)
	}
	if declared >= 0 {
		if written > declared {
			return fail(fmt.Errorf("object %s exceeds its declared %d bytes (read %d)", key, declared, written))
		}
		if written < declared {
			return fail(fmt.Errorf("object %s is short: read %d, declared %d", key, written, declared))
		}
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != wantDigest {
		return fail(fmt.Errorf("digest mismatch: index %s fetched %s", wantDigest, got))
	}
	if serr := tmp.Sync(); serr != nil {
		return fail(serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpName)
		return "", cerr
	}
	if rerr := os.Rename(tmpName, final); rerr != nil {
		os.Remove(tmpName)
		return "", rerr
	}
	return final, nil
}

// fetchKeyBounded reads at most limit bytes (bounded allocation). An object
// LARGER than the limit is rejected explicitly; shorter objects are the
// caller's business (digests and downstream checks bind content).
func fetchKeyBounded(ctx context.Context, store chunkstore.Keyed, key string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("object %s bound %d not positive", key, limit)
	}
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, rerr := io.ReadAll(io.LimitReader(rc, limit+1))
	if rerr != nil {
		return nil, rerr
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("object %s exceeds the %d-byte bound", key, limit)
	}
	return raw, nil
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
