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

// Package checkpointpublish distributes a checkpoint's memory chunks to a
// chunk store and records the outcome in a persisted state machine:
//
//	local_ready -> publishing -> published
//	                    `-> publish_failed (retryable; Run resumes)
//
// Semantics the batch-3 plan pins: publishing is an external step (the
// checkpoint RPC returns before any of it — fail-open to local restore);
// only `published` unlocks cross-node placement; published objects are
// immutable and self-contained, so the source node can reclaim its local
// artifact once every consumer has fetched. State lives beside the
// catalogued artifact roots, not inside the sealed checkpoint directory.
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/internal/sha256batch"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

const packPayloadBudget = 16 << 20
const maxPackPayloadBudget = 64 << 20

// PackTimings reports wall-clock phases and summed worker times in nanoseconds.
// BuildTotal and UploadTotal overlap across workers: neither is CPU time.
type PackTimings struct {
	Prepare     time.Duration `json:"prepare_ns"`
	Classify    time.Duration `json:"classify_ns"`
	PackWall    time.Duration `json:"pack_wall_ns"`
	BuildTotal  time.Duration `json:"build_total_ns"`
	UploadTotal time.Duration `json:"upload_total_ns"`
	Artifacts   time.Duration `json:"artifacts_ns"`
}

func validPackedID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?#%")
}

// parallelPackWork cancels sibling requests on the first failure, and always
// joins workers before their buffers or shared result maps leave scope.
func parallelPackWork(ctx context.Context, n, workers int, fn func(context.Context, int) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if err := fn(ctx, i); err != nil {
					once.Do(func() { first = err; cancel() })
				}
			}
		}()
	}
loop:
	for i := 0; i < n; i++ {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

func packedMemoryClosure(m *checkpointchunks.Manifest, raw []byte) error {
	if err := checkpointchunks.ValidateTransport(m); err != nil {
		return err
	}
	if m.File != "memory" || m.FileSize <= 0 || m.FileDigestMode != checkpointchunks.FileDigestChunks || checkpointchunks.RootDigest(m.Entries) != m.FileDigest {
		return fmt.Errorf("packed publication requires sealed memory in chunks digest mode")
	}
	var fc struct {
		MemorySize       int64             `json:"memory_size"`
		MemoryDigestMode string            `json:"memory_digest_mode"`
		Digests          map[string]string `json:"digests"`
	}
	if err := json.Unmarshal(raw, &fc); err != nil {
		return err
	}
	if fc.MemorySize != m.FileSize || fc.MemoryDigestMode != m.FileDigestMode || fc.Digests["memory"] != m.FileDigest {
		return fmt.Errorf("Firecracker manifest and packed memory identity disagree")
	}
	return nil
}

func boundedPackMetadata(ctx context.Context, store chunkstore.Keyed, key string) ([]byte, error) {
	const limit = 64 << 20
	body, err := store.GetKey(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("pack metadata %s exceeds size bound", key)
	}
	return raw, nil
}

// fetchKeyToFileAtMost streams an object into an EXCLUSIVE temp file inside
// tempDir, accepting at most maxBytes (a LimitReader(max+1) hard-stops the
// copy; an overlong object fails immediately without ever buffering past
// the bound), verifies the digest of the accepted bytes, and atomically
// renames within tempDir. Unlike fetchKeyToFile (EXACT declared length),
// the size is an UPPER bound: shorter objects are the caller's business.
// Returns the final path and the actual size.
func fetchKeyToFileAtMost(ctx context.Context, store chunkstore.Keyed, key, wantDigest string, maxBytes int64, tempDir string) (string, int64, error) {
	if !checkpointchunks.ValidDigest(wantDigest) {
		return "", 0, fmt.Errorf("digest for %s is not a valid sha256 hex string", key)
	}
	if maxBytes <= 0 {
		return "", 0, fmt.Errorf("object %s bound %d not positive", key, maxBytes)
	}
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp(tempDir, ".sidetmp-*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	fail := func(e error) (string, int64, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", 0, e
	}
	hash := sha256.New()
	buf := make([]byte, 1<<20)
	written, cerr := copyWithContext(ctx, io.MultiWriter(tmp, hash), io.LimitReader(rc, maxBytes+1), buf)
	if cerr != nil {
		return fail(cerr)
	}
	if written > maxBytes {
		return fail(fmt.Errorf("object %s exceeds the %d-byte bound (read %d)", key, maxBytes, written))
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != wantDigest {
		return fail(fmt.Errorf("digest mismatch: index %s fetched %s", wantDigest, got))
	}
	if serr := tmp.Sync(); serr != nil {
		return fail(serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpName)
		return "", 0, cerr
	}
	final := filepath.Join(tempDir, "sidecar.bin")
	if rerr := os.Rename(tmpName, final); rerr != nil {
		os.Remove(tmpName)
		return "", 0, rerr
	}
	return final, written, nil
}

// fetchKeyToTempFile streams an object into a process-temp file, hashing
// while copying (context-aware; O(buffer) memory for any object size), and
// verifies the whole-object digest and declared size before returning the
// path. The CALLER removes the file.
func fetchKeyToTempFile(ctx context.Context, store chunkstore.Keyed, key, wantDigest string, declared int64) (string, error) {
	if !checkpointchunks.ValidDigest(wantDigest) {
		return "", fmt.Errorf("digest for %s is not a valid sha256 hex string", key)
	}
	if declared <= 0 || declared > 1<<40 {
		return "", fmt.Errorf("object %s declared size %d out of bounds", key, declared)
	}
	rc, err := store.GetKey(ctx, key)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp("", "pack-baseline-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	fail := func(e error) (string, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", e
	}
	hash := sha256.New()
	buf := make([]byte, 1<<20)
	// The declared size is a HARD STREAM BOUND: the copy reads at most
	// declared+1 bytes (one extra detects an overlong body), so a hostile
	// INDEX declaring 1KiB cannot make a huge object fill the temp
	// directory before the length check fires.
	written, cerr := copyWithContext(ctx, io.MultiWriter(tmp, hash), io.LimitReader(rc, declared+1), buf)
	if cerr != nil {
		return fail(cerr)
	}
	if written > declared {
		return fail(fmt.Errorf("object %s exceeds its declared %d bytes (read %d)", key, declared, written))
	}
	if written < declared {
		return fail(fmt.Errorf("object %s is short: read %d, declared %d", key, written, declared))
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != wantDigest {
		return fail(fmt.Errorf("digest mismatch: index %s fetched %s", wantDigest, got))
	}
	if serr := tmp.Sync(); serr != nil {
		return fail(serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpName)
		return "", cerr
	}
	return tmpName, nil
}

func loadPackBaseline(ctx context.Context, store chunkstore.Keyed, id string) (*checkpointchunks.Manifest, error) {
	// Shared extraction chain (artifact_verify.go): INDEX identity + bundle
	// declaration + ONE bundle GET with exact length and whole-object
	// digest + part whitelist/digest/span checks + sidecar/INDEX closure —
	// the same fail-closed strength as materialization, one implementation.
	index, err := FetchVerifiedIndex(ctx, store, id)
	if err != nil {
		return nil, err
	}
	files, err := FetchVerifiedSidecars(ctx, store, id, index,
		[]string{checkpointchunks.ManifestName, "manifest.json"})
	if err != nil {
		return nil, err
	}
	m, err := checkpointchunks.DecodeTransport(files[checkpointchunks.ManifestName])
	if err != nil {
		return nil, err
	}
	if err := VerifySidecarIndexClosure(m, index); err != nil {
		return nil, err
	}
	if err := packedMemoryClosure(m, files["manifest.json"]); err != nil {
		return nil, err
	}
	return m, nil
}

func runPacked(ctx context.Context, dir, id string, store chunkstore.Store, m *checkpointchunks.Manifest, state State, result Result, opts Options, class *chunkClassification) (Result, error) {
	phaseStart := time.Now()
	timings := &PackTimings{}
	result.PackTimings = timings
	// The packed stage's wall survives failures: any exit before the
	// success point below (classify, build, or a pack PUT dying) still
	// records PackWall. The success path caps it at the LAST PACK PUT —
	// the artifact-set stage after it keeps its own meta/index walls, so
	// PackWall never swallows them.
	packStageStart := phaseStart
	defer func() {
		if timings.PackWall == 0 && result.Phases != nil {
			result.Phases.PackWall = time.Since(packStageStart)
		}
	}()
	// Failure keeps the attempt's attribution: counters travel with the
	// instrumented store wrapper the caller installed.
	var counters *phaseCounters
	if inst, ok := store.(interface{ counters() *phaseCounters }); ok {
		counters = inst.counters()
	}
	fail := func(err error) (Result, error) { return failAttempt(&result, counters, state, err) }
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		return fail(fmt.Errorf("packed publication requires keyed store"))
	}
	if !validPackedID(id) || opts.PackBytes < m.ChunkBytes {
		return fail(fmt.Errorf("invalid packed checkpoint ID or pack smaller than chunk"))
	}
	if _, err := os.Stat(filepath.Join(dir, MaterializedMarker)); err == nil {
		return fail(fmt.Errorf("cannot republish a materialized memory placeholder"))
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fail(err)
	}
	if err := packedMemoryClosure(m, raw); err != nil {
		return fail(err)
	}
	transport := *m
	transport.Version = checkpointchunks.PackedVersion
	if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
		transport.Version = checkpointchunks.RootPackedVersion
	}
	transport.Packs = make(map[string]checkpointchunks.PackReference)
	if err := checkpointchunks.ValidateTransport(&transport); err != nil {
		return fail(err)
	}
	if err := writeStateMeasured(state, &result.StateTimings.Publishing); err != nil {
		return result, err
	}
	memory, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		return fail(err)
	}
	defer memory.Close()
	info, err := memory.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Size() != m.FileSize {
		return fail(fmt.Errorf("source memory size/type changed"))
	}
	var base *checkpointchunks.Manifest
	if opts.BaseID != "" {
		base, err = loadPackBaseline(ctx, keyed, opts.BaseID)
		if err != nil {
			// Context cancellation and deadline expiry are NEVER
			// auto-base fallbacks: a cancelled attempt must not continue
			// producing store operations under a dead context (which
			// would also fail, but semantically the attempt is over, not
			// "the parent was bad"). These hard-return for BOTH explicit
			// and auto origins.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return fail(fmt.Errorf("load pack baseline: %w", err))
			}
			if opts.autoBaseOrigin {
				// Auto-resolved base: the hint was a performance
				// optimization, never a correctness requirement. Parent
				// unavailability, corruption, or identity mismatch falls
				// back to a no-base publish under the SAME ctx — no
				// preflight, no second read, no TOCTOU window. Context
				// errors were already handled above. The decision record
				// flips to reflect the fallback; the actual reuse amount
				// (packs_skip) stays the ground truth for what was
				// actually salvaged from the baseline.
				base = nil
				if result.AutoBase != nil {
					result.AutoBase.Used = false
					result.AutoBase.Reason = autoBaseUnavailable
				}
			} else {
				// Explicit -base-id: the caller named this parent; a
				// failure to load it is a hard error (historical
				// semantics unchanged).
				return fail(fmt.Errorf("load pack baseline: %w", err))
			}
		}
	}
	timings.Prepare = time.Since(phaseStart)
	phaseStart = time.Now()
	unique := uniqueSortedChunks(m)
	parentPacks := map[string]bool{}
	if base != nil {
		for _, c := range unique {
			if ref, ok := base.Packs[c.Digest]; ok {
				if ref.Length != min(int64(m.ChunkBytes), m.FileSize-c.Offset) {
					return fail(fmt.Errorf("baseline chunk length differs"))
				}
				key, err := ref.Key()
				if err != nil {
					return fail(err)
				}
				parentPacks[key] = false
			}
		}
		keys := []string{}
		for digest := range parentPacks {
			keys = append(keys, digest)
		}
		present := make([]bool, len(keys))
		err = parallelPackWork(ctx, len(keys), result.Workers, func(ctx context.Context, i int) error {
			var err error
			present[i], err = keyed.HasKey(ctx, keys[i])
			if err != nil {
				return err
			}
			if present[i] {
				// Sweep fence (probe only): a marked baseline pack is
				// scheduled for collection; min-age cannot protect the reuse.
				// Dropping the reuse routes those chunks through the local
				// repack below — nothing is uploaded under THIS key here, so
				// there is nothing to claim; the fresh pack gets the full
				// claim lifecycle at its own upload site.
				fenced, ferr := gcReuseFenced(ctx, keyed, keys[i])
				if ferr != nil {
					return ferr
				}
				present[i] = !fenced
			}
			return nil
		})
		if err != nil {
			return fail(err)
		}
		for i, k := range keys {
			parentPacks[k] = present[i]
			if present[i] {
				result.PacksSkip++
			}
		}
	}
	missing := make([]bool, len(unique))
	var mu sync.Mutex
	if class != nil {
		// Adaptive pack: the decision-time classification already probed
		// every unique digest — map its verdicts instead of probing again.
		// PARENT-PACK REUSE COMES FIRST: with a resolved base (explicit or
		// auto), a chunk whose digest lives in a parent pack that probed
		// present and unfenced adopts that pack reference into the
		// transport and skips — this is the only legitimate source for an
		// INHERITED digest (its local region is a hole; repacking it is
		// impossible). Only then do missing/refresh verdicts repack, and
		// an inherited chunk with no reusable parent pack fails closed
		// here — never by reading the local hole bytes.
		for i, c := range unique {
			if base != nil {
				if ref, ok := base.Packs[c.Digest]; ok {
					key, err := ref.Key()
					if err != nil {
						return fail(err)
					}
					if parentPacks[key] {
						transport.Packs[c.Digest] = ref
						if ref.Identity != "" {
							transport.Version = checkpointchunks.RootPackedVersion
						}
						result.ChunksSkip++
						continue
					}
				}
			}
			switch class.classByDigest[c.Digest] {
			case classMissing, classRefresh:
				if c.Inherited {
					return fail(fmt.Errorf(
						"inherited chunk %s at %d has no reusable parent pack; the parent generation's packs must be republished before this artifact",
						c.Digest[:12], c.Offset))
				}
				missing[i] = true
			default:
				result.ChunksSkip++
			}
		}
	} else {
		err = parallelPackWork(ctx, len(unique), result.Workers, func(ctx context.Context, i int) error {
			c := unique[i]
			length := min(int64(m.ChunkBytes), m.FileSize-c.Offset)
			var ref checkpointchunks.PackReference
			reuse := false
			if base != nil {
				ref, reuse = base.Packs[c.Digest]
				if reuse {
					key, err := ref.Key()
					if err != nil {
						return err
					}
					reuse = parentPacks[key]
				}
			}
			present := c.Digest == checkpointchunks.ZeroChunkDigest(int(length))
			if !present && !reuse && !opts.PackSkipChunkProbe {
				ok, err := store.Has(ctx, c.Digest)
				if err != nil {
					return err
				}
				if ok {
					// Sweep fence (probe only): a marked standalone object cannot
					// be leaned on — route the chunk through the local repack
					// instead. An inherited hole has no local bytes, so a marked
					// parent fails here rather than sealing zeros under its
					// digest. Nothing is uploaded under this key in this pass;
					// the pack that carries the bytes gets the claim lifecycle.
					fenced, ferr := gcReuseFenced(ctx, keyed, chunkstore.PlainKey(c.Digest))
					if ferr != nil {
						return ferr
					}
					if fenced && c.Inherited {
						return fmt.Errorf(
							"inherited chunk %s is marked for collection by a bucket sweep; the parent generation's object must be republished before this artifact",
							c.Digest[:12])
					}
					present = !fenced
				}
			}
			if present || reuse {
				mu.Lock()
				result.ChunksSkip++
				if reuse {
					transport.Packs[c.Digest] = ref
					if ref.Identity != "" {
						transport.Version = checkpointchunks.RootPackedVersion
					}
				}
				mu.Unlock()
			} else {
				if c.Inherited {
					// Same fail-closed outcome as the build-time digest
					// check, stated where the decision is made: a hole
					// can never hash to the inherited digest, and its
					// bytes must never be read into a pack.
					return fmt.Errorf(
						"inherited chunk %s at %d has no reusable parent pack; the parent generation's packs must be republished before this artifact",
						c.Digest[:12], c.Offset)
				}
				missing[i] = true
			}
			return nil
		})
	}
	if err != nil {
		return fail(err)
	}
	timings.Classify = time.Since(phaseStart)
	phaseStart = time.Now()
	type packJob struct {
		chunks []checkpointchunks.Chunk
		size   int
	}
	jobs := []packJob{}
	current := packJob{}
	for i, c := range unique {
		if !missing[i] {
			continue
		}
		n := int(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
		if current.size+n > opts.PackBytes {
			jobs = append(jobs, current)
			current = packJob{}
		}
		current.chunks = append(current.chunks, c)
		current.size += n
	}
	if current.size > 0 {
		jobs = append(jobs, current)
	}
	budget := opts.PackPayloadBytes
	if budget == 0 {
		budget = packPayloadBudget
	}
	result.PackPayloadBudget = budget
	result.Workers = min(result.Workers, budget/opts.PackBytes)
	var activePayload, peakPayload atomic.Int64
	err = parallelPackWork(ctx, len(jobs), result.Workers, func(ctx context.Context, i int) error {
		buildStart := time.Now()
		job := jobs[i]
		active := activePayload.Add(int64(job.size))
		for peak := peakPayload.Load(); active > peak; peak = peakPayload.Load() {
			if peakPayload.CompareAndSwap(peak, active) {
				break
			}
		}
		defer activePayload.Add(-int64(job.size))
		// Streaming verified PUT (opt-in): with chunks-v1 identity the pack
		// key derives from part metadata alone (digest + length per chunk,
		// never the pack bytes), so when the flag is on the full pack buffer
		// is NEVER allocated. Parts come straight from the manifest; source
		// verification (ReadAt + sha256 per chunk) happens inside the reader
		// while the store consumes it. Flag-off and legacy-identity runs
		// keep the historical buffer path below, byte for byte.
		streaming := opts.PackStreamingPut && opts.PackIdentity == checkpointchunks.PackIdentityChunks
		var buf []byte
		var digest string
		if streaming {
			parts := make([]checkpointchunks.PackPart, 0, len(job.chunks))
			for _, c := range job.chunks {
				parts = append(parts, checkpointchunks.PackPart{Digest: c.Digest, Length: int64(chunkByteLen(m, c))})
			}
			// Shadowed err on purpose: the outer err is shared by every
			// pack worker — assigning it here would be a data race.
			d, derr := checkpointchunks.PackRootDigest(parts)
			if derr != nil {
				return derr
			}
			digest = d
		} else {
			buf = make([]byte, job.size)
			offset := 0
			var parts []checkpointchunks.PackPart
			if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
				parts = make([]checkpointchunks.PackPart, 0, len(job.chunks))
			}
			batchSize := 1
			if opts.PackBatchHash {
				batchSize = 16
			}
			for start := 0; start < len(job.chunks); start += batchSize {
				if err := ctx.Err(); err != nil {
					return err
				}
				chunks := job.chunks[start:min(start+batchSize, len(job.chunks))]
				var inputs [16][]byte
				var sums [16][32]byte
				for i, c := range chunks {
					n := int(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
					part := buf[offset : offset+n]
					if _, err := memory.ReadAt(part, c.Offset); err != nil {
						return fmt.Errorf("read packed chunk: %w", err)
					}
					inputs[i] = part
					offset += n
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if opts.PackBatchHash {
					sha256batch.Sum256(inputs[:len(chunks)], &sums)
				} else {
					sums[0] = sha256.Sum256(inputs[0])
				}
				for i, c := range chunks {
					if hex.EncodeToString(sums[i][:]) != c.Digest {
						return fmt.Errorf("source chunk %s changed before pack publication", c.Digest)
					}
					if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
						parts = append(parts, checkpointchunks.PackPart{Digest: c.Digest, Length: int64(len(inputs[i]))})
					}
				}
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
				var err error
				digest, err = checkpointchunks.PackRootDigest(parts)
				if err != nil {
					return err
				}
			} else {
				sum := sha256.Sum256(buf)
				digest = hex.EncodeToString(sum[:])
			}
		}
		key, err := (checkpointchunks.PackReference{Identity: opts.PackIdentity, Digest: digest}).Key()
		if err != nil {
			return err
		}
		buildTime := time.Since(buildStart)
		uploadStart := time.Now()
		present, err := keyed.HasKey(ctx, key)
		if err != nil {
			return err
		}
		claim := "" // this acquisition's handle; empty = no claim held
		// One release point for every path: a pack upload that fails after
		// the fence claim was acquired must not leak the claim (it would
		// block later sweeps and publishes on the key for the claim
		// grace). The success path releases early and empties the handle,
		// making the deferred release a no-op.
		defer func() {
			if claim != "" {
				gcReleaseClaim(ctx, keyed, key, claim)
			}
		}()
		// Streaming: the reader's cumulative ReadAt+hash time is the real
		// "build" work — collected from every reader this job creates (each
		// PUT gets a fresh one, because gcGuardFreshUpload may re-invoke
		// putPack after the first body was consumed).
		streamVerify := time.Duration(0)
		putPack := func() error {
			if streaming {
				r := opts.newPackStreamReader(ctx, memory, m, job.chunks)
				err := keyed.PutKey(ctx, key, r)
				streamVerify += time.Duration(r.buildTime())
				return err
			}
			return keyed.PutKey(ctx, key, bytes.NewReader(buf))
		}
		if present {
			// Sweep fence: a marked pack is scheduled for collection; the
			// bytes are already in hand, so re-PUT them under the claim.
			body, fenced, ferr := gcFenceClaim(ctx, keyed, key)
			if ferr != nil {
				return ferr
			}
			claim = body
			present = !fenced
		}
		if !present {
			if err := putPack(); err != nil {
				return err
			}
		} else if streaming {
			// Present and unmarked: the buffer path verified every chunk
			// during the build this path skipped — drain a fresh reader to
			// verify the source the same way (bytes discarded; a mutated
			// chunk still fails the publish closed).
			r := opts.newPackStreamReader(ctx, memory, m, job.chunks)
			_, derr := io.Copy(io.Discard, r)
			streamVerify += time.Duration(r.buildTime())
			if derr != nil {
				return derr
			}
		}
		if claim != "" {
			gcReleaseClaim(ctx, keyed, key, claim)
			claim = ""
		} else if err := gcGuardFreshUpload(ctx, keyed, key, putPack); err != nil {
			return err
		}
		uploadTime := time.Since(uploadStart)
		mu.Lock()
		defer mu.Unlock()
		timings.BuildTotal += buildTime + streamVerify
		timings.UploadTotal += uploadTime
		if present {
			result.PacksSkip++
			result.ChunksSkip += len(job.chunks)
		} else {
			result.PacksPut++
			result.ChunksPut += len(job.chunks)
		}
		offset := 0
		for _, c := range job.chunks {
			n := min(int64(m.ChunkBytes), m.FileSize-c.Offset)
			transport.Packs[c.Digest] = checkpointchunks.PackReference{Identity: opts.PackIdentity, Digest: digest, Offset: int64(offset), Length: n, ObjectSize: int64(job.size)}
			offset += int(n)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	result.PackPayloadPeak = peakPayload.Load()
	timings.PackWall = time.Since(phaseStart)
	phaseStart = time.Now()
	if result.Phases != nil {
		result.Phases.PackWall = timings.PackWall
	}
	if err := checkpointchunks.ValidateTransport(&transport); err != nil {
		return fail(err)
	}
	if err := publishArtifactSetWithTransport(ctx, dir, id, keyed, &state, &transport, result.Phases, opts.OverlayWorkers); err != nil {
		return fail(err)
	}
	timings.Artifacts = time.Since(phaseStart)
	state.State = StatePublished
	state.PublishedAt = time.Now().UTC()
	state.ChunksPut = result.ChunksPut + result.ChunksSkip
	state.LastError = ""
	if err := writeStateMeasured(state, &result.StateTimings.Published); err != nil {
		return result, err
	}
	result.State = state
	if result.Phases != nil {
		// Concurrent accumulated totals from the pack workers (they
		// overlap each other and the walls; never addable).
		result.Phases.PackBuildTimeTotal = timings.BuildTotal
		result.Phases.PackUploadTimeTotal = timings.UploadTotal
	}
	return result, nil
}
