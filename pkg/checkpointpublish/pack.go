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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

func loadPackBaseline(ctx context.Context, store chunkstore.Keyed, id string) (*checkpointchunks.Manifest, error) {
	raw, err := boundedPackMetadata(ctx, store, ArtifactKey(id, IndexName))
	if err != nil {
		return nil, err
	}
	var index ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, err
	}
	if index.CheckpointID != id {
		return nil, fmt.Errorf("baseline index names %q instead of %q", index.CheckpointID, id)
	}
	files := map[string][]byte{}
	for _, name := range []string{checkpointchunks.ManifestName, "manifest.json"} {
		raw, err := boundedPackMetadata(ctx, store, ArtifactKey(id, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != index.Files[name] {
			return nil, fmt.Errorf("baseline %s checksum mismatch", name)
		}
		files[name] = raw
	}
	m, err := checkpointchunks.DecodeTransport(files[checkpointchunks.ManifestName])
	if err != nil {
		return nil, err
	}
	if m.FileDigest != index.MemoryRoot || m.ChunkCount != index.ChunkCount {
		return nil, fmt.Errorf("baseline index memory identity mismatch")
	}
	if err := packedMemoryClosure(m, files["manifest.json"]); err != nil {
		return nil, err
	}
	return m, nil
}

func runPacked(ctx context.Context, dir, id string, store chunkstore.Store, m *checkpointchunks.Manifest, state State, result Result, opts Options) (Result, error) {
	phaseStart := time.Now()
	timings := &PackTimings{}
	result.PackTimings = timings
	fail := func(err error) (Result, error) { return failState(state, err) }
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
			return fail(fmt.Errorf("load pack baseline: %w", err))
		}
	}
	timings.Prepare = time.Since(phaseStart)
	phaseStart = time.Now()
	unique := []checkpointchunks.Chunk{}
	seen := map[string]bool{}
	for _, c := range m.Entries {
		if !seen[c.Digest] {
			seen[c.Digest] = true
			unique = append(unique, c)
		}
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].Digest < unique[j].Digest })
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
			return err
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
			var err error
			present, err = store.Has(ctx, c.Digest)
			if err != nil {
				return err
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
			missing[i] = true
		}
		return nil
	})
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
		buf := make([]byte, job.size)
		offset := 0
		var parts []checkpointchunks.PackPart
		if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
			parts = make([]checkpointchunks.PackPart, 0, len(job.chunks))
		}
		for _, c := range job.chunks {
			n := int(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
			part := buf[offset : offset+n]
			if _, err := memory.ReadAt(part, c.Offset); err != nil {
				return fmt.Errorf("read packed chunk: %w", err)
			}
			sum := sha256.Sum256(part)
			if hex.EncodeToString(sum[:]) != c.Digest {
				return fmt.Errorf("source chunk %s changed before pack publication", c.Digest)
			}
			if opts.PackIdentity == checkpointchunks.PackIdentityChunks {
				parts = append(parts, checkpointchunks.PackPart{Digest: c.Digest, Length: int64(n)})
			}
			offset += n
		}
		var digest string
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
		if !present {
			if err := keyed.PutKey(ctx, key, bytes.NewReader(buf)); err != nil {
				return err
			}
		}
		uploadTime := time.Since(uploadStart)
		mu.Lock()
		defer mu.Unlock()
		timings.BuildTotal += buildTime
		timings.UploadTotal += uploadTime
		if present {
			result.PacksSkip++
			result.ChunksSkip += len(job.chunks)
		} else {
			result.PacksPut++
			result.ChunksPut += len(job.chunks)
		}
		offset = 0
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
	if err := checkpointchunks.ValidateTransport(&transport); err != nil {
		return fail(err)
	}
	if err := publishArtifactSetWithTransport(ctx, dir, id, keyed, &state, &transport); err != nil {
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
	return result, nil
}
