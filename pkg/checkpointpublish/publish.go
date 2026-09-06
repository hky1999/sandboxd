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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// States of the publish state machine.
const (
	StateLocalReady    = "local_ready"
	StatePublishing    = "publishing"
	StatePublished     = "published"
	StatePublishFailed = "publish_failed"
)

// StateDirName is the sibling directory holding publish states, relative to
// a catalogued checkpoint root. The catalog scanner skips it naturally: it
// carries no manifest.json.
const StateDirName = ".publish"

// State is the persisted publish record for one checkpoint.
type State struct {
	CheckpointID string `json:"checkpoint_id"`
	Dir          string `json:"dir"`
	State        string `json:"state"`
	Store        string `json:"store,omitempty"`
	ChunksTotal  int    `json:"chunks_total"`
	ChunksPut    int    `json:"chunks_put"`
	// ArtifactSet records whether the non-memory files (manifest, chunks
	// sidecar, vmstate, overlay) are uploaded under the artifact namespace —
	// what a node with no visibility into the source directory needs to
	// materialize a restorable copy (memory itself is served by digest from
	// the chunk objects).
	ArtifactSet bool      `json:"artifact_set"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// StatePath returns the state file location for a checkpoint directory.
func StatePath(checkpointDir string) string {
	return filepath.Join(filepath.Dir(checkpointDir), StateDirName, filepath.Base(checkpointDir)+".json")
}

// Status reads the persisted state for a checkpoint directory. A missing
// state file is not an error: the checkpoint was never published, which the
// caller represents as a nil state (local-only).
func Status(checkpointDir string) (*State, error) {
	raw, err := os.ReadFile(StatePath(checkpointDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode publish state: %w", err)
	}
	return &state, nil
}

func writeState(state State) error {
	path := StatePath(state.Dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Write-through-temp + atomic rename: a daemon or CLI reading the
	// state concurrently (publishd scanners, catalog) must never observe a
	// half-written JSON, and a crash mid-write must leave the previous
	// state intact.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Result summarizes one Run.
type Result struct {
	PacksPut   int   `json:"packs_put,omitempty"`
	PacksSkip  int   `json:"packs_skip,omitempty"`
	Workers    int   `json:"workers"` // actual memory upload concurrency
	State      State `json:"state"`
	ChunksPut  int   `json:"chunks_put"`  // objects written this run
	ChunksSkip int   `json:"chunks_skip"` // objects already in the store
}

// Run publishes the checkpoint's memory chunks: it computes (or reuses) the
// chunk manifest, streams every chunk the store does not already hold, and
// drives the persisted state machine. It is idempotent — a failed or
// interrupted run resumes and re-puts only what is missing. The memory file
// is opened once and seeked per chunk.
func Run(ctx context.Context, checkpointDir, id string, store chunkstore.Store, storeName string) (Result, error) {
	return RunWithOptions(ctx, checkpointDir, id, store, storeName, Options{})
}

// Options bounds memory upload concurrency independently of host CPU count.
// Zero Workers preserves Run's default (at most eight GOMAXPROCS workers).
type Options struct {
	Workers   int
	PackBytes int    // zero keeps version-1 single-chunk publication
	BaseID    string // optional verified published baseline in the same store
}

// RunWithOptions is Run with an explicit memory-upload concurrency bound.
// Overlay publication retains its own bounded worker pool.
func RunWithOptions(ctx context.Context, checkpointDir, id string, store chunkstore.Store, storeName string, opts Options) (Result, error) {
	if opts.Workers < 0 || opts.Workers > 64 {
		return Result{}, fmt.Errorf("publish workers must be between 0 and 64, got %d", opts.Workers)
	}
	if opts.PackBytes < 0 || opts.PackBytes > checkpointchunks.MaxPackBytes || (opts.PackBytes > 0 && opts.PackBytes < 4096) {
		return Result{}, fmt.Errorf("pack bytes must be zero or between 4096 and %d", checkpointchunks.MaxPackBytes)
	}
	if opts.BaseID != "" && (opts.PackBytes == 0 || !validPackedID(opts.BaseID) || opts.BaseID == id) {
		return Result{}, fmt.Errorf("pack base ID must be a distinct checkpoint ID with packing enabled")
	}
	workers := opts.Workers
	if workers == 0 {
		workers = min(runtime.GOMAXPROCS(0), 8)
	}
	result := Result{Workers: workers}
	state := State{
		CheckpointID: id,
		Dir:          checkpointDir,
		State:        StatePublishing,
		Store:        storeName,
		StartedAt:    time.Now().UTC(),
	}
	if previous, err := Status(checkpointDir); err == nil && previous != nil {
		state.ChunksTotal, state.ChunksPut = previous.ChunksTotal, previous.ChunksPut
		// Stamp THIS attempt's own start: cn-publishd's stale-lease requeue
		// judges liveness by StartedAt, and an inherited first-generation
		// timestamp would let a retry in flight be re-claimed as a crash
		// leftover (F8). A full owner lease is still future work; this
		// closes the practical gap.
		state.StartedAt = time.Now().UTC()
	}

	manifest, err := checkpointchunks.Load(checkpointDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return failState(state, err)
		}
		manifest, err = checkpointchunks.Compute(ctx, checkpointDir, checkpointchunks.DefaultChunkBytes)
		if err != nil {
			return failState(state, err)
		}
	}
	state.ChunksTotal = manifest.ChunkCount
	if opts.PackBytes > 0 {
		return runPacked(ctx, checkpointDir, id, store, manifest, state, result, opts)
	}

	if err := writeState(state); err != nil {
		return result, err
	}

	memory, err := os.Open(filepath.Join(checkpointDir, manifest.File))
	if err != nil {
		return failState(state, err)
	}
	defer memory.Close()

	// O-1: parallel chunk upload. Sequential PUTs bound the publish wall
	// clock by per-request latency (~25ms/object, 54s for 2,200 chunks at
	// 4GiB); overlapping round trips with a worker pool compresses the
	// same bytes into the bandwidth-bound floor.
	// Error slot: every read and write goes through errMu; failedFlag is
	// the lock-free fast path workers check per job. (A sync.Once around
	// the first writer does not guard concurrent readers — the race the
	// source review reproduced with injected HEAD errors.)
	var errMu sync.Mutex
	uploadErr := error(nil)
	failedFlag := atomic.Bool{}
	failUpload := func(cause error) {
		errMu.Lock()
		if uploadErr == nil {
			uploadErr = cause
		}
		errMu.Unlock()
		failedFlag.Store(true)
	}
	readUploadErr := func() error {
		errMu.Lock()
		defer errMu.Unlock()
		return uploadErr
	}
	// P2: request dedup by digest. Entries repeat digests heavily (the
	// all-zero chunk alone recurs thousands of times at 4GiB); Has/Put is
	// keyed by content, so one representative entry per unique digest
	// serves every duplicate. This collapses the HEAD count from
	// len(Entries) to the number of distinct chunks.
	uniqueChunks := make([]checkpointchunks.Chunk, 0, len(manifest.Entries))
	seenDigest := make(map[string]struct{}, len(manifest.Entries))
	for _, chunk := range manifest.Entries {
		if _, dup := seenDigest[chunk.Digest]; dup {
			continue
		}
		seenDigest[chunk.Digest] = struct{}{}
		uniqueChunks = append(uniqueChunks, chunk)
	}
	type uploadJob struct {
		chunk checkpointchunks.Chunk
	}
	upload := make(chan uploadJob, workers*2)
	var skippedCount int64
	var wg sync.WaitGroup
	var progress int64
	var progressMu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, manifest.ChunkBytes)
			for job := range upload {
				if failedFlag.Load() {
					continue // drain
				}
				if ok, err := store.Has(ctx, job.chunk.Digest); err != nil {
					failUpload(fmt.Errorf("has chunk %s: %w", job.chunk.Digest[:12], err))
					continue
				} else if ok {
					atomic.AddInt64(&skippedCount, 1)
					continue
				}
				if _, err := memory.ReadAt(buf, job.chunk.Offset); err != nil &&
					!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					failUpload(fmt.Errorf("read chunk at %d: %w", job.chunk.Offset, err))
					continue
				}
				end := int(manifest.FileSize - job.chunk.Offset)
				if end > manifest.ChunkBytes {
					end = manifest.ChunkBytes
				}
				if err := store.Put(ctx, job.chunk.Digest, &byteReader{b: buf[:end]}); err != nil {
					failUpload(fmt.Errorf("put chunk at %d: %w", job.chunk.Offset, err))
					continue
				}
				progressMu.Lock()
				progress++
				state.ChunksPut = int(progress)
				progressMu.Unlock()
			}
		}()
	}
	// O-1b: workers run Has+Put together; the producer feeds only unique
	// digests (P2) and stops at the first failure or cancellation.
	put := 0
	skipped := 0
	for _, chunk := range uniqueChunks {
		if failedFlag.Load() {
			break
		}
		if err := ctx.Err(); err != nil {
			failUpload(err)
			break
		}
		upload <- uploadJob{chunk: chunk}
	}
	close(upload)
	wg.Wait()
	if err := readUploadErr(); err != nil {
		return failState(state, err)
	}
	put = int(progress)
	skipped = int(atomic.LoadInt64(&skippedCount))

	// Artifact set: everything a blind node needs to materialize the
	// checkpoint except the memory bytes themselves.
	if keyed, ok := store.(chunkstore.Keyed); ok {
		if err := publishArtifactSet(ctx, checkpointDir, id, keyed, &state); err != nil {
			return failState(state, err)
		}
	} else {
		return failState(state, errors.New("store backend cannot host artifact sets"))
	}

	state.State = StatePublished
	state.PublishedAt = time.Now().UTC()
	state.ChunksPut = put + skipped
	state.LastError = ""
	if err := writeState(state); err != nil {
		return result, err
	}
	result.State = state
	result.ChunksPut, result.ChunksSkip = put, skipped
	return result, nil
}

func failState(state State, cause error) (Result, error) {
	state.State = StatePublishFailed
	state.LastError = cause.Error()
	if err := writeState(state); err != nil {
		return Result{}, err
	}
	return Result{State: state}, cause
}

// byteReader adapts a byte slice to a one-shot Reader.
type byteReader struct {
	b []byte
}

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
