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
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
}

// Result summarizes one Run.
type Result struct {
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
	result := Result{}
	state := State{
		CheckpointID: id,
		Dir:          checkpointDir,
		State:        StatePublishing,
		Store:        storeName,
		StartedAt:    time.Now().UTC(),
	}
	if previous, err := Status(checkpointDir); err == nil && previous != nil {
		state.ChunksTotal, state.ChunksPut = previous.ChunksTotal, previous.ChunksPut
		state.StartedAt = previous.StartedAt
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
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	type uploadJob struct {
		chunk checkpointchunks.Chunk
	}
	upload := make(chan uploadJob, workers*2)
	var uploadErr error
	var uploadErrOnce sync.Once
	var skippedCount int64
	failUpload := func(cause error) {
		uploadErrOnce.Do(func() { uploadErr = cause })
	}
	var wg sync.WaitGroup
	var progress int64
	var progressMu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, manifest.ChunkBytes)
			for job := range upload {
				if uploadErr != nil {
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
	// O-1b: parallel Has pre-check. Feeding the sequential loop from the
	// main goroutine bounded the publish at HEAD latency x total chunks
	// (16-50s for 16,384 entries); workers now do Has+Put together.
	put := 0
	skipped := 0
	for _, chunk := range manifest.Entries {
		if uploadErr != nil {
			break
		}
		if err := ctx.Err(); err != nil {
			uploadErr = err
			break
		}
		upload <- uploadJob{chunk: chunk}
	}
	close(upload)
	wg.Wait()
	if uploadErr != nil {
		return failState(state, uploadErr)
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
