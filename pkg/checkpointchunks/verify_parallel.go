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

package checkpointchunks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
)

// Keep a bounded number of reusable buffers, including the producer's buffer.
// Large chunks and single-CPU callers retain the serial verifier's footprint.
func parallelVerificationWorkers(m *Manifest) int {
	if m.ChunkBytes <= 0 {
		return 1
	}
	return max(1, min(runtime.GOMAXPROCS(0), 8, len(m.Entries), (8<<20)/m.ChunkBytes-1))
}

// verifyContentsParallel leaves reading and hole queries in the producer.
// Workers only verify owned buffers; all workers are joined on every exit.
func verifyContentsParallel(ctx context.Context, reader io.Reader, m *Manifest, workers int) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job struct {
		index int
		data  []byte
	}
	jobs := make(chan job, workers)
	buffers := make(chan []byte, workers+1)
	// Allocate lazily: an all-hole backing needs no chunk buffers at all.
	for i := 0; i < cap(buffers); i++ {
		buffers <- nil
	}
	var wg sync.WaitGroup
	var failed sync.Once
	var workerErr error
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() == nil {
					chunk := m.Entries[j.index]
					var got string
					if chunk.Digest == ZeroChunkDigest(len(j.data)) && verifiedZeroBytes(j.data) {
						got = chunk.Digest
					} else {
						sum := sha256.Sum256(j.data)
						got = hex.EncodeToString(sum[:])
					}
					if got != chunk.Digest {
						failed.Do(func() {
							workerErr = fmt.Errorf("chunk %d (offset %d) digest mismatch: manifest %s on disk %s", j.index, chunk.Offset, chunk.Digest, got)
							cancel()
						})
					}
				}
				// Each in-flight job owns one of cap(buffers) tokens, so returning
				// its buffer cannot block, even after the producer exits.
				buffers <- j.data[:cap(j.data)]
			}
		}()
	}
	defer func() {
		if retErr != nil {
			cancel()
		}
		close(jobs)
		wg.Wait()
		// The error slot is read only after all writers have joined.
		if workerErr != nil {
			retErr = workerErr
			return
		}
		if retErr != nil {
			return
		}
		if retErr = ctx.Err(); retErr != nil {
			return
		}
		if got := RootDigest(m.Entries); got != m.FileDigest {
			retErr = fmt.Errorf("chunk root digest mismatch: manifest %s on disk %s", m.FileDigest, got)
		}
	}()
	for i, chunk := range m.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := expectedChunkLen(m, i)
		if chunk.Digest == ZeroChunkDigest(int(length)) {
			if holes, ok := reader.(interface{ skipZeroHole(int64) (bool, error) }); ok {
				skipped, err := holes.skipZeroHole(length)
				if err != nil {
					return err
				}
				if skipped {
					continue
				}
			}
		}
		var buf []byte
		select {
		case buf = <-buffers:
		case <-ctx.Done():
			return ctx.Err()
		}
		if buf == nil {
			buf = make([]byte, m.ChunkBytes)
		}
		n, err := io.ReadFull(reader, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if int64(n) != length {
			return fmt.Errorf("chunk %d short: %d bytes", i, n)
		}
		select {
		case jobs <- job{index: i, data: buf[:n]}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
