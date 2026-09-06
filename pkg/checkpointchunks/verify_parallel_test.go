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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"runtime"
	"testing"
)

func parallelFixture(size, chunkBytes int) ([]byte, *Manifest) {
	data := make([]byte, size)
	_, _ = rand.New(rand.NewSource(90)).Read(data)
	m := &Manifest{Version: 1, File: "memory", FileSize: int64(size), ChunkBytes: chunkBytes, FileDigestMode: FileDigestChunks}
	for off := 0; off < size; off += chunkBytes {
		sum := sha256.Sum256(data[off:min(off+chunkBytes, size)])
		m.Entries = append(m.Entries, Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
	}
	m.ChunkCount = len(m.Entries)
	m.FileDigest = RootDigest(m.Entries)
	return data, m
}

func TestParallelVerificationLogicalOracle(t *testing.T) {
	for _, size := range []int{0, 19, 8192, 32*8192 + 37} {
		data, m := parallelFixture(size, 8192)
		for _, workers := range []int{2, 4, 8} {
			if err := verifyContentsParallel(context.Background(), bytes.NewReader(data), m, workers); err != nil {
				t.Fatalf("size=%d workers=%d: %v", size, workers, err)
			}
		}
	}
	data, m := parallelFixture(24*4096+17, 4096)
	for i := range m.Entries {
		bad := append([]byte(nil), data...)
		bad[m.Entries[i].Offset] ^= 1
		if verifyContentsParallel(context.Background(), bytes.NewReader(bad), m, 4) == nil {
			t.Fatalf("accepted damaged chunk %d", i)
		}
	}
	m.FileDigest = ZeroChunkDigest(17)
	if verifyContentsParallel(context.Background(), bytes.NewReader(data), m, 4) == nil {
		t.Fatal("accepted wrong root")
	}
}

type observedVerificationReader struct {
	*bytes.Reader
	buffers [][]byte
	failAt  int
	cancel  context.CancelFunc
}

func (r *observedVerificationReader) Read(p []byte) (int, error) {
	r.buffers = append(r.buffers, p)
	if len(r.buffers) == r.failAt {
		if r.cancel != nil {
			r.cancel()
		} else {
			return 0, io.ErrClosedPipe
		}
	}
	return r.Reader.Read(p)
}

func TestParallelVerificationExitsJoinWorkers(t *testing.T) {
	data, m := parallelFixture(32*(64<<10)+17, 64<<10)
	for _, cancelled := range []bool{false, true} {
		for round := 0; round < 20; round++ {
			ctx, cancel := context.WithCancel(context.Background())
			reader := &observedVerificationReader{Reader: bytes.NewReader(data), failAt: 5}
			want := error(io.ErrClosedPipe)
			if cancelled {
				reader.cancel = cancel
				want = context.Canceled
			}
			err := verifyContentsParallel(ctx, reader, m, 4)
			cancel()
			if !errors.Is(err, want) {
				t.Fatalf("cancel=%v got %v", cancelled, err)
			}
			// Read retained the exact buffers handed to workers. Under -race this
			// catches hashing after the verifier has returned, rather than relying
			// on a global goroutine count or an arbitrary sleep.
			for _, buf := range reader.buffers {
				clear(buf)
			}
		}
	}
	if err := verifyContentsParallel(context.Background(), bytes.NewReader(data[:len(data)-1]), m, 4); err == nil {
		t.Fatal("accepted short tail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyContentsParallel(ctx, bytes.NewReader(data), m, 4); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestParallelVerificationReusesBoundedBuffers(t *testing.T) {
	data, m := parallelFixture(128*4096+17, 4096)
	reader := &observedVerificationReader{Reader: bytes.NewReader(data)}
	if err := verifyContentsParallel(context.Background(), reader, m, 4); err != nil {
		t.Fatal(err)
	}
	buffers := map[*byte]bool{}
	for _, buf := range reader.buffers {
		// ReadFull may call Read again with a subslice for a short tail.
		if cap(buf) == m.ChunkBytes {
			buffers[&buf[0]] = true
		}
	}
	if len(buffers) > 5 {
		t.Fatalf("allocated %d buffers for 4 workers", len(buffers))
	}
}

func TestParallelVerificationWorkerBudget(t *testing.T) {
	old := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(old)
	for _, chunk := range []int{4096, 256 << 10, 1 << 20, 4 << 20, 16 << 20} {
		m := &Manifest{ChunkBytes: chunk, Entries: make([]Chunk, 100)}
		workers := parallelVerificationWorkers(m)
		if workers < 1 || workers > 8 {
			t.Fatalf("workers=%d", workers)
		}
		if workers > 1 && (workers+1)*chunk > 8<<20 {
			t.Fatal("exceeded buffer budget")
		}
	}
	runtime.GOMAXPROCS(1)
	if n := parallelVerificationWorkers(&Manifest{ChunkBytes: 4096, Entries: make([]Chunk, 100)}); n != 1 {
		t.Fatalf("single CPU workers=%d", n)
	}
}
