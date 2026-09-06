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

package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// Compare to independently hashed logical bytes, including data crossing a
// chunk boundary, holes, allocated zeroes, a non-aligned tail and empty files.
func TestScanFileChunksLogicalBytes(t *testing.T) {
	const chunk = checkpointchunks.DefaultChunkBytes
	for _, dense := range []bool{false, true} {
		for _, size := range []int{0, 19, chunk, 4*chunk + 37} {
			data := make([]byte, size)
			for _, off := range []int{17, chunk - 3, chunk + 3, 3*chunk + 1} {
				if off < size {
					data[off] = byte(off%251 + 1)
				}
			}
			path := filepath.Join(t.TempDir(), "overlay")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Truncate(int64(size)); err != nil {
				t.Fatal(err)
			}
			if dense {
				if _, err = f.WriteAt(data, 0); err != nil {
					t.Fatal(err)
				}
			} else {
				for i, v := range data {
					if v != 0 {
						if _, err = f.WriteAt([]byte{v}, int64(i)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			m, err := scanFileChunks(context.Background(), path, "overlay")
			if err != nil {
				t.Fatal(err)
			}
			var entries []checkpointchunks.Chunk
			for off := 0; off < size; off += chunk {
				sum := sha256.Sum256(data[off:min(off+chunk, size)])
				entries = append(entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
			}
			if m.FileSize != int64(size) || m.ChunkCount != len(entries) || m.FileDigest != checkpointchunks.RootDigest(entries) {
				t.Fatalf("dense=%v size=%d: incorrect geometry/root: %+v", dense, size, m)
			}
			for i, want := range entries {
				if m.Entries[i] != want {
					t.Fatalf("dense=%v chunk %d: got %+v want %+v", dense, i, m.Entries[i], want)
				}
			}
		}
	}
}

func BenchmarkScanFileChunks(b *testing.B) {
	path := os.Getenv("AKERNEL_SCAN_BENCH_FILE")
	if path == "" {
		path = filepath.Join(b.TempDir(), "overlay")
		f, err := os.Create(path)
		if err != nil {
			b.Fatal(err)
		}
		if err = f.Truncate(8 << 30); err != nil {
			b.Fatal(err)
		}
		block := make([]byte, 8<<20)
		for i := range block {
			block[i] = byte(i%251 + 1)
		}
		if _, err = f.WriteAt(block, 0); err != nil {
			b.Fatal(err)
		}
		if err = f.Close(); err != nil {
			b.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size()) // Logical bytes, not physical disk throughput.
	b.ReportAllocs()
	b.ResetTimer()
	var root string
	for i := 0; i < b.N; i++ {
		m, err := scanFileChunks(context.Background(), path, "overlay")
		if err != nil {
			b.Fatal(err)
		}
		root = m.FileDigest
		if len(m.Entries) == 0 {
			b.Fatal("empty benchmark artifact")
		}
	}
	b.StopTimer()
	b.Logf("root=%s", root)
}
