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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"golang.org/x/sys/unix"
)

func TestMemorySealExtentLogicalOracle(t *testing.T) {
	const chunk = checkpointchunks.DefaultChunkBytes
	for _, shape := range []string{"holes", "mixed", "allocated-zero", "preallocated", "entropy", "short-tail"} {
		for _, mode := range []string{checkpointchunks.FileDigestChunks, checkpointchunks.FileDigestSha256, ""} {
			t.Run(shape+"/"+mode, func(t *testing.T) {
				size := 8*chunk + 37
				if shape == "short-tail" {
					size = 19
				}
				data := make([]byte, size)
				if shape == "entropy" {
					_, _ = rand.New(rand.NewSource(83)).Read(data)
				}
				if shape == "mixed" || shape == "preallocated" || shape == "short-tail" {
					for _, off := range []int{0, 18, chunk - 1, chunk, 3*chunk + 11, size - 1} {
						if off < size {
							data[off] = byte(off%251 + 1)
						}
					}
				}
				dir := t.TempDir()
				path := filepath.Join(dir, "memory")
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err = f.Truncate(int64(size)); err != nil {
					t.Fatal(err)
				}
				if shape == "preallocated" {
					if err = unix.Fallocate(int(f.Fd()), 0, 0, int64(size)); err != nil {
						t.Fatal(err)
					}
				}
				if shape == "entropy" || shape == "allocated-zero" {
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
				if err = f.Sync(); err != nil {
					t.Fatal(err)
				}
				got, err := digestMemoryWithChunkScan(context.Background(), path, mode, nil)
				if err != nil {
					t.Fatal(err)
				}
				var entries []checkpointchunks.Chunk
				for off := 0; off < size; off += chunk {
					sum := sha256.Sum256(data[off:min(off+chunk, size)])
					entries = append(entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
				}
				sum := sha256.Sum256(data)
				want := hex.EncodeToString(sum[:])
				if mode == checkpointchunks.FileDigestChunks {
					want = checkpointchunks.RootDigest(entries)
				}
				if got != want {
					t.Fatalf("root got %s want %s", got, want)
				}
				m, err := checkpointchunks.Load(dir)
				if err != nil {
					t.Fatal(err)
				}
				if m.File != "memory" || m.FileSize != int64(size) || m.ChunkCount != len(entries) || !reflect.DeepEqual(m.Entries, entries) || m.FileDigest != want {
					t.Fatalf("sidecar mismatch: %+v", m)
				}
				disk, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(disk, data) {
					t.Fatal("sealing modified memory")
				}
			})
		}
	}
}

func TestMemorySealCancellationPreservesSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	if err := os.WriteFile(path, make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(dir, checkpointchunks.ManifestName)
	before := []byte("existing sidecar")
	if err := os.WriteFile(sidecar, before, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := digestMemoryWithChunkScan(ctx, path, checkpointchunks.FileDigestChunks, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("cancelled seal replaced sidecar")
	}
}

func BenchmarkMemorySealExtent(b *testing.B) {
	// A dedicated fixture directory is required: sealing writes chunks.json.
	path := os.Getenv("AKERNEL_MEMORY_SEAL_BENCH_FILE")
	if path == "" {
		b.Skip("set an owned memory fixture path")
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	rchar := func() uint64 {
		data, err := os.ReadFile("/proc/self/io")
		if err != nil {
			b.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "rchar:" {
				n, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					b.Fatal(err)
				}
				return n
			}
		}
		b.Fatal("missing rchar")
		return 0
	}
	before := rchar()
	b.SetBytes(info.Size())
	b.ResetTimer()
	var root string
	for i := 0; i < b.N; i++ {
		root, err = digestMemoryWithChunkScan(context.Background(), path, checkpointchunks.FileDigestChunks, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	after := rchar()
	b.ReportMetric(float64(after-before)/float64(b.N), "rchar-B/op")
	b.Log(fmt.Sprintf("logical_bytes=%d root=%s", info.Size(), root))
}
