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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

func TestLocalRestoreVerificationClosure(t *testing.T) {
	for _, mutation := range []string{"valid", "no-outer-digest", "outer-size", "outer-root", "sidecar-root", "sidecar-file", "memory-name", "short-memory"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "memory")
			data := make([]byte, 2*checkpointchunks.DefaultChunkBytes+17)
			data[0] = 1
			data[len(data)-1] = 2
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			root, err := digestMemoryWithChunkScan(context.Background(), path, checkpointchunks.FileDigestChunks)
			if err != nil {
				t.Fatal(err)
			}
			m, err := checkpointchunks.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			artifact := &firecrackerCheckpointArtifact{Files: firecrackerCheckpointFiles{Memory: path}, Manifest: &firecrackerCheckpointManifest{MemorySize: int64(len(data)), MemoryDigestMode: checkpointchunks.FileDigestChunks, Digests: map[string]string{"memory": root}}}
			switch mutation {
			case "no-outer-digest":
				delete(artifact.Manifest.Digests, "memory")
			case "outer-size":
				artifact.Manifest.MemorySize++
			case "outer-root":
				artifact.Manifest.Digests["memory"] = checkpointchunks.ZeroChunkDigest(17)
			case "sidecar-root":
				m.FileDigest = checkpointchunks.ZeroChunkDigest(17)
			case "sidecar-file":
				m.File = "other"
			case "memory-name":
				artifact.Files.Memory = filepath.Join(dir, "other")
			case "short-memory":
				if err = os.Truncate(path, int64(len(data)-1)); err != nil {
					t.Fatal(err)
				}
			}
			if err = checkpointchunks.Write(dir, m); err != nil {
				t.Fatal(err)
			}
			cache := checkpointDigestCache{}
			err = cache.verifyFirecrackerCheckpointMemoryChunks(context.Background(), artifact)
			valid := mutation == "valid" || mutation == "no-outer-digest"
			if (err == nil) != valid {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLocalRestoreVerifierFailureJoinsWorkers(t *testing.T) {
	count := func() int {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		if n == len(buf) {
			t.Fatal("goroutine dump truncated")
		}
		count := 0
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, "verifyFirecrackerCheckpointMemoryChunks.func") || strings.Contains(stack, "verifyContentsParallel.func") {
				count++
			}
		}
		return count
	}
	for _, cancelled := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "memory")
		data := make([]byte, 2*checkpointchunks.DefaultChunkBytes)
		data[0] = 1
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		root, err := digestMemoryWithChunkScan(context.Background(), path, checkpointchunks.FileDigestChunks)
		if err != nil {
			t.Fatal(err)
		}
		artifact := &firecrackerCheckpointArtifact{Files: firecrackerCheckpointFiles{Memory: path}, Manifest: &firecrackerCheckpointManifest{MemorySize: int64(len(data)), MemoryDigestMode: checkpointchunks.FileDigestChunks, Digests: map[string]string{"memory": root}}}
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		} else if err := os.Truncate(path, 1); err != nil {
			t.Fatal(err)
		}
		before := count()
		cache := checkpointDigestCache{}
		err = cache.verifyFirecrackerCheckpointMemoryChunks(ctx, artifact)
		cancel()
		if err == nil {
			t.Fatal("failure probe unexpectedly succeeded")
		}
		if after := count(); after != before {
			t.Errorf("cancelled=%v verifier goroutines before=%d after=%d", cancelled, before, after)
		}
	}
}

func BenchmarkLocalRestoreContents(b *testing.B) {
	path := os.Getenv("AKERNEL_BACKING_BENCH_FILE")
	if path == "" {
		b.Skip("set an owned complete local memory fixture")
	}
	m, err := checkpointchunks.LoadTransport(filepath.Dir(path))
	if err != nil {
		b.Fatal(err)
	}
	artifact := &firecrackerCheckpointArtifact{Files: firecrackerCheckpointFiles{Memory: path}, Manifest: &firecrackerCheckpointManifest{MemorySize: m.FileSize, MemoryDigestMode: checkpointchunks.FileDigestChunks, Digests: map[string]string{"memory": m.FileDigest}}}
	rchar := func() uint64 {
		data, err := os.ReadFile("/proc/self/io")
		if err != nil {
			b.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "rchar:" {
				n, err := strconv.ParseUint(f[1], 10, 64)
				if err != nil {
					b.Fatal(err)
				}
				return n
			}
		}
		b.Fatal("rchar missing")
		return 0
	}
	before := rchar()
	b.SetBytes(m.FileSize)
	b.ResetTimer()
	cache := checkpointDigestCache{}
	for i := 0; i < b.N; i++ {
		if err := cache.verifyFirecrackerCheckpointMemoryChunks(context.Background(), artifact); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	after := rchar()
	b.ReportMetric(float64(after-before)/float64(b.N), "rchar-B/op")
	b.Logf("logical_bytes=%d root=%s", m.FileSize, m.FileDigest)
}
