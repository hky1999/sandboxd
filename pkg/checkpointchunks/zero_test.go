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
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
)

func TestZeroChunkDigestConcurrentLengths(t *testing.T) {
	for _, n := range []int{0, 1, 4096, 65537, 262145} {
		want := sha256.Sum256(make([]byte, n))
		expected := hex.EncodeToString(want[:])
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make(chan string, 64)
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; results <- ZeroChunkDigest(n) }()
		}
		close(start)
		wg.Wait()
		close(results)
		for got := range results {
			if got != expected {
				t.Fatalf("length %d: %s want %s", n, got, expected)
			}
		}
	}
}
func BenchmarkZeroChunkDigestColdConcurrent(b *testing.B) {
	const n = 256 << 10
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		zeroChunkDigestCache.Delete(n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for j := 0; j < 64; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; ZeroChunkDigest(n) }()
		}
		close(start)
		wg.Wait()
	}
}
