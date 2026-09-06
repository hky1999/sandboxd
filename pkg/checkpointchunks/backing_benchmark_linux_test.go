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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func BenchmarkVerifiedMemoryBacking(b *testing.B) {
	path := os.Getenv("AKERNEL_BACKING_BENCH_FILE")
	if path == "" {
		b.Skip("set an owned sealed memory fixture")
	}
	dir := filepath.Dir(path)
	m, err := Load(dir)
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
	b.SetBytes(m.FileSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyMemoryBacking(context.Background(), dir, m.FileDigest, m.FileDigestMode); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	after := rchar()
	b.ReportMetric(float64(after-before)/float64(b.N), "rchar-B/op")
	b.Logf("logical_bytes=%d root=%s", m.FileSize, m.FileDigest)
}
