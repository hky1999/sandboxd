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
	"testing"
)

func TestComputeAndVerify(t *testing.T) {
	dir := t.TempDir()
	// 2.5 chunks of data at 256KiB, deterministic bytes.
	size := int64(2*DefaultChunkBytes + DefaultChunkBytes/2)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	manifest, err := Compute(context.Background(), dir, 0)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if manifest.ChunkCount != 3 || manifest.FileSize != size {
		t.Fatalf("manifest = %+v", manifest)
	}
	if len(manifest.Entries) != 3 || manifest.Entries[2].Offset != 2*DefaultChunkBytes {
		t.Fatalf("entries = %+v", manifest.Entries)
	}
	if manifest.Entries[0].Digest == manifest.Entries[2].Digest {
		t.Fatal("distinct chunks hashed identically")
	}

	if err := Verify(context.Background(), dir); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Mutate one byte: chunk and file digests must both fail.
	data[10] ^= 0xFF
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), dir); err == nil {
		t.Fatal("mutated artifact verified")
	}
}
