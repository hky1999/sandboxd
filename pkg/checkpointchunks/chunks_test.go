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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsMalformedDigests(t *testing.T) {
	dir := t.TempDir()
	// F2: digests are object keys; empty or non-hex values must fail Load
	// rather than panic on slicing or path-traverse the store.
	for name, digest := range map[string]string{
		"empty":       "",
		"not-hex":     "zz" + strings.Repeat("a", 62),
		"wrong-case":  strings.ToUpper(strings.Repeat("a", 64)),
		"too-short":   "abcd",
		"path-escape": strings.Repeat("a", 60) + "../../",
	} {
		manifest := map[string]any{
			"version": 1, "file": "memory", "file_size": 1,
			"chunk_bytes": 256, "chunk_count": 1,
			"entries": []map[string]any{{"offset": 0, "digest": digest}},
		}
		raw, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatalf("%s digest accepted by Load", name)
		}
	}
	// A well-formed digest still loads.
	manifest := map[string]any{
		"version": 1, "file": "memory", "file_size": 1,
		"chunk_bytes": 256, "chunk_count": 1,
		"entries": []map[string]any{{"offset": 0, "digest": strings.Repeat("a", 64)}},
	}
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}
