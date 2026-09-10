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

package checkpointpublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func TestMaterializePackedTransportClosure(t *testing.T) {
	ctx := context.Background()
	source := fixtureCheckpoint(t)
	writeFullArtifact(t, source)
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "packed"
	if _, err := Run(ctx, source, id, store, "test-local"); err != nil {
		t.Fatal(err)
	}
	raw, err := fetchKey(ctx, store, ArtifactKey(id, IndexName))
	if err != nil {
		t.Fatal(err)
	}
	var index ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	m, err := checkpointchunks.Load(source)
	if err != nil {
		t.Fatal(err)
	}
	memory := mustMemoryBytes(t, source)
	sum := sha256.Sum256(memory)
	packDigest := hex.EncodeToString(sum[:])
	if err := store.PutKey(ctx, checkpointchunks.PackKey(packDigest), bytes.NewReader(memory)); err != nil {
		t.Fatal(err)
	}
	m.Version = 2
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	m.Packs = map[string]checkpointchunks.PackReference{}
	for _, c := range m.Entries {
		m.Packs[c.Digest] = checkpointchunks.PackReference{Digest: packDigest, Offset: c.Offset, Length: min(int64(m.ChunkBytes), m.FileSize-c.Offset), ObjectSize: m.FileSize}
	}
	index.MemoryRoot = m.FileDigest
	// The bundle era lands the small files in one object, so the packed
	// views this test builds must ride that object: put() records the
	// body, commit() rebuilds the bundle from the overrides plus the
	// files publish produced (vmstate, overlay sidecar) and re-digests.
	overrides := map[string][]byte{}
	put := func(name string, v any) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		index.Files[name] = hex.EncodeToString(h[:])
		overrides[name] = data
	}
	put("manifest.json", map[string]any{"version": 2, "snapshot_type": "SoftDirty", "memory_size": m.FileSize, "memory_digest_mode": "chunks", "digests": map[string]string{"memory": m.FileDigest}})
	put(checkpointchunks.ManifestName, m)
	commit := func() {
		t.Helper()
		var bundle []byte
		parts := make([]BundlePart, 0, len(index.Bundle.Parts))
		for _, part := range index.Bundle.Parts {
			body, ok := overrides[part.Name]
			if !ok {
				var err error
				body, err = os.ReadFile(filepath.Join(source, part.Name))
				if err != nil {
					t.Fatal(err)
				}
			}
			h := sha256.Sum256(body)
			var prefix [8]byte
			binary.BigEndian.PutUint64(prefix[:], uint64(len(body)))
			parts = append(parts, BundlePart{
				Name: part.Name, Offset: int64(len(bundle)) + 8,
				Length: int64(len(body)), Digest: hex.EncodeToString(h[:]),
			})
			bundle = append(bundle, prefix[:]...)
			bundle = append(bundle, body...)
		}
		index.Bundle = &BundleInfo{Parts: parts}
		index.Bundle.Size = int64(len(bundle))
		sum := sha256.Sum256(bundle)
		index.Bundle.Digest = hex.EncodeToString(sum[:])
		if err := store.PutKey(ctx, ArtifactKey(id, BundleName), bytes.NewReader(bundle)); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(index)
		if err := store.PutKey(ctx, ArtifactKey(id, IndexName), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	commit()
	target := filepath.Join(t.TempDir(), "blind")
	if err := Materialize(ctx, target, id, store); err != nil {
		t.Fatal(err)
	}
	loaded, err := checkpointchunks.LoadTransport(target)
	if err != nil || len(loaded.Packs) != 2 {
		t.Fatalf("packed sidecar lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, MaterializedMarker)); err != nil {
		t.Fatal(err)
	}
	// Even an INDEX rehashed to match a structurally bad sidecar cannot
	// make that sidecar acceptable to a blind node.
	c := m.Entries[0]
	ref := m.Packs[c.Digest]
	ref.Length--
	m.Packs[c.Digest] = ref
	put(checkpointchunks.ManifestName, m)
	commit()
	badTarget := filepath.Join(t.TempDir(), "bad")
	if err := Materialize(ctx, badTarget, id, store); err == nil {
		t.Fatal("accepted corrupt packed range")
	}
	if _, err := os.Stat(badTarget); !os.IsNotExist(err) {
		t.Fatalf("failed materialization committed target: %v", err)
	}
}
