// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// compressedFixture is a full artifact whose memory compresses well:
// distinct chunk contents so dedup cannot mask missing objects.
func compressedFixture(t *testing.T, chunks int) (string, [][]byte) {
	t.Helper()
	dir := t.TempDir()
	chunkBytes := 4096
	blocks := make([][]byte, chunks)
	for i := range blocks {
		blocks[i] = bytes.Repeat([]byte{byte('a' + i)}, chunkBytes)
	}
	data := bytes.Join(blocks, nil)
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFullArtifact(t, dir)
	m, err := checkpointchunks.Compute(context.Background(), dir, chunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := checkpointchunks.Write(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir, blocks
}

func TestCompressedPublishRoundtripAndMarker(t *testing.T) {
	ctx := context.Background()
	source, blocks := compressedFixture(t, 4)
	id := "comp-rt"
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(source, checkpointchunks.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunWithOptions(ctx, source, id, store, "test-local", Options{CompressChunks: true, Workers: 2})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if result.ChunksPut == 0 || result.ChunksSkip != 0 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	// The sealed sidecar never learns about transport compression.
	after, err := os.ReadFile(filepath.Join(source, checkpointchunks.ManifestName))
	if err != nil || !bytes.Equal(sealed, after) {
		t.Fatalf("sealed sidecar mutated by compressed publication")
	}
	// Every nonzero chunk object is compressed-only, decodes to its
	// recorded length, and hashes to its digest.
	m := mustManifest(t, source)
	for i, entry := range m.Entries {
		if entry.Digest == checkpointchunks.ZeroChunkDigest(chunkLen(t, m, i)) {
			continue
		}
		if ok, _ := store.Has(ctx, entry.Digest); ok {
			t.Fatalf("plain object exists for %s", entry.Digest[:12])
		}
		rc, err := store.GetKey(ctx, chunkstore.CompressedKey(entry.Digest))
		if err != nil {
			t.Fatalf("compressed object missing for %s: %v", entry.Digest[:12], err)
		}
		rc.Close()
	}
	// The INDEX advertises the compression marker on its sidecar view.
	index := fetchIndex(t, ctx, store, id)
	if index.MemoryRoot != m.FileDigest {
		t.Fatalf("index root %s, sidecar %s", index.MemoryRoot, m.FileDigest)
	}
	// Materialization lands the transport sidecar (marker included) and
	// a blind reader can decode every chunk back to the sealed bytes.
	blind := filepath.Join(filepath.Dir(source), "blind")
	if err := Materialize(ctx, blind, id, store); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	transport, err := checkpointchunks.LoadTransport(blind)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Compression != checkpointchunks.CompressionZstd {
		t.Fatalf("materialized sidecar compression = %q", transport.Compression)
	}
	for i, entry := range transport.Entries {
		length := chunkLen(t, transport, i)
		if entry.Digest == checkpointchunks.ZeroChunkDigest(length) {
			continue
		}
		raw, err := fetchKey(ctx, store, chunkstore.CompressedKey(entry.Digest))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := chunkstore.DecompressChunkBody(raw, length)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		sum := sha256.Sum256(plain)
		if hex.EncodeToString(sum[:]) != entry.Digest {
			t.Fatalf("chunk %d decoded bytes fail its digest", i)
		}
		if i < len(blocks) && !bytes.Equal(plain, blocks[i]) {
			t.Fatalf("chunk %d decoded bytes differ from the source", i)
		}
	}
}

func TestCompressedPublishReusesPlainObjects(t *testing.T) {
	ctx := context.Background()
	source, _ := compressedFixture(t, 3)
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// One chunk already exists uncompressed (a pre-compression share or
	// a packed-era leftover): it must be reused as-is, not re-uploaded
	// as a duplicate compressed body.
	m := mustManifest(t, source)
	shared := m.Entries[1]
	plainBlock, err := os.ReadFile(filepath.Join(source, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, shared.Digest, bytes.NewReader(
		plainBlock[shared.Offset:shared.Offset+int64(chunkLen(t, m, 1))])); err != nil {
		t.Fatal(err)
	}
	result, err := RunWithOptions(ctx, source, "comp-share", store, "test-local", Options{CompressChunks: true, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChunksSkip != 1 || result.ChunksPut != 2 {
		t.Fatalf("plain share not reused: %+v", result)
	}
	if ok, _ := store.HasKey(ctx, chunkstore.CompressedKey(shared.Digest)); ok {
		t.Fatal("reused plain chunk also uploaded a compressed duplicate")
	}
}

func TestCompressedPublishResumeSkipsWritten(t *testing.T) {
	ctx := context.Background()
	source, _ := compressedFixture(t, 3)
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{CompressChunks: true, Workers: 2}
	if _, err := RunWithOptions(ctx, source, "comp-resume", store, "test-local", opts); err != nil {
		t.Fatal(err)
	}
	again, err := RunWithOptions(ctx, source, "comp-resume", store, "test-local", opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.ChunksPut != 0 {
		t.Fatalf("resume re-uploaded compressed chunks: %+v", again)
	}
}

func TestCompressedOptionsRejections(t *testing.T) {
	source, _ := compressedFixture(t, 1)
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunWithOptions(context.Background(), source, "comp-bad", store, "test-local",
		Options{CompressChunks: true, PackBytes: 8192}); err == nil {
		t.Fatal("compression with packing accepted")
	}
	if ok, _ := store.HasKey(context.Background(), ArtifactKey("comp-bad", IndexName)); ok {
		t.Fatal("rejected options committed an INDEX")
	}
}

func mustManifest(t *testing.T, dir string) *checkpointchunks.Manifest {
	t.Helper()
	m, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func chunkLen(t *testing.T, m *checkpointchunks.Manifest, i int) int {
	t.Helper()
	length := int(min(int64(m.ChunkBytes), m.FileSize-m.Entries[i].Offset))
	if length <= 0 {
		t.Fatalf("chunk %d length %d", i, length)
	}
	return length
}

func fetchIndex(t *testing.T, ctx context.Context, store chunkstore.Keyed, id string) *ArtifactIndex {
	t.Helper()
	raw, err := fetchKey(ctx, store, ArtifactKey(id, IndexName))
	if err != nil {
		t.Fatal(err)
	}
	var index ArtifactIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	return &index
}
