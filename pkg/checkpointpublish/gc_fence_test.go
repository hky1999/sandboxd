// Copyright 2026 Ant Group Corporation.
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

// Sweep-fence tests: a Has-hit reuse of an object carrying a gc-marks/<key>
// mark must not skip the upload. The mark says a bucket sweep judged the
// object dead and may collect it once the grace elapses; min-age cannot
// protect the reuse because the object is old by construction.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// TestPublishRefreshesSweepMarkedReuse: an unmarked rerun skips (the
// pre-existing dedup contract), a marked rerun re-uploads — refreshing the
// object so the sweep's delete-time recheck spares it.
func TestPublishRefreshesSweepMarkedReuse(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, err := chunkstore.NewLocal(filepath.Join(filepath.Dir(dir), "store"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if first.ChunksPut == 0 {
		t.Fatalf("first publish uploaded nothing: %+v", first)
	}
	again, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("unmarked rerun: %v", err)
	}
	if again.ChunksSkip == 0 {
		t.Fatalf("unmarked rerun lost the dedup skip: %+v", again)
	}

	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(store)
	for _, entry := range manifest.Entries {
		if err := keyed.PutKey(context.Background(), GCMarkKey(chunkstore.PlainKey(entry.Digest)), strings.NewReader("marked")); err != nil {
			t.Fatal(err)
		}
	}
	fenced, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("marked rerun: %v", err)
	}
	if fenced.ChunksPut != first.ChunksPut || fenced.ChunksSkip != 0 {
		t.Fatalf("marked reuse not refreshed: put=%d skip=%d want put=%d skip=0",
			fenced.ChunksPut, fenced.ChunksSkip, first.ChunksPut)
	}
}

// TestPublishRefusesSweepMarkedInheritedHole: a digest-inherited entry has
// no local bytes — its content lives in the store under the parent's digest.
// A marked parent object means the parent generation is on its way out;
// publishing against it must fail rather than seal zeros under the digest.
func TestPublishRefusesSweepMarkedInheritedHole(t *testing.T) {
	parent := make([]byte, 300<<10)
	for i := range parent {
		parent[i] = byte(i*7 + 1)
	}
	sum := sha256.Sum256(parent)
	parentDigest := hex.EncodeToString(sum[:])
	dir := t.TempDir()
	// Sparse local artifact: the hole IS the parent content.
	if err := os.WriteFile(filepath.Join(dir, "memory"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "memory"), int64(len(parent))); err != nil {
		t.Fatal(err)
	}
	manifest := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: int64(len(parent)),
		ChunkBytes: checkpointchunks.DefaultChunkBytes, ChunkCount: 2,
		FileDigestMode: checkpointchunks.FileDigestChunks,
	}
	manifest.Entries = append(manifest.Entries,
		checkpointchunks.Chunk{Offset: 0, Digest: parentDigest, Inherited: true},
		checkpointchunks.Chunk{Offset: checkpointchunks.DefaultChunkBytes, Digest: parentDigest, Inherited: true},
	)
	if err := checkpointchunks.Write(dir, manifest); err != nil {
		t.Fatal(err)
	}
	store, err := chunkstore.NewLocal(filepath.Join(dir, "..", "hole-store"))
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(store)
	// The parent object exists (the reuse would otherwise be a hit) and a
	// sweep marked it.
	if err := store.Put(context.Background(), parentDigest, strings.NewReader(string(parent))); err != nil {
		t.Fatal(err)
	}
	if err := keyed.PutKey(context.Background(), GCMarkKey(chunkstore.PlainKey(parentDigest)), strings.NewReader("marked")); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err == nil || !strings.Contains(err.Error(), "marked for collection") {
		t.Fatalf("expected the marked inherited hole to fail the publish, got %v", err)
	}
}
