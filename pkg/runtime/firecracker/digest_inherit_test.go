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

package firecracker

// Digest-inheritance sealing tests: a sparse artifact's hole chunks carry the
// parent generation's bytes, so sealing must copy the parent digests (and
// mark the entries inherited) instead of zeroing them; the tier selection
// must route a lost byte lineage with a usable chunk manifest to an
// incremental first window instead of a Full that pulls every cold page.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

func writeInheritFixture(t *testing.T, touched []byte, parent *checkpointchunks.Manifest) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) > 0 {
		if _, err := f.Write(touched); err != nil {
			t.Fatal(err)
		}
	}
	// Extend to the full parent size so the untouched tail stays a hole.
	if err := f.Truncate(4 * checkpointchunks.DefaultChunkBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path
}

func TestScanFileChunksInheritsHoles(t *testing.T) {
	// Parent manifest with four distinct digests on the default grid.
	parent := &checkpointchunks.Manifest{
		Version:    1,
		File:       "memory",
		FileSize:   4 * checkpointchunks.DefaultChunkBytes,
		ChunkBytes: checkpointchunks.DefaultChunkBytes,
	}
	for i := 0; i < 4; i++ {
		block := make([]byte, checkpointchunks.DefaultChunkBytes)
		block[0] = byte(i + 1)
		sum := sha256.Sum256(block)
		parent.Entries = append(parent.Entries, checkpointchunks.Chunk{
			Offset: int64(i) * checkpointchunks.DefaultChunkBytes,
			Digest: hex.EncodeToString(sum[:]),
		})
	}
	parent.ChunkCount = len(parent.Entries)
	parent.FileDigest = checkpointchunks.RootDigest(parent.Entries)

	// Local artifact: only chunk 2 was touched; 0/1/3 are holes.
	touched := make([]byte, checkpointchunks.DefaultChunkBytes)
	touched[0] = 'X'
	path := writeInheritFixture(t,
		touched, // chunk 0 region becomes data; truncate leaves 1..3 as holes
		parent)
	// Overwrite chunk-0 expectation: the sealed digest of the touched block.
	touchedSum := sha256.Sum256(touched)

	got, err := scanFileChunks(context.Background(), path, "memory", parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 4 {
		t.Fatalf("entries=%d want 4", len(got.Entries))
	}
	if got.Entries[0].Digest != hex.EncodeToString(touchedSum[:]) || got.Entries[0].Inherited {
		t.Fatalf("chunk 0 not sealed from local data: %+v", got.Entries[0])
	}
	for _, i := range []int{1, 2, 3} {
		e := got.Entries[i]
		if !e.Inherited || e.Digest != parent.Entries[i].Digest {
			t.Fatalf("chunk %d not inherited from parent: %+v want digest %s",
				i, e, parent.Entries[i].Digest[:12])
		}
	}
	if got.InheritedFromRoot != parent.FileDigest {
		t.Fatalf("audit root not recorded: %q", got.InheritedFromRoot)
	}
	// The root must be derivable from the merged entries alone.
	if checkpointchunks.RootDigest(got.Entries) != got.FileDigest {
		t.Fatal("root digest does not match entries")
	}
}

func TestScanFileChunksInheritRequiresParentEntry(t *testing.T) {
	parent := &checkpointchunks.Manifest{
		Version:    1,
		File:       "memory",
		FileSize:   4 * checkpointchunks.DefaultChunkBytes,
		ChunkBytes: checkpointchunks.DefaultChunkBytes,
		ChunkCount: 2, // deliberately covers fewer entries than the artifact
	}
	block := make([]byte, checkpointchunks.DefaultChunkBytes)
	sum := sha256.Sum256(block)
	parent.Entries = append(parent.Entries,
		checkpointchunks.Chunk{Offset: 0, Digest: hex.EncodeToString(sum[:])},
		checkpointchunks.Chunk{Offset: checkpointchunks.DefaultChunkBytes, Digest: hex.EncodeToString(sum[:])},
	)
	path := writeInheritFixture(t, nil, parent)
	_, err := scanFileChunks(context.Background(), path, "memory", parent)
	if err == nil || !strings.Contains(err.Error(), "no parent entry to inherit") {
		t.Fatalf("expected inheritance failure for uncovered hole, got %v", err)
	}
}

func TestTierSelectsInheritedIncrementalWindow(t *testing.T) {
	snapshotType, base, incremental, layoutSize, err := selectFirecrackerSnapshotTierUsable(
		64<<10, "", false, true, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotType != firecrackerSnapshotTypeSoftDirty || base != "" ||
		incremental || layoutSize != 64<<10 {
		t.Fatalf("lost lineage with chunk manifest did not take the inherited SoftDirty window: type=%q base=%q incr=%v layout=%d",
			snapshotType, base, incremental, layoutSize)
	}
	// Without a chunk manifest the Full fallback stands.
	snapshotType, _, _, layoutSize, err = selectFirecrackerSnapshotTierUsable(
		64<<10, "", false, true, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotType != firecrackerSnapshotTypeFull || layoutSize != 0 {
		t.Fatalf("lost lineage without chunk manifest must stay Full: type=%q layout=%d",
			snapshotType, layoutSize)
	}
}
