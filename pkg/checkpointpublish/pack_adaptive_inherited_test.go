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

// Adaptive × auto-base × DIGEST-INHERITED child regression tests.
//
// A REAL child generation of a pack-only parent carries Inherited entries
// whose local memory regions are HOLES: the bytes exist only inside the
// parent generation's pack objects. Earlier fixtures (real bytes locally,
// only a base_memory hint) never exercised that shape — classification saw
// ordinary local chunks. These tests build the real shape: the child's
// inherited regions are zeros on disk and can NEVER satisfy a digest check
// from local bytes, so any pass that reads them is a guaranteed failure.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// inheritedChildFixture builds a child whose FIRST chunk(s) are digest-
// inherited from parentDir's sealed sidecar (holes locally) and whose LAST
// chunk is freshly dirty. The child sidecar is NOT computable from the
// local file — exactly the real sealing semantics.
func inheritedChildFixture(t *testing.T, root, parentDir, parentID, childID string) (string, string) {
	t.Helper()
	pm, err := checkpointchunks.Load(parentDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pm.Entries) < 2 {
		t.Fatalf("parent fixture needs >=2 chunks, has %d", len(pm.Entries))
	}
	childData := make([]byte, pm.FileSize) // all zeros = inherited holes
	last := pm.Entries[len(pm.Entries)-1]
	for i := int(last.Offset); i < len(childData); i++ {
		childData[i] = byte(i*7 + 3) // fresh dirty tail, different from parent
	}
	lastLen := min(int64(pm.ChunkBytes), pm.FileSize-last.Offset)
	sum := sha256.Sum256(childData[last.Offset : last.Offset+lastLen])
	if hex.EncodeToString(sum[:]) == last.Digest {
		t.Fatal("dirty tail must differ from the parent's last chunk")
	}
	entries := make([]checkpointchunks.Chunk, len(pm.Entries))
	for i, e := range pm.Entries[:len(pm.Entries)-1] {
		entries[i] = checkpointchunks.Chunk{Offset: e.Offset, Digest: e.Digest, Inherited: true}
	}
	entries[len(entries)-1] = checkpointchunks.Chunk{Offset: last.Offset, Digest: hex.EncodeToString(sum[:])}

	dir := filepath.Join(root, childID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), childData, 0o600); err != nil {
		t.Fatal(err)
	}
	cm := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: pm.FileSize,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		ChunkBytes:     pm.ChunkBytes, ChunkCount: len(entries), Entries: entries,
		FileDigest:        checkpointchunks.RootDigest(entries),
		InheritedFromRoot: pm.FileDigest,
	}
	raw, err := json.Marshal(cm)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointchunks.ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fc := map[string]any{
		"version": 2, "snapshot_type": "SoftDirty", "memory_size": cm.FileSize,
		"memory_digest_mode": checkpointchunks.FileDigestChunks,
		"digests":            map[string]string{"memory": cm.FileDigest},
		"base_memory":        parentID,
	}
	fcRaw, _ := json.Marshal(fc)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), fcRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vmstate-bytes"), 0o600)
	os.WriteFile(filepath.Join(dir, "overlay.ext4"), []byte("overlay-bytes"), 0o600)
	return dir, entries[0].Digest // child dir + the inherited digest
}

// publishInheritedParent publishes a chunks-v1 PACK-ONLY parent (no
// standalone chunk objects exist for its digests).
func publishInheritedParent(t *testing.T, root, parentID string, store chunkstore.Store) string {
	t.Helper()
	dir := adaptivePackedFixtureIn(t, root, parentID, adaptivePatternData())
	if _, err := RunWithOptions(context.Background(), dir, parentID, store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks}); err != nil {
		t.Fatalf("publish parent %s: %v", parentID, err)
	}
	return dir
}

// TestAdaptiveAutoBaseInheritedChildPublishes: the REAL child shape —
// Inherited entries over local holes, parent published pack-only, adaptive
// selects pack, auto-base resolves the parent. Must succeed by adopting the
// parent's verified pack references for the inherited digests; the holes
// must never be uploaded (no standalone object appears for them).
func TestAdaptiveAutoBaseInheritedChildPublishes(t *testing.T) {
	root := t.TempDir()
	store := adaptiveStoreSingle(t)
	parentDir := publishInheritedParent(t, root, "inh-parent", store)
	child, inheritedDigest := inheritedChildFixture(t, root, parentDir, "inh-parent", "inh-child")

	res, err := RunWithOptions(context.Background(), child, "inh-child", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			AdaptivePackThresholdBytes: 1, PackAutoBase: true})
	if err != nil {
		t.Fatalf("inherited child publish (adaptive+auto-base): %v", err)
	}
	if res.LayoutDecision == nil || res.LayoutDecision.Chosen != layoutPack {
		t.Fatalf("adaptive must choose pack: %+v", res.LayoutDecision)
	}
	if res.AutoBase == nil || !res.AutoBase.Used {
		t.Fatalf("auto-base must resolve the parent: %+v", res.AutoBase)
	}
	if res.PacksSkip == 0 {
		t.Fatalf("parent pack must be reused for the inherited chunk: %+v", res)
	}
	keyed, _ := store.(chunkstore.Keyed)
	if ok, _ := keyed.HasKey(context.Background(), chunkstore.PlainKey(inheritedDigest)); ok {
		t.Fatal("a standalone object appeared for an inherited hole — local hole bytes must never be uploaded")
	}
	if _, e := keyed.GetKey(context.Background(), ArtifactKey("inh-child", IndexName)); e != nil {
		t.Fatalf("INDEX: %v", e)
	}
	// FULL remote-memory verification: every logical block must be
	// restorable from the adopted parent packs plus the child's own packs —
	// a published transport that omitted some inherited digest's pack
	// reference would surface here as an unrecoverable artifact.
	if _, err := VerifyMemoryArtifact(context.Background(), "inh-child", keyed); err != nil {
		t.Fatalf("verify memory artifact: %v", err)
	}
	st, _ := Status(child)
	if st == nil || st.State != StatePublished {
		t.Fatalf("state: %+v", st)
	}
}

// TestAdaptiveAutoBaseInheritedPackMarked: the parent's only pack is
// sweep-marked — reuse is fenced and repacking an inherited hole is
// impossible, so the publish must fail closed naming the inherited chunk.
func TestAdaptiveAutoBaseInheritedPackMarked(t *testing.T) {
	root := t.TempDir()
	store, storeRoot := adaptiveStore(t)
	parentDir := publishInheritedParent(t, root, "inh-parent", store)
	// Mark EVERY pack object the parent produced: the store layout maps
	// keys to paths directly, so the walked relative path IS the key.
	keyed, _ := store.(chunkstore.Keyed)
	filepath.WalkDir(storeRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(storeRoot, path)
		if strings.Contains(rel, "memory-packs") || strings.Contains(rel, "memory-chunk-packs-v1") {
			if err := keyed.PutKey(context.Background(), GCMarkKey(rel), strings.NewReader("marked")); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	child, _ := inheritedChildFixture(t, root, parentDir, "inh-parent", "inh-child")
	_, err := RunWithOptions(context.Background(), child, "inh-child", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			AdaptivePackThresholdBytes: 1, PackAutoBase: true})
	if err == nil || !strings.Contains(err.Error(), "inherited") {
		t.Fatalf("marked parent pack must fail closed on the inherited chunk, got: %v", err)
	}
	if _, e := keyed.GetKey(context.Background(), ArtifactKey("inh-child", IndexName)); e == nil {
		t.Fatal("a failed inherited publish must not leave an INDEX behind")
	}
}

// TestAdaptiveAutoBaseParentUnavailableFails: the hint points at a parent
// that was never published to this store — auto-base falls back to no-base,
// and the inherited hole with no reusable parent pack must fail closed
// (never read the hole).
func TestAdaptiveAutoBaseParentUnavailableFails(t *testing.T) {
	root := t.TempDir()
	elsewhere := adaptiveStoreSingle(t)
	parentDir := publishInheritedParent(t, root, "inh-parent", elsewhere)
	fresh := adaptiveStoreSingle(t)
	child, _ := inheritedChildFixture(t, root, parentDir, "inh-parent", "inh-child")
	_, err := RunWithOptions(context.Background(), child, "inh-child", fresh, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			AdaptivePackThresholdBytes: 1, PackAutoBase: true})
	if err == nil || !strings.Contains(err.Error(), "inherited") {
		t.Fatalf("parent unavailable + inherited hole must fail closed, got: %v", err)
	}
	freshKeyed, _ := fresh.(chunkstore.Keyed)
	if _, e := freshKeyed.GetKey(context.Background(), ArtifactKey("inh-child", IndexName)); e == nil {
		t.Fatal("a failed inherited publish must not leave an INDEX behind")
	}
}

// TestAdaptivePlainInheritedFailsClosed: adaptive chooses PLAIN (threshold
// above the missing bytes) — the plain stage cannot serve an inherited hole
// and must fail closed at its own upload point.
func TestAdaptivePlainInheritedFailsClosed(t *testing.T) {
	root := t.TempDir()
	store := adaptiveStoreSingle(t)
	parentDir := publishInheritedParent(t, root, "inh-parent", store)
	child, _ := inheritedChildFixture(t, root, parentDir, "inh-parent", "inh-child")
	res, err := RunWithOptions(context.Background(), child, "inh-child", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			AdaptivePackThresholdBytes: 1 << 40, PackAutoBase: true})
	if err == nil || !strings.Contains(err.Error(), "inherited") {
		t.Fatalf("plain layout with inherited hole must fail closed, got: %v (res=%+v)", err, res)
	}
	plainKeyed, _ := store.(chunkstore.Keyed)
	if _, e := plainKeyed.GetKey(context.Background(), ArtifactKey("inh-child", IndexName)); e == nil {
		t.Fatal("a failed inherited publish must not leave an INDEX behind")
	}
}
