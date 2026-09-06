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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

func sealedSparseBaseFixture(t *testing.T) (*firecrackerInstance, string, *firecrackerCheckpointManifest, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	data := make([]byte, 1<<20)
	data[4099] = 0xA7
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0xA7}, 4099); err != nil {
		t.Fatal(err)
	}
	f.Close()
	info, err := os.Stat(path)
	if err != nil || !firecrackerMemoryHasHoles(info) {
		t.Fatalf("fixture must have actual sparse allocation: %v", err)
	}
	chunks, err := checkpointchunks.Compute(context.Background(), dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	chunks.FileDigestMode = checkpointchunks.FileDigestChunks
	chunks.FileDigest = checkpointchunks.RootDigest(chunks.Entries)
	if err = checkpointchunks.Write(dir, chunks); err != nil {
		t.Fatal(err)
	}
	manifest := &firecrackerCheckpointManifest{MemorySize: int64(len(data)), MemoryDigestMode: chunks.FileDigestMode, Digests: map[string]string{"memory": chunks.FileDigest}}
	instance := &firecrackerInstance{state: firecrackerPersistedState{MemoryMiB: 1}}
	return instance, path, manifest, data
}
func TestSealedSparseBaseLifecycle(t *testing.T) {
	original := cloneFileIoctl
	reflinkUsed := false
	cloneFileIoctl = func(dst, src *os.File) error {
		err := original(dst, src)
		if err == nil {
			reflinkUsed = true
		}
		return err
	}
	t.Cleanup(func() { cloneFileIoctl = original })
	instance, path, m, data := sealedSparseBaseFixture(t)
	adoptSealedCheckpointMemory(context.Background(), instance, path, m)
	proof := instance.checkpointBaseProof()
	if proof == nil {
		t.Fatal("local seal did not acquire proof")
	}
	typ, base, _, size, err := selectCheckpointTierWithProof(instance.snapshot(), "", proof)
	if err != nil || typ != firecrackerSnapshotTypeSoftDirty || base != path {
		t.Fatalf("tier: %s %s %v", typ, base, err)
	}
	files, err := prepareCheckpointWithProof(context.Background(), filepath.Join(t.TempDir(), "next"), base, size, proof)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(files.Memory)
	if err != nil || !bytes.Equal(copied, data) {
		t.Fatal("cloned base differs")
	}
	// Patch and seal the next local generation. Reflink filesystems retain
	// legitimate holes; fallback files may be dense. Both must preserve lineage.
	nextFile, err := os.OpenFile(files.Memory, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nextFile.WriteAt([]byte{0x5B}, 32769)
	nextFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	data[32769] = 0x5B
	nextChunks, err := checkpointchunks.Compute(context.Background(), filepath.Dir(files.Memory), 4096)
	if err != nil {
		t.Fatal(err)
	}
	nextChunks.FileDigestMode = checkpointchunks.FileDigestChunks
	nextChunks.FileDigest = checkpointchunks.RootDigest(nextChunks.Entries)
	if err = checkpointchunks.Write(filepath.Dir(files.Memory), nextChunks); err != nil {
		t.Fatal(err)
	}
	nextManifest := &firecrackerCheckpointManifest{MemorySize: int64(len(data)), MemoryDigestMode: nextChunks.FileDigestMode, Digests: map[string]string{"memory": nextChunks.FileDigest}}
	adoptSealedCheckpointMemory(context.Background(), instance, files.Memory, nextManifest)
	typ, nextBase, _, _, err := selectCheckpointTierWithProof(instance.snapshot(), "", instance.checkpointBaseProof())
	if err != nil || typ != firecrackerSnapshotTypeSoftDirty || nextBase != files.Memory {
		t.Fatal("next generation lost valid lineage")
	}
	got, err := os.ReadFile(files.Memory)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("next generation lost bytes")
	}
	t.Logf("reflink=%t next_proof=%t", reflinkUsed, instance.checkpointBaseProof() != nil)
	// Re-establish the sparse fixture so the restart assertion below cannot
	// accidentally pass through a dense fallback clone.
	adoptSealedCheckpointMemory(context.Background(), instance, path, m)
	// The public conservative adoption path, used by restore, still rejects
	// the same sparse file rather than creating a proof from its geometry.
	restored := &firecrackerInstance{state: firecrackerPersistedState{MemoryMiB: 1}}
	adoptCheckpointMemory(restored, path, true)
	if !restored.snapshot().BaseMemoryLineageLost || restored.checkpointBaseProof() != nil {
		t.Fatal("restore blessed unproven sparse base")
	}
	// Serialized runtime state never contains a proof. A recovered association
	// therefore cannot make a sparse file eligible by itself.
	raw, err := json.Marshal(instance.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var state firecrackerPersistedState
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	typ, base, _, _, err = selectCheckpointTierWithProof(state, "", nil)
	if err != nil || typ != firecrackerSnapshotTypeFull || base != "" {
		t.Fatal("restart inherited sparse proof")
	}
}
func TestSparseProofMutationRejectedBeforeUse(t *testing.T) {
	for _, kind := range []string{"marker", "replace", "content", "size", "path"} {
		t.Run(kind, func(t *testing.T) {
			instance, path, m, _ := sealedSparseBaseFixture(t)
			adoptSealedCheckpointMemory(context.Background(), instance, path, m)
			p := instance.checkpointBaseProof()
			if p == nil {
				t.Fatal("no proof")
			}
			switch kind {
			case "marker":
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".materialized"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "replace":
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				q := path + "new"
				if err = os.WriteFile(q, b, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(q, path); err != nil {
					t.Fatal(err)
				}
			case "content":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte{9}, 0)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "size":
				if err := os.Truncate(path, 2<<20); err != nil {
					t.Fatal(err)
				}
			case "path":
				instance.mu.Lock()
				instance.state.BaseMemoryPath = path + "wrong"
				instance.mu.Unlock()
			}
			typ, base, _, size, err := selectCheckpointTierWithProof(instance.snapshot(), "", p)
			if err != nil {
				t.Fatal(err)
			}
			if typ == firecrackerSnapshotTypeFull {
				if base != "" {
					t.Fatal("Full retained base")
				}
				return
			}
			target := filepath.Join(t.TempDir(), "next")
			if _, err = prepareCheckpointWithProof(context.Background(), target, base, size, p); err == nil {
				t.Fatal("used changed proof")
			}
			if _, err = os.Stat(filepath.Join(target, "memory")); !os.IsNotExist(err) {
				t.Fatalf("invalid clone remains: %v", err)
			}
		})
	}
}
func TestSparseProofClearedAndBadSealRejected(t *testing.T) {
	for _, op := range []string{"set", "clear", "lost", "wrong-root", "marker"} {
		t.Run(op, func(t *testing.T) {
			instance, path, m, _ := sealedSparseBaseFixture(t)
			adoptSealedCheckpointMemory(context.Background(), instance, path, m)
			if instance.checkpointBaseProof() == nil {
				t.Fatal("no initial proof")
			}
			switch op {
			case "set":
				instance.setBaseMemory(path, false)
			case "clear":
				instance.clearBaseMemory()
			case "lost":
				instance.markBaseMemoryLineageLost()
			case "wrong-root":
				m.Digests["memory"] = checkpointchunks.ZeroChunkDigest(1)
				adoptSealedCheckpointMemory(context.Background(), instance, path, m)
			case "marker":
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".materialized"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				adoptSealedCheckpointMemory(context.Background(), instance, path, m)
			}
			if instance.checkpointBaseProof() != nil {
				t.Fatal("stale proof remains")
			}
			typ, _, _, _, err := selectCheckpointTierWithProof(instance.snapshot(), "", nil)
			if err != nil || typ != firecrackerSnapshotTypeFull {
				t.Fatalf("unsafe next tier: %s %v", typ, err)
			}
		})
	}
}

func TestDenseBaseMarkerAddedAfterAdoption(t *testing.T) {
	for _, link := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "memory")
		if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 1<<20), 0600); err != nil {
			t.Fatal(err)
		}
		instance := &firecrackerInstance{state: firecrackerPersistedState{MemoryMiB: 1}}
		adoptCheckpointMemory(instance, path, false)
		if instance.snapshot().BaseMemoryPath != path {
			t.Fatal("dense fixture was not adopted")
		}
		marker := filepath.Join(dir, ".materialized")
		if link {
			if err := os.Symlink("missing-marker-target", marker); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.WriteFile(marker, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		typ, base, _, _, err := selectCheckpointTierWithProof(instance.snapshot(), "", nil)
		if err != nil || typ != firecrackerSnapshotTypeFull || base != "" {
			t.Fatal("tier accepted marked dense base")
		}
		adoptCheckpointMemory(instance, path, false)
		if !instance.snapshot().BaseMemoryLineageLost {
			t.Fatal("adoption accepted materialized marker")
		}
	}
}

func TestSealedCheckpointContinuationPolicy(t *testing.T) {
	for _, leaveRunning := range []bool{false, true} {
		name := "stopping"
		if leaveRunning {
			name = "continuing"
		}
		t.Run(name, func(t *testing.T) {
			instance, path, manifest, data := sealedSparseBaseFixture(t)
			adoptSealedCheckpointMemory(context.Background(), instance, path, manifest)
			if instance.checkpointBaseProof() == nil {
				t.Fatal("fixture has no previous proof")
			}
			updateSealedCheckpointLineage(context.Background(), instance, path, manifest, leaveRunning)
			state, proof := instance.checkpointStateAndProof()
			typ, base, _, _, err := selectCheckpointTierWithProof(state, "", proof)
			if err != nil {
				t.Fatal(err)
			}
			if leaveRunning {
				if proof == nil || typ != firecrackerSnapshotTypeSoftDirty || base != path {
					t.Fatal("continuing checkpoint lost its verified base")
				}
			} else {
				// This is the state before stop is attempted. If stop fails and the
				// process survives, a subsequent checkpoint must not patch its old base.
				if proof != nil || !state.BaseMemoryLineageLost || base != "" || typ != firecrackerSnapshotTypeFull {
					t.Fatalf("stopping lineage retained: %+v", state)
				}
				if _, _, _, _, err = selectCheckpointTierWithProof(state, firecrackerSnapshotTypeSoftDirty, proof); err == nil {
					t.Fatal("explicit delta accepted after invalidation")
				}
				raw, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				var recovered firecrackerPersistedState
				if err = json.Unmarshal(raw, &recovered); err != nil {
					t.Fatal(err)
				}
				if !recovered.BaseMemoryLineageLost || recovered.BaseMemoryPath != "" {
					t.Fatal("persisted stale lineage")
				}
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, data) {
				t.Fatal("lineage policy changed sealed bytes")
			}
		})
	}
}

func TestStoppingLineageInvalidatesAfterCancellation(t *testing.T) {
	instance, path, manifest, _ := sealedSparseBaseFixture(t)
	adoptSealedCheckpointMemory(context.Background(), instance, path, manifest)
	// Cancellation after sealing must not leave the previous dirty window
	// eligible for reuse if source cleanup fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	updateSealedCheckpointLineage(ctx, instance, path, manifest, false)
	state, proof := instance.checkpointStateAndProof()
	if proof != nil || state.BaseMemoryPath != "" || !state.BaseMemoryLineageLost {
		t.Fatal("old proof survived stopping policy")
	}
}
