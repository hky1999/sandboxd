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
	"os"
	"path/filepath"
	"testing"
)

func TestFirecrackerBaseMemoryUsable(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base-memory")
	writeArtifactComponent(t, base, 64<<10)
	if !firecrackerBaseMemoryUsable(base, 64<<10) {
		t.Fatal("a matching regular base is not usable")
	}
	if firecrackerBaseMemoryUsable(base, 32<<10) {
		t.Fatal("a size-mismatched base is usable")
	}
	if firecrackerBaseMemoryUsable(filepath.Join(dir, "missing"), 64<<10) {
		t.Fatal("a missing base is usable")
	}
	link := filepath.Join(dir, "base-link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatalf("symlink base: %v", err)
	}
	if firecrackerBaseMemoryUsable(link, 64<<10) {
		t.Fatal("a symlinked base is usable")
	}
}

func newIncrementalTestHandler(t *testing.T) (*Handler, *firecrackerInstance, string) {
	t.Helper()
	storageRoot := t.TempDir()
	handler := &Handler{storageRoot: storageRoot}
	sandboxID := "sbox-incremental-test"
	if err := os.Mkdir(filepath.Join(storageRoot, sandboxID), 0700); err != nil {
		t.Fatalf("create storage dir: %v", err)
	}
	instance := &firecrackerInstance{}
	return handler, instance, sandboxID
}

func TestAdoptCheckpointMemoryAdvancesBase(t *testing.T) {
	handler, instance, sandboxID := newIncrementalTestHandler(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "gen1-memory")
	writeArtifactComponent(t, first, 64<<10)

	handler.adoptCheckpointMemory(instance, first, sandboxID, true)
	state := instance.snapshot()
	if state.BaseMemoryPath == "" || !state.BaseMemoryIncremental {
		t.Fatalf("base lineage not adopted: %+v", state)
	}
	baseContent, err := os.ReadFile(state.BaseMemoryPath)
	if err != nil {
		t.Fatalf("read adopted base: %v", err)
	}
	firstContent, _ := os.ReadFile(first)
	if string(baseContent) != string(firstContent) {
		t.Fatal("adopted base diverged from the checkpoint memory")
	}

	// A second adoption replaces the base without leaving staging behind.
	second := filepath.Join(dir, "gen2-memory")
	writeArtifactComponent(t, second, 32<<10)
	handler.adoptCheckpointMemory(instance, second, sandboxID, false)
	state = instance.snapshot()
	if state.BaseMemoryIncremental {
		t.Fatal("checkpoint adoption kept the restore marker")
	}
	entries, err := os.ReadDir(filepath.Dir(state.BaseMemoryPath))
	if err != nil {
		t.Fatalf("scan storage dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("adoption left %d files behind, want 1", len(entries))
	}
	secondContent, _ := os.ReadFile(second)
	baseContent, _ = os.ReadFile(state.BaseMemoryPath)
	if string(baseContent) != string(secondContent) {
		t.Fatal("adopted base was not replaced")
	}
}

func TestAdoptCheckpointMemoryDropsLineageOnFailure(t *testing.T) {
	handler, instance, sandboxID := newIncrementalTestHandler(t)
	memory := filepath.Join(t.TempDir(), "memory")
	writeArtifactComponent(t, memory, 64<<10)

	// A sandbox ID that escapes the storage root must not adopt anything.
	handler.adoptCheckpointMemory(instance, memory, "../"+sandboxID, true)
	if instance.snapshot().BaseMemoryPath != "" {
		t.Fatal("base adopted outside the storage root")
	}

	// An empty memory path is a no-op, not a failure.
	handler.adoptCheckpointMemory(instance, "", sandboxID, true)
	if instance.snapshot().BaseMemoryPath != "" {
		t.Fatal("empty adoption changed the lineage")
	}
}

func TestDisarmBaseMemoryRemovesBase(t *testing.T) {
	handler, instance, sandboxID := newIncrementalTestHandler(t)
	memory := filepath.Join(t.TempDir(), "memory")
	writeArtifactComponent(t, memory, 64<<10)
	handler.adoptCheckpointMemory(instance, memory, sandboxID, false)
	base := instance.snapshot().BaseMemoryPath
	if base == "" {
		t.Fatal("adoption failed")
	}

	handler.disarmBaseMemory(instance, sandboxID)
	if instance.snapshot().BaseMemoryPath != "" {
		t.Fatal("disarm kept the lineage")
	}
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("disarmed base file still present: %v", err)
	}
	// Disarming without a lineage is a no-op.
	handler.disarmBaseMemory(instance, sandboxID)
}

func TestDiscardUnsealedFirecrackerCheckpoint(t *testing.T) {
	dir := t.TempDir()
	files := firecrackerCheckpointFiles{
		State:   filepath.Join(dir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
	}
	for _, path := range []string{files.State, files.Memory} {
		writeArtifactComponent(t, path, 4096)
	}
	discardUnsealedFirecrackerCheckpoint(files)
	for _, path := range []string{files.State, files.Memory, files.Overlay} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("component %s survived the discard: %v", path, err)
		}
	}
}
