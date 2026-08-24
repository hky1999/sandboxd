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

func TestAdoptCheckpointMemoryRecordsArtifactMemory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "gen1"), 0700); err != nil {
		t.Fatalf("create artifact dir: %v", err)
	}
	instance := &firecrackerInstance{}
	memory := filepath.Join(dir, "gen1", firecrackerCheckpointMemoryName)
	writeArtifactComponent(t, memory, 64<<10)

	adoptCheckpointMemory(instance, memory, true)
	state := instance.snapshot()
	if state.BaseMemoryPath != memory || !state.BaseMemoryIncremental {
		t.Fatalf("base lineage not adopted: %+v", state)
	}

	// A later checkpoint adoption flips the ledger marker: the next
	// generation diffs through the soft-dirty window, not the pagemap.
	writeArtifactComponent(t, memory, 64<<10)
	adoptCheckpointMemory(instance, memory, false)
	state = instance.snapshot()
	if state.BaseMemoryPath != memory || state.BaseMemoryIncremental {
		t.Fatalf("checkpoint adoption kept the restore marker: %+v", state)
	}
}

func TestAdoptCheckpointMemoryDropsUnusableLineage(t *testing.T) {
	dir := t.TempDir()
	instance := &firecrackerInstance{}
	link := filepath.Join(dir, "memory-link")
	if err := os.Symlink(filepath.Join(dir, "memory"), link); err != nil {
		t.Fatalf("symlink memory: %v", err)
	}

	adoptCheckpointMemory(instance, link, false)
	if instance.snapshot().BaseMemoryPath != "" {
		t.Fatal("a symlinked memory was adopted as a base")
	}

	memory := filepath.Join(dir, "memory")
	writeArtifactComponent(t, memory, 64<<10)
	adoptCheckpointMemory(instance, memory, false)
	if instance.snapshot().BaseMemoryPath == "" {
		t.Fatal("adoption failed for a regular memory file")
	}
	instance.clearBaseMemory()
	if instance.snapshot().BaseMemoryPath != "" || instance.snapshot().BaseMemoryIncremental {
		t.Fatal("clearBaseMemory left the lineage behind")
	}
	// Clearing again is a no-op.
	if instance.clearBaseMemory() {
		t.Fatal("second clear reported a change")
	}
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
