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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
)

func TestSelectFirecrackerSnapshotTier(t *testing.T) {
	dir := t.TempDir()
	usableBase := filepath.Join(dir, "gen0", firecrackerCheckpointMemoryName)
	if err := os.Mkdir(filepath.Dir(usableBase), 0700); err != nil {
		t.Fatalf("create base dir: %v", err)
	}
	writeArtifactComponent(t, usableBase, 1<<20)
	driftedBase := filepath.Join(dir, "drifted", firecrackerCheckpointMemoryName)

	for _, tc := range []struct {
		name            string
		memorySize      int64
		base            string
		baseIncremental bool
		lineageLost     bool
		requested       string
		wantType        string
		wantBase        string
		wantLayoutSize  int64
		wantErr         bool
	}{
		{
			name:           "auto without base establishes a Full baseline",
			memorySize:     1 << 20,
			wantType:       firecrackerSnapshotTypeFull,
			wantLayoutSize: 0,
		},
		{
			name:            "auto with checkpoint base keeps soft-dirty windows",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: false,
			wantType:        firecrackerSnapshotTypeSoftDirty,
			wantBase:        usableBase,
			wantLayoutSize:  1 << 20,
		},
		{
			name:            "auto after restore runs incremental",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: true,
			wantType:        firecrackerSnapshotTypeIncremental,
			wantBase:        usableBase,
			wantLayoutSize:  1 << 20,
		},
		{
			name:           "auto with drifted base forces Full",
			memorySize:     1 << 20,
			base:           driftedBase,
			wantType:       firecrackerSnapshotTypeFull,
			wantLayoutSize: 0,
		},
		{
			name:           "auto with lost lineage forces Full",
			memorySize:     1 << 20,
			lineageLost:    true,
			wantType:       firecrackerSnapshotTypeFull,
			wantLayoutSize: 0,
		},
		{
			name:            "lost lineage ignores a recorded base",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: false,
			lineageLost:     true,
			wantType:        firecrackerSnapshotTypeFull,
			wantLayoutSize:  0,
		},
		{
			name:        "explicit SoftDirty with lost lineage is an error",
			memorySize:  1 << 20,
			lineageLost: true,
			requested:   firecrackerSnapshotTypeSoftDirty,
			wantErr:     true,
		},
		{
			name:        "explicit Incremental with lost lineage is an error",
			memorySize:  1 << 20,
			lineageLost: true,
			requested:   firecrackerSnapshotTypeIncremental,
			wantErr:     true,
		},
		{
			name:            "explicit Full with lost lineage restarts the chain",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: true,
			lineageLost:     true,
			requested:       firecrackerSnapshotTypeFull,
			wantType:        firecrackerSnapshotTypeFull,
			wantLayoutSize:  0,
		},
		{
			name:            "explicit Full drops the lineage and the size",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: true,
			requested:       firecrackerSnapshotTypeFull,
			wantType:        firecrackerSnapshotTypeFull,
			wantLayoutSize:  0,
		},
		{
			name:       "explicit Incremental without a base is an error",
			memorySize: 1 << 20,
			requested:  firecrackerSnapshotTypeIncremental,
			wantErr:    true,
		},
		{
			name:            "explicit Incremental with a checkpoint base is an error",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: false,
			requested:       firecrackerSnapshotTypeIncremental,
			wantErr:         true,
		},
		{
			name:            "explicit Incremental after restore is honored",
			memorySize:      1 << 20,
			base:            usableBase,
			baseIncremental: true,
			requested:       firecrackerSnapshotTypeIncremental,
			wantType:        firecrackerSnapshotTypeIncremental,
			wantBase:        usableBase,
			wantLayoutSize:  1 << 20,
		},
		{
			name:           "explicit SoftDirty without a base is a first window",
			memorySize:     1 << 20,
			requested:      firecrackerSnapshotTypeSoftDirty,
			wantType:       firecrackerSnapshotTypeSoftDirty,
			wantLayoutSize: 1 << 20,
		},
		{
			name:      "unknown snapshot type is rejected",
			requested: "Lazy",
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshotType, base, _, layoutSize, err := selectFirecrackerSnapshotTier(
				tc.memorySize, tc.base, tc.baseIncremental, tc.lineageLost, tc.requested,
			)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tier selection succeeded: %+v", tc)
				}
				return
			}
			if err != nil {
				t.Fatalf("tier selection failed: %v", err)
			}
			if snapshotType != tc.wantType {
				t.Fatalf("snapshot type %q, want %q", snapshotType, tc.wantType)
			}
			if base != tc.wantBase {
				t.Fatalf("base %q, want %q", base, tc.wantBase)
			}
			if layoutSize != tc.wantLayoutSize {
				t.Fatalf("layout size %d, want %d", layoutSize, tc.wantLayoutSize)
			}
		})
	}
}

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
	// An unusable adoption must force the Full recovery path: the VMM
	// ledger may still be armed against the recorded base.
	if !instance.snapshot().BaseMemoryLineageLost {
		t.Fatal("an unusable adoption kept the lineage trusted")
	}

	memory := filepath.Join(dir, "memory")
	writeArtifactComponent(t, memory, 64<<10)
	adoptCheckpointMemory(instance, memory, false)
	state := instance.snapshot()
	if state.BaseMemoryPath == "" {
		t.Fatal("adoption failed for a regular memory file")
	}
	if state.BaseMemoryLineageLost {
		t.Fatal("a successful adoption kept the lineage marked lost")
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

// TestBaseMemoryLineageLostSurvivesRestart pins the recovery contract: once
// the lineage is marked lost, persisting and re-reading the instance state
// must keep the marker and the cleared base, so a later daemon restart can
// never resurrect a stale base the VMM ledger may no longer match.
func TestBaseMemoryLineageLostSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "gen1"), 0700); err != nil {
		t.Fatalf("create artifact dir: %v", err)
	}
	instance := &firecrackerInstance{}
	memory := filepath.Join(dir, "gen1", firecrackerCheckpointMemoryName)
	writeArtifactComponent(t, memory, 64<<10)

	// A checkpointed sandbox with a healthy lineage.
	adoptCheckpointMemory(instance, memory, false)
	if instance.snapshot().BaseMemoryLineageLost {
		t.Fatal("a healthy lineage is marked lost")
	}

	// The discard-recovery path: the VMM wrote and re-armed, the caller
	// dropped the generation.
	instance.markBaseMemoryLineageLost()

	// Persist and reload, as a daemon restart does.
	data, err := json.Marshal(instance.snapshot())
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	var reloaded firecrackerPersistedState
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if reloaded.BaseMemoryPath != "" {
		t.Fatalf("reloaded state kept the base %q", reloaded.BaseMemoryPath)
	}
	if !reloaded.BaseMemoryLineageLost {
		t.Fatal("reloaded state lost the lineage-lost marker")
	}

	// The marker forces the Full recovery tier until a new base is adopted.
	snapshotType, base, _, layoutSize, err := selectFirecrackerSnapshotTier(
		64<<10, reloaded.BaseMemoryPath, reloaded.BaseMemoryIncremental,
		reloaded.BaseMemoryLineageLost, "",
	)
	if err != nil || snapshotType != firecrackerSnapshotTypeFull ||
		base != "" || layoutSize != 0 {
		t.Fatalf("lost lineage did not force Full: type=%q base=%q layout=%d err=%v",
			snapshotType, base, layoutSize, err)
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

func TestResolveRequestedSnapshotTypeGatesIncrementalOnMode(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		requested string
		want      string
		wantErr   bool
	}{
		// Default mode: everything becomes Full or is rejected outright.
		{mode: firecrackerCheckpointModeFull, requested: "", want: firecrackerSnapshotTypeFull},
		{mode: firecrackerCheckpointModeFull, requested: firecrackerSnapshotTypeFull, want: firecrackerSnapshotTypeFull},
		{mode: firecrackerCheckpointModeFull, requested: firecrackerSnapshotTypeSoftDirty, wantErr: true},
		{mode: firecrackerCheckpointModeFull, requested: firecrackerSnapshotTypeIncremental, wantErr: true},
		// Opt-in mode: the request passes through untouched for tier
		// selection to validate.
		{mode: firecrackerCheckpointModeIncremental, requested: "", want: ""},
		{mode: firecrackerCheckpointModeIncremental, requested: firecrackerSnapshotTypeFull, want: firecrackerSnapshotTypeFull},
		{mode: firecrackerCheckpointModeIncremental, requested: firecrackerSnapshotTypeSoftDirty, want: firecrackerSnapshotTypeSoftDirty},
	} {
		got, err := resolveRequestedSnapshotType(tc.mode, tc.requested)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("mode=%q requested=%q: gate accepted it as %q", tc.mode, tc.requested, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("mode=%q requested=%q: %v", tc.mode, tc.requested, err)
		}
		if got != tc.want {
			t.Fatalf("mode=%q requested=%q: got %q want %q", tc.mode, tc.requested, got, tc.want)
		}
	}
}

func TestValidateFirecrackerCheckpointMode(t *testing.T) {
	for _, mode := range []string{"", "full", "incremental"} {
		if err := validateFirecrackerCheckpointMode(mode); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
	for _, mode := range []string{"Full", "INCREMENTAL", "soft-dirty", "auto"} {
		if err := validateFirecrackerCheckpointMode(mode); err == nil {
			t.Fatalf("mode %q accepted", mode)
		}
	}
}

func TestApplyFirecrackerDefaultsNormalizesCheckpointMode(t *testing.T) {
	value := config.FirecrackerConfig{}
	applyFirecrackerDefaults(&value)
	if value.CheckpointMode != firecrackerCheckpointModeFull {
		t.Fatalf("unset checkpoint_mode defaulted to %q", value.CheckpointMode)
	}
	value = config.FirecrackerConfig{CheckpointMode: firecrackerCheckpointModeIncremental}
	applyFirecrackerDefaults(&value)
	if value.CheckpointMode != firecrackerCheckpointModeIncremental {
		t.Fatalf("explicit checkpoint_mode overwritten: %q", value.CheckpointMode)
	}
}
