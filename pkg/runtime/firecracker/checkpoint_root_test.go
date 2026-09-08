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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// sealV2ChunksModeArtifactFixture seals a v2 directory in chunks digest
// mode, so the memory AND overlay sidecars exist — the only shape whose
// every artifact carries a verifiable root and therefore the shape an
// identified restore operation can bind. The default fixture seals in
// whole-file mode and writes no overlay sidecar: its overlay has no
// content root, and restore operations refuse it by design while the
// legacy Start keeps accepting it.
func sealV2ChunksModeArtifactFixture(t *testing.T, dir string, memorySize int64) firecrackerCheckpointFiles {
	t.Helper()
	files, err := prepareFirecrackerCheckpointV2(dir, "", memorySize)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	writeArtifactComponent(t, files.State, 8<<10)
	writeArtifactComponent(t, files.Memory, int(memorySize))
	writeArtifactComponent(t, files.Overlay, 32<<10)
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{
		SnapshotType:     firecrackerSnapshotTypeSoftDirty,
		MemorySize:       memorySize,
		MemoryDigestMode: checkpointchunks.FileDigestChunks,
	}, true); err != nil {
		t.Fatalf("seal v2 checkpoint: %v", err)
	}
	return files
}

// restoreRootHandler reuses the start fixture around a chunks-mode sealed
// artifact, the shape an expected-root restore consumes.
func restoreRootHandler(t *testing.T, sandboxID, vmmBinary string) (*Handler, runtimecore.StartConfig, string) {
	t.Helper()
	handler, config, bundlePath := startRollbackHandler(t, sandboxID, vmmBinary)
	checkpointDir := filepath.Join(t.TempDir(), "gen1")
	sealV2ChunksModeArtifactFixture(t, checkpointDir, 1<<20)
	config.CheckpointDir = checkpointDir
	return handler, config, bundlePath
}

// The Restore entry enforces the operation's expected checkpoint root against
// the manifest view it actually opens: a correct root passes the identity
// check and reaches the next validation stage, while a wrong root — including
// a fully self-consistent replacement artifact under the same path — is
// refused before any sandbox resource, storage directory, or VMM action.
func TestRestoreVerifiesExpectedCheckpointRoot(t *testing.T) {
	bindCheckpoint := func(dir string) string {
		binding, err := checkpointroot.Bind(dir)
		if err != nil {
			t.Fatalf("bind %s: %v", dir, err)
		}
		return binding.RootDigest
	}

	t.Run("correct root passes identity to the next stage", func(t *testing.T) {
		handler, config, bundlePath := restoreRootHandler(
			t, startRollbackSandboxID("s0436ok"), startRollbackIdentifiedVMM(t),
		)
		config.ExpectedCheckpointRoot = bindCheckpoint(config.CheckpointDir)
		err := handler.Restore(context.Background(), config)
		// The fixture's VMM fails later, at the cgroup attach — proving the
		// identity check passed and the flow advanced past it.
		if err == nil || !strings.Contains(err.Error(), "attach restored Firecracker to cgroup") {
			t.Fatalf("Restore error = %v, want the later cgroup-attach stage", err)
		}
		if strings.Contains(err.Error(), "expected root") || strings.Contains(err.Error(), "content root") {
			t.Fatalf("the correct root was refused: %v", err)
		}
		// The flow really did create its resources before that stage.
		if _, statErr := os.Stat(handler.storageRoot); statErr != nil {
			t.Fatalf("storage root missing after a passed identity check: %v", statErr)
		}
		releaseStartRollbackRetained(t, handler, config.ID)
		_ = bundlePath
	})

	t.Run("wrong root refuses before resource effects", func(t *testing.T) {
		handler, config, bundlePath := restoreRootHandler(
			t, startRollbackSandboxID("s0436bad"), startRollbackIdentifiedVMM(t),
		)
		correct := bindCheckpoint(config.CheckpointDir)
		config.ExpectedCheckpointRoot = strings.Repeat("0", checkpointroot.DigestHexLen)
		err := handler.Restore(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), "does not match the operation's expected root") {
			t.Fatalf("Restore error = %v, want the expected-root refusal", err)
		}
		if strings.Contains(correct, "0") && correct == strings.Repeat("0", checkpointroot.DigestHexLen) {
			t.Fatal("fixture root collides with the wrong-root pin")
		}
		assertStartRollbackReleased(t, handler, config.ID, bundlePath)
		if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
			t.Fatalf("identity refusal spawned VMM processes: %v", pids)
		}
	})

	t.Run("same-path self-consistent replacement refuses", func(t *testing.T) {
		handler, config, bundlePath := restoreRootHandler(
			t, startRollbackSandboxID("s0436swap"), startRollbackIdentifiedVMM(t),
		)
		original := bindCheckpoint(config.CheckpointDir)
		// Replace the whole artifact with a different but fully valid seal
		// under the SAME path: every file is self-consistent, only the
		// identity changed.
		dir := config.CheckpointDir
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
		sealV2ChunksModeArtifactFixture(t, dir, 2<<20)
		replacement := bindCheckpoint(dir)
		if replacement == original {
			t.Fatal("the replacement artifact did not change the content root")
		}
		config.ExpectedCheckpointRoot = original
		err = handler.Restore(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), "does not match the operation's expected root") {
			t.Fatalf("Restore error = %v, want the expected-root refusal", err)
		}
		assertStartRollbackReleased(t, handler, config.ID, bundlePath)
		if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
			t.Fatalf("identity refusal spawned VMM processes: %v", pids)
		}
	})

	t.Run("legacy restore without an expected root is unchanged", func(t *testing.T) {
		handler, config, _ := restoreRollbackHandler(
			t, startRollbackSandboxID("s0436leg"), startRollbackIdentifiedVMM(t),
		)
		config.ExpectedCheckpointRoot = ""
		err := handler.Restore(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), "attach restored Firecracker to cgroup") {
			t.Fatalf("Restore error = %v, want the later cgroup-attach stage", err)
		}
		releaseStartRollbackRetained(t, handler, config.ID)
	})
}

// The capability the server gates identified restore operations on is
// declared, and the v1 archive layout — which carries no sealed manifest —
// cannot verify a root and says so explicitly instead of ignoring the pin.
func TestRestoreRootCapabilityAndArchiveLayout(t *testing.T) {
	handler := &Handler{}
	if !handler.SupportsCheckpointRootVerification() {
		t.Fatal("the Firecracker handler must declare root verification support")
	}

	handler2, config, bundlePath := restoreRollbackHandler(
		t, startRollbackSandboxID("s0436arc"), startRollbackIdentifiedVMM(t),
	)
	archiveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(archiveDir, checkpointImageName),
		[]byte("not really a tar"), 0600); err != nil {
		t.Fatal(err)
	}
	config.CheckpointDir = archiveDir
	config.ExpectedCheckpointRoot = strings.Repeat("a", checkpointroot.DigestHexLen)
	err := handler2.Restore(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "cannot verify expected checkpoint root") {
		t.Fatalf("Restore error = %v, want the archive-layout refusal", err)
	}
	assertStartRollbackReleased(t, handler2, config.ID, bundlePath)
}

// An oversized manifest.json is refused by its stat through the shared
// bounded reader — before any byte is buffered — at the very entry of both
// legacy and identified restores; a sparse file claims the size without
// allocating it, so the refusal cannot have read the content.
func TestRestoreRefusesOversizeManifestWithoutReadingIt(t *testing.T) {
	bloat := func(t *testing.T, dir string) {
		f, err := os.Create(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(checkpointroot.MaxManifestBytes + 1)); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	t.Run("identified restore refuses before resource effects", func(t *testing.T) {
		handler, config, bundlePath := restoreRootHandler(
			t, startRollbackSandboxID("s0520big"), startRollbackIdentifiedVMM(t),
		)
		binding, err := checkpointroot.Bind(config.CheckpointDir)
		if err != nil {
			t.Fatalf("bind the sealed fixture: %v", err)
		}
		bloat(t, config.CheckpointDir)
		config.ExpectedCheckpointRoot = binding.RootDigest
		err = handler.Restore(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("Restore error = %v, want the oversize-manifest refusal", err)
		}
		assertStartRollbackReleased(t, handler, config.ID, bundlePath)
		if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
			t.Fatalf("oversize refusal spawned VMM processes: %v", pids)
		}
	})

	t.Run("legacy restore refuses identically", func(t *testing.T) {
		handler, config, bundlePath := restoreRollbackHandler(
			t, startRollbackSandboxID("s0520leg"), startRollbackIdentifiedVMM(t),
		)
		bloat(t, config.CheckpointDir)
		config.ExpectedCheckpointRoot = ""
		err := handler.Restore(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("Restore error = %v, want the oversize-manifest refusal", err)
		}
		assertStartRollbackReleased(t, handler, config.ID, bundlePath)
	})
}
