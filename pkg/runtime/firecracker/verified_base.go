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
	"fmt"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/sirupsen/logrus"
)

// Only a successful local seal can create this association. It is not a
// persisted completeness flag, and matches is not a content-integrity check:
// the verified clone must still validate the actual source fd before use.
type verifiedBaseMemory struct {
	path  string
	size  int64
	proof *checkpointchunks.BackingProof
}

func (p *verifiedBaseMemory) matches(path string, size int64) bool {
	if p == nil || p.proof == nil || p.path != path || p.size != size {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return false
	}
	_, err = os.Lstat(filepath.Join(filepath.Dir(path), ".materialized"))
	return os.IsNotExist(err)
}

func adoptSealedCheckpointMemory(ctx context.Context, instance *firecrackerInstance, path string, manifest *firecrackerCheckpointManifest) {
	// Digest lineage propagation: an inherited (sparse-holed) generation
	// keeps the manifest-side lineage alive so the NEXT generation can
	// inherit again; a solid generation returns to the byte-base world.
	if sealed, err := checkpointchunks.Load(filepath.Dir(path)); err == nil {
		if sealed.InheritedFromRoot != "" {
			instance.setBaseChunkManifest(filepath.Join(filepath.Dir(path), checkpointchunks.ManifestName))
		} else {
			instance.setBaseChunkManifest("")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !firecrackerMemoryHasHoles(info) {
		adoptCheckpointMemory(instance, path, false)
		return
	}
	// The expected digest comes from the seal just completed by Checkpoint,
	// not a newly discovered sidecar or a recovered on-disk boolean.
	if manifest == nil || info.Size() != manifest.MemorySize {
		instance.markBaseMemoryLineageLost()
		return
	}
	proof, err := checkpointchunks.VerifyMemoryBacking(ctx, filepath.Dir(path), manifest.Digests["memory"], manifest.MemoryDigestMode)
	if err != nil {
		logrus.Warnf("firecracker: cannot prove sealed sparse base %s complete; dropping lineage: %v", path, err)
		instance.markBaseMemoryLineageLost()
		return
	}
	instance.setBaseMemoryProof(path, false, &verifiedBaseMemory{path: path, size: info.Size(), proof: proof})
}

func selectCheckpointTierWithProof(state firecrackerPersistedState, requested string, proof *verifiedBaseMemory) (string, string, bool, int64, error) {
	size := int64(state.MemoryMiB) << 20
	usable := firecrackerBaseMemoryUsable(state.BaseMemoryPath, size)
	if proof != nil {
		usable = proof.matches(state.BaseMemoryPath, size)
	}
	chunksOK := state.BaseChunkManifestPath != ""
	return selectFirecrackerSnapshotTierUsable(size, state.BaseMemoryPath, state.BaseMemoryIncremental, state.BaseMemoryLineageLost, requested, usable, chunksOK)
}

func prepareCheckpointWithProof(ctx context.Context, dir, base string, size int64, proof *verifiedBaseMemory) (firecrackerCheckpointFiles, error) {
	if base == "" || proof == nil {
		return prepareFirecrackerCheckpointV2(dir, base, size)
	}
	if !proof.matches(base, size) {
		return firecrackerCheckpointFiles{}, fmt.Errorf("verified base association changed before layout")
	}
	return prepareFirecrackerCheckpointWithClone(dir, base, size, func(source, destination string) (bool, error) {
		if source != proof.path {
			return false, fmt.Errorf("verified clone source mismatch")
		}
		return cloneVerifiedBackingNoSync(ctx, proof.proof, destination)
	})
}

// updateSealedCheckpointLineage runs only after artifact sealing succeeds.
// A stop-and-copy source has no next incremental consumer. Invalidate its
// previous window before attempting to stop, so even a failed stop cannot
// reuse the old base after the VMM has advanced its dirty ledger.
func updateSealedCheckpointLineage(ctx context.Context, instance *firecrackerInstance, path string, manifest *firecrackerCheckpointManifest, leaveRunning bool) {
	if !leaveRunning {
		instance.markBaseMemoryLineageLost()
		return
	}
	adoptSealedCheckpointMemory(ctx, instance, path, manifest)
}
