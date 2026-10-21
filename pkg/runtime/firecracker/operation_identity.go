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
	"fmt"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

var _ runtimecore.StrictDeleteHandler = (*Handler)(nil)
var _ runtimecore.CheckpointRootVerifier = (*Handler)(nil)

// This capability binds the identity at actual restore consumption. It does
// not claim the separate failed-start cleanup proof capability.
func (handler *Handler) SupportsCheckpointRootVerification() bool { return true }

func verifyFirecrackerExpectedRoot(cfg runtimecore.StartConfig, artifact *firecrackerCheckpointArtifact) error {
	if cfg.ExpectedCheckpointRoot == "" {
		return nil
	}
	if artifact.Layout != firecrackerCheckpointLayoutV2Directory {
		return fmt.Errorf("Firecracker expected checkpoint root requires a sealed v2 directory")
	}
	binding, err := checkpointroot.RootFromView(cfg.CheckpointDir, artifact.ManifestRaw)
	if err != nil {
		return fmt.Errorf("verify Firecracker checkpoint root: %w", err)
	}
	if binding.RootDigest != cfg.ExpectedCheckpointRoot {
		return fmt.Errorf("Firecracker checkpoint content root %s does not match expected root %s", binding.RootDigest, cfg.ExpectedCheckpointRoot)
	}
	// The caller still owns the immutable directory contract for the full
	// reader lifetime; this is not protection against concurrent malicious writes.
	return nil
}

func verifyFirecrackerGeneration(state firecrackerPersistedState, expected string) error {
	if expected == "" || state.Generation == "" || state.Generation != expected {
		return fmt.Errorf("Firecracker sandbox %s runtime generation %q does not match expected %q: %w",
			state.ID, state.Generation, expected, errord.ErrFailedPrecondition)
	}
	return nil
}

// lookupStrictInstance MUST NOT use lookupInstance/recoverState: recovery can
// signal processes or remove artifacts before the generation has been checked.
// A matching on-disk record is loaded passively; the delete path rechecks its
// generation under operationMu before any mutation, guest request, or signal.
func (handler *Handler) lookupStrictInstance(id, expected string) (*firecrackerInstance, error) {
	if expected == "" {
		return nil, fmt.Errorf("strict Firecracker delete requires a generation: %w", errord.ErrFailedPrecondition)
	}
	handler.mu.RLock()
	instance := handler.instances[id]
	handler.mu.RUnlock()
	if instance != nil {
		return instance, nil
	}
	bundle, err := util.JoinWithinRoot(handler.sandboxRoot, id)
	if err != nil {
		return nil, err
	}
	state, err := readFirecrackerState(bundle)
	if err != nil {
		return nil, err
	}
	if err := verifyFirecrackerGeneration(state, expected); err != nil {
		return nil, err
	}
	if err := handler.validatePersistedState(id, bundle, state); err != nil {
		return nil, err
	}
	passive := &firecrackerInstance{state: state, done: make(chan struct{})}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if existing := handler.instances[id]; existing != nil {
		return existing, nil
	}
	if handler.instances == nil {
		handler.instances = make(map[string]*firecrackerInstance)
	}
	handler.instances[id] = passive
	return passive, nil
}

func missingFirecrackerRetirementState(id string) error {
	return fmt.Errorf("Firecracker sandbox %s has no runtime identity to retire: %w", id, errord.ErrNotFound)
}

func syncFirecrackerIdentityDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeFirecrackerIdentityState(state firecrackerPersistedState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	if err := util.AtomicWriteFile(path, data, 0600); err != nil {
		return err
	}
	if err := syncFirecrackerIdentityDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync Firecracker runtime identity directory: %w", err)
	}
	return nil
}
