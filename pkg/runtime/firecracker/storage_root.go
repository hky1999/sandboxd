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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
)

// An override selects a directory, not a migration. Preserve the historical
// hidden child exactly when the option is absent.
func selectFirecrackerPrivateStorageRoot(filestore, override, sandboxRoot, runtimeRoot string) (string, error) {
	legacy := filepath.Join(filestore, ".firecracker")
	if override == "" {
		return legacy, nil
	}
	if !filepath.IsAbs(override) || strings.ContainsRune(override, 0) {
		return "", fmt.Errorf("Firecracker storage_dir must be an absolute directory path")
	}
	selected := filepath.Clean(override)
	if selected == string(filepath.Separator) {
		return "", fmt.Errorf("Firecracker storage_dir must not be the filesystem root")
	}
	for _, managed := range []string{sandboxRoot, runtimeRoot, filestore} {
		if managed == "" {
			continue
		}
		absolute, err := filepath.Abs(managed)
		if err != nil {
			return "", fmt.Errorf("resolve Firecracker managed directory: %w", err)
		}
		if managed == filestore && selected == filepath.Join(absolute, ".firecracker") {
			continue
		}
		if firecrackerStoragePathsOverlap(selected, absolute) {
			return "", fmt.Errorf("Firecracker storage_dir %s overlaps managed directory %s", selected, absolute)
		}
	}
	return selected, nil
}

func firecrackerStoragePathsOverlap(a, b string) bool {
	within := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return within(a, b) || within(b, a)
}

// Validate passively before directory creation, recovery, or process signals.
// Existing identity paths must remain usable; a new root must never silently
// turn live or retained Firecracker state into an undiscoverable orphan.
func validateFirecrackerPrivateStorageLocation(sandboxRoot, storageRoot string) error {
	entries, err := os.ReadDir(sandboxRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing Firecracker storage identities: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !config.IsValidSandboxID(entry.Name()) {
			continue
		}
		state, err := readFirecrackerState(filepath.Join(sandboxRoot, entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read Firecracker storage identity %s: %w", entry.Name(), err)
		}
		directory := filepath.Join(storageRoot, entry.Name())
		if state.ID != entry.Name() || filepath.Clean(state.OverlayPath) != filepath.Join(directory, "overlay.ext4") {
			return fmt.Errorf("Firecracker storage_dir conflicts with existing identity for %s; storage migration is required", entry.Name())
		}
		if state.VirtioFS != nil && filepath.Clean(state.VirtioFS.SharedDir) != filepath.Join(directory, firecrackerVirtioFSSharedDir) {
			return fmt.Errorf("Firecracker storage_dir conflicts with existing virtio-fs identity for %s; storage migration is required", entry.Name())
		}
	}
	return nil
}
