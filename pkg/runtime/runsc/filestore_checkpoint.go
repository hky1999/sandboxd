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

package runsc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	filestoreDirectoryName    = "filestores"
	filestoreManifestName     = "filestores.json"
	maxFilestoreManifestBytes = 1 << 20
)

// filestoreRestoreDirectory recognizes a runsc-issued external-content
// artifact. Legacy checkpoints have no filestores directory. A present but
// incomplete directory must fail rather than fall back to a consuming restore.
// runsc verifies resource identities and content fingerprints before boot;
// sandboxd additionally confines every manifest path to this artifact.
func filestoreRestoreDirectory(checkpointDir string) (string, error) {
	if !filepath.IsAbs(checkpointDir) {
		return "", fmt.Errorf("checkpoint directory must be absolute")
	}
	dir := filepath.Join(checkpointDir, filestoreDirectoryName)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect filestore directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("filestore directory must be a directory, not a symlink or file")
	}
	manifestPath := filepath.Join(dir, filestoreManifestName)
	info, err = os.Lstat(manifestPath)
	if err != nil {
		return "", fmt.Errorf("incomplete filestore checkpoint: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFilestoreManifestBytes {
		return "", fmt.Errorf("filestore manifest must be a regular file of at most %d bytes", maxFilestoreManifestBytes)
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return "", fmt.Errorf("open filestore manifest: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFilestoreManifestBytes+1))
	if err != nil {
		return "", fmt.Errorf("read filestore manifest: %w", err)
	}
	if len(data) > maxFilestoreManifestBytes {
		return "", fmt.Errorf("filestore manifest is too large")
	}
	var manifest struct {
		Filestores json.RawMessage `json:"filestores"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Filestores) == 0 {
		return "", fmt.Errorf("invalid filestore manifest: expected filestores entries")
	}
	var entries []struct {
		File      string `json:"file"`
		SizeBytes uint64 `json:"size_bytes"`
	}
	if err := json.Unmarshal(manifest.Filestores, &entries); err != nil {
		return "", fmt.Errorf("invalid filestore entries: %w", err)
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		index, err := strconv.Atoi(strings.TrimPrefix(entry.File, "filestore-"))
		if err != nil || index < 0 || entry.File != fmt.Sprintf("filestore-%d", index) || seen[entry.File] {
			return "", fmt.Errorf("invalid or duplicate filestore artifact name %q", entry.File)
		}
		seen[entry.File] = true
		info, err := os.Lstat(filepath.Join(dir, entry.File))
		if err != nil {
			return "", fmt.Errorf("inspect filestore artifact %q: %w", entry.File, err)
		}
		if !info.Mode().IsRegular() || uint64(info.Size()) != entry.SizeBytes {
			return "", fmt.Errorf("filestore artifact %q must be a regular file with the recorded size", entry.File)
		}
	}
	return dir, nil
}
