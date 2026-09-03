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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// runscCheckpointManifestName matches the Firecracker v2 layout so the node
// catalog lists and verifies runsc artifacts with the same code path: a
// version-2 manifest whose digests name the files it sealed.
const runscCheckpointManifestName = "manifest.json"

// runscCheckpointManifest is the seal runsc checkpoints carry: one sha256
// per artifact file, written after runsc finishes checkpointing. snapshot
// restores verify it before replay when present.
type runscCheckpointManifest struct {
	Version      int               `json:"version"`
	SnapshotType string            `json:"snapshot_type"`
	CreatedAt    time.Time         `json:"created_at"`
	Artifacts    []string          `json:"artifacts"`
	Digests      map[string]string `json:"digests"`
}

// sealRunscCheckpoint digests every artifact file runsc wrote (checkpoint
// image, page metadata, pages) and lands the manifest as the commit marker.
// The digests are sequential whole-file hashes: runsc artifacts do not carry
// a chunk scan yet, so the cost matches the Firecracker pre-scan baseline
// (~0.4GB/s/core here); adopting the chunk machinery is a follow-up.
func sealRunscCheckpoint(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list runsc checkpoint directory: %w", err)
	}
	manifest := runscCheckpointManifest{
		Version:      2,
		SnapshotType: "runsc",
		CreatedAt:    time.Now().UTC(),
		Digests:      make(map[string]string),
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".img" {
			continue
		}
		digest, err := digestRunscFile(ctx, filepath.Join(dir, name))
		if err != nil {
			return err
		}
		manifest.Digests[name] = digest
		manifest.Artifacts = append(manifest.Artifacts, name)
	}
	if len(manifest.Artifacts) == 0 {
		return fmt.Errorf("runsc checkpoint directory %s holds no artifacts", dir)
	}
	sort.Strings(manifest.Artifacts)

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(dir, runscCheckpointManifestName),
		append(encoded, '\n'), 0o600,
	)
}

// verifyRunscCheckpoint re-hashes the recorded artifacts and compares. A
// directory without a manifest predates sealing and restores unverified,
// mirroring the Firecracker pre-tuple behavior.
func verifyRunscCheckpoint(ctx context.Context, dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, runscCheckpointManifestName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var manifest runscCheckpointManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("decode runsc checkpoint manifest: %w", err)
	}
	for _, name := range manifest.Artifacts {
		want, recorded := manifest.Digests[name]
		if !recorded || want == "" {
			continue
		}
		got, err := digestRunscFile(ctx, filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("runsc checkpoint artifact %s digest mismatch: manifest %s on disk %s",
				name, want, got)
		}
	}
	return nil
}

func digestRunscFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
