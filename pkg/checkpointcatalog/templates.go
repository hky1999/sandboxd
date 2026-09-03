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

package checkpointcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// registryName matches the template manufacture pipeline
// (deploy/fc-template.sh), which writes the registry next to the
// content-addressed template directories.
const registryName = "templates.json"

// templateComponentOrder is the exact concatenation order the manufacture
// pipeline hashes into a template id: manifest first, then the components in
// this order. The content address is only meaningful if the bytes and their
// order are reproduced exactly.
var templateComponentOrder = []string{"manifest.json", "vmstate", "memory", "overlay.ext4"}

// TemplateEntry is one registered template as seen through the catalog.
type TemplateEntry struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Dir          string            `json:"dir"`
	SnapshotType string            `json:"snapshot_type"`
	MemoryMiB    int64             `json:"memory_mib"`
	CreatedAt    string            `json:"created_at"`
	Compat       *Compat           `json:"compat,omitempty"`
	Digests      map[string]string `json:"digests,omitempty"`
}

// templateRegistry mirrors templates.json.
type templateRegistry struct {
	Templates []struct {
		ID           string            `json:"id"`
		Name         string            `json:"name"`
		Dir          string            `json:"dir"`
		SnapshotType string            `json:"snapshot_type"`
		MemorySize   int64             `json:"memory_size"`
		CreatedAt    string            `json:"created_at"`
		Compat       *Compat           `json:"compat"`
		Digests      map[string]string `json:"digests"`
	} `json:"templates"`
}

// TemplateVerifyResult is the outcome of re-checking a template's registry
// claims: the content-address id and the recorded component digests.
type TemplateVerifyResult struct {
	ID         string           `json:"id"`
	Dir        string           `json:"dir"`
	IDOK       bool             `json:"id_ok"`
	DigestOK   bool             `json:"digest_ok"`
	Components []ComponentCheck `json:"components"`
	Error      string           `json:"error,omitempty"`
}

// ListTemplates inventories the template registries under the configured
// template roots. Like the checkpoint view this is live: the registry file
// is re-read per request, and entries whose directory no longer exists are
// skipped — a template that is not on disk cannot be derived from.
func ListTemplates(ctx context.Context, cfg Config) ([]TemplateEntry, error) {
	entries := make([]TemplateEntry, 0, 8)
	seen := make(map[string]struct{})
	for _, root := range cfg.TemplateRoots {
		raw, err := os.ReadFile(filepath.Join(root, registryName))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read template registry %s: %w", root, err)
		}
		var registry templateRegistry
		if err := json.Unmarshal(raw, &registry); err != nil {
			return nil, fmt.Errorf("decode template registry %s: %w", root, err)
		}
		for _, t := range registry.Templates {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// The registry's dir is written from the node that
			// manufactured the template and may be absolute there but
			// absent here: the same registry is mounted at different
			// paths across nodes. Prefer the recorded path when it
			// resolves, and fall back to this node's root-relative
			// location before giving up on the entry.
			dir := t.Dir
			if dir == "" || !dirExists(dir) {
				local := filepath.Join(root, t.ID)
				if !dirExists(local) {
					continue
				}
				dir = local
			}
			if _, dup := seen[t.ID]; dup {
				continue
			}
			seen[t.ID] = struct{}{}
			entries = append(entries, TemplateEntry{
				ID:           t.ID,
				Name:         t.Name,
				Dir:          dir,
				SnapshotType: t.SnapshotType,
				MemoryMiB:    (t.MemorySize + (1 << 20) - 1) >> 20,
				CreatedAt:    t.CreatedAt,
				Compat:       t.Compat,
				Digests:      t.Digests,
			})
		}
	}
	return entries, nil
}

// FindTemplate returns the registered template for id, or an error naming
// the miss.
func FindTemplate(ctx context.Context, cfg Config, id string) (TemplateEntry, error) {
	entries, err := ListTemplates(ctx, cfg)
	if err != nil {
		return TemplateEntry{}, err
	}
	for _, e := range entries {
		if e.ID == id {
			return e, nil
		}
	}
	return TemplateEntry{}, fmt.Errorf("template %q not found in catalog", id)
}

// VerifyTemplate re-derives the template's content address — the same
// ordered concatenation the manufacture pipeline hashed — and re-checks the
// recorded component digests. A template whose id no longer matches its
// bytes has been mutated after registration and must not be derived from.
func VerifyTemplate(ctx context.Context, cfg Config, id string) (TemplateVerifyResult, error) {
	entry, err := FindTemplate(ctx, cfg, id)
	if err != nil {
		return TemplateVerifyResult{}, err
	}
	result := TemplateVerifyResult{ID: entry.ID, Dir: entry.Dir, DigestOK: true}

	hash := sha256.New()
	for _, name := range templateComponentOrder {
		f, err := os.Open(filepath.Join(entry.Dir, name))
		if err != nil {
			result.Error = fmt.Sprintf("open %s: %v", name, err)
			result.IDOK, result.DigestOK = false, false
			return result, nil
		}
		if _, err := io.Copy(hash, f); err != nil {
			f.Close()
			result.Error = fmt.Sprintf("hash %s: %v", name, err)
			result.IDOK, result.DigestOK = false, false
			return result, nil
		}
		f.Close()
		if err := ctx.Err(); err != nil {
			return TemplateVerifyResult{}, err
		}
	}
	recomputed := hex.EncodeToString(hash.Sum(nil))[:len(entry.ID)]
	result.IDOK = recomputed == entry.ID
	if !result.IDOK {
		result.Error = fmt.Sprintf("content address drifted: registry %s recomputed %s",
			entry.ID, recomputed)
	}

	for name, want := range entry.Digests {
		check := ComponentCheck{Name: name, Path: filepath.Join(entry.Dir, name), Record: true}
		got, err := digestFile(ctx, check.Path)
		switch {
		case err != nil:
			check.Error = err.Error()
			result.DigestOK = false
		case got != want:
			check.Error = fmt.Sprintf("manifest %s on disk %s", want, got)
			result.DigestOK = false
		default:
			check.OK = true
		}
		result.Components = append(result.Components, check)
	}
	return result, nil
}

func dirExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}
