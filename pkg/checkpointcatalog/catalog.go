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

// Package checkpointcatalog exposes a read-only inventory of the Firecracker
// v2 checkpoint directories configured on this node. The catalog is a view
// over caller-owned artifact directories, not a database: every request
// re-reads the manifests on disk, so entries appear and disappear with the
// artifacts themselves and nothing can drift out of sync.
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
	"sort"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
)

// manifestName matches the Firecracker v2 layout; its presence is the
// commit marker that makes a directory a sealed checkpoint.
const manifestName = "manifest.json"

// Config selects the listen surfaces, the caller-owned roots to inventory,
// and the node record to advertise.
type Config struct {
	// SockPath is the Unix socket the admin HTTP server listens on.
	SockPath string
	// Listen optionally serves the same endpoints over TCP (host:port) so
	// off-node consumers — the placement locator — can reach the catalog.
	Listen string
	// Dirs are scanned one level deep: every immediate subdirectory that
	// carries a manifest.json becomes an entry.
	Dirs []string
	// Node is the node record served at /api/v1/node. Nil disables the
	// endpoint; the wiring fills it from the runtime configuration.
	Node *checkpointlocator.NodeRecord
	// TemplateRoots are template-manufacture roots (templates.json plus
	// content-addressed directories) inventoried at /api/v1/templates.
	TemplateRoots []string
}

// Compat is the software-stack tuple a checkpoint pins. A cross-node
// consumer compares it against the target node's stack before placing a
// restore; an absent tuple means the artifact predates the pin.
type Compat struct {
	Arch        string `json:"arch,omitempty"`
	Firecracker string `json:"firecracker,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Initrd      string `json:"initrd,omitempty"`
	Vcpus       uint32 `json:"vcpus,omitempty"`
	KernelArgs  string `json:"kernel_args,omitempty"`
}

// Entry is one checkpoint directory as seen through the catalog.
type Entry struct {
	ID           string            `json:"id"`
	Dir          string            `json:"dir"`
	SnapshotType string            `json:"snapshot_type"`
	MemoryMiB    int64             `json:"memory_mib"`
	CreatedAt    time.Time         `json:"created_at"`
	BaseMemory   string            `json:"base_memory,omitempty"`
	Compat       *Compat           `json:"compat,omitempty"`
	Digests      map[string]string `json:"digests,omitempty"`
}

// manifest mirrors the Firecracker v2 manifest fields the catalog projects.
// It deliberately does not import the runtime package: the catalog only
// reads what cross-node consumers need to place a restore.
type manifest struct {
	Version      int               `json:"version"`
	SnapshotType string            `json:"snapshot_type"`
	MemorySize   int64             `json:"memory_size"`
	BaseMemory   string            `json:"base_memory"`
	CreatedAt    time.Time         `json:"created_at"`
	Compat       *Compat           `json:"compat"`
	Digests      map[string]string `json:"digests"`
}

// ComponentCheck reports the digest verification of one recorded component.
type ComponentCheck struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Record bool   `json:"recorded"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// VerifyResult is the outcome of re-checking a checkpoint's recorded
// digests against the bytes currently on disk.
type VerifyResult struct {
	ID         string           `json:"id"`
	Dir        string           `json:"dir"`
	DigestOK   bool             `json:"digest_ok"`
	Components []ComponentCheck `json:"components"`
}

// List inventories every checkpoint directory under the configured roots.
// Unreadable or malformed entries are skipped: the catalog serves what it
// can prove, and a half-written directory without a manifest is not a
// checkpoint.
func List(ctx context.Context, cfg Config) ([]Entry, error) {
	entries := make([]Entry, 0, 16)
	seen := make(map[string]struct{})
	for _, root := range cfg.Dirs {
		subs, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("scan checkpoint root %s: %w", root, err)
		}
		for _, sub := range subs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !sub.IsDir() {
				continue
			}
			dir := filepath.Join(root, sub.Name())
			m, err := readManifest(dir)
			if err != nil {
				continue
			}
			id := sub.Name()
			if _, dup := seen[id]; dup {
				// IDs are directory basenames; keep the first and qualify
				// later duplicates by their root so every entry stays
				// addressable.
				id = fmt.Sprintf("%s:%s", filepath.Base(root), id)
			}
			seen[id] = struct{}{}
			entry := Entry{
				ID:           id,
				Dir:          dir,
				SnapshotType: m.SnapshotType,
				MemoryMiB:    (m.MemorySize + (1 << 20) - 1) >> 20,
				CreatedAt:    m.CreatedAt,
				BaseMemory:   m.BaseMemory,
				Digests:      m.Digests,
			}
			entry.Compat = m.Compat
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// Find returns the entry for id, or an error naming the miss.
func Find(ctx context.Context, cfg Config, id string) (Entry, error) {
	entries, err := List(ctx, cfg)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range entries {
		if e.ID == id {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("checkpoint %q not found in catalog", id)
}

// Verify recomputes the sha256 of every component with a recorded digest
// and reports per-component outcomes. Components without a recorded digest
// (the overlay by policy, memory when digest_memory is off) are reported
// unverified rather than failed: the manifest never claimed them.
func Verify(ctx context.Context, cfg Config, id string) (VerifyResult, error) {
	entry, err := Find(ctx, cfg, id)
	if err != nil {
		return VerifyResult{}, err
	}
	result := VerifyResult{ID: entry.ID, Dir: entry.Dir, DigestOK: true}
	names := make([]string, 0, len(entry.Digests))
	for name := range entry.Digests {
		names = append(names, name)
	}
	sort.Strings(names) // stable component order in the response
	for _, name := range names {
		want := entry.Digests[name]
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
	if len(result.Components) == 0 {
		// A manifest without any digest claims nothing verifiable; say so
		// instead of silently reporting success.
		result.DigestOK = false
		result.Components = append(result.Components, ComponentCheck{
			Name:   "manifest",
			Record: false,
			Error:  "manifest records no component digests",
		})
	}
	return result, nil
}

func readManifest(dir string) (*manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Version != 2 {
		return nil, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	return &m, nil
}

func digestFile(ctx context.Context, path string) (string, error) {
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
