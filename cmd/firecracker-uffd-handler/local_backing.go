package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// openLocalMemoryBacking returns nil for an explicit remote placeholder.
// Sparse local artifacts require content verification; allocation alone never
// authorizes their zero holes. Dense legacy artifacts retain their existing
// compatibility path. The caller owns the returned descriptor and must keep
// the managed artifact immutable for the lifetime of page serving.
func openLocalMemoryBacking(ctx context.Context, path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if materializedMarkerPresent(dir) {
		return nil, nil
	}
	if fileFullyAllocated(path) {
		return os.Open(path)
	}
	if filepath.Base(path) != "memory" {
		return nil, fmt.Errorf("verified sparse backing must be named memory")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest struct {
		MemorySize       int64             `json:"memory_size"`
		MemoryDigestMode string            `json:"memory_digest_mode"`
		Digests          map[string]string `json:"digests"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || manifest.MemorySize <= 0 || info.Size() != manifest.MemorySize {
		return nil, fmt.Errorf("sparse backing does not match manifest memory size")
	}
	// Keep the descriptor whose contents were checked; do not reopen the path
	// or rescan the whole image just to obtain a second descriptor.
	return checkpointchunks.OpenVerifiedMemoryBacking(ctx, dir, manifest.Digests["memory"], manifest.MemoryDigestMode)
}
