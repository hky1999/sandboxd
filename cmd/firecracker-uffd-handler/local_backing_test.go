package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

func sparseLocalFixture(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "memory")
	data := make([]byte, 1<<20)
	data[4103] = 0xa7
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt(data[4096:8192], 4096); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if fileFullyAllocated(path) {
		t.Fatal("fixture must actually be sparse")
	}
	chunks, err := checkpointchunks.Compute(context.Background(), dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	chunks.FileDigestMode = checkpointchunks.FileDigestChunks
	chunks.FileDigest = checkpointchunks.RootDigest(chunks.Entries)
	if err = checkpointchunks.Write(dir, chunks); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"memory_size": len(data), "memory_digest_mode": chunks.FileDigestMode, "digests": map[string]string{"memory": chunks.FileDigest}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func TestSparseLocalBackingServesVerifiedPages(t *testing.T) {
	path, data := sparseLocalFixture(t)
	f, err := openLocalMemoryBacking(context.Background(), path)
	if err != nil || f == nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	// No store, cache, or network client is present: both nonzero and hole
	// pages must be supplied by the descriptor that was actually verified.
	s := &faultServer{source: &pageSource{file: f}}
	for _, offset := range []uint64{0, 4096, 8192, (1 << 20) - 4096} {
		got, err := s.resolveChunk(offset, 4096)
		if err != nil || !bytes.Equal(got, data[offset:offset+4096]) {
			t.Fatalf("page %d: %v", offset, err)
		}
	}
}

func TestSparseLocalBackingRejectsInvalidProof(t *testing.T) {
	for _, name := range []string{"root", "mode", "size", "missing-digest", "missing-sidecar", "content", "symlink", "other-name", "cancel"} {
		t.Run(name, func(t *testing.T) {
			path, _ := sparseLocalFixture(t)
			dir := filepath.Dir(path)
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "root", "mode", "size", "missing-digest":
				raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
				must(err)
				var m map[string]any
				must(json.Unmarshal(raw, &m))
				switch name {
				case "root":
					m["digests"] = map[string]string{"memory": string(bytes.Repeat([]byte{'0'}, 64))}
				case "mode":
					m["memory_digest_mode"] = "unknown"
				case "size":
					m["memory_size"] = 4096
				case "missing-digest":
					delete(m, "digests")
				}
				raw, err = json.Marshal(m)
				must(err)
				must(os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600))
			case "missing-sidecar":
				must(os.Remove(filepath.Join(dir, checkpointchunks.ManifestName)))
			case "content":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				must(err)
				_, err = f.WriteAt([]byte{0x55}, 4103)
				must(err)
				must(f.Close())
			case "symlink":
				must(os.Rename(path, path+"-real"))
				must(os.Symlink(path+"-real", path))
			case "other-name":
				other := filepath.Join(dir, "other")
				must(os.Rename(path, other))
				path = other
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			f, err := openLocalMemoryBacking(ctx, path)
			if f != nil {
				f.Close()
				t.Fatal("invalid proof returned a descriptor")
			}
			if err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestMaterializedBackingNeverSelectedLocally(t *testing.T) {
	for _, name := range []string{"sparse", "dense", "dangling-marker"} {
		t.Run(name, func(t *testing.T) {
			path, data := sparseLocalFixture(t)
			if name == "dense" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if !fileFullyAllocated(path) {
					t.Fatal("dense fixture not allocated")
				}
			}
			marker := filepath.Join(filepath.Dir(path), ".materialized")
			var err error
			if name == "dangling-marker" {
				err = os.Symlink("absent", marker)
			} else {
				err = os.WriteFile(marker, []byte("remote"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			f, err := openLocalMemoryBacking(context.Background(), path)
			if f != nil {
				f.Close()
				t.Fatal("placeholder selected locally")
			}
			if err != nil {
				t.Fatalf("placeholder should select chunk path: %v", err)
			}
		})
	}
}

func TestSparseLocalBackingFailedVerificationClosesFD(t *testing.T) {
	path, _ := sparseLocalFixture(t)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte{0x19}, 4103); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		f, err = openLocalMemoryBacking(context.Background(), path)
		if f != nil {
			f.Close()
			t.Fatal("corrupt backing opened")
		}
		if err == nil {
			t.Fatal("corruption accepted")
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == path {
			t.Fatalf("failed proof leaked fd %s", entry.Name())
		}
	}
}
