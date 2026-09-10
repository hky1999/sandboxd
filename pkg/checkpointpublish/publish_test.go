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

package checkpointpublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func fixtureCheckpoint(t *testing.T) string {
	t.Helper()
	// t.TempDir() layout mirrors a catalog root: <root>/<id>/ with the
	// state at <root>/.publish/<id>.json — see StatePath.
	dir := t.TempDir()
	data := make([]byte, 300<<10)
	for i := range data {
		data[i] = byte(i * 3)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunPublishesAndResumes(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, err := chunkstore.NewLocal(filepath.Join(filepath.Dir(dir), "store"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.State.State != StatePublished || result.ChunksPut != 2 {
		t.Fatalf("result = %+v", result)
	}
	state, err := Status(dir)
	if err != nil || state == nil || state.State != StatePublished {
		t.Fatalf("status = %+v, %v", state, err)
	}

	// A second run re-puts nothing.
	again, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if again.ChunksPut != 0 || again.ChunksSkip != 2 {
		t.Fatalf("rerun = %+v", again)
	}

	// Never-published sibling reads as nil.
	other := filepath.Join(filepath.Dir(dir), "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if state, err := Status(other); err != nil || state != nil {
		t.Fatalf("unpublished status = %+v, %v", state, err)
	}
}

type failingStore struct {
	inner *chunkstore.Local
	fail  bool
}

func (f *failingStore) Put(ctx context.Context, digest string, r io.Reader) error {
	if f.fail {
		return errors.New("store unavailable")
	}
	return f.inner.Put(ctx, digest, r)
}
func (f *failingStore) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	return f.inner.Get(ctx, digest)
}
func (f *failingStore) Has(ctx context.Context, digest string) (bool, error) {
	return f.inner.Has(ctx, digest)
}
func (f *failingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if f.fail {
		return errors.New("store unavailable")
	}
	return f.inner.PutKey(ctx, key, r)
}
func (f *failingStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return f.inner.GetKey(ctx, key)
}
func (f *failingStore) HasKey(ctx context.Context, key string) (bool, error) {
	return f.inner.HasKey(ctx, key)
}

func TestPublishMaterializeRoundtrip(t *testing.T) {
	source := fixtureCheckpoint(t)
	// Complete artifact shape: manifest + chunk sidecar + vmstate + overlay.
	writeFullArtifact(t, source)

	storeRoot := filepath.Join(filepath.Dir(source), "roundtrip-store")
	local, err := chunkstore.NewLocal(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	var store chunkstore.Store = local
	_ = store
	id := filepath.Base(source)
	result, err := Run(context.Background(), source, id, store, storeRoot)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !result.State.ArtifactSet {
		t.Fatal("artifact set not published")
	}

	// Materialize into a directory that never saw the source.
	blind := filepath.Join(filepath.Dir(source), "blind-copy")
	var keyed chunkstore.Keyed = local
	if err := Materialize(context.Background(), blind, id, keyed); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	for _, name := range []string{"manifest.json", "chunks.json", "vmstate", "overlay.ext4", MaterializedMarker} {
		if _, err := os.Stat(filepath.Join(blind, name)); err != nil {
			t.Fatalf("materialized %s missing: %v", name, err)
		}
	}
	// Memory is a sparse placeholder of the manifest size, not a copy.
	var manifest struct {
		MemorySize int64 `json:"memory_size"`
	}
	raw, _ := os.ReadFile(filepath.Join(blind, "manifest.json"))
	_ = json.Unmarshal(raw, &manifest)
	info, err := os.Stat(filepath.Join(blind, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != manifest.MemorySize {
		t.Fatalf("placeholder size %d, want %d", info.Size(), manifest.MemorySize)
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys.Blocks > 8 {
		t.Fatalf("placeholder allocated %d blocks; want sparse", sys.Blocks)
	}

	// A tampered object must fail materialization of a second copy.
	// Bundle-era artifact sets land the small files in one object, so the
	// tamper point is the bundle itself (part digests stay checked).
	tamperKey := ArtifactKey(id, BundleName)
	_ = local.PutKey(context.Background(), tamperKey, strings.NewReader("tampered"))
	second := filepath.Join(filepath.Dir(source), "blind-copy-2")
	if err := Materialize(context.Background(), second, id, keyed); err == nil {
		t.Fatal("tampered artifact set materialized")
	} else if !strings.Contains(err.Error(), "digest mismatch") &&
		!strings.Contains(err.Error(), "bundle size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeFullArtifact(t *testing.T, dir string) {
	t.Helper()
	manifest := map[string]any{
		"version": 2, "snapshot_type": "SoftDirty",
		"memory_size": len(mustMemoryBytes(t, dir)),
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"vmstate":      "vmstate-bytes",
		"overlay.ext4": "overlay-bytes",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Chunks-digest deployments ship the writable layer from a sidecar
	// (digest-keyed chunk objects instead of one whole-file object). With
	// the bundle era collapsing the small files into a single GET, those
	// overlay chunk fetches are the remaining mid-materialization boundary.
	overlay := []byte("overlay-bytes")
	sum := sha256.Sum256(overlay)
	scan := &checkpointchunks.Manifest{
		Version:        1,
		File:           "overlay.ext4",
		FileSize:       int64(len(overlay)),
		ChunkBytes:     checkpointchunks.DefaultChunkBytes,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries:        []checkpointchunks.Chunk{{Offset: 0, Digest: hex.EncodeToString(sum[:])}},
	}
	scan.ChunkCount = len(scan.Entries)
	scan.FileDigest = checkpointchunks.RootDigest(scan.Entries)
	if err := checkpointchunks.WriteNamed(dir, OverlaySidecarName, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointchunks.Compute(context.Background(), dir, checkpointchunks.DefaultChunkBytes); err != nil {
		t.Fatal(err)
	}
}

func mustMemoryBytes(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOverlayChunkedRoundtrip(t *testing.T) {
	source := fixtureCheckpoint(t)
	writeFullArtifact(t, source)
	// A fresh overlay sidecar makes the writable layer ship chunk-by-chunk.
	if _, err := checkpointchunks.Compute(context.Background(), source, checkpointchunks.DefaultChunkBytes); err != nil {
		t.Fatal(err)
	}
	if err := writeOverlaySidecar(t, source); err != nil {
		t.Fatal(err)
	}

	storeRoot := filepath.Join(filepath.Dir(source), "oc-store")
	local, err := chunkstore.NewLocal(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(source)
	if _, err := Run(context.Background(), source, id, local, storeRoot); err != nil {
		t.Fatalf("publish: %v", err)
	}

	blind := filepath.Join(filepath.Dir(source), "oc-blind")
	var keyed chunkstore.Keyed = local
	if err := Materialize(context.Background(), blind, id, keyed); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	// Reassembled overlay must be byte-identical to the source's.
	src, err := os.ReadFile(filepath.Join(source, "overlay.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(blind, "overlay.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, got) {
		t.Fatalf("reassembled overlay diverged: %d vs %d bytes", len(src), len(got))
	}
}

func writeOverlaySidecar(t *testing.T, dir string) error {
	t.Helper()
	overlay, err := os.ReadFile(filepath.Join(dir, "overlay.ext4"))
	if err != nil {
		return err
	}
	const chunkBytes = checkpointchunks.DefaultChunkBytes
	scan := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(overlay)),
		ChunkBytes: chunkBytes, FileDigestMode: checkpointchunks.FileDigestChunks,
	}
	for off := 0; off < len(overlay); off += chunkBytes {
		end := off + chunkBytes
		if end > len(overlay) {
			end = len(overlay)
		}
		sum := sha256.Sum256(overlay[off:end])
		scan.Entries = append(scan.Entries, checkpointchunks.Chunk{
			Offset: int64(off), Digest: hex.EncodeToString(sum[:]),
		})
	}
	scan.ChunkCount = len(scan.Entries)
	scan.FileDigest = checkpointchunks.RootDigest(scan.Entries)
	return checkpointchunks.WriteNamed(dir,
		checkpointchunks.SidecarName("overlay.ext4"), scan)
}

func TestRunFailureIsPersistedAndRetryable(t *testing.T) {
	dir := fixtureCheckpoint(t)
	inner, err := chunkstore.NewLocal(filepath.Join(filepath.Dir(dir), "store2"))
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{inner: inner, fail: true}

	if _, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store"); err == nil {
		t.Fatal("failing run succeeded")
	}
	state, err := Status(dir)
	if err != nil || state == nil || state.State != StatePublishFailed {
		t.Fatalf("failed state = %+v, %v", state, err)
	}
	if !strings.Contains(state.LastError, "store unavailable") {
		t.Fatalf("last error = %q", state.LastError)
	}

	// Recovery: same store, failure cleared, resumes to published.
	store.fail = false
	result, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil || result.State.State != StatePublished {
		t.Fatalf("retry = %+v, %v", result, err)
	}
}

type uploadGateStore struct {
	chunkstore.Store
	chunkstore.Keyed
	entered chan struct{}
	release chan struct{}
	active  atomic.Int64
	peak    atomic.Int64
}

func (s *uploadGateStore) Has(ctx context.Context, digest string) (bool, error) {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for old := s.peak.Load(); active > old; old = s.peak.Load() {
		if s.peak.CompareAndSwap(old, active) {
			break
		}
	}
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return s.Store.Has(ctx, digest)
}

func TestPublishExplicitConcurrencyBound(t *testing.T) {
	for _, workers := range []int{1, 3, 16} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			dir := t.TempDir()
			data := make([]byte, 20*checkpointchunks.DefaultChunkBytes)
			for i := range data {
				data[i] = byte(i/checkpointchunks.DefaultChunkBytes + 1)
			}
			if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0600); err != nil {
				t.Fatal(err)
			}
			local, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			store := &uploadGateStore{Store: local, Keyed: local, entered: make(chan struct{}, 20), release: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				result, err := RunWithOptions(ctx, dir, "gate", store, "test", Options{Workers: workers})
				if err == nil && (result.Workers != workers || result.ChunksPut != 20) {
					err = fmt.Errorf("unexpected result: %+v", result)
				}
				done <- err
			}()
			for i := 0; i < workers; i++ {
				select {
				case <-store.entered:
				case <-ctx.Done():
					t.Fatal("did not reach configured concurrency")
				}
			}
			close(store.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if peak := store.peak.Load(); peak != int64(workers) {
				t.Fatalf("peak=%d, want %d", peak, workers)
			}
		})
	}
}

func TestPublishInvalidConcurrencyDoesNotTouchState(t *testing.T) {
	for _, workers := range []int{-1, 65} {
		dir := filepath.Join(t.TempDir(), "absent")
		if _, err := RunWithOptions(context.Background(), dir, "bad", nil, "test", Options{Workers: workers}); err == nil {
			t.Fatal("invalid concurrency accepted")
		}
		if _, err := os.Stat(filepath.Dir(StatePath(dir))); !os.IsNotExist(err) {
			t.Fatalf("state directory touched: %v", err)
		}
	}
}

func TestMaterializeOverlayExactLengths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bodies    [][]byte
		fileSize  int64
		wantError bool
	}{
		{"short", [][]byte{{1, 2, 3}}, 4, true},
		{"long", [][]byte{{1, 2, 3, 4, 5}}, 4, true},
		{"short-zero-in-full-slot", [][]byte{{0, 0, 0}, {1, 2, 3}}, 7, true},
		{"full-zero-in-tail-slot", [][]byte{{1, 2, 3, 4}, {0, 0, 0, 0}}, 7, true},
		{"digest-used-at-two-lengths", [][]byte{{1, 2, 3, 4}, {1, 2, 3, 4}}, 7, true},
		{"valid-repeated-and-tail", [][]byte{{1, 2, 3, 4}, {1, 2, 3, 4}, {5, 6, 7}}, 11, false},
		{"valid-zero-and-tail", [][]byte{{0, 0, 0, 0}, {0, 0, 0}}, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			scan := &checkpointchunks.Manifest{Version: 1, File: "overlay.ext4", FileSize: tc.fileSize, ChunkBytes: 4, FileDigestMode: checkpointchunks.FileDigestChunks}
			var expected []byte
			for i, body := range tc.bodies {
				sum := sha256.Sum256(body)
				digest := hex.EncodeToString(sum[:])
				scan.Entries = append(scan.Entries, checkpointchunks.Chunk{Offset: int64(i * 4), Digest: digest})
				if err := store.PutKey(context.Background(), OverlayChunkKey(digest), bytes.NewReader(body)); err != nil {
					t.Fatal(err)
				}
				expected = append(expected, body...)
			}
			scan.ChunkCount = len(scan.Entries)
			scan.FileDigest = checkpointchunks.RootDigest(scan.Entries)
			if err := checkpointchunks.WriteNamed(dir, OverlaySidecarName, scan); err != nil {
				t.Fatal(err)
			}
			err = materializeOverlayChunks(context.Background(), dir, "test", store)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "length") {
					t.Fatalf("want length rejection, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "overlay.ext4"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("content mismatch: got %x want %x", got, expected)
			}
		})
	}
}
