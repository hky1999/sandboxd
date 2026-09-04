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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

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

	// A tampered INDEX digest must fail materialization of a second copy.
	tamperKey := ArtifactKey(id, "vmstate")
	_ = local.PutKey(context.Background(), tamperKey, strings.NewReader("tampered"))
	second := filepath.Join(filepath.Dir(source), "blind-copy-2")
	if err := Materialize(context.Background(), second, id, keyed); err == nil {
		t.Fatal("tampered artifact set materialized")
	} else if !strings.Contains(err.Error(), "digest mismatch") {
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
