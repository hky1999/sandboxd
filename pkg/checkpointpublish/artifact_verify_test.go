// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpointpublish

// Shared-bound tests for the artifact verification chain: a DECLARED size
// is a hard stream bound (an overlong object is rejected after at most
// declared+1 bytes, never by filling the disk first), a short/empty
// MemoryRoot fails closed without panicking, and the bound holds on BOTH
// consumers (FetchVerifiedSidecars here, and the materialize bundle fetch
// in the artifact_set tests below).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// byteCountingKeyed wraps a Keyed store and counts the bytes actually READ
// out of GET bodies, PER KEY — the assertion behind "hard stream bound"
// claims (exact, no slack: a bounded fetch of a declared object may read
// at most declared+1 bytes of THAT key, whatever else the caller fetches).
// (Distinct from materialize_cache_test's countingKeyed, which counts CALLS.)
type byteCountingKeyed struct {
	chunkstore.Keyed
	mu     sync.Mutex
	perKey map[string]int64
}

func (c *byteCountingKeyed) readOf(key string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.perKey[key]
}

func (c *byteCountingKeyed) total() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var t int64
	for _, v := range c.perKey {
		t += v
	}
	return t
}

func (c *byteCountingKeyed) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := c.Keyed.GetKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return &countingRC{rc: rc, c: c, key: key}, nil
}

type countingRC struct {
	rc  io.ReadCloser
	c   *byteCountingKeyed
	key string
}

func (r *countingRC) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	r.c.mu.Lock()
	r.c.perKey[r.key] += int64(n)
	r.c.mu.Unlock()
	return n, err
}

func (r *countingRC) Close() error { return r.rc.Close() }

// stageOversizedBundle publishes one real-shape artifact whose bundle
// object is followed by a huge tail (e.g. declared ~small, stored huge).
func stageOversizedBundle(t *testing.T, store chunkstore.Keyed) *ArtifactIndex {
	t.Helper()
	sidecar := []byte(`{"version":2,"file":"memory","file_size":4096,"chunk_bytes":4096,"chunk_count":1,"file_digest_mode":"chunks","entries":[{"offset":0,"digest":"` + strings.Repeat("ab", 32) + `"}]}`)
	fc := []byte(`{"version":2,"memory_size":4096,"memory_digest_mode":"chunks"}`)
	vm := []byte("vm")
	files := map[string]string{}
	var bundle []byte
	var parts []BundlePart
	addPart := func(name string, body []byte) {
		sum := sha256.Sum256(body)
		var prefix [8]byte
		length := uint64(len(body))
		for i := 0; i < 8; i++ {
			prefix[7-i] = byte(length >> (8 * i))
		}
		parts = append(parts, BundlePart{Name: name, Offset: int64(len(bundle)) + 8, Length: int64(len(body)), Digest: hex.EncodeToString(sum[:])})
		bundle = append(append(bundle, prefix[:]...), body...)
		files[name] = hex.EncodeToString(sum[:])
	}
	addPart("manifest.json", fc)
	addPart(checkpointchunks.ManifestName, sidecar)
	addPart("vmstate", vm)
	addPart("overlay.ext4", []byte("ov"))
	// The declared bundle is `len(bundle)` bytes; append a huge tail so the
	// STORED object is far larger than declared.
	stored := append(bundle, bytes.Repeat([]byte{7}, 8<<20)...)
	sum := sha256.Sum256(stored)
	if err := store.PutKey(context.Background(), ArtifactKey("ovl", BundleName),
		bytes.NewReader(stored)); err != nil {
		t.Fatal(err)
	}
	m := &checkpointchunks.Manifest{FileDigest: strings.Repeat("cd", 32), ChunkCount: 1}
	index := &ArtifactIndex{
		CheckpointID: "ovl", ChunkCount: 1, MemoryRoot: m.FileDigest, Files: files,
		Bundle: &BundleInfo{Digest: hex.EncodeToString(sum[:]), Size: int64(len(stored)), Parts: parts},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutKey(context.Background(), ArtifactKey("ovl", IndexName), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return index
}

// TestFetchSidecarsOverlongBundleReadsAtMostDeclaredPlusOne: the bundle GET
// must stop after Bundle.Size+1 bytes — the huge tail is never streamed.
func TestFetchSidecarsOverlongBundleReadsAtMostDeclaredPlusOne(t *testing.T) {
	base, _ := adaptiveStore(t)
	keyed, _ := base.(chunkstore.Keyed)
	counting := &byteCountingKeyed{Keyed: keyed, perKey: map[string]int64{}}
	index := stageOversizedBundle(t, counting)
	// Declare the SMALL size while the stored object carries the huge tail.
	small := index.Bundle.Size - int64(8<<20)
	index.Bundle.Size = small
	_, err := FetchVerifiedSidecars(context.Background(), counting, "ovl", index,
		[]string{checkpointchunks.ManifestName})
	if err == nil || !strings.Contains(err.Error(), "declared") {
		t.Fatalf("overlong bundle must fail on the declared bound, got: %v", err)
	}
	// EXACT bound on the bundle key: at most small+1 bytes streamed; the
	// 8MiB tail beyond the declaration was never read.
	if got := counting.readOf(ArtifactKey("ovl", BundleName)); got > small+1 {
		t.Fatalf("bundle GET streamed %d bytes — the declared bound is not a hard stream stop (limit %d)", got, small+1)
	}
}

// TestMaterializeOverlongBundleReadsAtMostDeclaredPlusOne: the SAME hard
// stream bound must hold on materialization's bundle fetch — a hostile
// INDEX declaring a small Bundle.Size cannot make the huge stored object
// stream to disk before the length check fires.
func TestMaterializeOverlongBundleReadsAtMostDeclaredPlusOne(t *testing.T) {
	base, _ := adaptiveStore(t)
	keyed, _ := base.(chunkstore.Keyed)
	counting := &byteCountingKeyed{Keyed: keyed, perKey: map[string]int64{}}
	index := stageOversizedBundle(t, counting)
	small := index.Bundle.Size - int64(8<<20)
	// Rewrite the STORED INDEX to declare the small size: materialize reads
	// its authority from the store, not from our in-memory copy.
	index.Bundle.Size = small
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	indexLen := int64(len(raw))
	if err := counting.PutKey(context.Background(), ArtifactKey("ovl", IndexName), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "mat")
	err = Materialize(context.Background(), dst, "ovl", counting)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("materialize must reject the overlong bundle on the declared bound, got: %v", err)
	}
	// EXACT: the bundle key streamed at most small+1 bytes; everything the
	// run read fits in INDEX + bundle bound with no slack.
	if got := counting.readOf(ArtifactKey("ovl", BundleName)); got > small+1 {
		t.Fatalf("materialize bundle GET streamed %d bytes (limit %d)", got, small+1)
	}
	if got := counting.total(); got > indexLen+small+1 {
		t.Fatalf("materialize read %d bytes total — INDEX(%d)+bundle bound(%d) exceeded", got, indexLen, small+1)
	}
}

// TestVerifySidecarIndexClosureShortRootNoPanic: malformed roots on EITHER
// side fail closed as digest errors (never an empty-vs-empty "agreement",
// never a sliced-prefix panic).
func TestVerifySidecarIndexClosureShortRootNoPanic(t *testing.T) {
	m := &checkpointchunks.Manifest{FileDigest: strings.Repeat("cd", 32), ChunkCount: 1}
	for _, root := range []string{"", "ab", "short-but-not-a-digest"} {
		if err := VerifySidecarIndexClosure(m, &ArtifactIndex{MemoryRoot: root, ChunkCount: 1}); err == nil {
			t.Fatalf("short MemoryRoot %q must fail closed", root)
		}
	}
	for _, root := range []string{"", "ab"} {
		bad := &checkpointchunks.Manifest{FileDigest: root, ChunkCount: 1}
		if err := VerifySidecarIndexClosure(bad, &ArtifactIndex{MemoryRoot: strings.Repeat("cd", 32), ChunkCount: 1}); err == nil {
			t.Fatalf("short sidecar root %q must fail closed", root)
		}
	}
	bothEmpty := &checkpointchunks.Manifest{ChunkCount: 1}
	if err := VerifySidecarIndexClosure(bothEmpty, &ArtifactIndex{MemoryRoot: "", ChunkCount: 1}); err == nil {
		t.Fatal("empty-vs-empty roots must fail the digest gate, not pass as agreement")
	}
}

// TestFetchKeyToFileDeclaredBoundIsHardStreamStop: DIRECT coverage of the
// materialize-side fetcher (fetchKeyToFile) — a small declared size against
// a huge object reads at most declared+1 bytes and rejects, never streaming
// the whole body to disk first.
func TestFetchKeyToFileDeclaredBoundIsHardStreamStop(t *testing.T) {
	base, _ := adaptiveStore(t)
	keyed, _ := base.(chunkstore.Keyed)
	counting := &byteCountingKeyed{Keyed: keyed, perKey: map[string]int64{}}
	body := bytes.Repeat([]byte{9}, 4<<20)
	if err := counting.PutKey(context.Background(), "huge/obj", bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	const declared = int64(4096)
	if _, err := fetchKeyToFile(context.Background(), counting, "huge/obj",
		hex.EncodeToString(make([]byte, 32)), declared, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "exceeds its declared") {
		t.Fatalf("overlong object must fail on the declared bound, got: %v", err)
	}
	// EXACT: at most declared+1 bytes of that key were ever read.
	if got := counting.readOf("huge/obj"); got > declared+1 {
		t.Fatalf("fetchKeyToFile streamed %d bytes for a %d-byte declared bound", got, declared)
	}
}

// TestDeclaredSizeCeilingBlocksOverflow: a declared size at (or beyond)
// MaxInt64 would overflow the declared+1 LimitReader into a negative N,
// disguising the rejection as a bogus "short" read — the 1<<40 ceiling must
// reject it first, at BOTH the INDEX gate and the fetchers.
func TestDeclaredSizeCeilingBlocksOverflow(t *testing.T) {
	idx := &ArtifactIndex{Bundle: &BundleInfo{Size: 1 << 62, Digest: strings.Repeat("ab", 32)}}
	if err := ValidateIndexBundle(idx); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("hostile Bundle.Size must hit the ceiling, got: %v", err)
	}
	base, _ := adaptiveStore(t)
	keyed, _ := base.(chunkstore.Keyed)
	if _, err := fetchKeyToFile(context.Background(), keyed, "k",
		strings.Repeat("ab", 32), 1<<62, t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("fetchKeyToFile must reject oversized declared sizes, got: %v", err)
	}
	if _, err := fetchKeyToTempFile(context.Background(), keyed, "k",
		strings.Repeat("ab", 32), 1<<62); err == nil ||
		!strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("fetchKeyToTempFile must reject oversized declared sizes, got: %v", err)
	}
}
