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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// countingKeyed wraps a Keyed store and counts GetKey calls: chunk GETs are
// exactly what the node cache exists to deduplicate.
type countingKeyed struct {
	chunkstore.Keyed
	gets atomic.Int64
}

func (c *countingKeyed) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	c.gets.Add(1)
	return c.Keyed.GetKey(ctx, key)
}

type overlayFixture struct {
	store    *countingKeyed
	sidecar  string // overlay sidecar to copy into each materialize target
	expected []byte
	nonzero  int // unique nonzero chunk digests (what the cache may hold)
}

// buildOverlayStore lays down n 4-byte chunks where every third is all-zero
// (exercising the zero-chunk sparse bypass) in a fresh local store.
func buildOverlayStore(t *testing.T, n int) *overlayFixture {
	t.Helper()
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scan := &checkpointchunks.Manifest{Version: 1, File: "overlay.ext4", FileSize: int64(n * 4), ChunkBytes: 4, FileDigestMode: checkpointchunks.FileDigestChunks}
	var expected []byte
	nonzero := 0
	for i := 0; i < n; i++ {
		var body []byte
		if i%3 == 0 {
			body = []byte{0, 0, 0, 0}
		} else {
			body = []byte{byte('a' + i%26), byte('A' + i%26), byte(i), 0x5a}
			nonzero++
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		scan.Entries = append(scan.Entries, checkpointchunks.Chunk{Offset: int64(i * 4), Digest: digest})
		if i%3 != 0 {
			if err := local.PutKey(context.Background(), OverlayChunkKey(digest), bytes.NewReader(body)); err != nil {
				t.Fatal(err)
			}
		}
		expected = append(expected, body...)
	}
	scan.ChunkCount = len(scan.Entries)
	scan.FileDigest = checkpointchunks.RootDigest(scan.Entries)
	sidecarDir := t.TempDir()
	if err := checkpointchunks.WriteNamed(sidecarDir, OverlaySidecarName, scan); err != nil {
		t.Fatal(err)
	}
	return &overlayFixture{
		store:    &countingKeyed{Keyed: local},
		sidecar:  filepath.Join(sidecarDir, OverlaySidecarName),
		expected: expected,
		nonzero:  nonzero,
	}
}

func materializeInto(t *testing.T, fx *overlayFixture, cache *chunkcache.Manager, workers int) []byte {
	t.Helper()
	target := t.TempDir()
	raw, err := os.ReadFile(fx.sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, OverlaySidecarName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := materializeOverlayChunks(context.Background(), target, "test", fx.store, cache, workers); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(target, "overlay.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A node cache fronting overlay materialization: the second restore of the
// same artifact performs ZERO chunk GETs, and zero chunks (which have no
// store objects) never occupy cache entries.
func TestMaterializeOverlayNodeCacheReuse(t *testing.T) {
	fx := buildOverlayStore(t, 9)
	root := t.TempDir()
	cache, err := chunkcache.Open(chunkcache.Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	first := materializeInto(t, fx, cache, 0)
	if !bytes.Equal(first, fx.expected) {
		t.Fatal("cold materialize output mismatch")
	}
	cold := fx.store.gets.Load()
	if cold == 0 {
		t.Fatal("cold materialize never touched the store")
	}
	if int64(fx.nonzero) != cold {
		t.Fatalf("cold GETs %d != unique nonzero chunks %d", cold, fx.nonzero)
	}

	second := materializeInto(t, fx, cache, 0)
	if !bytes.Equal(second, fx.expected) {
		t.Fatal("warm materialize output mismatch")
	}
	if n := fx.store.gets.Load(); n != cold {
		t.Fatalf("warm restore went to the store: %d extra GET(s)", n-cold)
	}
	st := cache.Status()
	if st.Entries != int64(fx.nonzero) || st.Misses != cold {
		t.Fatalf("cache admitted %d entries from %d misses; zero chunks must bypass (nonzero=%d)",
			st.Entries, st.Misses, fx.nonzero)
	}
}

// Restore vs eviction concurrency: with watermarks far below the working
// set and eviction hammering the same root, materialize still produces
// byte-identical output (the restore pin protects the working set; even an
// unpinned eviction only costs a refetch, never wrong bytes).
func TestMaterializeOverlayUnderEvictionPressure(t *testing.T) {
	fx := buildOverlayStore(t, 12)
	root := t.TempDir()
	cache, err := chunkcache.Open(chunkcache.Config{Root: root, HighWatermark: 3 * 4, LowWatermark: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				cache.EvictIfNeeded(context.Background())
			}
		}
	}()
	got := materializeInto(t, fx, cache, 0)
	close(stop)
	<-done
	if !bytes.Equal(got, fx.expected) {
		t.Fatal("output corrupted by concurrent eviction")
	}
}

// Cache admission ordering: chunks are only cached through a materialize
// that first fetched and verified the artifact INDEX (the remote_ready
// marker). A store holding chunk objects but no INDEX must fail before any
// byte reaches the cache — unpublished content can never enter the
// evictable namespace.
func TestMaterializeCachesNothingWithoutIndex(t *testing.T) {
	fx := buildOverlayStore(t, 6)
	cache, err := chunkcache.Open(chunkcache.Config{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	err = MaterializeWithOptions(context.Background(), filepath.Join(t.TempDir(), "t"), "noidx", fx.store, MaterializeOptions{Cache: cache})
	if err == nil {
		t.Fatal("materialize without INDEX succeeded")
	}
	if st := cache.Status(); st.Entries != 0 || st.Misses != 0 {
		t.Fatalf("cache admitted %d entries without a verified INDEX", st.Entries)
	}
	if n := fx.store.gets.Load(); n != 1 { // exactly the failed INDEX fetch
		t.Fatalf("store GETs = %d, want exactly the INDEX probe", n)
	}
}

// VerifyMemoryTransport battery: the consumer formats — pack range reads
// and compressed bodies with the plain-object fallback — plus truncated and
// corrupted failures, over an httptest-backed Remote store (the real HTTP
// paths, including the 404 fallback).
func TestVerifyMemoryTransportFormats(t *testing.T) {
	chunkA := bytes.Repeat([]byte{0xA5}, 4096)
	chunkB := bytes.Repeat([]byte{0x5A}, 4096)
	chunkC := bytes.Repeat([]byte{0x77}, 4096)
	zero := bytes.Repeat([]byte{0}, 4096)
	dig := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	packBody := func() []byte { return append(append([]byte{}, chunkA...), chunkB...) }

	type setup func(store chunkstore.Keyed) error
	run := func(t *testing.T, name string, setupFn setup, wantErr bool, check func(t *testing.T, res MemoryVerification)) {
		t.Run(name, func(t *testing.T) {
			// Minimal in-memory object server speaking the Remote store's
			// contract: GET (with RFC Range), PUT, 404 on miss.
			objects := map[string][]byte{}
			var mu sync.Mutex
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := strings.TrimPrefix(r.URL.Path, "/")
				mu.Lock()
				defer mu.Unlock()
				switch r.Method {
				case http.MethodPut:
					body, _ := io.ReadAll(r.Body)
					objects[key] = body
					w.WriteHeader(http.StatusOK)
				case http.MethodGet:
					body, ok := objects[key]
					if !ok {
						http.NotFound(w, r)
						return
					}
					if rng := r.Header.Get("Range"); rng != "" {
						var a, b int64
						if n, _ := fmt.Sscanf(rng, "bytes=%d-%d", &a, &b); n == 2 {
							w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", a, b, len(body)))
							w.WriteHeader(http.StatusPartialContent)
							w.Write(body[a : b+1])
							return
						}
					}
					w.Write(body)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer srv.Close()
			store, err := chunkstore.Open(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			keyed := store.(chunkstore.Keyed)
			manifest := &checkpointchunks.Manifest{
				Version: checkpointchunks.RootPackedVersion, File: "memory",
				FileSize: 4 * 4096, ChunkBytes: 4096, FileDigestMode: checkpointchunks.FileDigestChunks,
				Compression: checkpointchunks.CompressionZstd,
			}
			for _, b := range [][]byte{chunkA, chunkB, chunkC, zero} {
				manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(len(manifest.Entries)) * 4096, Digest: dig(b)})
			}
			manifest.ChunkCount = len(manifest.Entries)
			manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
			manifest.Packs = map[string]checkpointchunks.PackReference{
				dig(chunkA): {Identity: checkpointchunks.PackIdentityChunks, Digest: dig(chunkB), Offset: 0, Length: 4096, ObjectSize: 8192},
				dig(chunkB): {Identity: checkpointchunks.PackIdentityChunks, Digest: dig(chunkB), Offset: 4096, Length: 4096, ObjectSize: 8192},
			}
			dir := t.TempDir()
			if err := checkpointchunks.WriteNamed(dir, checkpointchunks.ManifestName, manifest); err != nil {
				t.Fatal(err)
			}
			if err := setupFn(keyed); err != nil {
				t.Fatal(err)
			}
			res, err := VerifyMemoryTransport(context.Background(), dir, keyed)
			if wantErr && err == nil {
				t.Fatalf("want error, got %+v", res)
			}
			if !wantErr && err != nil {
				t.Fatalf("verify: %v (%+v)", err, res)
			}
			if check != nil {
				check(t, res)
			}
		})
	}
	packKey := func() string { return "memory-chunk-packs-v1/" + dig(chunkB) }
	put := func(store chunkstore.Keyed, key string, body []byte) error {
		return store.PutKey(context.Background(), key, bytes.NewReader(body))
	}
	run(t, "packs-and-compressed-ok", func(store chunkstore.Keyed) error {
		if err := put(store, packKey(), packBody()); err != nil {
			return err
		}
		compressed, err := chunkstore.CompressChunkBody(chunkC)
		if err != nil {
			return err
		}
		return put(store, chunkstore.CompressedKey(dig(chunkC)), compressed)
	}, false, func(t *testing.T, res MemoryVerification) {
		if res.ChunksVerified != 3 || res.ZeroSkipped != 1 || res.PacksRead != 2 || res.CompressedRead != 1 {
			t.Fatalf("unexpected summary: %+v", res)
		}
	})
	run(t, "compressed-404-falls-back-to-plain", func(store chunkstore.Keyed) error {
		if err := put(store, packKey(), packBody()); err != nil {
			return err
		}
		return put(store, dig(chunkC)[:2]+"/"+dig(chunkC), chunkC)
	}, false, func(t *testing.T, res MemoryVerification) {
		if res.CompressedRead != 0 || res.PlainRead != 1 {
			t.Fatalf("plain fallback not exercised: %+v", res)
		}
	})
	run(t, "compressed-404-plain-overlong-fails", func(store chunkstore.Keyed) error {
		if err := put(store, packKey(), packBody()); err != nil {
			return err
		}
		// No .z object: the plain fallback must serve — and REJECT an
		// overlong plain body by length, not by digest accident.
		return put(store, dig(chunkC)[:2]+"/"+dig(chunkC), append(append([]byte{}, chunkC...), 0x42))
	}, true, nil)
	run(t, "truncated-pack-fails", func(store chunkstore.Keyed) error {
		short := packBody()[:6144]
		return put(store, packKey(), short)
	}, true, nil)
	run(t, "corrupted-pack-fails", func(store chunkstore.Keyed) error {
		bad := packBody()
		copy(bad[4096:], bytes.Repeat([]byte{0x01}, 4096))
		return put(store, packKey(), bad)
	}, true, nil)
}

// Pin decision seam (G): with watermarks ARMED a failed restore pin is
// fatal; unarmed it is tolerated. MaterializeWithOptions delegates here.
func TestRestorePinDecision(t *testing.T) {
	armed, err := chunkcache.Open(chunkcache.Config{Root: t.TempDir(), HighWatermark: 1 << 20, LowWatermark: 1 << 19})
	if err != nil {
		t.Fatal(err)
	}
	defer armed.Close()
	unarmed, err := chunkcache.Open(chunkcache.Config{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer unarmed.Close()
	pinErr := fmt.Errorf("pin sabotaged")
	if err := restorePinDecision(armed, pinErr); err == nil {
		t.Fatal("armed cache tolerated a pin failure")
	}
	if err := restorePinDecision(unarmed, pinErr); err != nil {
		t.Fatalf("unarmed cache must tolerate pin failure: %v", err)
	}
	if err := restorePinDecision(armed, nil); err != nil {
		t.Fatalf("nil pin error must pass: %v", err)
	}
}

// IsNotFound regressions: the local ENOENT and HTTP 404 shapes both count
// as not-found for the compressed→plain fallback (shared consumer semantic).
func TestIsNotFoundLocalAndHTTP(t *testing.T) {
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.GetKey(context.Background(), "aa/"+strings.Repeat("a", 64)); !chunkstore.IsNotFound(err) {
		t.Fatalf("local ENOENT not recognized: %v", err)
	}
	objects := map[string][]byte{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if b, ok := objects[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	remote, err := chunkstore.Open(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.(chunkstore.Keyed).GetKey(context.Background(), "aa/"+strings.Repeat("a", 64)); !chunkstore.IsNotFound(err) {
		t.Fatalf("HTTP 404 not recognized: %v", err)
	}
	if chunkstore.IsNotFound(fmt.Errorf("some other error")) {
		t.Fatal("unrelated error misclassified")
	}
}

// P2-D: overlong plain bodies are rejected by the verifier (exact-length
// read), on both the HTTP and local backends.
func TestVerifyMemoryTransportRejectsOverlong(t *testing.T) {
	chunk := bytes.Repeat([]byte{0x33}, 4096)
	sum := sha256.Sum256(chunk)
	d := hex.EncodeToString(sum[:])
	overlong := append(append([]byte{}, chunk...), 0x42) // one trailing byte
	manifest := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: 4096, ChunkBytes: 4096,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries:        []checkpointchunks.Chunk{{Offset: 0, Digest: d}},
	}
	manifest.ChunkCount = 1
	manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
	dir := t.TempDir()
	if err := checkpointchunks.WriteNamed(dir, checkpointchunks.ManifestName, manifest); err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{d[:2] + "/" + d: overlong}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if b, ok := objects[strings.TrimPrefix(r.URL.Path, "/")]; ok && r.Method == http.MethodGet {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	remoteStore, err := chunkstore.Open(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMemoryTransport(context.Background(), dir, remoteStore.(chunkstore.Keyed)); err == nil {
		t.Fatal("HTTP overlong body accepted")
	}
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := local.PutKey(context.Background(), d[:2]+"/"+d, bytes.NewReader(overlong)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMemoryTransport(context.Background(), dir, local); err == nil {
		t.Fatal("local overlong body accepted")
	}
}

// P2-E: RunWithOptions rejects out-of-range concurrency and the
// compress+pack combination instead of clamping or ignoring.
func TestRunWithOptionsRejectsInvalidKnobs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	for _, opts := range []Options{
		{OverlayWorkers: -1},
		{OverlayWorkers: 65},
		{PackPayloadBytes: (65 << 20) + 1},
		{CompressChunks: true, PackBytes: 4 << 20},
	} {
		if _, err := RunWithOptions(context.Background(), dir, "bad", nil, "test", opts); err == nil {
			t.Fatalf("options %+v accepted", opts)
		}
	}
}

// P2-D: overlay materialization rejects SHORT and OVERLONG chunk bodies by
// LENGTH and commits NOTHING (staging is removed, target stays absent).
func TestMaterializeOverlayExactLengthShortAndOverlong(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra int // bytes appended to the correct 4-byte chunk body
	}{
		{"short", -1},
		{"overlong", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte{1, 2, 3, 4}
			var stored []byte
			if tc.extra > 0 {
				stored = append(append([]byte{}, body...), make([]byte, tc.extra)...)
			} else {
				stored = body[:len(body)+tc.extra]
			}
			sum := sha256.Sum256(body)
			digest := hex.EncodeToString(sum[:])
			scan := &checkpointchunks.Manifest{Version: 1, File: "overlay.ext4", FileSize: 4, ChunkBytes: 4, FileDigestMode: checkpointchunks.FileDigestChunks,
				Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: digest}}}
			scan.ChunkCount = 1
			scan.FileDigest = checkpointchunks.RootDigest(scan.Entries)
			local, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := local.PutKey(context.Background(), OverlayChunkKey(digest), bytes.NewReader(stored)); err != nil {
				t.Fatal(err)
			}
			target := t.TempDir()
			if err := checkpointchunks.WriteNamed(target, OverlaySidecarName, scan); err != nil {
				t.Fatal(err)
			}
			err = materializeOverlayChunks(context.Background(), target, "test", local, nil, 0)
			if err == nil {
				t.Fatal("wrong-length overlay chunk accepted")
			}
			if !strings.Contains(err.Error(), "length") && !strings.Contains(err.Error(), "expected") {
				t.Fatalf("not a length rejection: %v", err)
			}
			// The raw materialize helper creates the overlay file eagerly;
			// on rejection NOTHING may be written into it (the Materialize
			// wrapper additionally removes its staging tree entirely).
			if raw, rerr := os.ReadFile(filepath.Join(target, "overlay.ext4")); rerr == nil && len(raw) != 0 {
				t.Fatalf("overlay bytes committed despite length rejection (%d bytes)", len(raw))
			}
		})
	}
}

// buildValidBundleArtifact creates a fully VALID bundle-era artifact (the
// production span format: Offset = body start after the 8-byte length
// prefix, Length = body length) and returns the store plus its id. The
// baseline materializes successfully — every hostile mutation below
// rebuilds from this shape and must fail BEFORE committing the target.
func buildValidBundleArtifact(t *testing.T, mutate func(index *ArtifactIndex, parts []BundlePart, bodies map[string][]byte)) (chunkstore.Keyed, string) {
	t.Helper()
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "hostile"
	memory := []byte("12345678")
	memDigest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	sidecar := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: int64(len(memory)), ChunkBytes: len(memory), ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestSha256, Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: memDigest(memory)}}}
	sidecarRaw, _ := json.Marshal(sidecar)
	overlay := bytes.Repeat([]byte{0x0E}, 16)
	bodies := map[string][]byte{
		"manifest.json":               []byte(`{"memory_size":8}`),
		checkpointchunks.ManifestName: sidecarRaw,
		"vmstate":                     []byte("VS"),
		"overlay.ext4":                overlay,
	}
	index := &ArtifactIndex{CheckpointID: id, MemoryRoot: sidecar.FileDigest, ChunkCount: 1, Files: map[string]string{}}
	info := &BundleInfo{}
	var bundle []byte
	for _, name := range []string{"manifest.json", checkpointchunks.ManifestName, "vmstate", "overlay.ext4"} {
		raw := bodies[name]
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		index.Files[name] = digest
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(len(raw)))
		part := BundlePart{Name: name, Offset: int64(len(bundle)) + 8, Length: int64(len(raw)), Digest: digest}
		bundle = append(bundle, prefix[:]...)
		bundle = append(bundle, raw...)
		info.Parts = append(info.Parts, part)
	}
	bsum := sha256.Sum256(bundle)
	info.Digest = hex.EncodeToString(bsum[:])
	info.Size = int64(len(bundle))
	index.Bundle = info
	if mutate != nil {
		mutate(index, info.Parts, bodies)
	}
	enc, _ := json.Marshal(index)
	if err := local.PutKey(context.Background(), ArtifactKey(id, IndexName), bytes.NewReader(enc)); err != nil {
		t.Fatal(err)
	}
	// Rebuild the bundle bytes honoring any part mutations? No: mutations
	// target metadata only (digest/span/name), so the original bundle stands.
	if err := local.PutKey(context.Background(), ArtifactKey(id, BundleName), bytes.NewReader(bundle)); err != nil {
		t.Fatal(err)
	}
	return local, id
}

func TestMaterializeHostileIndex(t *testing.T) {
	// Baseline MUST succeed first: the fixture is provably valid.
	store, id := buildValidBundleArtifact(t, nil)
	if err := Materialize(context.Background(), filepath.Join(t.TempDir(), "ok"), id, store); err != nil {
		t.Fatalf("valid baseline fixture failed: %v", err)
	}
	cases := []struct {
		name     string
		keywords []string
		mutate   func(index *ArtifactIndex, parts []BundlePart, bodies map[string][]byte)
	}{
		{"part-traversal", []string{"expected files", "safe basename"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[0].Name = "../evil"
		}},
		{"part-duplicate", []string{"twice"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[1].Name = parts[0].Name
			parts[1].Digest = parts[0].Digest // keep digests consistent so DUPLICATION is what fires
		}},
		{"part-missing", []string{"missing from the bundle parts", "twice"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			// Rename the last part onto the first (digests aligned): the
			// duplicate coverage leaves overlay.ext4 uncovered.
			parts[len(parts)-1].Name = parts[0].Name
			parts[len(parts)-1].Digest = parts[0].Digest
		}},
		{"extra-index-key", []string{"unexpected file"}, func(ix *ArtifactIndex, _ []BundlePart, _ map[string][]byte) {
			ix.Files["extra.txt"] = strings.Repeat("c", 64)
		}},
		{"part-digest-disagrees", []string{"disagrees"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[0].Digest = strings.Repeat("d", 64)
		}},
		{"span-overflow", []string{"span out of range"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[0].Offset = int64(math.MaxInt64 - 4)
			parts[0].Length = 8
		}},
		{"span-zero-length", []string{"span out of range"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[0].Length = 0
		}},
		{"span-negative-length", []string{"span out of range"}, func(ix *ArtifactIndex, parts []BundlePart, _ map[string][]byte) {
			parts[0].Length = -8
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, id := buildValidBundleArtifact(t, func(ix *ArtifactIndex, parts []BundlePart, bodies map[string][]byte) {
				tc.mutate(ix, parts, bodies)
			})
			target := filepath.Join(t.TempDir(), "blind")
			err := Materialize(context.Background(), target, id, store)
			if err == nil {
				t.Fatal("hostile INDEX materialized")
			}
			ok := false
			for _, kw := range tc.keywords {
				if strings.Contains(err.Error(), kw) {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("error %q lacks keywords %v", err.Error(), tc.keywords)
			}
			// No escape anywhere: the traversal target must not exist
			// inside the artifact, beside it, or in the parent of the
			// staging area (Materialize stages under <parent>/.materialize).
			for _, escape := range []string{
				filepath.Join(target, "evil"),
				filepath.Join(target, "..", "evil"),
				filepath.Join(filepath.Dir(target), "evil"),
				filepath.Join(filepath.Dir(target), ".materialize", "evil"),
			} {
				if abs, aerr := filepath.Abs(escape); aerr == nil {
					if _, serr := os.Stat(abs); serr == nil {
						t.Fatalf("traversal escaped to %s", abs)
					}
				}
			}
			// And the failed target must not have been committed at all.
			if entries, rerr := os.ReadDir(target); rerr == nil && len(entries) > 0 {
				t.Fatalf("failed materialize committed %d entries", len(entries))
			}
		})
	}
	t.Run("index-oversize", func(t *testing.T) {
		local, err := chunkstore.NewLocal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := local.PutKey(context.Background(), ArtifactKey("big", IndexName), bytes.NewReader(make([]byte, 64<<20+2))); err != nil {
			t.Fatal(err)
		}
		if err := Materialize(context.Background(), filepath.Join(t.TempDir(), "t"), "big", local); err == nil {
			t.Fatal("oversized INDEX accepted")
		}
	})
	t.Run("overlay-workers-rejected", func(t *testing.T) {
		for _, w := range []int{-1, 65} {
			if err := MaterializeWithOptions(context.Background(), filepath.Join(t.TempDir(), "x"), "n", nil, MaterializeOptions{OverlayWorkers: w}); err == nil {
				t.Fatalf("OverlayWorkers=%d accepted", w)
			}
		}
	})
}

// Large-part streaming proof: a 96 MiB overlay part materializes with heap
// growth far below the part size (the extraction streams with an O(buffer)
// footprint; an O(part) allocation would show ~96 MiB).
func TestMaterializeLargePartStreamsNotAllocates(t *testing.T) {
	if testing.Short() {
		t.Skip("96MiB fixture")
	}
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "bigpart"
	const partSize = 96 << 20
	// Stream the overlay content from a repeating deterministic block so
	// neither the fixture build nor the store copy allocates the whole part.
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte(i*31 + 7)
	}
	overlayDigest := sha256.New()
	for i := 0; i < partSize/len(block); i++ {
		overlayDigest.Write(block)
	}
	overlaySum := hex.EncodeToString(overlayDigest.Sum(nil))
	memory := []byte("12345678")
	memDigest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	sidecar := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: 8, ChunkBytes: 8, ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestSha256, Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: memDigest(memory)}}}
	sidecarRaw, _ := json.Marshal(sidecar)
	manifest := []byte(`{"memory_size":8}`)
	vm := []byte("VS")
	index := &ArtifactIndex{CheckpointID: id, MemoryRoot: sidecar.FileDigest, ChunkCount: 1, Files: map[string]string{
		"manifest.json": memDigest(manifest), checkpointchunks.ManifestName: memDigest(sidecarRaw), "vmstate": memDigest(vm), "overlay.ext4": overlaySum,
	}}
	info := &BundleInfo{}
	pipeFile, err := os.CreateTemp(t.TempDir(), "bundle-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pipeFile.Name())
	bundleHash := sha256.New()
	offset := int64(0)
	writePart := func(body io.Reader, size int64, name, digest string) error {
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(size))
		if _, err := pipeFile.Write(prefix[:]); err != nil {
			return err
		}
		bundleHash.Write(prefix[:])
		partHash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(pipeFile, partHash, bundleHash), body); err != nil {
			return err
		}
		offset += 8 + size
		info.Parts = append(info.Parts, BundlePart{Name: name, Offset: offset - size, Length: size, Digest: digest})
		return nil
	}
	for _, small := range []struct {
		name string
		body []byte
	}{{"manifest.json", manifest}, {checkpointchunks.ManifestName, sidecarRaw}, {"vmstate", vm}} {
		if err := writePart(bytes.NewReader(small.body), int64(len(small.body)), small.name, memDigest(small.body)); err != nil {
			t.Fatal(err)
		}
	}
	rep := bytes.NewReader(nil)
	_ = rep
	if err := writePart(newRepeatReader(block, partSize/len(block)), partSize, "overlay.ext4", overlaySum); err != nil {
		t.Fatal(err)
	}
	info.Digest = hex.EncodeToString(bundleHash.Sum(nil))
	st, _ := pipeFile.Stat()
	info.Size = st.Size()
	index.Bundle = info
	enc, _ := json.Marshal(index)
	if err := local.PutKey(context.Background(), ArtifactKey(id, IndexName), bytes.NewReader(enc)); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := local.PutKey(context.Background(), ArtifactKey(id, BundleName), pipeFile); err != nil {
		t.Fatal(err)
	}
	pipeFile.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	target := filepath.Join(t.TempDir(), "big")
	if err := Materialize(context.Background(), target, id, local); err != nil {
		t.Fatalf("large-part materialize failed: %v", err)
	}
	runtime.ReadMemStats(&after)
	grew := int64(after.TotalAlloc - before.TotalAlloc)
	if err := compareDigestFile(filepath.Join(target, "overlay.ext4"), overlaySum); err != nil {
		t.Fatal(err)
	}
	// Total allocations during the whole materialize must stay far below
	// 2x part size (streaming copies dominate; an O(part) in-memory split
	// plus write would push well past that).
	// Measured streaming footprint is ~5MiB for a 96MiB part (ratio
	// ~0.05). The gate sits at partSize/4: ~5x headroom over the measured
	// value, yet an O(part) whole-body allocation (>= partSize) fails it
	// outright.
	if grew > partSize/4 {
		t.Fatalf("materialize allocated %d bytes for a %d-byte part — not streaming", grew, partSize)
	}
}

func compareDigestFile(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("file digest %s want %s", got, want)
	}
	return nil
}

type repeatReader struct {
	block   []byte
	repeats int
	off     int
	n       int
}

func newRepeatReader(block []byte, repeats int) *repeatReader {
	return &repeatReader{block: block, repeats: repeats}
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n >= r.repeats*len(r.block) {
		return 0, io.EOF
	}
	copied := 0
	for len(p) > 0 && r.n < r.repeats*len(r.block) {
		c := copy(p, r.block[r.off:])
		r.off += c
		if r.off == len(r.block) {
			r.off = 0
		}
		r.n += c
		p = p[c:]
		copied += c
	}
	return copied, nil
}

// Legacy-bundle baseline compatibility: a >64MiB bundle (whole overlay.ext4
// embedded, pre-sidecar era) must still load as a PACK BASELINE — streamed,
// not buffered (the old 64MiB in-memory cap rejected it outright).
func TestLoadPackBaselineLargeLegacyBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("70MiB fixture")
	}
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "biglegacy"
	const overlaySize = 70 << 20
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte(i*17 + 3)
	}
	overlayDigest := sha256.New()
	for i := 0; i < overlaySize/len(block); i++ {
		overlayDigest.Write(block)
	}
	overlaySum := hex.EncodeToString(overlayDigest.Sum(nil))
	memory := []byte("12345678")
	memDigest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	var manifest []byte
	_ = manifest
	sidecar := &checkpointchunks.Manifest{Version: checkpointchunks.PackedVersion, File: "memory", FileSize: 8, ChunkBytes: 8, ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestChunks, Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: memDigest(memory)}}}
	sidecar.Entries[0].Digest = memDigest(memory)
	sidecar.FileDigest = checkpointchunks.RootDigest(sidecar.Entries)
	sidecarRaw, _ := json.Marshal(sidecar)
	manifest = []byte(`{"memory_size":8,"memory_digest_mode":"chunks","digests":{"memory":"` + sidecar.FileDigest + `"}}`)
	vm := []byte("VS")
	index := &ArtifactIndex{CheckpointID: id, MemoryRoot: sidecar.FileDigest, ChunkCount: 1,
		Files: map[string]string{
			"manifest.json":               memDigest(manifest),
			checkpointchunks.ManifestName: memDigest(sidecarRaw),
			"vmstate":                     memDigest(vm),
			"overlay.ext4":                overlaySum,
		}}
	info := &BundleInfo{}
	bf, err := os.CreateTemp(t.TempDir(), "legacy-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bf.Name())
	bundleHash := sha256.New()
	offset := int64(0)
	writePart := func(body io.Reader, size int64, name, digest string) error {
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(size))
		if _, err := bf.Write(prefix[:]); err != nil {
			return err
		}
		bundleHash.Write(prefix[:])
		partHash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(bf, partHash, bundleHash), body); err != nil {
			return err
		}
		offset += 8 + size
		info.Parts = append(info.Parts, BundlePart{Name: name, Offset: offset - size, Length: size, Digest: digest})
		return nil
	}
	for _, small := range []struct {
		name string
		body []byte
	}{{"manifest.json", manifest}, {checkpointchunks.ManifestName, sidecarRaw}, {"vmstate", vm}} {
		if err := writePart(bytes.NewReader(small.body), int64(len(small.body)), small.name, memDigest(small.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePart(newRepeatReader(block, overlaySize/len(block)), overlaySize, "overlay.ext4", overlaySum); err != nil {
		t.Fatal(err)
	}
	info.Digest = hex.EncodeToString(bundleHash.Sum(nil))
	st, _ := bf.Stat()
	info.Size = st.Size()
	index.Bundle = info
	enc, _ := json.Marshal(index)
	if err := local.PutKey(context.Background(), ArtifactKey(id, IndexName), bytes.NewReader(enc)); err != nil {
		t.Fatal(err)
	}
	if _, err := bf.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := local.PutKey(context.Background(), ArtifactKey(id, BundleName), bf); err != nil {
		t.Fatal(err)
	}
	bf.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m, err := loadPackBaseline(context.Background(), local, id)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("large legacy bundle baseline failed: %v", err)
	}
	if m == nil || m.ChunkCount != 1 {
		t.Fatal("baseline manifest not loaded")
	}
	// Measured streaming footprint is ~1MiB for a 70MiB bundle. Gate at
	// overlaySize/4: catches any O(bundle) allocation with wide margin.
	grewB := int64(after.TotalAlloc - before.TotalAlloc)
	if grewB > overlaySize/4 {
		t.Fatalf("baseline load allocated %d bytes for a %d-byte bundle — not streaming", grewB, overlaySize)
	}
}

// copyWithContext contracts: cancellation propagates; a short-writing
// destination surfaces io.ErrShortWrite (never a silent truncation).
func TestCopyWithContextCancellationAndShortWrite(t *testing.T) {
	buf := make([]byte, 4096)
	// Cancellation before any read.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := copyWithContext(ctx, io.Discard, strings.NewReader("data"), buf)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy: n=%d err=%v", n, err)
	}
	// Short writer: accepts only 1 byte per write.
	short := &shortWriter{}
	n, err = copyWithContext(context.Background(), short, bytes.NewReader(make([]byte, 100)), buf)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write not detected: n=%d err=%v", n, err)
	}
}

type shortWriter struct{}

func (w *shortWriter) Write(p []byte) (int, error) { return 1, nil }

// RED-FIRST reproduction of the formalB failure: publishing with
// compress/pack rewrites ONLY the remote transport sidecar (the sealed
// local sidecar is never touched), so a verifier that reads the LOCAL
// sidecar probes plain keys that do not exist. The artifact-scoped
// verifier must resolve the sidecar from the remote INDEX.
func TestVerifyMemoryArtifactCompressedAndPacked(t *testing.T) {
	buildDir := func(t *testing.T) string {
		dir := t.TempDir()
		mem := bytes.Repeat([]byte{0xA7}, 8192) // 4 chunks of 2048
		manifest := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: int64(len(mem)), ChunkBytes: 2048}
		for off := 0; off < len(mem); off += 2048 {
			sum := sha256.Sum256(mem[off : off+2048])
			manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
		}
		manifest.ChunkCount = len(manifest.Entries)
		manifest.FileDigestMode = checkpointchunks.FileDigestChunks
		manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
		if err := checkpointchunks.Write(dir, manifest); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "memory"), mem, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"memory_size":8192,"memory_digest_mode":"chunks"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vmstate"), []byte("VS"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), bytes.Repeat([]byte{0x0E}, 16), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"compressed", Options{CompressChunks: true}},
		{"packed", Options{PackBytes: 4 << 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := buildDir(t)
			if tc.name == "packed" {
				// packed closure requires the FC manifest to bind the memory root
				manifest, _ := checkpointchunks.Load(dir)
				fc := fmt.Sprintf(`{"memory_size":8192,"memory_digest_mode":"chunks","digests":{"memory":"%s"}}`, manifest.FileDigest)
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(fc), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			local, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RunWithOptions(context.Background(), dir, "redtest", local, "test", tc.opts); err != nil {
				t.Fatalf("publish: %v", err)
			}
			// OLD behavior (documented red): local-sidecar verifier fails.
			if _, err := VerifyMemoryTransport(context.Background(), dir, local); err == nil {
				t.Fatalf("%s: local-sidecar verifier unexpectedly passed", tc.name)
			} else {
				t.Logf("red confirmed (%s): %v", tc.name, err)
			}
			// NEW artifact-scoped verifier must resolve the remote sidecar
			// via the INDEX and verify every chunk.
			res, err := VerifyMemoryArtifact(context.Background(), "redtest", local)
			if err != nil {
				t.Fatalf("%s: artifact verifier: %v", tc.name, err)
			}
			if res.ChunksVerified != 4 || res.ZeroSkipped != 0 {
				t.Fatalf("%s: unexpected summary %+v", tc.name, res)
			}
			if tc.name == "compressed" && res.CompressedRead != 4 {
				t.Fatalf("compressed reads = %d, want 4", res.CompressedRead)
			}
			if tc.name == "packed" && res.PacksRead != 4 {
				t.Fatalf("pack reads = %d, want 4", res.PacksRead)
			}
		})
	}
}

// Targeted battery for the artifact-scoped verifier hardening: concurrent
// per-file resolution isolation, sidecar size bound, duplicate bundle part,
// INDEX-vs-transport identity mismatch — plus the compressed/pack happy
// paths already covered above.
func TestVerifyMemoryArtifactHardening(t *testing.T) {
	buildPublished := func(t *testing.T, id string, opts Options) (chunkstore.Keyed, *ArtifactIndex) {
		t.Helper()
		dir := t.TempDir()
		mem := bytes.Repeat([]byte{0x5C}, 4096)
		manifest := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: int64(len(mem)), ChunkBytes: 2048}
		for off := 0; off < len(mem); off += 2048 {
			sum := sha256.Sum256(mem[off : off+2048])
			manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
		}
		manifest.ChunkCount = len(manifest.Entries)
		manifest.FileDigestMode = checkpointchunks.FileDigestChunks
		manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
		checkpointchunks.Write(dir, manifest)
		os.WriteFile(filepath.Join(dir, "memory"), mem, 0o600)
		os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(fmt.Sprintf(`{"memory_size":4096,"memory_digest_mode":"chunks","digests":{"memory":"%s"}}`, manifest.FileDigest)), 0o600)
		os.WriteFile(filepath.Join(dir, "vmstate"), []byte("VS"), 0o600)
		os.WriteFile(filepath.Join(dir, "overlay.ext4"), bytes.Repeat([]byte{1}, 16), 0o600)
		target := filepath.Join(filepath.Dir(dir), id)
		os.RemoveAll(target)
		if err := os.Rename(dir, target); err != nil {
			t.Fatal(err)
		}
		local, err := chunkstore.NewLocal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RunWithOptions(context.Background(), target, id, local, "test", opts); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
		return local, nil
	}

	t.Run("concurrent-per-file-isolated", func(t *testing.T) {
		// Hand-built LEGACY (Bundle==nil) artifacts: per-file chunks.json
		// objects. A barrier store forces both verifiers' INDEX+sidecar
		// reads to overlap in time, proving isolation is not serialization
		// luck.
		buildLegacy := func(id string, seed byte, gate *barrierGate) chunkstore.Keyed {
			local, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			mem := bytes.Repeat([]byte{seed}, 4096)
			manifest := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: 4096, ChunkBytes: 2048}
			for off := 0; off < len(mem); off += 2048 {
				sum := sha256.Sum256(mem[off : off+2048])
				manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
			}
			manifest.ChunkCount = len(manifest.Entries)
			manifest.FileDigestMode = checkpointchunks.FileDigestChunks
			manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
			raw, _ := json.Marshal(manifest)
			sum := sha256.Sum256(raw)
			index := ArtifactIndex{CheckpointID: id, MemoryRoot: manifest.FileDigest, ChunkCount: manifest.ChunkCount,
				Files: map[string]string{
					checkpointchunks.ManifestName: hex.EncodeToString(sum[:]),
					"manifest.json":               "0" + strings.Repeat("0", 63),
				}}
			// assert the legacy shape BEFORE verifying
			if index.Bundle != nil {
				t.Fatal("fixture unexpectedly bundle-era")
			}
			enc, _ := json.Marshal(index)
			if err := local.PutKey(context.Background(), ArtifactKey(id, IndexName), bytes.NewReader(enc)); err != nil {
				t.Fatal(err)
			}
			if err := local.PutKey(context.Background(), ArtifactKey(id, checkpointchunks.ManifestName), bytes.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			// plain chunk objects
			for _, e := range manifest.Entries {
				off := int(e.Offset)
				if err := local.PutKey(context.Background(), e.Digest[:2]+"/"+e.Digest, bytes.NewReader(mem[off:off+2048])); err != nil {
					t.Fatal(err)
				}
			}
			// Barrier sits EXACTLY on the legacy per-file sidecar GetKey -
			// the stage whose exclusive-temp-dir isolation is under test.
			return &barrierStore{Keyed: local, id: id, gate: gate, sidecarOnly: true}
		}
		gate := newBarrierGate(2)
		storeA := buildLegacy("leg-a", 0x11, gate)
		storeB := buildLegacy("leg-b", 0x22, gate)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, c := range []struct {
			id    string
			store chunkstore.Keyed
		}{{"leg-a", storeA}, {"leg-b", storeB}} {
			wg.Add(1)
			go func(c struct {
				id    string
				store chunkstore.Keyed
			}) {
				defer wg.Done()
				res, err := VerifyMemoryArtifact(context.Background(), c.id, c.store)
				if err == nil && res.ChunksVerified != 2 {
					err = fmt.Errorf("%s: chunks_verified=%d want 2", c.id, res.ChunksVerified)
				}
				if err != nil {
					errs <- fmt.Errorf("%s: %w", c.id, err)
				}
			}(c)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		if got := gate.arrived.Load(); got != 2 {
			t.Fatalf("barrier arrivals = %d, want exactly 2", got)
		}
	})

	t.Run("barrier-missing-party-times-out", func(t *testing.T) {
		// ONE verifier against a gate expecting TWO: the sidecar GetKey
		// must return the barrier-timeout error quickly (watchdog proof),
		// never hang the suite.
		local, err := chunkstore.NewLocal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		mem := bytes.Repeat([]byte{0x33}, 4096)
		manifest := &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: 4096, ChunkBytes: 2048}
		for off := 0; off < len(mem); off += 2048 {
			sum := sha256.Sum256(mem[off : off+2048])
			manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(off), Digest: hex.EncodeToString(sum[:])})
		}
		manifest.ChunkCount = len(manifest.Entries)
		manifest.FileDigestMode = checkpointchunks.FileDigestChunks
		manifest.FileDigest = checkpointchunks.RootDigest(manifest.Entries)
		raw, _ := json.Marshal(manifest)
		sum := sha256.Sum256(raw)
		index := ArtifactIndex{CheckpointID: "lone", MemoryRoot: manifest.FileDigest, ChunkCount: manifest.ChunkCount,
			Files: map[string]string{checkpointchunks.ManifestName: hex.EncodeToString(sum[:])}}
		enc, _ := json.Marshal(index)
		local.PutKey(context.Background(), ArtifactKey("lone", IndexName), bytes.NewReader(enc))
		local.PutKey(context.Background(), ArtifactKey("lone", checkpointchunks.ManifestName), bytes.NewReader(raw))
		gate := newBarrierGate(2)
		store := &barrierStore{Keyed: local, id: "lone", gate: gate, sidecarOnly: true}
		start := time.Now()
		_, err = VerifyMemoryArtifact(context.Background(), "lone", store)
		if err == nil || !strings.Contains(err.Error(), "barrier timeout") {
			t.Fatalf("want barrier-timeout error, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 15*time.Second {
			t.Fatalf("watchdog too slow: %s", elapsed)
		}
	})

	t.Run("oversized-sidecar-bounded", func(t *testing.T) {
		// A generating store produces maxIndexBytes+1 bytes on demand (no
		// max+1 allocation); the resolver must fail with the EXACT bound
		// error and the count store proves it read <= max+1 bytes.
		counter := newCountingReaderStore(maxIndexBytes + 1)
		sum := sha256.Sum256(nil)
		index := ArtifactIndex{CheckpointID: "big", MemoryRoot: strings.Repeat("a", 64), ChunkCount: 1,
			Files: map[string]string{checkpointchunks.ManifestName: hex.EncodeToString(sum[:])}}
		enc, _ := json.Marshal(index)
		counter.objects[ArtifactKey("big", IndexName)] = enc
		_, err := VerifyMemoryArtifact(context.Background(), "big", counter)
		if err == nil {
			t.Fatal("oversized sidecar accepted")
		}
		if !strings.Contains(err.Error(), "exceeds the") || !strings.Contains(err.Error(), "-byte bound") {
			t.Fatalf("not the bound gate: %v", err)
		}
		if counter.read > maxIndexBytes+1 {
			t.Fatalf("read %d bytes, want <= %d", counter.read, maxIndexBytes+1)
		}
	})

	t.Run("duplicate-bundle-part", func(t *testing.T) {
		store, _ := buildPublished(t, "dup-part", Options{PackBytes: 4 << 20})
		// Tamper the INDEX: list the sidecar part twice.
		raw, err := store.(chunkstore.Keyed).GetKey(context.Background(), ArtifactKey("dup-part", IndexName))
		if err != nil {
			t.Fatal(err)
		}
		idxRaw, _ := io.ReadAll(raw)
		raw.Close()
		var index ArtifactIndex
		json.Unmarshal(idxRaw, &index)
		for i := range index.Bundle.Parts {
			if index.Bundle.Parts[i].Name == checkpointchunks.ManifestName {
				index.Bundle.Parts = append(index.Bundle.Parts, index.Bundle.Parts[i])
				break
			}
		}
		enc, _ := json.Marshal(index)
		// Recompute nothing: the INDEX object is replaced wholesale.
		if err := store.(chunkstore.Keyed).PutKey(context.Background(), ArtifactKey("dup-part", IndexName), bytes.NewReader(enc)); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyMemoryArtifact(context.Background(), "dup-part", store); err == nil {
			t.Fatal("duplicate bundle part accepted")
		} else if !strings.Contains(err.Error(), "twice") {
			t.Fatalf("not a duplicate rejection: %v", err)
		}
	})

	t.Run("index-transport-identity-mismatch", func(t *testing.T) {
		store, _ := buildPublished(t, "id-mismatch", Options{CompressChunks: true})
		raw, _ := store.(chunkstore.Keyed).GetKey(context.Background(), ArtifactKey("id-mismatch", IndexName))
		idxRaw, _ := io.ReadAll(raw)
		raw.Close()
		var index ArtifactIndex
		json.Unmarshal(idxRaw, &index)
		index.MemoryRoot = strings.Repeat("b", 64) // lie about the root
		enc, _ := json.Marshal(index)
		store.(chunkstore.Keyed).PutKey(context.Background(), ArtifactKey("id-mismatch", IndexName), bytes.NewReader(enc))
		if _, err := VerifyMemoryArtifact(context.Background(), "id-mismatch", store); err == nil {
			t.Fatal("identity mismatch accepted")
		} else if !strings.Contains(err.Error(), "disagrees with index memory root") {
			t.Fatalf("not the identity gate: %v", err)
		}
		// Same for chunk count.
		store2, _ := buildPublished(t, "cnt-mismatch", Options{CompressChunks: true})
		raw2, _ := store2.(chunkstore.Keyed).GetKey(context.Background(), ArtifactKey("cnt-mismatch", IndexName))
		idx2, _ := io.ReadAll(raw2)
		raw2.Close()
		var index2 ArtifactIndex
		json.Unmarshal(idx2, &index2)
		index2.ChunkCount = 99
		enc2, _ := json.Marshal(index2)
		store2.(chunkstore.Keyed).PutKey(context.Background(), ArtifactKey("cnt-mismatch", IndexName), bytes.NewReader(enc2))
		if _, err := VerifyMemoryArtifact(context.Background(), "cnt-mismatch", store2); err == nil {
			t.Fatal("chunk count mismatch accepted")
		} else if !strings.Contains(err.Error(), "chunk count") {
			t.Fatalf("not the count gate: %v", err)
		}
	})
}

// barrierGate is a channel barrier: the expected parties' blocking reads
// overlap once all have arrived; a missing party unblocks everyone via the
// short test timeout (no Cond.Wait sleep-forever, no watcher goroutine).
type barrierGate struct {
	ready    chan struct{}
	once     sync.Once
	expected int
	arrived  atomic.Int32
}

func newBarrierGate(expected int) *barrierGate {
	return &barrierGate{ready: make(chan struct{}), expected: expected}
}

func (g *barrierGate) wait(ctx context.Context) error {
	if g.arrived.Add(1) == int32(g.expected) {
		// Last party: release everyone. Non-blocking, never a spin loop.
		g.once.Do(func() { close(g.ready) })
	}
	select {
	case <-g.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("barrier timeout: %d of %d arrived", g.arrived.Load(), g.expected)
	}
}

type barrierStore struct {
	chunkstore.Keyed
	id          string
	gate        *barrierGate
	sidecarOnly bool
}

func (b *barrierStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if b.sidecarOnly && key == ArtifactKey(b.id, checkpointchunks.ManifestName) {
		if err := b.gate.wait(ctx); err != nil {
			return nil, err
		}
	}
	return b.Keyed.GetKey(ctx, key)
}

// countingReaderStore serves a generated body of up to max bytes for the
// sidecar key and raw bytes for the INDEX; read counts every byte pulled.
func newCountingReaderStore(max int64) *countingReaderStore {
	return &countingReaderStore{objects: map[string][]byte{}, max: max}
}

type countingReaderStore struct {
	objects map[string][]byte
	max     int64
	read    int64
}

func (c *countingReaderStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if raw, ok := c.objects[key]; ok {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	return &genCountingReader{max: c.max, store: c}, nil
}
func (c *countingReaderStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	return nil
}
func (c *countingReaderStore) HasKey(ctx context.Context, key string) (bool, error) {
	return false, nil
}

type genCountingReader struct {
	max   int64
	n     int64
	store *countingReaderStore
}

func (r *genCountingReader) Read(p []byte) (int, error) {
	if r.n >= r.max {
		return 0, io.EOF
	}
	remaining := r.max - r.n
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	for i := range p {
		p[i] = byte(r.n + int64(i))
	}
	r.n += int64(len(p))
	r.store.read += int64(len(p))
	return len(p), nil
}
func (r *genCountingReader) Close() error { return nil }

// P1-E: the legacy per-ID overlay fallback fires ONLY for a genuinely
// absent global key. A permission-style failure on the global key must
// surface as-is — never be masked by silently serving the legacy copy.
// (Red test for the old code, which probed legacy on ANY global error and
// would have "succeeded" here.)
func TestOverlayLegacyFallbackOnlyOnNotFound(t *testing.T) {
	fx := buildOverlayStore(t, 6)
	// Serve the legacy namespace from the same bodies so the OLD code's
	// fallback would have found everything it needed.
	for _, e := range fx.sidecarEntries() {
		rc, err := fx.store.GetKey(context.Background(), OverlayChunkKey(e.Digest))
		if err != nil {
			if chunkstore.IsNotFound(err) {
				continue // zero chunks have no objects
			}
			t.Fatal(err)
		}
		body, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			t.Fatal(rerr)
		}
		if err := fx.store.PutKey(context.Background(), legacyOverlayChunkKey("test", e.Digest), bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	// Fail ONLY global-key GETs with a non-NotFound error.
	masked := &globalKeyFailingStore{inner: fx.store}
	target := t.TempDir()
	raw, err := os.ReadFile(fx.sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, OverlaySidecarName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = materializeOverlayChunks(context.Background(), target, "test", masked, nil, 0)
	if err == nil {
		t.Fatal("permission error on the global key was masked by the legacy fallback")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("want the global-key error to surface, got: %v", err)
	}
}

// globalKeyFailingStore turns every GLOBAL overlay-chunk GET into a
// permission failure while delegating everything else (legacy keys, PUTs,
// existence checks) to the inner store.
type globalKeyFailingStore struct {
	inner chunkstore.Keyed
}

func (g *globalKeyFailingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	return g.inner.PutKey(ctx, key, r)
}
func (g *globalKeyFailingStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.HasPrefix(key, "overlay-chunks/") {
		return nil, fmt.Errorf("s3 getkey %s: %w", key, fs.ErrPermission)
	}
	return g.inner.GetKey(ctx, key)
}
func (g *globalKeyFailingStore) HasKey(ctx context.Context, key string) (bool, error) {
	return g.inner.HasKey(ctx, key)
}

// sidecarEntries lists the overlay manifest entries of the fixture.
func (f *overlayFixture) sidecarEntries() []checkpointchunks.Chunk {
	raw, err := os.ReadFile(f.sidecar)
	if err != nil {
		panic(err)
	}
	var m checkpointchunks.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	return m.Entries
}

// P1-E: an INDEX whose BUNDLE declares a zero (or negative) size is
// malformed and must be rejected at decode time — before any bounded fetch
// degenerates into a zero-byte expectation.
func TestIndexBundleSizeMustBePositive(t *testing.T) {
	digest := digestOfBytes([]byte("bundle-bytes"))
	store := &staticKeyStore{m: map[string][]byte{}}
	for _, size := range []int64{0, -1} {
		idx := ArtifactIndex{
			CheckpointID: "c1",
			MemoryRoot:   digest,
			ChunkCount:   1,
			Files:        map[string]string{checkpointchunks.ManifestName: digest},
			Bundle:       &BundleInfo{Digest: digest, Size: size, Parts: []BundlePart{{Name: checkpointchunks.ManifestName, Offset: 8, Length: 4, Digest: digest}}},
		}
		raw, err := json.Marshal(idx)
		if err != nil {
			t.Fatal(err)
		}
		store.m[ArtifactKey("c1", IndexName)] = raw
		_, _, err = resolveArtifactSidecar(context.Background(), "c1", store)
		if err == nil {
			t.Fatalf("bundle size %d accepted", size)
		}
		if !strings.Contains(err.Error(), "size") {
			t.Fatalf("bundle size %d: unexpected error: %v", size, err)
		}
	}
	// Sanity: a malformed digest is rejected the same way.
	store.m[ArtifactKey("c1", IndexName)] = []byte(`{"checkpoint_id":"c1","files":{` +
		`"` + checkpointchunks.ManifestName + `":"` + digest + `"},` +
		`"bundle":{"digest":"not-a-digest","size":16}}`)
	if _, _, err := resolveArtifactSidecar(context.Background(), "c1", store); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("invalid bundle digest accepted: %v", err)
	}
}

// staticKeyStore is a read-only map-backed Keyed for INDEX decode tests;
// it counts BUNDLE object GETs so tests can prove validation happens
// BEFORE any bundle fetch.
type staticKeyStore struct {
	m          map[string][]byte
	bundleGets atomic.Int64
}

func (s *staticKeyStore) PutKey(context.Context, string, io.Reader) error {
	return errors.New("unsupported")
}
func (s *staticKeyStore) GetKey(_ context.Context, key string) (io.ReadCloser, error) {
	if strings.HasSuffix(key, "/"+BundleName) {
		s.bundleGets.Add(1)
	}
	if b, ok := s.m[key]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return nil, fs.ErrNotExist
}
func (s *staticKeyStore) HasKey(_ context.Context, key string) (bool, error) {
	_, ok := s.m[key]
	return ok, nil
}

func digestOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// P1-F: the pack baseline (the FOURTH INDEX consumer) validates the BUNDLE
// descriptor BEFORE any bundle GET — size 0/-1 and a malformed digest all
// fail with zero bundle-object fetches.
func TestPackBaselineRejectsInvalidBundleBeforeFetch(t *testing.T) {
	digest := digestOfBytes([]byte("baseline"))
	for _, tc := range []struct {
		name   string
		bundle *BundleInfo
		want   string
	}{
		{"size 0", &BundleInfo{Digest: digest, Size: 0}, "size"},
		{"size negative", &BundleInfo{Digest: digest, Size: -1}, "size"},
		{"bad digest", &BundleInfo{Digest: "not-a-digest", Size: 16}, "digest"},
	} {
		idx := ArtifactIndex{
			CheckpointID: "c1",
			Files:        map[string]string{checkpointchunks.ManifestName: digest},
			Bundle:       tc.bundle,
		}
		raw, err := json.Marshal(idx)
		if err != nil {
			t.Fatal(err)
		}
		store := &staticKeyStore{m: map[string][]byte{ArtifactKey("c1", IndexName): raw}}
		if _, err := loadPackBaseline(context.Background(), store, "c1"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
		if n := store.bundleGets.Load(); n != 0 {
			t.Fatalf("%s: bundle object fetched %d time(s) before validation", tc.name, n)
		}
	}
}
