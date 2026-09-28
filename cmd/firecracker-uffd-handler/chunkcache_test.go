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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
)

var errServedMismatch = errors.New("served bytes differ from verified content")

// cacheFixture wires one "sandbox" (faultServer + per-sandbox staging cache)
// to an http chunk store through a shared node cache root.
type cacheFixture struct {
	srv    *faultServer
	gets   *atomic.Int64
	tmpDir string
}

func newCacheFixture(t *testing.T, chunk []byte, gets *atomic.Int64, storeURL, cacheRoot string) *cacheFixture {
	t.Helper()
	tmp, err := os.MkdirTemp("", "uffd-cc-*")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(chunk)
	manifest := &checkpointchunks.Manifest{
		Version:    1,
		File:       "memory",
		FileSize:   int64(len(chunk)),
		ChunkBytes: len(chunk),
		ChunkCount: 1,
		Entries:    []checkpointchunks.Chunk{{Offset: 0, Digest: hex.EncodeToString(digest[:])}},
	}
	cachePath := filepath.Join(tmp, "cache")
	cacheFile, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := chunkcache.Open(chunkcache.Config{Root: cacheRoot, HighWatermark: 0, LowWatermark: 0})
	if err != nil {
		t.Fatal(err)
	}
	src := &pageSource{
		chunk:         uint64(len(chunk)),
		inflight:      make(map[uint64]chan struct{}),
		fetched:       make(map[uint64]struct{}),
		cache:         cacheFile,
		cachePath:     cachePath,
		chunkManifest: manifest,
		chunkStore:    storeURL,
		chunkLocal:    cacheRoot,
		chunkCache:    manager,
	}
	f := &cacheFixture{srv: &faultServer{source: src, chunk: uint64(len(chunk))}, gets: gets, tmpDir: tmp}
	t.Cleanup(func() {
		manager.Close()
		cacheFile.Close()
		os.RemoveAll(tmp)
	})
	return f
}

func newCountingStore(t *testing.T, chunk []byte, gets *atomic.Int64) *httptest.Server {
	t.Helper()
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		_, _ = w.Write(chunk)
	}))
	t.Cleanup(store.Close)
	return store
}

// Two concurrent uffd handlers (separate per-sandbox staging caches) sharing
// one node cache root must produce exactly one store GET for the same
// digest: the manager's cross-instance claim serializes download, verify
// and publish.
func TestNodeCacheSharedAcrossSandboxesSingleGET(t *testing.T) {
	chunk := make([]byte, 8192)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	var gets atomic.Int64
	store := newCountingStore(t, chunk, &gets)
	root := t.TempDir()

	f1 := newCacheFixture(t, chunk, &gets, store.URL, root)
	f2 := newCacheFixture(t, chunk, &gets, store.URL, root)

	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, f := range []*cacheFixture{f1, f2} {
		go func(f *cacheFixture) {
			<-start
			if err := f.srv.fetchChunk(0); err != nil {
				errs <- err
				return
			}
			got, ok := f.srv.readCache(0, uint64(len(chunk)))
			if !ok || string(got) != string(chunk) {
				errs <- errServedMismatch
				return
			}
			errs <- nil
		}(f)
	}
	close(start)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("sandbox fetch: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("sandbox fetch never returned")
		}
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("store served %d GETs for one digest, want 1", n)
	}
}

// A later sandbox on the same node hits the persistent cache and never
// touches the store; a corrupted cached copy self-heals via one refetch.
func TestNodeCacheWarmHitAndPoisonSelfHeal(t *testing.T) {
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte('w')
	}
	var gets atomic.Int64
	store := newCountingStore(t, chunk, &gets)
	root := t.TempDir()
	digest := hex.EncodeToString(func() []byte { s := sha256.Sum256(chunk); return s[:] }())

	f1 := newCacheFixture(t, chunk, &gets, store.URL, root)
	if err := f1.srv.fetchChunk(0); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 1 {
		t.Fatalf("cold fetch did %d GETs", gets.Load())
	}

	f2 := newCacheFixture(t, chunk, &gets, store.URL, root)
	if err := f2.srv.fetchChunk(0); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("warm hit went to the store (%d GETs)", n)
	}

	// Corrupt the cached copy: the next sandbox must refetch and serve good
	// bytes rather than the poisoned ones.
	path := filepath.Join(root, digest[:2], digest)
	if err := os.WriteFile(path, []byte("poisoned!"), 0o600); err != nil {
		t.Fatal(err)
	}
	f3 := newCacheFixture(t, chunk, &gets, store.URL, root)
	if err := f3.srv.fetchChunk(0); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("poisoned copy did not self-heal with one refetch (%d GETs)", n)
	}
	got, ok := f3.srv.readCache(0, uint64(len(chunk)))
	if !ok || string(got) != string(chunk) {
		t.Fatal("served bytes after self-heal are wrong")
	}
}

// Background prefetch stands down while a foreground fault fetch is in
// flight and proceeds once the foreground load clears.
func TestPrefetchYieldsToForeground(t *testing.T) {
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte('p')
	}
	var gets atomic.Int64
	store := newCountingStore(t, chunk, &gets)
	f := newCacheFixture(t, chunk, &gets, store.URL, t.TempDir())
	stop := make(chan struct{})
	defer close(stop)
	fetch := f.srv.yieldingFetch(stop)

	f.srv.source.foreground.Add(1) // a fault-path fetch is in flight
	done := make(chan error, 1)
	go func() { done <- fetch(0) }()
	// While foreground work is pending the prefetch worker must not fetch.
	time.Sleep(150 * time.Millisecond)
	if gets.Load() != 0 {
		t.Fatalf("prefetch fetched during foreground work (%d GETs)", gets.Load())
	}
	f.srv.source.foreground.Add(-1)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("prefetch fetch: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prefetch never ran after foreground cleared")
	}
	if gets.Load() != 1 {
		t.Fatalf("prefetch did not fetch after yielding (%d GETs)", gets.Load())
	}
}

// D regression: an http chunk store with an EMPTY -chunk-local keeps the
// historical no-local-persistent-cache behavior (the manager must not be
// opened — an empty root would be a fatal startup error).
func TestNodeCacheEnabledGuard(t *testing.T) {
	cases := []struct {
		store, local string
		want         bool
	}{
		{"http://minio:19000/bucket", "", false},
		{"https://minio:19000/bucket", "", false},
		{"http://minio:19000/bucket", "/mnt/cache/chunk-store", true},
		{"https://minio:19000/bucket", "/mnt/cache/chunk-store", true},
		{"/var/lib/chunks", "/mnt/cache/chunk-store", false},
		{"/var/lib/chunks", "", false},
	}
	for _, c := range cases {
		if got := nodeCacheEnabled(c.store, c.local); got != c.want {
			t.Fatalf("nodeCacheEnabled(%q, %q) = %v, want %v", c.store, c.local, got, c.want)
		}
	}
}

// P2-D: overlong plain bodies are rejected by LENGTH (not by an incidental
// digest mismatch) on both the HTTP and local store paths, and nothing is
// published into the node cache on rejection.
func TestPlainChunkOverlongRejectedHTTPAndLocal(t *testing.T) {
	chunk := make([]byte, 8192)
	for i := range chunk {
		chunk[i] = byte(i & 0x7f)
	}
	overlong := append(append([]byte{}, chunk...), 0x99) // valid prefix + 1 byte
	var gets atomic.Int64
	// HTTP store serves the overlong body.
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		w.Write(overlong)
	}))
	defer store.Close()
	root := t.TempDir()
	f := newCacheFixture(t, chunk, &gets, store.URL, root)
	err := f.srv.fetchChunk(0)
	if err == nil {
		t.Fatal("HTTP overlong body accepted")
	}
	if !strings.Contains(err.Error(), "longer") && !strings.Contains(err.Error(), "length") {
		t.Fatalf("error is not a length rejection: %v", err)
	}
	// Nothing may be published into the node cache, and the per-sandbox
	// bitmap must not mark the chunk fetched.
	if entries, _ := os.ReadDir(root); len(entries) > 0 {
		dirs, _ := os.ReadDir(root)
		for _, d := range dirs {
			if d.Name() == "locks" || d.Name() == "pins" {
				continue
			}
			t.Fatalf("node cache published data for a rejected body: %v", d.Name())
		}
	}
	f.srv.source.inflightMu.Lock()
	fetched := len(f.srv.source.fetched)
	f.srv.source.inflightMu.Unlock()
	if fetched != 0 {
		t.Fatal("per-sandbox bitmap marked an overlong chunk as fetched")
	}

	// Local store path: a file LONGER than the chunk must be rejected too.
	dir := t.TempDir()
	digest := hex.EncodeToString(func() []byte { s := sha256.Sum256(chunk); return s[:] }())
	os.MkdirAll(filepath.Join(dir, digest[:2]), 0o755)
	os.WriteFile(filepath.Join(dir, digest[:2], digest), overlong, 0o600)
	tmp := t.TempDir()
	cacheFile, err := os.OpenFile(filepath.Join(tmp, "cache"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer cacheFile.Close()
	src := &pageSource{
		chunk:         uint64(len(chunk)),
		inflight:      make(map[uint64]chan struct{}),
		fetched:       make(map[uint64]struct{}),
		cache:         cacheFile,
		chunkManifest: manifestFor(chunk),
		chunkStore:    dir,
	}
	srvLocal := &faultServer{source: src, chunk: uint64(len(chunk))}
	err = srvLocal.fetchChunk(0)
	if err == nil {
		t.Fatal("local overlong file accepted")
	}
	if !strings.Contains(err.Error(), "length") && !strings.Contains(err.Error(), "want") {
		t.Fatalf("error is not a length rejection: %v", err)
	}
}

func manifestFor(chunk []byte) *checkpointchunks.Manifest {
	digest := sha256.Sum256(chunk)
	return &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: int64(len(chunk)), ChunkBytes: len(chunk), ChunkCount: 1,
		Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: hex.EncodeToString(digest[:])}},
	}
}

// P1-D: the two prefetch regimes are deliberately different. The chunk-
// store CAS path defaults to ZERO background GETs (opt-in only, mandatory
// finite budget); the legacy remote-memory path keeps its historical
// default (4 workers, whole-artifact walk).
func TestPrefetchPlanSeparatesRegimes(t *testing.T) {
	cases := []struct {
		name                    string
		remote, chunkStore      string
		legacyWorkers, legacyMB int
		chunkWorkers, chunkMB   int
		wantWorkers             int
		wantBudget              uint64
	}{
		{"chunk-store defaults to lazy (zero background)", "", "http://s3/cn-m0", 4, 0, 0, 0, 0, 0},
		{"chunk-store explicit bounded enable", "", "http://s3/cn-m0", 4, 0, 2, 64, 2, 64 << 20},
		{"budget without workers stays inert", "", "http://s3/cn-m0", 4, 0, 0, 512, 0, 0},
		{"legacy remote keeps default whole-artifact walk", "http://s3/mem", "", 4, 0, 0, 0, 4, 0},
		{"legacy remote keeps explicit budget", "http://s3/mem", "", 4, 32, 0, 0, 4, 32 << 20},
		{"legacy disabled", "http://s3/mem", "", 0, 0, 0, 0, 0, 0},
		{"no source at all", "", "", 4, 0, 8, 64, 0, 0},
		{"local chunk-store dir is also opt-in", "", "/var/lib/chunks", 4, 0, 0, 0, 0, 0},
	}
	for _, c := range cases {
		w, b := prefetchPlan(c.remote, c.chunkStore, c.legacyWorkers, c.legacyMB, c.chunkWorkers, c.chunkMB)
		if w != c.wantWorkers || b != c.wantBudget {
			t.Fatalf("%s: prefetchPlan = (%d, %d), want (%d, %d)", c.name, w, b, c.wantWorkers, c.wantBudget)
		}
	}
}

// P1-D: workers>0 without a finite budget must be rejected — that exact
// combination is the "lazy restore silently downloads the whole artifact"
// failure mode. Negatives and the watermark MiB ceiling are enforced too.
func TestValidateChunkPrefetchFlags(t *testing.T) {
	if err := validateChunkPrefetchFlags(0, 0); err != nil {
		t.Fatalf("default 0/0 must be valid: %v", err)
	}
	if err := validateChunkPrefetchFlags(0, 64); err != nil {
		t.Fatalf("budget without workers is inert, must be valid: %v", err)
	}
	if err := validateChunkPrefetchFlags(1, int(chunkcache.MaxWatermarkMiB)); err != nil {
		t.Fatalf("budget at the ceiling must be valid: %v", err)
	}
	if err := validateChunkPrefetchFlags(2, 0); err == nil {
		t.Fatal("workers>0 with budget 0 must be rejected")
	}
	if err := validateChunkPrefetchFlags(-1, 0); err == nil {
		t.Fatal("negative workers must be rejected")
	}
	if err := validateChunkPrefetchFlags(0, -1); err == nil {
		t.Fatal("negative budget must be rejected")
	}
	if err := validateChunkPrefetchFlags(1, int(chunkcache.MaxWatermarkMiB)+1); err == nil {
		t.Fatal("budget above the ceiling must be rejected")
	}
	if err := validateChunkPrefetchFlags(16, 32); err != nil {
		t.Fatalf("16 workers (the execution ceiling) must be valid: %v", err)
	}
	if err := validateChunkPrefetchFlags(17, 32); err == nil {
		t.Fatal("17 workers must be rejected, never silently capped (P1-G)")
	}
}

// P1-D timing: once a background prefetch fetch is ALREADY in flight (and
// blocked inside the store), a foreground fault for a DIFFERENT chunk must
// be served at the next opportunity — it does not queue behind the
// remaining speculative work, and the background side resumes only after
// the foreground load clears.
func TestForegroundServedWhilePrefetchInFlight(t *testing.T) {
	const chunkLen = 4096
	chunkA := bytes.Repeat([]byte{0xA}, chunkLen)
	chunkB := bytes.Repeat([]byte{0xB}, chunkLen)
	sum := sha256.Sum256(chunkA)
	dA := hex.EncodeToString(sum[:])
	sum = sha256.Sum256(chunkB)
	dB := hex.EncodeToString(sum[:])

	aStarted := make(chan struct{})
	var aOnce sync.Once
	releaseA := make(chan struct{})
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dA) {
			aOnce.Do(func() { close(aStarted) })
			<-releaseA // the background prefetch GET parks here
			_, _ = w.Write(chunkA)
			return
		}
		_, _ = w.Write(chunkB)
	}))
	t.Cleanup(store.Close)

	root := t.TempDir()
	tmp, err := os.MkdirTemp("", "uffd-fg-*")
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(tmp, "cache")
	cacheFile, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := chunkcache.Open(chunkcache.Config{Root: root, HighWatermark: 0, LowWatermark: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Close()
		cacheFile.Close()
		os.RemoveAll(tmp)
	})
	src := &pageSource{
		chunk:     chunkLen,
		inflight:  make(map[uint64]chan struct{}),
		fetched:   make(map[uint64]struct{}),
		cache:     cacheFile,
		cachePath: cachePath,
		chunkManifest: &checkpointchunks.Manifest{Version: 1, File: "memory", FileSize: 2 * chunkLen, ChunkBytes: chunkLen, ChunkCount: 2,
			Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: dA}, {Offset: chunkLen, Digest: dB}}},
		chunkStore: store.URL,
		chunkLocal: root,
		chunkCache: manager,
	}
	srv := &faultServer{source: src, chunk: chunkLen}

	stop := make(chan struct{})
	defer close(stop)
	fetch := srv.yieldingFetch(stop)
	bgErr := make(chan error, 1)
	go func() { bgErr <- fetch(0) }() // background prefetch of chunk 0
	<-aStarted                        // ... is now parked INSIDE the store

	// The foreground fault for chunk 1 must complete while 0 is parked.
	fgErr := make(chan error, 1)
	go func() {
		src.foreground.Add(1) // exactly what the fault path does
		err := srv.fetchChunk(1)
		src.foreground.Add(-1)
		fgErr <- err
	}()
	select {
	case err := <-fgErr:
		if err != nil {
			t.Fatalf("foreground fetch queued behind in-flight prefetch: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreground fetch never completed while prefetch was parked")
	}
	got, ok := srv.readCache(chunkLen, chunkLen)
	if !ok || !bytes.Equal(got, chunkB) {
		t.Fatal("foreground served wrong bytes")
	}

	close(releaseA)
	if err := <-bgErr; err != nil {
		t.Fatalf("background fetch after resume: %v", err)
	}
}

// gatedChunkStore serves named chunk bodies, optionally parking a digest's
// GET on a gate channel and signaling its start — the harness for prefetch
// scheduling/causality tests.
type gatedChunkStore struct {
	gets   sync.Map // digest -> *atomic.Int64
	bodies map[string][]byte
	gates  map[string]chan struct{}
	starts map[string]chan struct{}
	onces  map[string]*sync.Once
	server *httptest.Server
}

func newGatedChunkStore(t *testing.T, bodies map[string][]byte, gates map[string]chan struct{}) *gatedChunkStore {
	t.Helper()
	g := &gatedChunkStore{
		bodies: bodies,
		gates:  gates,
		starts: map[string]chan struct{}{},
		onces:  map[string]*sync.Once{},
	}
	for d := range bodies {
		g.starts[d] = make(chan struct{})
		g.onces[d] = &sync.Once{}
	}
	g.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var digest string
		if parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/"); len(parts) == 2 {
			digest = parts[1]
		}
		body, ok := g.bodies[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if n, ok := g.gets.Load(digest); ok {
			n.(*atomic.Int64).Add(1)
		}
		if ch, ok := g.starts[digest]; ok {
			g.onces[digest].Do(func() { close(ch) })
		}
		if gate, ok := g.gates[digest]; ok && gate != nil {
			<-gate
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(g.server.Close)
	return g
}

func (g *gatedChunkStore) count(digest string) int64 {
	if n, ok := g.gets.Load(digest); ok {
		return n.(*atomic.Int64).Load()
	}
	return 0
}

// multiChunkFixture builds a faultServer over a manifest with the given
// chunk bodies (chunk size = len of the first), backed by the given store.
func multiChunkFixture(t *testing.T, storeURL, cacheRoot string, chunkLen int, bodies map[string][]byte, order ...string) (*faultServer, *pageSource) {
	t.Helper()
	manifest := &checkpointchunks.Manifest{Version: 1, File: "memory", ChunkBytes: chunkLen, FileDigestMode: checkpointchunks.FileDigestChunks}
	var total int
	for _, d := range order {
		manifest.Entries = append(manifest.Entries, checkpointchunks.Chunk{Offset: int64(total), Digest: d})
		total += len(bodies[d])
	}
	manifest.ChunkCount = len(manifest.Entries)
	manifest.FileSize = int64(total)
	tmp, err := os.MkdirTemp("", "uffd-multi-*")
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(tmp, "cache")
	cacheFile, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := chunkcache.Open(chunkcache.Config{Root: cacheRoot, HighWatermark: 0, LowWatermark: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Close()
		cacheFile.Close()
		os.RemoveAll(tmp)
	})
	src := &pageSource{
		chunk:         uint64(chunkLen),
		inflight:      make(map[uint64]chan struct{}),
		fetched:       make(map[uint64]struct{}),
		cache:         cacheFile,
		cachePath:     cachePath,
		chunkManifest: manifest,
		chunkStore:    storeURL,
		chunkLocal:    cacheRoot,
		chunkCache:    manager,
	}
	return &faultServer{source: src, chunk: uint64(chunkLen)}, src
}

func digestOfBody(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// P1-D causality (C): with a background prefetch of A already parked inside
// the store AND a foreground fault for B parked (foreground counter > 0),
// releasing A must NOT let the walk start the next speculative chunk C —
// C begins only after the foreground load clears. Uses the REAL
// runPrefetch + yieldingFetch semantics, not just the counter.
func TestPrefetchDefersNextSpeculativeChunkWhileForegroundPending(t *testing.T) {
	const chunkLen = 4096
	chunkA := bytes.Repeat([]byte{0xA}, chunkLen)
	chunkB := bytes.Repeat([]byte{0xB}, chunkLen)
	chunkC := bytes.Repeat([]byte{0xC}, chunkLen)
	dA, dB, dC := digestOfBody(chunkA), digestOfBody(chunkB), digestOfBody(chunkC)

	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	store := newGatedChunkStore(t,
		map[string][]byte{dA: chunkA, dB: chunkB, dC: chunkC},
		map[string]chan struct{}{dA: releaseA, dB: releaseB})
	for _, d := range []string{dA, dB, dC} {
		store.gets.Store(d, &atomic.Int64{})
	}
	root := t.TempDir()
	srv, src := multiChunkFixture(t, store.server.URL, root, chunkLen,
		map[string][]byte{dA: chunkA, dB: chunkB, dC: chunkC}, dA, dB, dC)

	stop := make(chan struct{})
	defer close(stop)
	bgDone := make(chan error, 1)
	go func() {
		completed, err := runPrefetch(stop, 3, 1, srv.yieldingFetch(stop))
		if err == nil && completed != 3 {
			err = fmt.Errorf("completed %d/3", completed)
		}
		bgDone <- err
	}()
	<-store.starts[dA] // background A is parked inside the store

	// Foreground fault for B starts and parks; the counter stays > 0.
	fgDone := make(chan error, 1)
	go func() {
		src.foreground.Add(1)
		err := srv.fetchChunk(1)
		src.foreground.Add(-1)
		fgDone <- err
	}()
	<-store.starts[dB] // B is parked inside the store

	close(releaseA) // A completes; the walk's next speculative step is C
	// While B is pending, C must NOT start (bounded observation window).
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-store.starts[dC]:
		t.Fatal("speculative chunk C started while a foreground fault was pending")
	case <-timer.C:
	}
	if n := store.count(dC); n != 0 {
		t.Fatalf("C was fetched %d times while foreground pending", n)
	}

	close(releaseB) // B completes; the foreground load clears
	if err := <-fgDone; err != nil {
		t.Fatalf("foreground fetch: %v", err)
	}
	select {
	case <-store.starts[dC]:
	case <-time.After(5 * time.Second):
		t.Fatal("C never started after the foreground load cleared")
	}
	if err := <-bgDone; err != nil {
		t.Fatalf("background walk: %v", err)
	}
}

// P1-D execution (D): a byte budget caps what the walk actually DOES, not
// just the plan — 3 chunks with a 2-chunk budget fetch exactly 2 (the third
// gets zero GETs), and a sub-one-chunk budget fetches nothing without
// panicking or deadlocking.
func TestPrefetchBudgetCapsExecution(t *testing.T) {
	const chunkLen = 4096
	bodies := map[string][]byte{}
	order := []string{}
	for _, seed := range []byte{1, 2, 3} {
		b := bytes.Repeat([]byte{seed}, chunkLen)
		d := digestOfBody(b)
		bodies[d] = b
		order = append(order, d)
	}
	if got := capChunksByBudget(3, chunkLen, 2*chunkLen); got != 2 {
		t.Fatalf("capChunksByBudget(3, %d, %d) = %d, want 2", chunkLen, 2*chunkLen, got)
	}
	if got := capChunksByBudget(3, chunkLen, 1); got != 0 {
		t.Fatalf("sub-one-chunk budget walks %d chunks, want 0", got)
	}

	store := newGatedChunkStore(t, bodies, nil)
	for d := range bodies {
		store.gets.Store(d, &atomic.Int64{})
	}
	root := t.TempDir()
	srv, _ := multiChunkFixture(t, store.server.URL, root, chunkLen, bodies, order...)

	stop := make(chan struct{})
	defer close(stop)
	completed, err := runPrefetch(stop, 2, 1, srv.yieldingFetch(stop)) // budget-capped walk
	if err != nil || completed != 2 {
		t.Fatalf("capped walk: completed=%d err=%v", completed, err)
	}
	total := int64(0)
	for _, d := range order {
		total += store.count(d)
	}
	if total != 2 {
		t.Fatalf("capped walk performed %d GETs, want exactly 2", total)
	}
	if n := store.count(order[2]); n != 0 {
		t.Fatalf("third chunk received %d GETs under a 2-chunk budget", n)
	}

	// Sub-one-chunk budget: zero-chunk walk returns immediately — no
	// panic, no deadlock, no GETs.
	completed, err = runPrefetch(stop, 0, 1, srv.yieldingFetch(stop))
	if err != nil || completed != 0 {
		t.Fatalf("zero-chunk walk: completed=%d err=%v", completed, err)
	}
	for _, d := range order {
		if n := store.count(d); n > 0 && d == order[2] {
			t.Fatalf("unexpected GET after zero-chunk walk")
		}
	}
}

// P1-E: the exact-length end-of-body proof is STRICT — a zero read without
// EOF is not evidence the body ended. All four post-body behaviors are
// covered: clean EOF succeeds, (0, customErr) fails with that error,
// (1, anything) is overlong, and repeated (0, nil) fails with
// io.ErrNoProgress after a bounded number of probes.
func TestStrictEOFProbe(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name  string
		r     io.Reader
		check func(error) bool
	}{
		{"clean EOF", fnReader{func([]byte) (int, error) { return 0, io.EOF }},
			func(e error) bool { return e == nil }},
		{"zero-read custom error", fnReader{func([]byte) (int, error) { return 0, errBoom }},
			func(e error) bool { return errors.Is(e, errBoom) }},
		{"one byte over", fnReader{func(p []byte) (int, error) { p[0] = 0xAA; return 1, nil }},
			func(e error) bool { return e != nil && strings.Contains(e.Error(), "longer") }},
		{"one byte with error", fnReader{func(p []byte) (int, error) { p[0] = 0xAA; return 1, errBoom }},
			func(e error) bool { return e != nil && strings.Contains(e.Error(), "longer") }},
		{"endless no-progress", fnReader{func([]byte) (int, error) { return 0, nil }},
			func(e error) bool { return errors.Is(e, io.ErrNoProgress) }},
	}
	for _, c := range cases {
		if err := strictEOFProbe(c.r, "fetch store chunk ab", 4096); !c.check(err) {
			t.Fatalf("%s: probe check failed, got %v", c.name, err)
		}
	}
}

// fnReader adapts a read function into an io.Reader for probe tests.
type fnReader struct {
	read func(p []byte) (int, error)
}

func (f fnReader) Read(p []byte) (int, error) { return f.read(p) }
