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

package main

// Regression tests for the F1/F6 cache-integrity fixes: a verified chunk
// must never be refetched (a background prefetch reaching it is a no-op,
// so poisoned store bytes cannot overwrite verified cache data while the
// fetched bitmap still vouches for it), waiters must observe leader
// failures instead of assuming success, and an unusable persistent cache
// copy (short or corrupt) is evicted so retries refetch from the store.

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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

type fixture struct {
	srv     *faultServer
	store   *httptest.Server
	gets    *atomic.Int64
	body    *atomic.Value // []byte served by the store
	tmpDir  string
	lcd     string // -chunk-local dir ("" when disabled)
	closing func()
}

func newFixture(t *testing.T, chunk []byte, withLocal bool) *fixture {
	t.Helper()
	tmp, err := os.MkdirTemp("", "uffd-f1-*")
	if err != nil {
		t.Fatal(err)
	}
	gets := &atomic.Int64{}
	body := &atomic.Value{}
	body.Store(append([]byte(nil), chunk...))
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		_, _ = w.Write(body.Load().([]byte))
	}))
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
	cache, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	lcd := ""
	if withLocal {
		lcd = filepath.Join(tmp, "local")
	}
	src := &pageSource{
		chunk:         uint64(len(chunk)),
		inflight:      make(map[uint64]*sync.WaitGroup),
		fetched:       make(map[uint64]struct{}),
		cache:         cache,
		cachePath:     cachePath,
		chunkManifest: manifest,
		chunkStore:    store.URL,
		chunkLocal:    lcd,
	}
	f := &fixture{
		srv:    &faultServer{source: src, chunk: uint64(len(chunk))},
		store:  store,
		gets:   gets,
		body:   body,
		tmpDir: tmp,
		lcd:    lcd,
	}
	t.Cleanup(func() {
		store.Close()
		if p := src.stopPersistence(); p != nil {
			p.wg.Wait()
		}
		cache.Close()
		os.RemoveAll(tmp)
	})
	return f
}

// TestVerifiedChunkNeverRefetched: after a chunk is fetched and verified,
// a second fetchChunk (the prefetch path) must be a no-op — no store GET,
// and bytes served afterwards still match the original verified content
// even when the store has since been poisoned.
func TestVerifiedChunkNeverRefetched(t *testing.T) {
	good := make([]byte, 4096)
	for i := range good {
		good[i] = byte('A')
	}
	f := newFixture(t, good, false)
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	base := f.gets.Load()
	// Poison the store: any refetch would deliver corrupt bytes.
	bad := make([]byte, 4096)
	for i := range bad {
		bad[i] = byte('B')
	}
	f.body.Store(bad)
	for i := 0; i < 5; i++ {
		if err := f.srv.fetchChunk(0); err != nil {
			t.Fatalf("refetch %d: %v", i, err)
		}
	}
	if n := f.gets.Load(); n != base {
		t.Fatalf("verified chunk was refetched: %d extra GET(s)", n-base)
	}
	got, ok := f.srv.readCache(0, 4096)
	if !ok || string(got) != string(good) {
		t.Fatalf("cache corrupted: served bytes differ from verified content")
	}
}

// TestWaiterSeesLeaderFailure: when the leader's fetch fails verification,
// a concurrent waiter must surface an error rather than returning nil, and
// the chunk must not be marked fetched.
func TestWaiterSeesLeaderFailure(t *testing.T) {
	good := make([]byte, 4096)
	for i := range good {
		good[i] = byte('G')
	}
	f := newFixture(t, good, false)
	// The manifest vouches for `good`; the store serves something else, so
	// every fetch attempt fails the digest check.
	bad := make([]byte, 4096)
	for i := range bad {
		bad[i] = byte('X')
	}
	f.body.Store(bad)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.srv.fetchChunk(0)
		}(i)
	}
	wg.Wait()
	anyErr := false
	for _, err := range errs {
		if err != nil {
			anyErr = true
		}
	}
	if !anyErr {
		t.Fatalf("all waiters returned nil despite the store serving bytes that fail the digest check")
	}
	f.srv.source.inflightMu.Lock()
	_, fetched := f.srv.source.fetched[0]
	f.srv.source.inflightMu.Unlock()
	if fetched {
		t.Fatalf("chunk marked fetched despite verification failure")
	}
}

// TestShortLocalCacheEvicted: a persistent cache copy that is shorter than
// the manifest length is evicted on first use, and the retry succeeds from
// the store.
func TestShortLocalCacheEvicted(t *testing.T) {
	good := make([]byte, 4096)
	for i := range good {
		good[i] = byte('C')
	}
	f := newFixture(t, good, true)
	digest := f.srv.source.chunkManifest.Entries[0].Digest
	shortPath := filepath.Join(f.lcd, digest[:2], digest)
	if err := os.MkdirAll(filepath.Dir(shortPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shortPath, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("fetch with short local copy: %v (retry should recover from store)", err)
	}
	if _, statErr := os.Stat(shortPath); !os.IsNotExist(statErr) {
		t.Fatalf("short persistent copy was not evicted")
	}
	// The retry loop inside fetchChunk should have recovered from the store.
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("retry after eviction: %v", err)
	}
}

// A shared all-zero digest is a complete specification of its bytes. Concurrent
// faults/prefetch must not download it or write a full-sized zero cache file.
func TestZeroChunksNeedNoStoreOrCache(t *testing.T) {
	f := newFixture(t, make([]byte, 8195), true)
	src := f.srv.source
	src.chunk = 4096
	src.chunkManifest.ChunkBytes = 4096
	src.chunkManifest.ChunkCount = 3
	src.chunkManifest.Entries = []checkpointchunks.Chunk{
		{Offset: 0, Digest: checkpointchunks.ZeroChunkDigest(4096)},
		{Offset: 4096, Digest: checkpointchunks.ZeroChunkDigest(4096)},
		{Offset: 8192, Digest: checkpointchunks.ZeroChunkDigest(3)},
	}
	// Even a corrupt authoritative object cannot change digest-derived zeroes.
	f.body.Store(bytes.Repeat([]byte{0xff}, 8195))
	var wg sync.WaitGroup
	for n := 0; n < 24; n++ {
		wg.Add(1)
		go func(index uint64) {
			defer wg.Done()
			if err := f.srv.fetchChunk(index); err != nil {
				t.Error(err)
				return
			}
			got, err := f.srv.resolveChunk(index*4096, 4096)
			want := 4096
			if index == 2 {
				want = 3
			}
			if err != nil || len(got) != want || !bytes.Equal(got, make([]byte, want)) {
				t.Errorf("chunk %d: len=%d err=%v", index, len(got), err)
			}
		}(uint64(n % 3))
	}
	wg.Wait()
	if f.gets.Load() != 0 {
		t.Fatalf("GET=%d for known zero chunks", f.gets.Load())
	}
	info, err := src.cache.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("zero cache grew to %d bytes", info.Size())
	}
	got, err := f.srv.resolveChunk(8193, 4096)
	if err != nil || len(got) != 2 {
		t.Fatalf("tail offset: %x, %v", got, err)
	}
	if _, err := f.srv.resolveChunk(8195, 4096); !errors.Is(err, io.EOF) {
		t.Fatalf("past tail: %v", err)
	}
}

func TestRepeatedDigestAcrossOffsets(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		name := "success"
		if failFirst {
			name = "failed-leader"
		}
		t.Run(name, func(t *testing.T) {
			const count = 64
			body := bytes.Repeat([]byte{1, 2, 3, 4}, 1024)
			f := newFixture(t, body, false)
			if failFirst {
				f.store.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := f.gets.Add(1)
					if n == 1 {
						_, _ = w.Write(bytes.Repeat([]byte{0xff}, len(body)))
						return
					}
					_, _ = w.Write(body)
				})
			}
			src := f.srv.source
			digest := src.chunkManifest.Entries[0].Digest
			src.chunkManifest.FileSize = int64(count * len(body))
			src.chunkManifest.ChunkCount = count
			src.chunkManifest.Entries = nil
			for i := 0; i < count; i++ {
				src.chunkManifest.Entries = append(src.chunkManifest.Entries, checkpointchunks.Chunk{Offset: int64(i * len(body)), Digest: digest})
			}
			start := make(chan struct{})
			errs := make(chan error, count)
			var wg sync.WaitGroup
			for i := 0; i < count; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					got, err := f.srv.resolveChunk(uint64(i*len(body)+17), 128)
					if err == nil && !bytes.Equal(got, body[17:145]) {
						err = fmt.Errorf("wrong bytes at position %d", i)
					}
					errs <- err
				}(i)
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			wantGets := int64(1)
			if failFirst {
				wantGets = 2
			}
			if got := f.gets.Load(); got != wantGets {
				t.Fatalf("GET=%d want=%d for %d positions", got, wantGets, count)
			}
			got, err := os.ReadFile(src.cachePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, bytes.Repeat(body, count)) {
				t.Fatal("logical cache layout differs")
			}
			// Revisit after poisoning the backend: verified extents stay immutable.
			f.body.Store(bytes.Repeat([]byte{0xff}, len(body)))
			if err := f.srv.fetchChunk(count - 1); err != nil {
				t.Fatal(err)
			}
			if f.gets.Load() != wantGets {
				t.Fatal("verified digest refetched")
			}
		})
	}
}

func TestRepeatedDigestDoesNotAliasDifferentLength(t *testing.T) {
	body := bytes.Repeat([]byte{1, 2, 3, 4}, 1024)
	f := newFixture(t, body, false)
	src := f.srv.source
	digest := src.chunkManifest.Entries[0].Digest
	src.chunkManifest.Entries = append(src.chunkManifest.Entries, checkpointchunks.Chunk{Offset: int64(len(body)), Digest: digest})
	src.chunkManifest.FileSize = int64(len(body) + len(body)/2)
	src.chunkManifest.ChunkCount = 2
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.fetchChunk(1); err == nil {
		t.Fatal("incorrect tail digest accepted by reuse")
	}
	if _, ok := src.fetched[1]; ok {
		t.Fatal("failed tail marked ready")
	}
}
