// Copyright (c) 2026 Ant Group Corporation.
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

// Compressed-transport fetch tests: with the sidecar's compression
// marker set, chunks arrive as zstd bodies under the ".z" key, decode to
// exactly the recorded length, and still pass the plaintext digest
// check; a missing compressed object falls back to the plain object
// (pre-compression shares), while a corrupt stream fails loudly.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

type compressedFixture struct {
	srv      *faultServer
	store    *httptest.Server
	getsZ    *atomic.Int64
	getsRaw  *atomic.Int64
	tmpDir   string
	cache    *os.File
	cacheURI string
}

// newCompressedFixture serves `zBody` at <aa>/<digest>.z and `plainBody`
// at <aa>/<digest>, counting each; either may be nil to 404 its key.
// The manifest always describes the PLAINTEXT (digest, size): compression
// never changes what the digest names.
func newCompressedFixture(t *testing.T, plainBody, zBody []byte, compression string) *compressedFixture {
	t.Helper()
	chunk := plainBody
	tmp, err := os.MkdirTemp("", "uffd-z-*")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(chunk)
	manifest := &checkpointchunks.Manifest{
		Version:     1,
		File:        "memory",
		FileSize:    int64(len(chunk)),
		ChunkBytes:  len(chunk),
		ChunkCount:  1,
		Compression: compression,
		Entries:     []checkpointchunks.Chunk{{Offset: 0, Digest: hex.EncodeToString(digest[:])}},
	}
	getsZ, getsRaw := &atomic.Int64{}, &atomic.Int64{}
	zKey := "/" + chunkstore.CompressedKey(manifest.Entries[0].Digest)
	rawKey := fmt.Sprintf("/%s/%s", manifest.Entries[0].Digest[:2], manifest.Entries[0].Digest)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case zKey:
			getsZ.Add(1)
			if zBody == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(zBody)
		case rawKey:
			getsRaw.Add(1)
			if plainBody == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(plainBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	cachePath := filepath.Join(tmp, "cache")
	cache, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	src := &pageSource{
		chunk:         uint64(len(chunk)),
		inflight:      make(map[uint64]chan struct{}),
		fetched:       make(map[uint64]struct{}),
		cache:         cache,
		cachePath:     cachePath,
		chunkManifest: manifest,
		chunkStore:    store.URL,
	}
	f := &compressedFixture{
		srv:      &faultServer{source: src, chunk: uint64(len(chunk))},
		store:    store,
		getsZ:    getsZ,
		getsRaw:  getsRaw,
		tmpDir:   tmp,
		cache:    cache,
		cacheURI: cachePath,
	}
	t.Cleanup(func() {
		store.Close()
		cache.Close()
		os.RemoveAll(tmp)
	})
	return f
}

func TestCompressedChunkFetchDecodesAndVerifies(t *testing.T) {
	plain := bytes.Repeat([]byte{0xC7}, 8192)
	z, err := chunkstore.CompressChunkBody(plain)
	if err != nil {
		t.Fatal(err)
	}
	// The plain body is servable but must never be requested while the
	// compressed object answers.
	f := newCompressedFixture(t, plain, z, checkpointchunks.CompressionZstd)
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if f.getsRaw.Load() != 0 {
		t.Fatalf("plain object fetched despite a compressed hit")
	}
	got, ok := f.srv.readCache(0, uint64(len(plain)))
	if !ok || !bytes.Equal(got, plain) {
		t.Fatal("decoded bytes differ from the original chunk")
	}
}

func TestCompressedChunkFallsBackToPlainObject(t *testing.T) {
	plain := bytes.Repeat([]byte{0x42}, 4096)
	// No compressed object at all (a pre-compression share); the digest
	// is over the plaintext, so the plain body verifies as-is.
	f := newCompressedFixture(t, plain, nil, checkpointchunks.CompressionZstd)
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("fallback fetch: %v", err)
	}
	if f.getsZ.Load() == 0 || f.getsRaw.Load() != 1 {
		t.Fatalf("expected one .z miss then one plain hit: z=%d raw=%d",
			f.getsZ.Load(), f.getsRaw.Load())
	}
	got, ok := f.srv.readCache(0, uint64(len(plain)))
	if !ok || !bytes.Equal(got, plain) {
		t.Fatal("fallback bytes differ")
	}
}

func TestCompressedChunkCorruptStreamFails(t *testing.T) {
	plain := bytes.Repeat([]byte{0x42}, 4096)
	z, err := chunkstore.CompressChunkBody(plain)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate the stream: decoding must fail, never serve partial
	// bytes, and never silently fall back to a plain object.
	f := newCompressedFixture(t, plain, z[:len(z)/2], checkpointchunks.CompressionZstd)
	if err := f.srv.fetchChunk(0); err == nil {
		t.Fatal("truncated zstd stream accepted")
	}
	if f.getsRaw.Load() != 0 {
		t.Fatal("corruption triggered a plain fallback")
	}
}

func TestUncompressedManifestNeverProbesZKey(t *testing.T) {
	plain := bytes.Repeat([]byte{0x99}, 2048)
	f := newCompressedFixture(t, plain, nil, "")
	if err := f.srv.fetchChunk(0); err != nil {
		t.Fatalf("plain fetch: %v", err)
	}
	if f.getsZ.Load() != 0 {
		t.Fatal("plain-manifest fetch probed the compressed key")
	}
}
