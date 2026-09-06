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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func packedFixture(t *testing.T, identity ...string) (*fixture, []byte, string) {
	t.Helper()
	data := bytes.Repeat([]byte("payload!"), 512)
	f := newFixture(t, data, false)
	pack := append([]byte("prefix"), data...)
	pack = append(pack, []byte("tail")...)
	sum := sha256.Sum256(pack)
	pd := hex.EncodeToString(sum[:])
	m := f.srv.source.chunkManifest
	m.Version = 2
	m.FileSize *= 2
	m.ChunkCount = 2
	m.Entries = append(m.Entries, checkpointchunks.Chunk{Offset: int64(len(data)), Digest: m.Entries[0].Digest})
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	m.Packs = map[string]checkpointchunks.PackReference{m.Entries[0].Digest: {Digest: pd, Offset: 6, Length: int64(len(data)), ObjectSize: int64(len(pack))}}
	if len(identity) > 0 && identity[0] != "" {
		parts := []checkpointchunks.PackPart{}
		for _, part := range [][]byte{pack[:6], data, pack[4102:]} {
			sum := sha256.Sum256(part)
			parts = append(parts, checkpointchunks.PackPart{Digest: hex.EncodeToString(sum[:]), Length: int64(len(part))})
		}
		root, err := checkpointchunks.PackRootDigest(parts)
		if err != nil {
			t.Fatal(err)
		}
		r := m.Packs[m.Entries[0].Digest]
		r.Identity = identity[0]
		r.Digest = root
		m.Packs[m.Entries[0].Digest] = r
		m.Version = 3
	}
	if err := checkpointchunks.ValidateTransport(m); err != nil {
		t.Fatal(err)
	}
	key, err := m.Packs[m.Entries[0].Digest].Key()
	if err != nil {
		t.Fatal(err)
	}
	return f, pack, key
}

func TestPackedFaultHTTPAndLocalDedup(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run("identity="+identity, func(t *testing.T) { packedFaultHTTPAndLocalDedup(t, identity) })
	}
}
func packedFaultHTTPAndLocalDedup(t *testing.T, identity string) {
	for _, backend := range []string{"http", "local"} {
		t.Run(backend, func(t *testing.T) {
			f, pack, key := packedFixture(t, identity)
			var gets atomic.Int64
			if backend == "http" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gets.Add(1)
					if r.URL.Path != "/"+key {
						t.Errorf("unexpected key %q", r.URL.Path)
					}
					http.ServeContent(w, r, "pack", time.Time{}, bytes.NewReader(pack))
				}))
				defer server.Close()
				f.srv.source.chunkStore = server.URL
			} else {
				dir := t.TempDir()
				store, err := chunkstore.NewLocal(dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.PutKey(context.Background(), key, bytes.NewReader(pack)); err != nil {
					t.Fatal(err)
				}
				f.srv.source.chunkStore = dir
			}
			for _, offset := range []uint64{0, 4096} {
				got, err := f.srv.resolveChunk(offset, 4096)
				if err != nil || !bytes.Equal(got, pack[6:4102]) {
					t.Fatalf("offset %d: length %d error %v", offset, len(got), err)
				}
			}
			if backend == "http" && gets.Load() != 1 {
				t.Fatalf("duplicate chunk fetched %d times", gets.Load())
			}
		})
	}
}

func TestPackedFaultFailureDoesNotPublishCache(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run("identity="+identity, func(t *testing.T) { packedFaultFailureDoesNotPublishCache(t, identity) })
	}
}
func packedFaultFailureDoesNotPublishCache(t *testing.T, identity string) {
	for _, mode := range []string{"bad-hash", "ignored-range", "wrong-range"} {
		t.Run(mode, func(t *testing.T) {
			f, pack, _ := packedFixture(t, identity)
			var repaired atomic.Bool
			var gets atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gets.Add(1)
				if !repaired.Load() {
					switch mode {
					case "ignored-range":
						w.WriteHeader(200)
						_, _ = w.Write(pack)
						return
					case "wrong-range":
						w.Header().Set("Content-Range", "bytes 0-4095/4106")
						w.WriteHeader(206)
						_, _ = w.Write(pack[6:4102])
						return
					case "bad-hash":
						bad := append([]byte(nil), pack...)
						bad[6] ^= 1
						http.ServeContent(w, r, "pack", time.Time{}, bytes.NewReader(bad))
						return
					}
				}
				http.ServeContent(w, r, "pack", time.Time{}, bytes.NewReader(pack))
			}))
			defer server.Close()
			f.srv.source.chunkStore = server.URL
			if err := f.srv.fetchChunkFromStore(0); err == nil {
				t.Fatal("accepted damaged pack response")
			}
			if len(f.srv.source.fetched) != 0 || len(f.srv.source.verifiedDigests) != 0 {
				t.Fatal("unverified bytes published")
			}
			repaired.Store(true)
			if err := f.srv.fetchChunkFromStore(0); err != nil {
				t.Fatal(err)
			}
			if gets.Load() != 2 {
				t.Fatalf("requests %d", gets.Load())
			}
		})
	}
}

func TestPackedFaultCancellation(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run("identity="+identity, func(t *testing.T) { packedFaultCancellation(t, identity) })
	}
}
func packedFaultCancellation(t *testing.T, identity string) {
	f, _, _ := packedFixture(t, identity)
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.srv.source.ctx = ctx
	f.srv.source.chunkStore = server.URL
	done := make(chan error, 1)
	go func() { done <- f.srv.fetchChunkFromStore(0) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packed request did not cancel")
	}
	if len(f.srv.source.fetched) != 0 {
		t.Fatal("cancelled read published cache")
	}
}
