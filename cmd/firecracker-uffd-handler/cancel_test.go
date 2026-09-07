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

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRangeCancellationStopsInFlightRequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusPartialContent)
		w.(http.Flusher).Flush()
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			return
		case <-release:
			_, _ = w.Write(make([]byte, 4096))
		}
	}))
	defer server.Close()
	cache, err := os.CreateTemp(t.TempDir(), "cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := faultServer{source: &pageSource{ctx: ctx, remote: server.URL, chunk: 4096, cache: cache, client: server.Client(), inflight: make(map[uint64]chan struct{}), fetched: make(map[uint64]struct{})}}
	done := make(chan error, 1)
	completed := false
	go func() { done <- s.fetchChunk(0) }()
	defer func() {
		close(release)
		if !completed {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("fetch did not finish after cleanup release")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		completed = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want cancellation, got %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("source cancellation left Range request running")
	}
	s.source.inflightMu.Lock()
	defer s.source.inflightMu.Unlock()
	if len(s.source.fetched) != 0 || len(s.source.inflight) != 0 {
		t.Fatal("canceled transfer was published or left in flight")
	}
}

// Signal only when the production wait evaluates Done; cancellation therefore
// tests a reached wait site, not merely a pre-canceled function entry.
type observedDoneContext struct {
	context.Context
	reached chan struct{}
	once    sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return c.Context.Done()
}

func TestFetchWaitersCancelWithoutClosingLeader(t *testing.T) {
	for _, digest := range []bool{false, true} {
		name := "chunk"
		if digest {
			name = "digest"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, bytes.Repeat([]byte{0x51}, 4096), false)
			ctx, cancel := context.WithCancel(context.Background())
			observed := &observedDoneContext{Context: ctx, reached: make(chan struct{})}
			f.srv.source.ctx = observed
			pending := make(chan struct{})
			if digest {
				entry := f.srv.source.chunkManifest.Entries[0]
				f.srv.source.digestInflight = map[chunkContentKey]chan struct{}{{digest: entry.Digest, length: 4096}: pending}
			} else {
				f.srv.source.inflight[0] = pending
			}
			done := make(chan error, 1)
			completed := false
			go func() {
				if digest {
					done <- f.srv.fetchChunkFromStore(0)
				} else {
					done <- f.srv.fetchChunk(0)
				}
			}()
			defer func() {
				cancel()
				close(pending)
				if !completed {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("waiter survived cleanup")
					}
				}
			}()
			select {
			case <-observed.reached:
			case <-time.After(3 * time.Second):
				t.Fatal("waiter did not reach cancellation select")
			}
			cancel()
			select {
			case err := <-done:
				completed = true
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("want cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("waiter did not cancel")
			}
			select {
			case <-pending:
				t.Fatal("waiter closed leader completion")
			default:
			}
			if f.gets.Load() != 0 || len(f.srv.source.fetched) != 0 {
				t.Fatal("canceled waiter fetched or published data")
			}
		})
	}
}

func TestCanceledFetchDoesNotStartRequest(t *testing.T) {
	f := newFixture(t, bytes.Repeat([]byte{0xA5}, 4096), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.srv.source.ctx = ctx
	if err := f.srv.fetchChunk(0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.gets.Load() != 0 {
		t.Fatal("canceled fetch reached store")
	}
}
