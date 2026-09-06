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

package chunkstore

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRangeBackends(t *testing.T) {
	content := []byte("head-MIDDLE-tail")
	local, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := local.PutKey(context.Background(), "packs/object", bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/packs/object" {
			t.Errorf("path %q", r.URL.Path)
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("missing identity encoding")
		}
		http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(content))
	}))
	defer server.Close()
	remote, err := Open(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]RangeReader{"local": local, "http": remote.(RangeReader)} {
		t.Run(name, func(t *testing.T) {
			for _, s := range []ObjectRange{{0, 4, int64(len(content))}, {5, 6, int64(len(content))}, {int64(len(content)) - 4, 4, int64(len(content))}, {0, int64(len(content)), int64(len(content))}} {
				data, err := reader.ReadKeyRange(context.Background(), "packs/object", s)
				if err != nil || !bytes.Equal(data, content[s.Offset:s.Offset+s.Length]) {
					t.Fatalf("%+v: %q, %v", s, data, err)
				}
			}
		})
	}
}

func TestRangeRejectsBadResponses(t *testing.T) {
	cases := []struct {
		name               string
		status             int
		cr, body, encoding string
		chunked            bool
	}{
		{"ignored", 200, "", "abc", "", false},
		{"missing", 206, "", "abc", "", false},
		{"wrong-start", 206, "bytes 0-2/10", "abc", "", false},
		{"wrong-end", 206, "bytes 2-5/10", "abc", "", false},
		{"wrong-total", 206, "bytes 2-4/11", "abc", "", false},
		{"unknown-total", 206, "bytes 2-4/*", "abc", "", false},
		{"short", 206, "bytes 2-4/10", "ab", "", true},
		{"long", 206, "bytes 2-4/10", "abcd", "", true},
		{"known-length-short", 206, "bytes 2-4/10", "ab", "", false},
		{"known-length-long", 206, "bytes 2-4/10", "abcd", "", false},
		{"encoded", 206, "bytes 2-4/10", "abc", "gzip", false},
		{"unsatisfiable", 416, "bytes */10", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") != "bytes=2-4" {
					t.Errorf("Range=%q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Range", tc.cr)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			store, _ := Open(server.URL)
			data, err := store.(RangeReader).ReadKeyRange(context.Background(), "pack", ObjectRange{2, 3, 10})
			if err == nil || data != nil {
				t.Fatalf("accepted malformed response: %q %v", data, err)
			}
		})
	}
}

func TestRangeValidationBeforeRequest(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	remote, _ := Open(server.URL)
	local, _ := NewLocal(t.TempDir())
	spans := []ObjectRange{{-1, 1, 5}, {0, 0, 5}, {0, -1, 5}, {0, 1, 0}, {5, 1, 5}, {4, 2, 5}, {math.MaxInt64, 1, math.MaxInt64}, {math.MaxInt64 - 1, 4, math.MaxInt64}, {0, MaxRangeReadBytes + 1, MaxRangeReadBytes + 1}}
	for _, reader := range []RangeReader{remote.(RangeReader), local} {
		for _, span := range spans {
			if _, err := reader.ReadKeyRange(context.Background(), "pack", span); err == nil {
				t.Errorf("accepted %+v", span)
			}
		}
		for _, key := range []string{"", ".", "/absolute", "../escape", "a/../../b", "a//b", "a/./b", "a?x", "a#x", "%2e%2e/escape", "a\\b"} {
			if _, err := reader.ReadKeyRange(context.Background(), key, ObjectRange{0, 1, 1}); err == nil {
				t.Errorf("accepted key %q", key)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid metadata reached server %d times", calls.Load())
	}
}

func TestRangeLocalSizeAndType(t *testing.T) {
	root := t.TempDir()
	local, _ := NewLocal(root)
	if err := os.WriteFile(filepath.Join(root, "pack"), []byte("abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{5, 7} {
		if _, err := local.ReadKeyRange(context.Background(), "pack", ObjectRange{0, 3, size}); err == nil {
			t.Fatal("accepted changed size")
		}
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := local.ReadKeyRange(context.Background(), "dir", ObjectRange{0, 1, 1}); err == nil {
		t.Fatal("accepted directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := local.ReadKeyRange(ctx, "pack", ObjectRange{0, 3, 6}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestRangeCancellationDuringBody(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 2-4/10")
		w.WriteHeader(206)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	store, _ := Open(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := store.(RangeReader).ReadKeyRange(ctx, "pack", ObjectRange{2, 3, 10}); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not cancel")
	}
}
