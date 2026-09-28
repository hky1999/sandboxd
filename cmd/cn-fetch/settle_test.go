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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/chunkcache"
)

// recordingSettler proves the CALL ORDER and the error contract of
// settleCache in BOTH modes: the settle operation (EvictIfNeeded when
// armed, Rescan when 0/0) must run BEFORE the status snapshot, and a
// settle failure must prevent any settled summary from being produced.
type recordingSettler struct {
	calls     []string
	evictErr  error
	rescanErr error
	status    chunkcache.Status
}

func (r *recordingSettler) EvictIfNeeded(ctx context.Context) error {
	r.calls = append(r.calls, "evict")
	return r.evictErr
}

func (r *recordingSettler) Rescan(ctx context.Context) error {
	r.calls = append(r.calls, "rescan")
	return r.rescanErr
}

func (r *recordingSettler) Status() chunkcache.Status {
	r.calls = append(r.calls, "status")
	return r.status
}

// Armed: settleCache must run the capacity pass FIRST and snapshot the
// status only after it succeeds — a pre-pass summary would misrepresent
// evictions and rescanned accounting as settled.
func TestSettleCacheArmedEvictBeforeStatus(t *testing.T) {
	r := &recordingSettler{status: chunkcache.Status{Entries: 7, IndexReady: true}}
	s, err := settleCache(context.Background(), r, true)
	if err != nil {
		t.Fatalf("settleCache(armed): %v", err)
	}
	if len(r.calls) != 2 || r.calls[0] != "evict" || r.calls[1] != "status" {
		t.Fatalf("call order = %v, want [evict status] (no double rescan)", r.calls)
	}
	if s.Entries != 7 || !s.IndexReady {
		t.Fatalf("returned status = %+v, want the post-pass snapshot", s)
	}
}

// 0/0 watermarks: EvictIfNeeded is a no-op, so the authoritative settle is
// an EXPLICIT Rescan, then Status — same order contract.
func TestSettleCacheUnarmedRescanBeforeStatus(t *testing.T) {
	r := &recordingSettler{status: chunkcache.Status{Entries: 2, IndexReady: true}}
	s, err := settleCache(context.Background(), r, false)
	if err != nil {
		t.Fatalf("settleCache(0/0): %v", err)
	}
	if len(r.calls) != 2 || r.calls[0] != "rescan" || r.calls[1] != "status" {
		t.Fatalf("call order = %v, want [rescan status]", r.calls)
	}
	if s.Entries != 2 || !s.IndexReady {
		t.Fatalf("returned status = %+v", s)
	}
}

// A settle that "succeeds" but reports index_ready=false must ALSO fail
// with the zero status — armed mode.
func TestSettleCacheArmedNotReadyFails(t *testing.T) {
	r := &recordingSettler{status: chunkcache.Status{Entries: 5, IndexReady: false}}
	s, err := settleCache(context.Background(), r, true)
	if err == nil {
		t.Fatal("not-ready status must not be returned as settled")
	}
	if s.Entries != 0 || s.IndexReady {
		t.Fatalf("must return the zero status, got %+v", s)
	}
	if len(r.calls) != 2 || r.calls[1] != "status" {
		t.Fatalf("calls = %v, want [evict status]", r.calls)
	}
}

// Same contract for the 0/0 explicit-Rescan path.
func TestSettleCacheUnarmedNotReadyFails(t *testing.T) {
	r := &recordingSettler{status: chunkcache.Status{Entries: 5, IndexReady: false}}
	s, err := settleCache(context.Background(), r, false)
	if err == nil {
		t.Fatal("not-ready status must not be returned as settled")
	}
	if s.Entries != 0 || s.IndexReady {
		t.Fatalf("must return the zero status, got %+v", s)
	}
}

// A failed capacity pass must surface as an error AND never call Status:
// no summary may be printed that could be mistaken for a settled one.
func TestSettleCacheArmedErrorPreventsStatus(t *testing.T) {
	sentinel := errors.New("node lock held by foreign evictor")
	r := &recordingSettler{evictErr: sentinel}
	s, err := settleCache(context.Background(), r, true)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("want wrapped sentinel error, got %v", err)
	}
	if len(r.calls) != 1 || r.calls[0] != "evict" {
		t.Fatalf("calls after failure = %v, want exactly [evict] (no status)", r.calls)
	}
	if s.Entries != 0 || s.IndexReady {
		t.Fatalf("failure must return the zero status, got %+v", s)
	}
}

// A failed Rescan in the 0/0 path has the same contract.
func TestSettleCacheUnarmedErrorPreventsStatus(t *testing.T) {
	sentinel := errors.New("rescan shard unreadable")
	r := &recordingSettler{rescanErr: sentinel}
	s, err := settleCache(context.Background(), r, false)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("want wrapped sentinel error, got %v", err)
	}
	if len(r.calls) != 1 || r.calls[0] != "rescan" {
		t.Fatalf("calls after failure = %v, want exactly [rescan] (no status)", r.calls)
	}
	if s.Entries != 0 || s.IndexReady {
		t.Fatalf("failure must return the zero status, got %+v", s)
	}
}

// printCacheSummary must carry index_ready so consumers can refuse a
// summary whose authoritative index view is not available.
func TestPrintCacheSummaryCarriesIndexReady(t *testing.T) {
	s := chunkcache.Status{Entries: 3, LogicalBytes: 100, AllocatedBytes: 128, IndexReady: true}
	out := captureStdout(t, func() { printCacheSummary(s) })
	for _, want := range []string{
		"chunk-cache: entries=3", "logical=100", "allocated=128",
		"hits=0 misses=0", "evictions=0", "pinned=0", "index_ready=true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary %q missing %q", out, want)
		}
	}
	bad := captureStdout(t, func() { printCacheSummary(chunkcache.Status{}) })
	if !strings.Contains(bad, "index_ready=false") {
		t.Fatalf("unset IndexReady must print index_ready=false, got %q", bad)
	}
}

// Real-manager integration, BOTH configurations: after a successful
// settle the summary must be post-pass — index_ready=true with accounting
// that matches the directory contents. Armed (usage under high): the
// capacity pass is the authoritative rescan. Unarmed (0/0): the explicit
// Rescan is.
func TestSettleCacheRealManagerBothConfigs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		high  int64
		low   int64
		armed bool
	}{
		{"armed under high", 1 << 20, 1 << 19, true},
		{"unarmed 0/0", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			m, err := chunkcache.Open(chunkcache.Config{
				Root:          root,
				HighWatermark: tc.high,
				LowWatermark:  tc.low,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			body := make([]byte, 4096)
			for i := range body {
				body[i] = byte(i)
			}
			if _, err := m.Fetch(context.Background(), digestOf(body), int64(len(body)), func(context.Context) ([]byte, error) {
				return body, nil
			}); err != nil {
				t.Fatal(err)
			}
			s, err := settleCache(context.Background(), m, tc.armed)
			if err != nil {
				t.Fatalf("settle: %v", err)
			}
			if !s.IndexReady {
				t.Fatal("post-settle summary must have index_ready=true")
			}
			if s.Entries != 1 || s.LogicalBytes != 4096 || s.AllocatedBytes <= 0 {
				t.Fatalf("post-settle accounting wrong: %+v", s)
			}
			if s.Evictions != 0 {
				t.Fatalf("no eviction expected in this scenario: %+v", s)
			}
		})
	}
}

// The watermark gate is a SEPARATE, materialize-only step: verify-mode
// argument validation must not depend on any cache parameter (compile-time
// separation — validateMode's signature has none).
var _ = chunkcache.ValidWatermarkMiB // referenced only by the materialize branch

// inferArtifactID: -id wins; -verify-memory + -checkpoint-dir infers the
// basename; anything else yields empty (the CLI then fails usage).
func TestInferArtifactID(t *testing.T) {
	if got, _ := inferArtifactID(true, "explicit", "/x/y"); got != "explicit" {
		t.Fatalf("explicit id must win, got %q", got)
	}
	if got, _ := inferArtifactID(true, "", "/a/b/ckpt-42"); got != "ckpt-42" {
		t.Fatalf("basename inference failed, got %q", got)
	}
	if got, _ := inferArtifactID(false, "", "/a/b/ckpt-42"); got != "" {
		t.Fatalf("non-verify mode must not infer, got %q", got)
	}
	if got, _ := inferArtifactID(true, "", ""); got != "" {
		t.Fatalf("no sources must yield empty, got %q", got)
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var sb strings.Builder
	if _, err := io.Copy(&sb, r); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// validateMode: the CLI's mode contract (P1 restore semantics).
func TestValidateMode(t *testing.T) {
	cases := []struct {
		name                     string
		verify                   bool
		into, id, ckptDir, store string
		wantErr                  bool
	}{
		{"materialize ok", false, "/x", "a1", "", "s", false},
		{"verify by id ok", true, "", "a1", "", "s", false},
		{"verify by checkpoint-dir ok", true, "", "", "/p/a2", "s", false},
		{"verify + into refused", true, "/x", "a1", "", "s", true},
		{"verify without id sources", true, "", "", "", "s", true},
		{"materialize missing into", false, "", "a1", "", "s", true},
		{"materialize missing id", false, "/x", "", "", "s", true},
		{"missing store", false, "/x", "a1", "", "", true},
		// verify mode never inspects cache flags: a half-configured cache
		// watermark pair (which MaterializeWithOptions would reject) must
		// not affect the verify argument path at all — validateMode takes
		// no cache parameters.
		{"verify ok regardless of cache flags", true, "", "a1", "", "s", false},
	}
	for _, c := range cases {
		err := validateMode(c.verify, c.into, c.id, c.ckptDir, c.store)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}
