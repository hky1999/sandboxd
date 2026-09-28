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

package checkpointpublish

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// PublishPhases is the attribution breakdown of one publish attempt (the
// publish-stage slice of T_remote). The ONLY end-to-end wall is
// ArtifactPhases.PublishWall (publish_end − publish_start, which also
// bounds the reconcile probe and the claim/intent acquisition before the
// run). Every field below is a PARTIAL span or an accumulated sum: the
// stage walls may OVERLAP each other and the spans they do not cover
// (reconcile probes, lock/intent acquisition, and in the packed path the
// publishing state write sits INSIDE PackWall, overlapping StateWall).
// They must never be added together or presented as reconstructing the
// attempt's wall — that claim was once made here and is false.
//
// The columns:
//
//   - ManifestLoadWall: sealed memory sidecar parse (the common path — no
//     hashing happens when the sidecar exists).
//   - ScanHashWall: memory chunk scan + digest computation, non-zero ONLY
//     when the sidecar was absent and Compute ran.
//   - UploadWall: standalone chunk upload stage (dedup + worker pool).
//   - PackWall: packed publication stage (baseline load through the last
//     pack PUT) — replaces UploadWall when packing is enabled; includes
//     the publishing state write, so it overlaps StateWall.
//   - MetaWall: artifact-set stage excluding the commit (overlay chunk
//     PUTs, bundle assembly, BUNDLE PUT).
//   - IndexWall: the INDEX commit PUT.
//   - StateWall: local publish-state persistence (sum of this attempt's
//     recorded state writes, including the failed write on failure).
//   - PackBuildTimeTotal / PackUploadTimeTotal: pack build and upload
//     times summed over CONCURRENT pack workers — accumulated totals, not
//     walls (they can exceed the attempt wall; see PackTimings).
//   - CompressTimeTotal: per-chunk zstd encode times summed over the
//     concurrent upload workers — same caveat.
//
// Request columns split three ways and never borrow from each other:
//
//   - Has* counts Has/HEAD probes.
//   - Get* counts GET requests. GetOpenTimeTotal is the header-side
//     latency only; GetTimeTotal is the FULL elapsed from request start
//     through body end (EOF or Close — an errored GET settles immediately
//     at its open latency), so GetTimeTotal − GetOpenTimeTotal is the
//     body transfer time. A headers-only metric would hide exactly the
//     network cost being attributed. GetBytes is the body streamed. This
//     is where reconciliation's INDEX/BUNDLE fetches land: they are GETs,
//     not Has probes, and must not be disguised as the latter. GC fence
//     MARK reads on sweep-marked keys also land here (rare; only under an
//     active sweep race).
//   - Put* counts data-plane PUTs (bytes included). GC bookkeeping —
//     publication intents and sweep claims, whether written through the
//     conditional primitives or the plain keyed surface under their gc-*
//     namespaces — is CONTROL traffic: counted ONLY under Control* and
//     never mixed into Put*. ControlReqs counts both conditional creates
//     and conditional deletes (they are individual control requests).
//
// Reconciliation (the zero-upload converge path) surfaces its probes in
// the Has*/Get* columns with all PUT and control columns zero — it uploads
// nothing by construction. Failed attempts keep their attribution: the
// counters are frozen at failure time, so already-observed GET/Has/PUT/
// control traffic and stage walls survive in the round summary.
type PublishPhases struct {
	ManifestLoadWall time.Duration `json:"manifest_load_wall"`
	ScanHashWall     time.Duration `json:"scan_hash_wall"`
	UploadWall       time.Duration `json:"upload_wall"`
	MetaWall         time.Duration `json:"meta_wall"`
	IndexWall        time.Duration `json:"index_wall"`
	PackWall         time.Duration `json:"pack_wall"`
	StateWall        time.Duration `json:"state_wall"`

	// Concurrent accumulated totals — never walls, never addable.
	PackBuildTimeTotal  time.Duration `json:"pack_build_time_total"`
	PackUploadTimeTotal time.Duration `json:"pack_upload_time_total"`
	CompressTimeTotal   time.Duration `json:"compress_time_total"`

	HasReqs          int           `json:"has_reqs"`
	HasTimeTotal     time.Duration `json:"has_time_total"`
	GetReqs          int           `json:"get_reqs"`
	GetOpenTimeTotal time.Duration `json:"get_open_time_total"` // headers only
	GetTimeTotal     time.Duration `json:"get_time_total"`      // open through body end
	GetBytes         int64         `json:"get_bytes"`           // body bytes streamed out of GETs
	PutReqs          int           `json:"put_reqs"`
	PutBytes         int64         `json:"put_bytes"`
	PutTimeTotal     time.Duration `json:"put_time_total"`

	ControlReqs      int           `json:"control_reqs"`       // GC intent/claim writes AND conditional deletes
	ControlTimeTotal time.Duration `json:"control_time_total"` // never part of Put*
}

// phaseCounters is the concurrency-safe accumulator the instrumented store
// and compression call sites feed; it is frozen into a PublishPhases when
// the attempt ends (successfully or not).
type phaseCounters struct {
	hasReqs   int64
	hasNanos  int64
	getReqs   int64
	getOpenNs int64
	getFullNs int64
	getBytes  int64
	putReqs   int64
	putNanos  int64
	putBytes  int64
	compNanos int64
	ctrlReqs  int64
	ctrlNanos int64
}

func (c *phaseCounters) addHas(d time.Duration) {
	atomic.AddInt64(&c.hasReqs, 1)
	atomic.AddInt64(&c.hasNanos, int64(d))
}

func (c *phaseCounters) addPut(bytes int64, d time.Duration) {
	atomic.AddInt64(&c.putReqs, 1)
	atomic.AddInt64(&c.putNanos, int64(d))
	atomic.AddInt64(&c.putBytes, bytes)
}

func (c *phaseCounters) addCompress(d time.Duration) {
	atomic.AddInt64(&c.compNanos, int64(d))
}

func (c *phaseCounters) addControl(d time.Duration) {
	atomic.AddInt64(&c.ctrlReqs, 1)
	atomic.AddInt64(&c.ctrlNanos, int64(d))
}

// beginGet opens a GET's accounting: the open latency lands immediately;
// the full elapsed (through body end) and the byte count are settled by
// the returned tracker exactly once — at EOF, at a body error, or at
// Close, whichever comes first.
func (c *phaseCounters) beginGet() *getTracker {
	atomic.AddInt64(&c.getReqs, 1)
	return &getTracker{c: c, start: time.Now()}
}

type getTracker struct {
	c          *phaseCounters
	start      time.Time
	bytes      int64
	settleOnce sync.Once
}

// open records the header-side latency (called once, right after the
// store call returns).
func (g *getTracker) open() {
	d := time.Since(g.start)
	atomic.AddInt64(&g.c.getOpenNs, int64(d))
}

// settleFailed closes an errored GET: no body will stream, so the full
// elapsed equals the open latency.
func (g *getTracker) settleFailed() {
	g.settleOnce.Do(func() {
		atomic.AddInt64(&g.c.getFullNs, int64(time.Since(g.start)))
	})
}

// settle records the body bytes and closes the full elapsed; idempotent.
func (g *getTracker) settle() {
	g.settleOnce.Do(func() {
		if n := atomic.LoadInt64(&g.bytes); n > 0 {
			atomic.AddInt64(&g.c.getBytes, n)
		}
		atomic.AddInt64(&g.c.getFullNs, int64(time.Since(g.start)))
	})
}

// snapshot freezes the counters into the request-attribution columns of a
// PublishPhases (walls are recorded separately by the stage timers).
func (c *phaseCounters) snapshot() PublishPhases {
	return PublishPhases{
		HasReqs:           int(atomic.LoadInt64(&c.hasReqs)),
		HasTimeTotal:      time.Duration(atomic.LoadInt64(&c.hasNanos)),
		GetReqs:           int(atomic.LoadInt64(&c.getReqs)),
		GetOpenTimeTotal:  time.Duration(atomic.LoadInt64(&c.getOpenNs)),
		GetTimeTotal:      time.Duration(atomic.LoadInt64(&c.getFullNs)),
		GetBytes:          atomic.LoadInt64(&c.getBytes),
		PutReqs:           int(atomic.LoadInt64(&c.putReqs)),
		PutBytes:          atomic.LoadInt64(&c.putBytes),
		PutTimeTotal:      time.Duration(atomic.LoadInt64(&c.putNanos)),
		CompressTimeTotal: time.Duration(atomic.LoadInt64(&c.compNanos)),
		ControlReqs:       int(atomic.LoadInt64(&c.ctrlReqs)),
		ControlTimeTotal:  time.Duration(atomic.LoadInt64(&c.ctrlNanos)),
	}
}

// hasAndGet reads just the read-side counters (for merging reconciliation
// probe traffic into an attempt's attribution without touching its PUT
// columns).
func (c *phaseCounters) hasAndGet() (hasReqs int, hasTotal time.Duration, getReqs int, getOpenTotal, getTotal time.Duration, getBytes int64) {
	return int(atomic.LoadInt64(&c.hasReqs)), time.Duration(atomic.LoadInt64(&c.hasNanos)),
		int(atomic.LoadInt64(&c.getReqs)), time.Duration(atomic.LoadInt64(&c.getOpenNs)),
		time.Duration(atomic.LoadInt64(&c.getFullNs)), atomic.LoadInt64(&c.getBytes)
}

// The instrumented wrappers count store traffic without changing behavior.
// CRITICAL property: CAPABILITY PRESERVATION. Optional-interface
// assertions on a store (chunkstore.Keyed, chunkstore.ExclusivePutter, ...)
// select real fallbacks in this package — a wrapper whose type always
// satisfies them would make incapable backends LOOK capable and silently
// change fail-closed paths (the artifact-set branch, the GC fence's
// "cannot fence" error). The wrappers are therefore TIERED: each tier's
// method set mirrors exactly what the inner store implements, so every
// type assertion answers the same before and after wrapping.

// storeInstrument is the base tier: chunkstore.Store only (plus the
// label). A backend without keyed access wrapped in this tier still fails
// every chunkstore.Keyed assertion, exactly as bare.
type storeInstrument struct {
	inner chunkstore.Store
	c     *phaseCounters
}

func (s *storeInstrument) Put(ctx context.Context, digest string, r io.Reader) error {
	count, body := planBodyCount(r)
	start := time.Now()
	err := s.inner.Put(ctx, digest, body)
	s.c.addPut(count(), time.Since(start))
	return err
}

func (s *storeInstrument) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	tr := s.c.beginGet()
	rc, err := s.inner.Get(ctx, digest)
	if err != nil {
		tr.open()
		tr.settleFailed()
		return rc, err
	}
	tr.open()
	return &settlingReadCloser{inner: rc, tr: tr}, nil
}

func (s *storeInstrument) Has(ctx context.Context, digest string) (bool, error) {
	start := time.Now()
	ok, err := s.inner.Has(ctx, digest)
	s.c.addHas(time.Since(start))
	return ok, err
}

// String forwards the store label so persisted states keep naming the real
// backend.
func (s *storeInstrument) String() string {
	if str, ok := s.inner.(fmt.Stringer); ok {
		return str.String()
	}
	return "store"
}

// keyedInstrument adds the Keyed surface; it exists only when the inner
// store implements it, so a Store-only backend keeps failing the
// assertion.
type keyedInstrument struct {
	storeInstrument
	keyed chunkstore.Keyed
}

func (s *keyedInstrument) PutKey(ctx context.Context, key string, r io.Reader) error {
	count, body := planBodyCount(r)
	start := time.Now()
	err := s.keyed.PutKey(ctx, key, body)
	if isControlKey(key) {
		// GC bookkeeping (publication intent, claims) written through the
		// plain keyed surface: control traffic, never data bytes.
		s.c.addControl(time.Since(start))
	} else {
		s.c.addPut(count(), time.Since(start))
	}
	return err
}

func (s *keyedInstrument) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	tr := s.c.beginGet()
	rc, err := s.keyed.GetKey(ctx, key)
	if err != nil {
		tr.open()
		tr.settleFailed()
		return rc, err
	}
	tr.open()
	return &settlingReadCloser{inner: rc, tr: tr}, nil
}

func (s *keyedInstrument) HasKey(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	ok, err := s.keyed.HasKey(ctx, key)
	s.c.addHas(time.Since(start))
	return ok, err
}

// exclInstrument adds the conditional-write surface (GC claims/intents);
// it exists only when the inner store implements ExclusivePutter, so
// keyed-but-not-exclusive backends keep taking the fence fallbacks.
// Conditional writes are CONTROL traffic: they never enter the data Put*
// columns.
type exclInstrument struct {
	keyedInstrument
	excl chunkstore.ExclusivePutter
}

func (s *exclInstrument) PutKeyIfAbsent(ctx context.Context, key string, body io.Reader) (bool, error) {
	start := time.Now()
	created, err := s.excl.PutKeyIfAbsent(ctx, key, body)
	s.c.addControl(time.Since(start))
	return created, err
}

func (s *exclInstrument) DeleteKeyIfMatch(ctx context.Context, key, etag string) (bool, error) {
	start := time.Now()
	deleted, err := s.excl.DeleteKeyIfMatch(ctx, key, etag)
	s.c.addControl(time.Since(start))
	return deleted, err
}

// instrumentStore picks the tier whose method set equals the inner store's
// capabilities.
func instrumentStore(store chunkstore.Store, c *phaseCounters) chunkstore.Store {
	base := storeInstrument{inner: store, c: c}
	if keyed, ok := store.(chunkstore.Keyed); !ok {
		return &base
	} else {
		keyedI := keyedInstrument{storeInstrument: base, keyed: keyed}
		if excl, ok := store.(chunkstore.ExclusivePutter); !ok {
			return &keyedI
		} else {
			return &exclInstrument{keyedInstrument: keyedI, excl: excl}
		}
	}
}

// counters exposes the accumulator shared by every tier (promoted through
// the embedding chain), so attempt finalization can find it without naming
// the tier type.
func (s *storeInstrument) counters() *phaseCounters { return s.c }

// isControlKey classifies GC bookkeeping keys (publication intents, sweep
// claims, marks) written through the plain keyed surface: they are control
// traffic and must never land in the data PUT columns.
func isControlKey(key string) bool {
	return strings.HasPrefix(key, GCPubIntentNamespace+"/") ||
		strings.HasPrefix(key, GCClaimNamespace+"/") ||
		strings.HasPrefix(key, GCMarkNamespace+"/")
}

// planBodyCount decides how to measure a PUT body's bytes while keeping the
// reader TRANSPARENT for the common bodies: *bytes.Reader and
// *strings.Reader pass through untouched (their Len() is the request size,
// and downstream stores may type-assert them — e.g. pack budget tests);
// any other reader is wrapped by countingReader.
func planBodyCount(r io.Reader) (count func() int64, body io.Reader) {
	switch v := r.(type) {
	case *bytes.Reader:
		n := int64(v.Len())
		return func() int64 { return n }, r
	case *strings.Reader:
		n := int64(v.Len())
		return func() int64 { return n }, r
	}
	// A SEEKABLE inner body must stay seekable through the counting layer:
	// Remote.PutKey's Seeker path (SeekEnd for ContentLength, SeekStart,
	// then a streamed body) is exactly what verified streaming pack PUTs
	// rely on — hiding the Seek behind a read-only wrapper would silently
	// reroute them into the buffered ReadAll path. Non-seekable bodies
	// keep the read-only wrapper and their historical behavior.
	if s, ok := r.(io.Seeker); ok {
		sc := &seekableCountingReader{countingReader: countingReader{inner: r}, seeker: s}
		return sc.count, sc
	}
	cr := &countingReader{inner: r}
	return cr.count, cr
}

// countingReader tallies the bytes a store consumed from a PUT body.
type countingReader struct {
	inner io.Reader
	n     int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	atomic.AddInt64(&r.n, int64(n))
	return n, err
}

func (r *countingReader) count() int64 { return atomic.LoadInt64(&r.n) }

// seekableCountingReader is a countingReader whose inner body is seekable;
// seeks are forwarded so the store's Seeker detection still succeeds.
type seekableCountingReader struct {
	countingReader
	seeker io.Seeker
}

func (r *seekableCountingReader) Seek(offset int64, whence int) (int64, error) {
	return r.seeker.Seek(offset, whence)
}

// settlingReadCloser streams a GET body through the tracker: every read
// tallies bytes; EOF, a body error, or Close settles the full elapsed and
// the byte count exactly once.
type settlingReadCloser struct {
	inner io.ReadCloser
	tr    *getTracker
}

func (r *settlingReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		atomic.AddInt64(&r.tr.bytes, int64(n))
	}
	if err != nil {
		r.tr.settle() // EOF or failure: the body is over
	}
	return n, err
}

func (r *settlingReadCloser) Close() error {
	r.tr.settle()
	return r.inner.Close()
}
