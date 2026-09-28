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

// Package chunkcache manages a node-local content-addressed cache of
// immutable, store-backed chunks (memory chunks and overlay chunks share it:
// both are addressed by the sha256 of their exact bytes, so one digest names
// one content regardless of which artifact referenced it).
//
// The three local data classes of the CrossNode plan stay distinct:
//
//   - unpublished spool (checkpoint dirs awaiting publish) is NEVER owned by
//     this package: eviction only ever unlinks files it can prove are cache
//     entries (shard layout under Root), so a unique copy outside Root
//     cannot be LRU'd away. Upload protection is that structural ownership
//     separation plus the checkpoint-admission gate — deliberately NOT a
//     cache pin.
//   - this cache holds only remote-backed immutable data: the sole write
//     path (Fetch/Publish) verifies the sha256 of the body against the
//     digest BEFORE anything becomes visible under the final name, so every
//     evictable byte is by construction re-fetchable from the store.
//   - active writable state (per-sandbox sparse staging files, writable
//     layers) lives outside Root and is never touched here.
//
// Concurrency and crash safety:
//
//   - cross-process missing-chunk dedup: one flock per digest under
//     Root/locks; exactly one process performs the network fetch +
//     verification + atomic publication (temp file, then rename) for a
//     digest at a time; followers wait and then read the published object
//     (reverifying — a read is only ever served from digest-verified bytes).
//   - capacity is decided on ALLOCATED bytes (st_blocks*512, the real disk
//     occupancy — sparse copies and block rounding diverge from file size),
//     never on logical sizes; Status reports both for observability.
//   - capacity is NODE-WIDE: each Manager's in-memory index is only a cache
//     of the directory, so the watermark check that follows a publication
//     takes the node-wide evict flock and REBUILDS its view from disk
//     (authoritative rescan) before evicting. No decision may be made from
//     a possibly-stale local counter; a dirty flag re-checks if more
//     publications landed during the pass.
//   - pins are flock-held files under Root/pins, published by rename while
//     the lock is already held, so the evictor never observes a live pin
//     without its lock. A holder crash releases the flock (kernel-owned),
//     making the pin stale; the evictor proves staleness with a non-blocking
//     shared probe and only then unlinks it. No pin can leak past the death
//     of its process, and no eviction can remove a pinned chunk.
//   - durability is cache-grade: renames are ordered after the full body
//     write but fsync happens on a bounded background queue. A crash may
//     lose or truncate a cached copy; the read path's length+digest check
//     evicts such a copy and refetches, so corruption is never served.
package chunkcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// Shard/pin/lock layout under Root. Chunk files keep the historical
// <root>/<digest[:2]>/<digest> layout so an existing -chunk-local directory
// remains readable; locks, pins, the evictor lock and the status file live
// in reserved directories whose names are not valid two-hex shards.
const (
	locksDir   = "locks"
	pinsDir    = "pins"
	evictLock  = ".evict.lock"
	statusName = "status.json"
	tmpPrefix  = ".tmp-"
	// staleTempAge bounds how long an abandoned temp file may survive; a
	// live publish never takes anywhere near this long.
	staleTempAge = time.Hour
	// followerPoll is the cross-process wait granularity while the leader
	// downloads and publishes.
	followerPoll = 25 * time.Millisecond
	// evictLockPoll waits for the node-wide evictor lock when a capacity
	// pass must run (correctness requires the lock; we never skip it).
	evictLockPoll = 100 * time.Millisecond
)

// Config tunes one Manager. HighWatermark/LowWatermark are ALLOCATED byte
// budgets (st_blocks*512 — real disk occupancy; block rounding and sparse
// files make this differ from file size, which is reported separately as
// logical bytes). Valid configurations are exactly (0,0) — eviction
// disabled, the historical unbounded behavior — or (high>0, 0<low<=high).
type Config struct {
	Root          string
	HighWatermark int64
	LowWatermark  int64
	// TouchEvery throttles LRU clock updates per entry: a hit rewrites the
	// file's mtime at most this often. Zero defaults to a minute.
	TouchEvery time.Duration
	// Logger receives eviction and reconciliation lines; nil discards them.
	Logger interface {
		Printf(format string, v ...any)
	}
	// StoreDomain binds the cache root to ONE store identity (endpoint or
	// path). A digest hit must not silently bypass the new store's
	// authorization: an Open against a different domain fails closed. Empty
	// keeps the historical unbound behavior for existing roots (operators
	// adopting domains must re-provision or consciously continue unbound).
	StoreDomain string
}

const domainFileName = ".store-domain"

// MaxWatermarkMiB is the largest MiB-scale flag value whose <<20 shift
// cannot overflow int64. ValidWatermarks itself is UNITS-AGNOSTIC (shape
// only); every MiB flag site validates through ValidWatermarkMiB.
const MaxWatermarkMiB = int64(math.MaxInt64 >> 20)

// ValidWatermarks enforces the documented shapes: both zero, or a strictly
// positive bounded pair. Half-configured pairs (one zero, one not) are
// rejected everywhere (Manager, CLI flags, daemon config).
func ValidWatermarks(high, low int64) error {
	if high < 0 || low < 0 {
		return fmt.Errorf("negative watermark")
	}
	if high == 0 && low == 0 {
		return nil
	}
	if high == 0 || low == 0 || low > high {
		return fmt.Errorf("watermarks must be 0/0 (disabled) or 0 < low <= high, got high=%d low=%d", high, low)
	}
	return nil
}

// ValidWatermarkMiB validates MiB-scale flags: the same shape rules plus the
// overflow bound — a value above MaxInt64>>20 could not be shifted left by
// 20 without wrapping negative.
func ValidWatermarkMiB(high, low int64) error {
	if err := ValidWatermarks(high, low); err != nil {
		return err
	}
	if high > MaxWatermarkMiB {
		return fmt.Errorf("watermark %d MiB exceeds MaxInt64>>20; the MiB<<20 shift would overflow", high)
	}
	return nil
}

// Entry accounting for one cached chunk. Size is logical; Allocated is
// st_blocks*512 as observed at scan/publish time. Watermark decisions use
// Allocated exclusively.
type entry struct {
	size      int64
	allocated int64
	lastTouch time.Time
}

// Status is a point-in-time snapshot for metrics, tests and tool summaries.
type Status struct {
	Entries        int64 `json:"entries"`
	LogicalBytes   int64 `json:"logical_bytes"`
	AllocatedBytes int64 `json:"allocated_bytes"`
	HighWatermark  int64 `json:"high_watermark"`
	LowWatermark   int64 `json:"low_watermark"`
	IndexReady     bool  `json:"index_ready"`
	Hits           int64 `json:"hits"`
	Misses         int64 `json:"misses"`
	HitBytes       int64 `json:"hit_bytes"`
	MissBytes      int64 `json:"miss_bytes"`
	Evictions      int64 `json:"evictions"`
	EvictedBytes   int64 `json:"evicted_bytes"`
	PinnedEntries  int64 `json:"pinned_entries"`
	PinnedBytes    int64 `json:"pinned_bytes"`
	// PinnedOverageBytes is the allocated total ABOVE the high watermark
	// that could not be reclaimed because the entries are pinned (soft-cap
	// semantics: pinned bytes may exceed high; see the contract).
	PinnedOverageBytes int64  `json:"pinned_overage_bytes"`
	PoisonedEvicted    int64  `json:"poisoned_evicted"`
	Waiters            int64  `json:"waiters"`
	DownloadErrors     int64  `json:"download_errors"`
	LastEvictErr       string `json:"last_evict_err,omitempty"`
}

// Manager is safe for concurrent use.
type Manager struct {
	cfg Config

	mu     sync.Mutex
	index  map[string]*entry
	ready  bool
	dirty  bool             // a publication landed during an in-flight capacity pass
	pinned map[string]int64 // digest -> logical size, from live pins (evictor view)

	hits, misses, hitBytes, missBytes atomic.Int64
	evictions, evictedBytes, poisoned atomic.Int64
	waiters, downloadErrors           atomic.Int64
	pinnedCount, pinnedBytes          atomic.Int64
	pinnedOverage                     atomic.Int64
	usageAllocated                    atomic.Int64
	lastEvictErr                      atomic.Pointer[string]

	// Capacity convergence is loss-free: every publication sets dirty and
	// sends into evictSig (capacity 1 — coalescing is safe because a pass
	// rescans everything); ONE long-lived worker runs the passes. A trigger
	// is never dropped on a busy node lock (the worker waits, bounded by
	// its context) and never dropped on the in-process CAS race that a
	// skip-on-busy design would lose (P1 interleaving: B publishes after
	// A's authoritative scan; B's trigger must still be honored).
	evictWG   sync.WaitGroup
	evictStop chan struct{}
	evictSig  chan struct{}
	// lifeCtx bounds EVERY long-running path (the evict worker's node-lock
	// waits, the initial scan) so Close can never hang on a cross-process
	// flock holder: cancel unblocks the waits, the waitgroups then drain.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc
	lifeWG     sync.WaitGroup

	// inflight dedups Fetch within this process; cross-process dedup is the
	// per-digest flock below. The registration loop in Fetch re-acquires
	// inflightMu on every iteration: a woken follower re-runs the election
	// instead of writing the map unlocked (concurrent-map-write hazard).
	inflightMu sync.Mutex
	inflight   map[string]chan struct{}

	// fsyncQ keeps durability off the fetch path: renames are immediate,
	// data hits disk on bounded background workers, and a full queue just
	// drops work (the read path self-heals truncated copies).
	fsyncWG   sync.WaitGroup
	fsyncStop chan struct{}
	fsyncCh   chan string

	// Per-instance test seams (P1-C/A/B): accounting and eviction must be
	// fail-closed, and their failure injection has to be per-Manager — a
	// package-global seam would race parallel tests. Production always
	// uses the os defaults set in Open.
	statAllocated func(path string) (fs.FileInfo, error)
	removePath    func(path string) error
}

// Open prepares the cache directory and starts the background index walk
// (byte accounting) plus the fsync workers. It does not block on the walk:
// Fetch works immediately from the filesystem; eviction waits for the index.
func Open(cfg Config) (*Manager, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("chunkcache: empty root")
	}
	if err := ValidWatermarks(cfg.HighWatermark, cfg.LowWatermark); err != nil {
		return nil, fmt.Errorf("chunkcache: %w", err)
	}
	if cfg.TouchEvery <= 0 {
		cfg.TouchEvery = time.Minute
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	cfg.Root = abs
	for _, dir := range []string{cfg.Root, filepath.Join(cfg.Root, locksDir), filepath.Join(cfg.Root, pinsDir)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("chunkcache: prepare %s: %w", dir, err)
		}
	}
	if err := m2bindDomain(cfg.Root, cfg.StoreDomain); err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:           cfg,
		index:         make(map[string]*entry),
		inflight:      make(map[string]chan struct{}),
		fsyncStop:     make(chan struct{}),
		fsyncCh:       make(chan string, 64),
		evictStop:     make(chan struct{}),
		evictSig:      make(chan struct{}, 1),
		statAllocated: os.Stat,
		removePath:    os.Remove,
	}
	m.lifeCtx, m.lifeCancel = context.WithCancel(context.Background())
	for i := 0; i < 2; i++ {
		m.fsyncWG.Add(1)
		go m.fsyncWorker()
	}
	if m.cfg.HighWatermark > 0 {
		m.evictWG.Add(1)
		go m.evictWorker()
	}
	m.lifeWG.Add(1)
	go func() {
		defer m.lifeWG.Done()
		ctx, cancel := context.WithTimeout(m.lifeCtx, 10*time.Minute)
		defer cancel()
		if err := m.Rescan(ctx); err != nil && m.cfg.Logger != nil && ctx.Err() == nil {
			m.cfg.Logger.Printf("chunkcache: initial scan: %v", err)
		}
		// Reclaim leftover overage from before this process started (a
		// restarted node with a full cache, or growth by processes that
		// ran without watermarks).
		if ctx.Err() == nil {
			_ = m.EvictIfNeeded(ctx)
		}
	}()
	return m, nil
}

// WatermarksArmed reports whether eviction is enabled; callers use it to
// decide whether a missing pin is fatal (with eviction armed, serving
// unpinned would silently drop the pin gate).
func (m *Manager) WatermarksArmed() bool { return m.cfg.HighWatermark > 0 }

func (m *Manager) logf(format string, v ...any) {
	if m.cfg.Logger != nil {
		m.cfg.Logger.Printf("chunkcache: "+format, v...)
	}
}

// chunkPath is the final, visible location of one digest.
func (m *Manager) chunkPath(digest string) string {
	return filepath.Join(m.cfg.Root, digest[:2], digest)
}

func (m *Manager) lockPath(digest string) string {
	return filepath.Join(m.cfg.Root, locksDir, digest)
}

// readVerified returns the cached body for digest iff it exists, has exactly
// length bytes and hashes to digest. Any other content is unlinked and
// counted as poisoned (self-healing after crashes or external corruption).
func (m *Manager) readVerified(digest string, length int64) ([]byte, bool) {
	path := m.chunkPath(digest)
	// Bounded exact-length read: a corrupted or adversarially huge cache
	// file must never trigger an unbounded allocation. Short AND overlong
	// are both poisoned (unlinked + refetched).
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	body, rerr := io.ReadAll(io.LimitReader(f, length+1))
	f.Close()
	if rerr != nil {
		return nil, false
	}
	if int64(len(body)) != length || !bytesMatchDigest(body, digest) {
		_ = os.Remove(path)
		m.poisoned.Add(1)
		m.logf("evicted poisoned cache entry %s (len %d want %d or digest mismatch)", digest[:12], len(body), length)
		m.mu.Lock()
		if e, ok := m.index[digest]; ok {
			m.usageAllocated.Add(-e.allocated)
			delete(m.index, digest)
		}
		m.mu.Unlock()
		return nil, false
	}
	return body, true
}

// touch advances the LRU clock: in-memory always, on-disk mtime at most once
// per TouchEvery (mtime is the cross-process LRU clock; atime is not —
// relatime mounts update it at most daily).
func (m *Manager) touch(digest string) {
	now := time.Now()
	m.mu.Lock()
	e, ok := m.index[digest]
	if ok {
		if now.Sub(e.lastTouch) >= m.cfg.TouchEvery {
			e.lastTouch = now
			m.mu.Unlock()
			_ = os.Chtimes(m.chunkPath(digest), now, now)
			return
		}
		e.lastTouch = now
	}
	m.mu.Unlock()
}

// Fetch returns the verified body for digest, consulting the cache first and
// calling miss exactly when a verified copy is not present. miss runs under
// the cross-process digest lock, so cluster-wide at most one miss per digest
// is in flight per node; its result is verified before publication and an
// unverified body is never cached or returned.
func (m *Manager) Fetch(ctx context.Context, digest string, length int64, miss func(context.Context) ([]byte, error)) ([]byte, error) {
	if !checkpointchunks.ValidDigest(digest) {
		return nil, fmt.Errorf("chunkcache: invalid digest %q", digest)
	}
	if length < 0 {
		return nil, fmt.Errorf("chunkcache: negative length for %s", digest[:12])
	}
	// Election loop. A woken follower RE-RUNS the loop (re-locking
	// inflightMu) instead of falling through to an unlocked map write;
	// after a failed leader each waiter becomes leader exactly once.
	for {
		if body, ok := m.readVerified(digest, length); ok {
			m.hits.Add(1)
			m.hitBytes.Add(length)
			// Adopt into the index if another process published it after
			// our last scan (capacity accounting must not miss it). The
			// adoption gate FAILS THE READ on a stat error — verified bytes
			// nobody accounted must not be returned (the second request
			// would otherwise bypass a failed publication's accounting).
			if err := m.adoptHit(digest, length); err != nil {
				return nil, err
			}
			m.touch(digest)
			return body, nil
		}
		m.inflightMu.Lock()
		if done, ok := m.inflight[digest]; ok {
			m.inflightMu.Unlock()
			m.waiters.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
			}
			continue // re-elect (read again, maybe lead)
		}
		done := make(chan struct{})
		m.inflight[digest] = done
		m.inflightMu.Unlock()
		m.misses.Add(1)
		m.missBytes.Add(length)
		body, err := m.fetchLocked(ctx, digest, length, miss)
		// Release leadership exactly once, then return the leader's result.
		m.inflightMu.Lock()
		delete(m.inflight, digest)
		close(done)
		m.inflightMu.Unlock()
		return body, err
	}
}

// fetchLocked runs with the in-process leadership for digest held. The
// cross-process flock serializes network fetch + verification + atomic
// publication node-wide.
func (m *Manager) fetchLocked(ctx context.Context, digest string, length int64, miss func(context.Context) ([]byte, error)) ([]byte, error) {
	lock, err := os.OpenFile(m.lockPath(digest), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("chunkcache: open digest lock: %w", err)
	}
	defer lock.Close()
	for {
		ferr := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch classifyFlockErr(ferr) {
		case flockAcquired:
			defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
			// Double-check: a leader between our miss and this lock may
			// already have published.
			if body, ok := m.readVerified(digest, length); ok {
				if err := m.adoptHit(digest, length); err != nil {
					return nil, err
				}
				return body, nil
			}
			body, merr := miss(ctx)
			if merr != nil {
				m.downloadErrors.Add(1)
				return nil, fmt.Errorf("chunkcache: fetch %s: %w", digest[:12], merr)
			}
			if int64(len(body)) != length || !bytesMatchDigest(body, digest) {
				m.downloadErrors.Add(1)
				return nil, fmt.Errorf("chunkcache: body for %s failed verification (len %d want %d)", digest[:12], len(body), length)
			}
			if perr := m.publish(digest, body); perr != nil {
				return nil, fmt.Errorf("chunkcache: publish %s: %w", digest[:12], perr)
			}
			// Auto-eviction fires ONLY here: after the leader's atomic
			// publication and accounting landed, and as a NODE-WIDE pass —
			// the local counter is not trusted for the decision (other
			// processes publish into the same root without our knowing).
			m.triggerEvict()
			return body, nil
		case flockRetry:
			continue // EINTR: immediate retry
		case flockFatal:
			return nil, fmt.Errorf("chunkcache: digest flock: %w", ferr)
		}
		// flockBusy: another process leads. Wait for its publication; every
		// recheck re-verifies, so we either adopt proven bytes (through the
		// same accounting gate as every other verified read) or, if the
		// leader failed, take over the lock and fetch ourselves.
		if body, ok := m.readVerified(digest, length); ok {
			if err := m.adoptHit(digest, length); err != nil {
				return nil, err
			}
			return body, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(followerPoll):
		}
	}
}

// publish makes verified bytes visible under the final name atomically. It
// never fsyncs inline (cache-grade durability; the fsync queue catches up).
func (m *Manager) publish(digest string, body []byte) error {
	final := m.chunkPath(digest)
	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tmpPrefix)
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, final); err != nil {
		return err
	}
	if err := m.accountPublished(digest, int64(len(body))); err != nil {
		// Fail-closed accounting (P1-A): the verified object exists, but
		// capacity cannot be trusted for it. Surface the error and leave
		// the index dirty (accountPublished did both).
		return err
	}
	m.mu.Lock()
	m.dirty = true // a capacity pass must re-check the disk
	m.mu.Unlock()
	select { // best-effort durability; a dropped job is self-healing
	case m.fsyncCh <- final:
	default:
	}
	return nil
}

func (m *Manager) fsyncWorker() {
	defer m.fsyncWG.Done()
	for {
		select {
		case <-m.fsyncStop:
			return
		case path := <-m.fsyncCh:
			if f, err := os.Open(path); err == nil {
				_ = f.Sync()
				f.Close()
			}
		}
	}
}

// Close performs one final bounded, authoritative convergence pass (the
// queue may hold the last trigger — e.g. a just-released pin with no
// further fetches), then stops background workers. A failed or timed-out
// final pass is recorded in Status().LastEvictErr and logged; Close does
// not return it because the cache remains correct regardless (entries are
// re-verified on read; the next process's startup pass reclaims). The
// manager must not be used afterwards.
func (m *Manager) Close() {
	// Bounded by construction: cancel FIRST so the worker's lock wait and
	// the initial scan abort, then run the final pass with a fresh bounded
	// context (a foreign flock holder delays only up to this budget), then
	// drain. A failed final pass is recorded, never fatal (the next
	// process's startup pass reclaims).
	m.lifeCancel()
	if m.cfg.HighWatermark > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := m.runCapacityPass(ctx); err != nil {
			m.recordEvictErr(err)
			m.logf("final convergence pass: %v", err)
		}
		cancel()
	}
	close(m.fsyncStop)
	if m.cfg.HighWatermark > 0 {
		close(m.evictStop)
	}
	m.fsyncWG.Wait()
	m.evictWG.Wait()
	m.lifeWG.Wait()
}

// triggerEvict asks for a capacity pass. Capacity-1 coalescing is safe: a
// pass is a full authoritative rescan, so one pending signal covers any
// number of publications; the dirty flag covers the signal-sent-during-pass
// race because the worker re-checks it before parking.
func (m *Manager) triggerEvict() {
	select {
	case m.evictSig <- struct{}{}:
	default:
	}
}

func (m *Manager) evictWorker() {
	defer m.evictWG.Done()
	for {
		select {
		case <-m.evictStop:
			return
		case <-m.evictSig:
		}
		// lifeCtx (cancelled by Close) bounds the node-lock wait: Close can
		// never hang behind a foreign flock holder.
		m.runCapacityPass(m.lifeCtx)
	}
}

// applyUsage records a digest's size and allocated bytes in the index.
// Caller must have obtained `allocated` WITHOUT swallowing errors (see
// adoptHit / accountPublished / Rescan).
func (m *Manager) applyUsage(digest string, size, allocated int64) {
	m.mu.Lock()
	if old, ok := m.index[digest]; ok {
		m.usageAllocated.Store(m.usageAllocated.Load() - old.allocated + allocated)
	} else {
		m.usageAllocated.Add(allocated)
	}
	m.index[digest] = &entry{size: size, allocated: allocated, lastTouch: time.Now()}
	m.mu.Unlock()
}

// adoptHit is the ONE accounting gate every verified-disk read of an
// untracked digest flows through: Fetch's outer hit, fetchLocked's
// post-lock double-check, and the follower recheck after another process
// published. The caller may return the body only after stat + allocated
// accounting succeeded. A stat failure FAILS THE READ in every
// configuration — returning verified bytes nobody accounted would let the
// next request silently bypass a failed publication's accounting. Every
// configuration records the error for Status().LastEvictErr and marks the
// index dirty; only with watermarks armed (an evict worker exists) does it
// also wake the authoritative capacity pass — a 0/0 configuration has no
// consumer for that signal.
func (m *Manager) adoptHit(digest string, length int64) error {
	if _, tracked := m.indexLookup(digest); tracked {
		return nil
	}
	fi, err := m.statAllocated(m.chunkPath(digest))
	if err != nil {
		werr := fmt.Errorf("chunkcache: adopt %s: accounting stat: %w", digest[:12], err)
		m.recordEvictErr(werr)
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
		if m.cfg.HighWatermark > 0 {
			m.triggerEvict()
		}
		m.logf("%v", werr)
		return werr
	}
	m.applyUsage(digest, length, allocatedFrom(fi))
	if m.cfg.HighWatermark > 0 {
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
		m.triggerEvict()
	}
	return nil
}

// accountPublished records a chunk THIS process just published. The object
// is valid on disk, but a stat failure means capacity accounting cannot be
// trusted for it: the error is RETURNED (never swallowed into allocated=0)
// and recorded for Status().LastEvictErr, with the index marked dirty.
// The capacity worker is woken only when watermarks are armed (a 0/0
// configuration starts no evict worker — the signal would have no
// consumer).
func (m *Manager) accountPublished(digest string, size int64) error {
	fi, err := m.statAllocated(m.chunkPath(digest))
	if err != nil {
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
		werr := fmt.Errorf("chunkcache: account published %s: %w", digest[:12], err)
		m.recordEvictErr(werr)
		if m.cfg.HighWatermark > 0 {
			m.triggerEvict()
		}
		return werr
	}
	m.applyUsage(digest, size, allocatedFrom(fi))
	return nil
}

// allocatedFrom computes st_blocks*512 from an ALREADY-OBTAINED FileInfo —
// no second stat whose failure could silently report zero (P1-A/P1-C: the
// old path re-statted by path and treated any error as allocated=0).
func allocatedFrom(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	// Non-Linux fallback: logical size rounded up to filesystem blocks.
	return (fi.Size() + 511) / 512 * 512
}

// Pin protects the given digests for the lifetime of the returned release
// function (or the death of this process — the kernel drops the flock).
// Typical lifecycles: a uffd handler holds a runtime pin for its artifact's
// chunk set for its whole life; cn-fetch/materialize holds a restore pin
// until the artifact is laid down. The publisher holds NO cache pin: its
// unpublished spool is protected structurally (separate ownership; see the
// package comment) — a pin must never substitute for that separation.
// domainFingerprint stores ONLY a sha256 of the normalized identity —
// never the raw store URL (it may embed credentials) or path.
func domainFingerprint(domain string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(domain)))
	return hex.EncodeToString(sum[:])
}

// m2bindDomain persists and enforces the root's store binding. All binders
// serialize on a dedicated flock (.store-domain.lock); the marker itself is
// written temp+fsync+RENAME, so a concurrent reader never observes a
// 0-byte/partial file. The read validates EXACTLY 64 hex chars. Binding
// onto a root that already holds chunks fails closed (unknown provenance).
func m2bindDomain(root, domain string) error {
	if domain == "" {
		return nil // unbound legacy behavior (operator's explicit choice)
	}
	marker := filepath.Join(root, domainFileName)
	lock, err := os.OpenFile(filepath.Join(root, domainFileName+".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("chunkcache: domain bind lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	if raw, rerr := os.ReadFile(marker); rerr == nil {
		got := strings.TrimSpace(string(raw))
		if !checkpointchunks.ValidDigest(got) {
			return fmt.Errorf("chunkcache: store-domain marker in %s is corrupt (not 64 hex chars)", root)
		}
		want := domainFingerprint(domain)
		if got != want {
			return fmt.Errorf("chunkcache: root %s is bound to a different store domain (fingerprint %s), refusing this store — re-provision the root to change stores", root, got)
		}
		return nil
	} else if !os.IsNotExist(rerr) {
		return rerr
	}
	// First bind: a root with pre-existing chunks is unknown provenance —
	// refuse instead of adopting old bytes as the new domain's cache.
	n, cerr := countChunkEntries(root)
	if cerr != nil {
		return fmt.Errorf("chunkcache: cannot inspect root %s for prior content: %w", root, cerr)
	}
	if n > 0 {
		return fmt.Errorf("chunkcache: root %s already holds %d chunk entries of unknown provenance; re-provision a fresh root to bind store domain", root, n)
	}
	tmp, err := os.CreateTemp(root, ".domain-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, werr := tmp.WriteString(domainFingerprint(domain) + "\n"); werr != nil {
		tmp.Close()
		os.Remove(tmpName)
		return werr
	}
	if serr := tmp.Sync(); serr != nil {
		tmp.Close()
		os.Remove(tmpName)
		return serr
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpName)
		return cerr
	}
	return os.Rename(tmpName, marker)
}

// countChunkEntries counts cache entries under the shard layout (used only
// for the first-bind provenance check).
func countChunkEntries(root string) (int, error) {
	shards, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, shard := range shards {
		if !shard.IsDir() || !isShardName(shard.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, shard.Name()))
		if err != nil {
			// Fail closed: an unreadable shard means we cannot PROVE the
			// root is empty, and first-binding must not proceed on doubt.
			return 0, err
		}
		for _, f := range files {
			if !f.IsDir() && checkpointchunks.ValidDigest(f.Name()) {
				n++
			}
		}
	}
	return n, nil
}

// globalPinSeq makes pin file names unique across all managers in this
// process (the pid separates processes).
var globalPinSeq atomic.Uint64

func (m *Manager) Pin(name string, digests []string) (func(), error) {
	return m.PinContext(context.Background(), name, digests)
}

// PinContext is Pin with a bounded wait: a foreign evict-lock holder delays
// publication at most until ctx ends, then the pin fails (callers fail
// closed when eviction is armed — see restorePinDecision / the handler).
func (m *Manager) PinContext(ctx context.Context, name string, digests []string) (func(), error) {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return nil, fmt.Errorf("chunkcache: invalid pin name %q", name)
	}
	dir := filepath.Join(m.cfg.Root, pinsDir)
	tmp, err := os.CreateTemp(dir, tmpPrefix)
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	fail := func(err error) (func(), error) {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	// Lock BEFORE publishing the name: the evictor's shared probe on the
	// final path then never races an unlocked live pin.
	if err := syscall.Flock(int(tmp.Fd()), syscall.LOCK_EX); err != nil {
		return fail(err)
	}
	body := strings.Builder{}
	for _, d := range digests {
		if !checkpointchunks.ValidDigest(d) {
			return fail(fmt.Errorf("chunkcache: pin lists invalid digest %q", d))
		}
		body.WriteString(d)
		body.WriteByte('\n')
	}
	if _, err := tmp.WriteString(body.String()); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	// The file name carries a globally-unique nonce (process id plus a
	// process-wide counter): two managers — in one process or across
	// processes — using the same label MUST NOT overwrite each other's live
	// pin. A rename over a held pin would let the first holder's release
	// unlink the second holder's protection. The label stays for humans.
	nonce := globalPinSeq.Add(1) // Add RETURNS the new value: no Add-then-Load race
	final := filepath.Join(dir, fmt.Sprintf("%s.%d.%d.pin", name, os.Getpid(), nonce))
	// Publish the pin's final name under a SHARED node evict lock so an
	// in-flight eviction cannot snapshot-and-delete between our rename and
	// its protectedSet read.
	evict, eerr := os.OpenFile(filepath.Join(m.cfg.Root, evictLock), os.O_CREATE|os.O_RDWR, 0o600)
	if eerr != nil {
		return fail(eerr)
	}
	for {
		err := syscall.Flock(int(evict.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		switch classifyFlockErr(err) {
		case flockAcquired:
		case flockRetry:
			continue
		case flockFatal:
			evict.Close()
			return fail(err)
		default: // busy: bounded wait, never an unbounded block
			select {
			case <-ctx.Done():
				evict.Close()
				return fail(ctx.Err())
			case <-time.After(evictLockPoll):
				continue
			}
		}
		break
	}
	renameErr := os.Rename(tmpName, final)
	syscall.Flock(int(evict.Fd()), syscall.LOCK_UN)
	evict.Close()
	if renameErr != nil {
		return fail(renameErr)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// Unlink first so the evictor can never mistake a released pin
			// for a stale one worth keeping; the held flock is irrelevant on
			// an unlinked inode.
			_ = os.Remove(final)
			tmp.Close()
			// A released pin may be the LAST event in the process (uffd
			// handler teardown, cn-fetch exit): with watermarks armed the
			// now-unpinned bytes must converge without waiting for a fetch
			// that may never come.
			m.triggerEvict()
		})
	}, nil
}

// protectedSet snapshots the digests currently protected by live pins.
// A pin file that yields to a non-blocking shared flock has no holder (its
// process died): it is provably stale and is unlinked, not honored.
//
// Fail-closed contract (P1-A): an unreadable or corrupt LIVE pin must abort
// eviction — never be treated as "no protection". Only genuinely concurrent
// disappearance (fs.ErrNotExist on open) is tolerated; every other open,
// flock, read, seek, or parse error returns. The body is read from the SAME
// descriptor the shared-flock probe ran on (never re-opened by path, which
// could observe a different or swapped file), and every non-empty line must
// be a strict 64-lowercase-hex digest.
func (m *Manager) protectedSet() (map[string]struct{}, int64, int64, error) {
	dir := filepath.Join(m.cfg.Root, pinsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, 0, err
	}
	protected := make(map[string]struct{})
	var pinnedBytes, pinnedCount int64
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".pin") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // vanished between listing and open: benign race
			}
			return nil, 0, 0, fmt.Errorf("chunkcache: open pin %s: %w", de.Name(), err)
		}
		switch ferr := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); {
		case ferr == nil:
			// No exclusive holder exists: stale pin from a dead process.
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			f.Close()
			_ = os.Remove(path)
			m.logf("removed stale pin %s (holder gone)", de.Name())
			continue
		case errors.Is(ferr, syscall.EWOULDBLOCK):
			// Held by a live owner: read on below, from this same fd.
		default:
			f.Close()
			return nil, 0, 0, fmt.Errorf("chunkcache: flock pin %s: %w", de.Name(), ferr)
		}
		raw, rerr := readAllFromStart(f)
		f.Close()
		if rerr != nil {
			return nil, 0, 0, fmt.Errorf("chunkcache: read pin %s: %w", de.Name(), rerr)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "" {
				continue
			}
			if !checkpointchunks.ValidDigest(line) {
				// A live pin naming anything but a strict digest is
				// corruption: pretending it protects nothing could evict a
				// chunk a live VM still faults on.
				return nil, 0, 0, fmt.Errorf("chunkcache: corrupt pin %s: %q is not a valid digest", de.Name(), line)
			}
			protected[line] = struct{}{}
			pinnedCount++
			if e, ok := m.indexLookup(line); ok {
				pinnedBytes += e.size
			}
		}
	}
	return protected, pinnedCount, pinnedBytes, nil
}

// readAllFromStart reads a whole already-open descriptor from offset 0 —
// the locked-fd counterpart of os.ReadFile that can never observe a
// different file than the one the flock was taken on.
func readAllFromStart(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

func (m *Manager) indexLookup(digest string) (*entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.index[digest]
	return e, ok
}

// EvictIfNeeded is the node-wide capacity pass: it takes the node evict
// flock (waiting, never skipping — a skipped pass is exactly how a shared
// root overfills while every process believes itself under budget), rebuilds
// its view from disk (authoritative rescan; local counters are only hints),
// and unlinks least-recently-touched unpinned entries until ALLOCATED usage
// is at or below the low watermark. A dirty flag set by concurrent
// publications re-runs the pass before releasing.
func (m *Manager) EvictIfNeeded(ctx context.Context) error {
	if m.cfg.HighWatermark <= 0 {
		return nil
	}
	err := m.runCapacityPass(ctx)
	if ctx.Err() != nil {
		// A cancelled pass must not become a lost trigger: re-signal so the
		// worker converges later.
		m.triggerEvict()
	}
	return err
}

// runCapacityPass takes the node-wide evict flock — WAITING, never
// skipping: a skipped pass is exactly how a shared root overfills while
// every process believes itself under budget — then rebuilds its view from
// disk (authoritative rescan; local counters are only hints) and unlinks
// least-recently-touched unpinned entries until ALLOCATED usage is at or
// below the low watermark, but only when the rescan shows usage ABOVE high.
// The dirty flag re-runs the pass when publications landed meanwhile.
func (m *Manager) runCapacityPass(ctx context.Context) error {
	lock, err := os.OpenFile(filepath.Join(m.cfg.Root, evictLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		m.recordEvictErr(err)
		return err
	}
	defer lock.Close()
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch classifyFlockErr(err) {
		case flockAcquired:
			// fall out of the loop holding the lock
		case flockRetry:
			continue
		case flockFatal:
			// A real flock failure (EBADF, ENOLCK, ...) must surface, not
			// spin as if it were a busy lock.
			m.recordEvictErr(err)
			return fmt.Errorf("chunkcache: evict flock: %w", err)
		default: // busy
			select {
			case <-ctx.Done():
				return ctx.Err() // the next publication re-triggers
			case <-time.After(evictLockPoll):
			}
			continue
		}
		break
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	for {
		if err := m.Rescan(ctx); err != nil {
			m.recordEvictErr(err)
			return err
		}
		// Decide on the AUTHORITATIVE post-rescan allocated total (never on
		// the possibly-stale local counter): evict only above high, down to
		// low. Below high this pass is a no-op even though it ran.
		m.mu.Lock()
		usage := int64(0)
		for _, e := range m.index {
			usage += e.allocated
		}
		m.mu.Unlock()
		if usage > m.cfg.HighWatermark {
			if err := m.evictToLow(ctx); err != nil {
				return err
			}
		}
		m.mu.Lock()
		dirty := m.dirty
		m.dirty = false
		ready := m.ready
		m.mu.Unlock()
		if !dirty || !ready {
			return nil
		}
		// Publications landed during this pass: re-scan and re-decide.
	}
}

// evictToLow runs under the node evict lock (EXCLUSIVE, covering the
// protectedSet snapshot AND every delete) with a freshly rescanned index —
// the other half of the Pin atomicity protocol.
func (m *Manager) evictToLow(ctx context.Context) error {
	protected, pinnedCount, pinnedBytes, err := m.protectedSet()
	if err != nil {
		m.recordEvictErr(err)
		return err
	}
	type cand struct {
		digest    string
		size      int64
		allocated int64
		lastTouch time.Time
	}
	m.mu.Lock()
	cands := make([]cand, 0, len(m.index))
	usage := int64(0)
	for d, e := range m.index {
		usage += e.allocated
		if _, pinned := protected[d]; !pinned {
			// VALUE copy: touch() mutates e.lastTouch under m.mu, so a
			// *entry referenced after Unlock would race the sort.
			cands = append(cands, cand{digest: d, size: e.size, allocated: e.allocated, lastTouch: e.lastTouch})
		}
	}
	m.mu.Unlock()
	sort.Slice(cands, func(i, j int) bool { return cands[i].lastTouch.Before(cands[j].lastTouch) })

	var evicted, evictedBytes int64
	for _, c := range cands {
		if usage <= m.cfg.LowWatermark {
			break
		}
		if err := ctx.Err(); err != nil {
			// A cancelled pass is INCOMPLETE, not done (P1-B): falling out
			// of the loop would run the pinned-overage accounting and write
			// a status that dresses the un-evicted remainder up as pinned
			// soft-cap bytes. Return the cancel; the publication path
			// re-triggers convergence later.
			m.recordEvictErr(err)
			return err
		}
		if err := m.removePath(m.chunkPath(c.digest)); err != nil && !os.IsNotExist(err) {
			// P1-B: an undeletable unpinned chunk is an ERROR, not an
			// eviction that quietly finished — falling through would write
			// a success/overage status over accounting we could not enact.
			werr := fmt.Errorf("chunkcache: evict %s: %w", c.digest[:12], err)
			m.recordEvictErr(werr)
			return werr
		}
		m.mu.Lock()
		delete(m.index, c.digest)
		m.mu.Unlock()
		usage -= c.allocated
		m.usageAllocated.Add(-c.allocated)
		evicted++
		evictedBytes += c.allocated
	}
	if evicted > 0 {
		m.evictions.Add(evicted)
		m.evictedBytes.Add(evictedBytes)
		m.logf("evicted %d entries (%d allocated bytes) to low watermark; allocated now ~%d (logical %d), pinned %d entries/%d bytes",
			evicted, evictedBytes, usage, m.logicalTotal(), pinnedCount, pinnedBytes)
	}
	// Soft-cap semantics: pins may hold usage above high. The overage is
	// OBSERVED and reported (metric + one log line), never "solved" by
	// evicting pinned data or by refusing fetches: a live VM's working set
	// is required data, and operators size high accordingly (see the
	// contract's ENOSPC note).
	if overage := usage - m.cfg.HighWatermark; overage > 0 {
		m.pinnedOverage.Store(overage)
		m.logf("pinned overage: %d allocated bytes above high %d remain pinned (%d entries pinned) — soft cap, not an error", overage, m.cfg.HighWatermark, pinnedCount)
	} else {
		m.pinnedOverage.Store(0)
	}
	m.pinnedCount.Store(pinnedCount)
	m.pinnedBytes.Store(pinnedBytes)
	return m.writeStatus(usage, pinnedCount, pinnedBytes)
}

// logicalTotal takes m.mu itself: callers hold NO lock here (an unlocked
// map iteration would race concurrent Fetch/publish mutations).
func (m *Manager) logicalTotal() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var logical int64
	for _, e := range m.index {
		logical += e.size
	}
	return logical
}

func (m *Manager) recordEvictErr(err error) {
	msg := err.Error()
	m.lastEvictErr.Store(&msg)
}

// writeStatus drops a small observability file under Root (atomic rename).
func (m *Manager) writeStatus(allocated, pinnedCount, pinnedBytes int64) error {
	s := m.Status()
	s.AllocatedBytes = allocated
	s.PinnedEntries = pinnedCount
	s.PinnedBytes = pinnedBytes
	return writeJSONAtomic(filepath.Join(m.cfg.Root, statusName), s)
}

// Status snapshots counters and accounting. Watermark decisions use
// AllocatedBytes; LogicalBytes is reported for observability only.
func (m *Manager) Status() Status {
	m.mu.Lock()
	ready := m.ready
	var logical, allocated int64
	entries := int64(len(m.index))
	for _, e := range m.index {
		logical += e.size
		allocated += e.allocated
	}
	m.mu.Unlock()
	s := Status{
		Entries:            entries,
		LogicalBytes:       logical,
		AllocatedBytes:     allocated,
		HighWatermark:      m.cfg.HighWatermark,
		LowWatermark:       m.cfg.LowWatermark,
		IndexReady:         ready,
		Hits:               m.hits.Load(),
		Misses:             m.misses.Load(),
		HitBytes:           m.hitBytes.Load(),
		MissBytes:          m.missBytes.Load(),
		Evictions:          m.evictions.Load(),
		EvictedBytes:       m.evictedBytes.Load(),
		PinnedEntries:      m.pinnedCount.Load(),
		PinnedBytes:        m.pinnedBytes.Load(),
		PinnedOverageBytes: m.pinnedOverage.Load(),
		PoisonedEvicted:    m.poisoned.Load(),
		Waiters:            m.waiters.Load(),
		DownloadErrors:     m.downloadErrors.Load(),
	}
	if p := m.lastEvictErr.Load(); p != nil {
		s.LastEvictErr = *p
	}
	return s
}

// Test seams for Rescan's fail-closed read errors (P1-C): permissions on a
// shared root defeat chmod-based tests, and racing a real unlink is not
// deterministic, so the shard listing and the DirEntry stat go through
// overridable indirections. Production always uses the os defaults.
var (
	readShardEntries = os.ReadDir
	dirEntryInfo     = func(de os.DirEntry) (fs.FileInfo, error) { return de.Info() }
)

// Rescan rebuilds the byte accounting from the directory contents and
// sweeps crash leftovers: abandoned temp files (by age) and stale pins.
// Entries whose files vanished are dropped; files that appeared externally
// are adopted (their bytes were only ever published post-verification).
//
// Fail-closed contract (P1-C): a shard listing or file stat error must
// RETURN, never be skipped — a skipped shard would produce an undercounted
// "trusted" status that watermark decisions then act on. Only genuinely
// concurrent disappearance (fs.ErrNotExist) is tolerated.
func (m *Manager) Rescan(ctx context.Context) error {
	index := make(map[string]*entry)
	shards, err := os.ReadDir(m.cfg.Root)
	if err != nil {
		return err
	}
	for _, shard := range shards {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !shard.IsDir() || !isShardName(shard.Name()) {
			continue
		}
		files, err := readShardEntries(filepath.Join(m.cfg.Root, shard.Name()))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // shard vanished concurrently: benign
			}
			return fmt.Errorf("chunkcache: rescan shard %s: %w", shard.Name(), err)
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			path := filepath.Join(m.cfg.Root, shard.Name(), name)
			if strings.HasPrefix(name, tmpPrefix) {
				sweepIfStale(path, f)
				continue
			}
			if !checkpointchunks.ValidDigest(name) {
				continue
			}
			info, err := dirEntryInfo(f)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue // file vanished concurrently: benign
				}
				return fmt.Errorf("chunkcache: rescan stat %s: %w", name, err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			index[name] = &entry{
				size:      info.Size(),
				allocated: allocatedFrom(info), // from the SAME FileInfo — no error-swallowing second stat
				lastTouch: info.ModTime(),
			}
		}
	}
	if _, _, _, err := m.protectedSet(); err != nil { // also sweeps stale pins
		m.logf("pin sweep: %v", err)
	}
	m.mu.Lock()
	// Merge, do not replace: the scan's directory listing races concurrent
	// publishes (this run and other processes'). Disk-observed size and
	// allocation win; the fresher lastTouch wins; an entry absent from the
	// listing is only dropped after a confirming stat (it may have been
	// created after the listing was taken).
	merged := make(map[string]*entry, len(index)+len(m.index))
	for d, e := range m.index {
		merged[d] = e
	}
	for d, e := range index {
		if old, ok := merged[d]; ok && old.lastTouch.After(e.lastTouch) {
			e.lastTouch = old.lastTouch
		}
		merged[d] = e
	}
	for d := range merged {
		if _, seen := index[d]; seen {
			continue
		}
		if _, err := os.Stat(m.chunkPath(d)); os.IsNotExist(err) {
			delete(merged, d)
		}
	}
	m.index = merged
	var total int64
	for _, e := range merged {
		total += e.allocated
	}
	m.usageAllocated.Store(total)
	m.ready = true
	m.mu.Unlock()
	return nil
}

func sweepIfStale(path string, f os.DirEntry) {
	info, err := f.Info()
	if err != nil {
		return
	}
	// Temps are never visible content: removal by age is always safe.
	if time.Since(info.ModTime()) > staleTempAge {
		_ = os.Remove(path)
	}
}

func isShardName(name string) bool {
	if len(name) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := name[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// flockOutcome classifies a non-blocking flock result.
type flockOutcome int

const (
	flockAcquired flockOutcome = iota // err == nil: we hold the lock
	flockBusy                         // EWOULDBLOCK/EAGAIN: someone else holds it
	flockRetry                        // EINTR: retry immediately
	flockFatal                        // anything else: surface, never spin
)

// classifyFlockErr is the single classification shared by the digest-claim
// and evictor lock loops (a misclassified EBADF used to spin as "busy").
func classifyFlockErr(err error) flockOutcome {
	if err == nil {
		return flockAcquired
	}
	switch {
	case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN):
		return flockBusy
	case errors.Is(err, syscall.EINTR):
		return flockRetry
	default:
		return flockFatal
	}
}

func bytesMatchDigest(body []byte, digest string) bool {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) == digest
}

func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), tmpPrefix)
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
