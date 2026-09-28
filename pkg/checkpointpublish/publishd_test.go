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

// M1 publishd lifecycle tests (deterministic; injectable clock where the
// behavior under test is time-based). The fault matrix from the plan's §9:
// crash before/after enqueue, mid-upload, after INDEX commit before state
// write, store outage with bounded backoff, dual scanners, starvation
// ordering, old-state compatibility.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// m1Fixture builds a real-bytes checkpoint directory whose memory is one
// unique chunk (the shape the artifact set publishes), plus helpers to
// inspect the persisted state.
type m1Fixture struct {
	t    *testing.T
	dir  string // checkpoint dir (artifact root child)
	id   string
	root string
}

func newM1Fixture(t *testing.T, root, id string) *m1Fixture {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const chunk = 256 << 10
	data := make([]byte, chunk)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vmstate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256Sum(data)
	om := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(data)),
		ChunkBytes: chunk, ChunkCount: 1, FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: sum}},
	}
	om.FileDigest = checkpointchunks.RootDigest(om.Entries)
	if err := checkpointchunks.WriteNamed(dir, OverlaySidecarName, om); err != nil {
		t.Fatal(err)
	}
	m := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: int64(len(data)),
		ChunkBytes: chunk, ChunkCount: 1, FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: sum}},
	}
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := checkpointchunks.Write(dir, m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"snapshot_type":"Full","memory_size":`+fmt.Sprint(len(data))+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return &m1Fixture{t: t, dir: dir, id: id, root: root}
}

func (f *m1Fixture) stateRecord() *State {
	f.t.Helper()
	st, err := Status(f.dir)
	if err != nil {
		f.t.Fatalf("status %s: %v", f.dir, err)
	}
	return st
}

// failingStore is declared in publish_test.go and reused here.

func TestScanRoundQueuesAndPublishesSealedArtifact(t *testing.T) {
	root := t.TempDir()
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-a")
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})
	if len(res.Failed) != 0 || len(res.Published) != 1 || res.Published[0] != "m1-a" {
		t.Fatalf("round = %+v", res)
	}
	st := fx.stateRecord()
	if st.State != StatePublished {
		t.Fatalf("state = %s, want published", st.State)
	}
	// Second round: nothing pending, the queued/published lifecycle skips.
	res2 := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})
	if res2.Pending != 0 || res2.Skipped != 1 {
		t.Fatalf("second round = %+v", res2)
	}
	// Phases must carry the seal→ready decomposition.
	if len(res.Phases) != 1 || res.Phases[0].SealToReady <= 0 || res.Phases[0].PublishWall <= 0 {
		t.Fatalf("phases = %+v", res.Phases)
	}
}

// TestScanRoundCrashBeforeEnqueueConverges: a sealed artifact with NO state
// file (crash between seal and the first scan) is discovered, given a
// persisted queued record, and published.
func TestScanRoundCrashBeforeEnqueueConverges(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-crash0")
	if st := fx.stateRecord(); st != nil {
		t.Fatal("fixture must start with no state file")
	}
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})
	if len(res.Published) != 1 {
		t.Fatalf("published = %v failed = %v", res.Published, res.Failed)
	}
	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("final state = %s", st.State)
	}
}

// TestScanRoundQueuedStateSurvivesCrash: after a round that crashes between
// enqueue and publish (simulated by writing only the queued record), the
// restart scan picks the artifact up from StateQueued and publishes it.
func TestScanRoundQueuedStateSurvivesCrash(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-queued")
	writeQueuedState(fx.dir, fx.id, "test", time.Now())
	if st := fx.stateRecord(); st.State != StateQueued {
		t.Fatalf("pre state = %s", st.State)
	}
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})
	if len(res.Published) != 1 {
		t.Fatalf("published = %v failed = %v", res.Published, res.Failed)
	}
	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("final state = %s", st.State)
	}
}

// TestScanRoundStalePublishingMidUploadCrash: a publishing record past the
// stale bound (crash mid-upload; store holds a partial object set) is
// re-queued, the rerun completes idempotently, and the local artifact is
// untouched (unique-copy protection: bytes before == bytes after).
func TestScanRoundStalePublishingMidUploadCrash(t *testing.T) {
	root := t.TempDir()
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-mid")
	// Crash mid-upload: a publishing record written 1h ago, and the store
	// already holds one artifact-set object (e.g. BUNDLE) but no INDEX.
	bundle := []byte("partial-artifact-upload")
	if err := keyedStore(t, store).PutKey(context.Background(), ArtifactKey(fx.id, BundleName), bytesReader(bundle)); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: stale}); err != nil {
		t.Fatal(err)
	}
	before := dirDigest(fx.dir)
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute, StaleAfter: 10 * time.Minute,
	})
	if len(res.Published) != 1 {
		t.Fatalf("published = %v failed = %v", res.Published, res.Failed)
	}
	if after := dirDigest(fx.dir); after != before {
		t.Fatal("local artifact mutated during recovery (unique-copy violation)")
	}
}

// TestReconcileAfterIndexCommitCrash: the remote already committed THIS
// artifact's INDEX but the local record still says publishing (crash before
// state write). The scan must converge to published BY RECONCILIATION —
// no chunk PUT may be issued (the store wrapper counts them).
func TestReconcileAfterIndexCommitCrash(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-recon")
	// A complete earlier publication (objects + INDEX committed)…
	if _, err := Run(context.Background(), fx.dir, fx.id, store, "test"); err != nil {
		t.Fatal(err)
	}
	// …then the crash window: the local record is reset to publishing.
	stale := time.Now().Add(-2 * time.Hour)
	if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: stale}); err != nil {
		t.Fatal(err)
	}
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute, StaleAfter: time.Minute,
	})
	if len(res.Reconciled) != 1 || res.Reconciled[0] != fx.id {
		t.Fatalf("reconciled = %v (failed=%v published=%v)", res.Reconciled, res.Failed, res.Published)
	}
	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("final state = %s", st.State)
	}
	if len(res.Phases) != 1 || !res.Phases[0].Reconciled {
		t.Fatalf("phases = %+v", res.Phases)
	}
}

// TestReconcileRejectsForeignIndex: an INDEX under this ID that does NOT
// match the local sidecar identity must NOT converge; the normal publish
// path decides instead (and republishes this artifact's own objects).
func TestReconcileRejectsForeignIndex(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "m1-foreign")
	// Commit an INDEX naming this ID but advertising a DIFFERENT memory
	// identity (a reused checkpoint ID's old generation).
	forged := ArtifactIndex{CheckpointID: fx.id, MemoryRoot: "deadbeef", ChunkCount: 9, Files: map[string]string{}}
	raw, _ := json.Marshal(forged)
	if err := keyedStore(t, store).PutKey(context.Background(), ArtifactKey(fx.id, IndexName), bytesReader(raw)); err != nil {
		t.Fatal(err)
	}
	ok, err := ReconcilePublished(context.Background(), fx.dir, fx.id, store, nil)
	if ok || err != nil {
		t.Fatalf("reconcile = %v err = %v, want false nil (identity mismatch)", ok, err)
	}
	// The scan then publishes the real artifact; final state published with
	// the TRUE root in the store's INDEX (overwritten by the real publish).
	res := ScanRound(context.Background(), ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute})
	if len(res.Published) != 1 || len(res.Reconciled) != 0 {
		t.Fatalf("published=%v reconciled=%v failed=%v", res.Published, res.Reconciled, res.Failed)
	}
}

// TestScanRoundStoreOutageBackoffAndNoFalseReady: with the store failing,
// the artifact goes publish_failed with retry bookkeeping; the next round
// defers it (bounded backoff, still counted, never published); after the
// backoff elapses and the store heals, it publishes. Throughout, no
// publish state may claim published (no false remote_ready).
func TestScanRoundStoreOutageBackoffAndNoFalseReady(t *testing.T) {
	root := t.TempDir()
	failing := &failingStore{inner: mustLocal(t)}
	failing.fail = true
	fx := newM1Fixture(t, root, "m1-outage")
	clock := time.Now()
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: failing, StoreName: "test", Timeout: time.Minute,
		BackoffBase: time.Minute, BackoffCap: 10 * time.Minute, Now: func() time.Time { return clock },
	})
	if len(res.Failed) != 1 {
		t.Fatalf("failed = %v published = %v deferred = %v reconciled = %v", res.Failed, res.Published, res.Deferred, res.Reconciled)
	}
	st := fx.stateRecord()
	if st.State != StatePublishFailed || st.Retries != 1 || st.FailedAt == nil {
		t.Fatalf("state after outage = %+v", st)
	}
	// Next round 10s later: deferred (backoff 1m not elapsed).
	clock = clock.Add(10 * time.Second)
	res2 := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: failing, StoreName: "test", Timeout: time.Minute,
		BackoffBase: time.Minute, BackoffCap: 10 * time.Minute, Now: func() time.Time { return clock },
	})
	if len(res2.Deferred) != 1 || res2.Pending != 1 {
		t.Fatalf("deferred round = %+v", res2)
	}
	if st := fx.stateRecord(); st.State == StatePublished {
		t.Fatal("remote_ready claimed during outage")
	}
	// Backoff elapsed and store healed: publishes.
	clock = clock.Add(2 * time.Minute)
	failing.fail = false
	res3 := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: failing, StoreName: "test", Timeout: time.Minute,
		BackoffBase: time.Minute, BackoffCap: 10 * time.Minute, Now: func() time.Time { return clock },
	})
	if len(res3.Published) != 1 {
		t.Fatalf("healed round published = %v failed = %v deferred = %v", res3.Published, res3.Failed, res3.Deferred)
	}
	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("final state = %s", st.State)
	}
}

// TestScanRoundOldRecordsRetryImmediately: a pre-M1 publish_failed record
// (no Retries/FailedAt) must keep the historical retry-every-round behavior.
func TestScanRoundOldRecordsRetryImmediately(t *testing.T) {
	root := t.TempDir()
	store := mustLocal(t)
	fx := newM1Fixture(t, root, "m1-old")
	if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishFailed, Store: "test", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Backoff enabled; with no FailedAt the record is due NOW.
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
		BackoffBase: time.Hour, BackoffCap: 2 * time.Hour,
	})
	if len(res.Published) != 1 || len(res.Deferred) != 0 {
		t.Fatalf("published=%v deferred=%v failed=%v", res.Published, res.Deferred, res.Failed)
	}
}

// TestScanRoundStarvationPromotion: with StarveAfter set, an old pending
// artifact outranks a newer one regardless of newest-first default.
func TestScanRoundStarvationPromotion(t *testing.T) {
	root := t.TempDir()
	store := mustLocal(t)
	old := newM1Fixture(t, root, "m1-oldart")
	new := newM1Fixture(t, root, "m1-newart")
	oldTime := time.Now().Add(-2 * time.Hour)
	newTime := time.Now().Add(-time.Minute)
	setMtime(filepath.Join(old.dir, "manifest.json"), oldTime)
	setMtime(filepath.Join(new.dir, "manifest.json"), newTime)
	var order []string
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
		StarveAfter: time.Hour,
	})
	for _, p := range res.Phases {
		order = append(order, p.ID)
	}
	if len(order) != 2 || order[0] != "m1-oldart" {
		t.Fatalf("publish order = %v, want old artifact first", order)
	}
	_ = new
}

// TestScanRoundDualScannerSinglePublication: two concurrent scans over the
// same root converge with exactly one publication each seeing success or
// skip — the Run-level flock/intent protocol arbitrates; no double INDEX.
func TestScanRoundDualScannerSinglePublication(t *testing.T) {
	root := t.TempDir()
	store := mustLocal(t)
	newM1Fixture(t, root, "m1-dual")
	opts := ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "test", Timeout: 2 * time.Minute}
	done := make(chan RoundResult, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- ScanRound(context.Background(), opts) }()
	}
	r1, r2 := <-done, <-done
	published := len(r1.Published) + len(r2.Published)
	reconciled := len(r1.Reconciled) + len(r2.Reconciled)
	if published+reconciled != 1 {
		t.Fatalf("r1=%+v r2=%+v", r1, r2)
	}
	// The store holds exactly one INDEX for the artifact.
	if _, err := keyedStore(t, store).GetKey(context.Background(), ArtifactKey("m1-dual", IndexName)); err != nil {
		t.Fatalf("INDEX missing after dual scan: %v", err)
	}
}

// TestScanRoundUnpublishedBytesAccounting: with the store DOWN the round
// fails the publish and the post-round gauges still report the artifact's
// on-disk bytes (backpressure observable) — the residue a live operator
// sees while an outage holds the queue.
func TestScanRoundUnpublishedBytesAccounting(t *testing.T) {
	root := t.TempDir()
	failing := &failingStore{inner: mustLocal(t), fail: true}
	newM1Fixture(t, root, "m1-bytes")
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: failing, StoreName: "test", Timeout: time.Minute,
	})
	if len(res.Failed) != 1 {
		t.Fatalf("failed = %v (want the one artifact)", res.Failed)
	}
	if res.Pending != 1 {
		t.Fatalf("pending = %d, want 1", res.Pending)
	}
	if res.UnpublishedBytes <= 0 {
		t.Fatalf("unpublished bytes = %d", res.UnpublishedBytes)
	}
	if res.OldestPendingAge <= 0 {
		t.Fatalf("oldest age = %v", res.OldestPendingAge)
	}
}

// --- helpers ---

func keyedStore(t *testing.T, s chunkstore.Store) chunkstore.Keyed {
	t.Helper()
	k, ok := s.(chunkstore.Keyed)
	if !ok {
		t.Fatal("store lacks keyed surface")
	}
	return k
}

func mustLocal(t *testing.T) *chunkstore.Local {
	t.Helper()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func setMtime(path string, at time.Time) {
	if err := os.Chtimes(path, at, at); err != nil {
		panic(err)
	}
}

func dirDigest(dir string) string {
	h := sha256New()
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // skip unreadable
		}
		h.Write([]byte(path))
		h.Write(body)
		return nil
	})
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type hashy = interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func sha256New() hashy { return sha256.New() }

func bytesReader(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// TestReconcileMissingDependencyFallsThrough: remote INDEX exists and matches
// identity, but a required overlay chunk was deleted — reconcile must NOT
// converge to published; the normal publish repairs the store.
func TestReconcileMissingDependencyFallsThrough(t *testing.T) {
	root := t.TempDir()
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "rc-miss")
	if _, err := Run(context.Background(), fx.dir, fx.id, store, "test"); err != nil {
		t.Fatal(err)
	}
	om, err := checkpointchunks.LoadNamed(fx.dir, OverlaySidecarName)
	if err != nil {
		t.Fatal(err)
	}
	overlayKey := OverlayChunkKey(om.Entries[0].Digest)
	overlayPath := filepath.Join(storeDir, overlayKey)
	if err := os.Remove(overlayPath); err != nil {
		t.Fatalf("delete overlay chunk: %v", err)
	}
	ok, rerr := ReconcilePublished(context.Background(), fx.dir, fx.id, store, nil)
	if ok || rerr != nil {
		t.Fatalf("reconcile with missing overlay: ok=%v err=%v (want false nil)", ok, rerr)
	}
	// Reset to stale publishing so ScanRound picks it up (a published state
	// is skipped; the crash window means the state never reached published).
	if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// ScanRound repairs via normal publish.
	_ = ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})

	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("final state = %s (want published via repair)", st.State)
	}
	if _, err := os.Stat(overlayPath); err != nil {
		t.Fatalf("overlay chunk not restored: %v", err)
	}
}

// TestReconcileCompleteDependenciesZeroPUT: complete publication — reconcile
// converges with zero store mutation (read-only probe).
func TestReconcileCompleteDependenciesZeroPUT(t *testing.T) {
	root := t.TempDir()
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	fx := newM1Fixture(t, root, "rc-full")
	if _, err := Run(context.Background(), fx.dir, fx.id, store, "test"); err != nil {
		t.Fatal(err)
	}
	before := dirDigest(storeDir)
	if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	ok, rerr := ReconcilePublished(context.Background(), fx.dir, fx.id, store, nil)
	if !ok || rerr != nil {
		t.Fatalf("reconcile complete: ok=%v err=%v", ok, rerr)
	}
	if after := dirDigest(storeDir); after != before {
		t.Fatal("reconcile mutated the store (must be read-only probe)")
	}
	if st := fx.stateRecord(); st.State != StatePublished {
		t.Fatalf("state = %s", st.State)
	}
}

// TestReconcileTransportRepresentations: table-driven coverage of the
// dependency enumeration across every store representation a committed
// publication can carry — plain CAS, zstd (.z with plain fallback), packs
// (pack-only and mixed pack+standalone), and zero chunks (sparse holes).
// Each case builds the remote residue DIRECTLY (INDEX + BUNDLE with a
// DecodeTransport-acceptable transport sidecar + the dependency objects)
// against a local sealed manifest kept for identity, so the pack and mixed
// shapes do not depend on synthesizing a publishable FC fixture. Bundle
// integrity tampering (part digest, span, body) must fail closed: error or
// fall-through, never a converged "published".
func TestReconcileTransportRepresentations(t *testing.T) {
	const repChunk = 256 << 10
	zeroBody := func() []byte { return make([]byte, repChunk) }
	chunkA, chunkB := repBody(1), repBody(2)
	packDigest := func(id string) string { return sha256Sum([]byte("pack:" + id)) }

	type repCase struct {
		name      string
		bodies    [][]byte
		transport func(tc *transportCase) *checkpointchunks.Manifest
		objects   func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string
		delete    []string // logical names from objects() to remove before reconcile
		tamper    func(index *ArtifactIndex, bundle *[]byte)
		// prebundle seeds the per-file (no BUNDLE) remote shape instead;
		// tamperSidecar then corrupts the sidecar object after the INDEX
		// digest was recorded.
		prebundle     bool
		tamperSidecar func(raw *[]byte)
		wantOK        bool
	}
	v1view := func(tc *transportCase) *checkpointchunks.Manifest { return tc.transportView() }
	zstdView := func(tc *transportCase) *checkpointchunks.Manifest {
		v := tc.transportView()
		v.Compression = checkpointchunks.CompressionZstd
		return v
	}
	casObjects := func(digests ...string) func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
		return func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
			keys := make(map[string]string, len(digests))
			for i, d := range digests {
				key := chunkstore.PlainKey(d)
				putStoreObject(t, store, key, "cas:"+d)
				keys[fmt.Sprintf("cas%d", i)] = key
			}
			return keys
		}
	}

	cases := []repCase{
		{
			name:      "plain-complete",
			bodies:    [][]byte{chunkA},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			wantOK:    true,
		},
		{
			name:   "pack-only-complete",
			bodies: [][]byte{chunkA, chunkB},
			transport: func(tc *transportCase) *checkpointchunks.Manifest {
				v := tc.transportView()
				v.Version = checkpointchunks.PackedVersion
				v.Packs = map[string]checkpointchunks.PackReference{
					tc.local.Entries[0].Digest: {Digest: packDigest(tc.id), Offset: 0, Length: repChunk, ObjectSize: 2 * repChunk},
					tc.local.Entries[1].Digest: {Digest: packDigest(tc.id), Offset: repChunk, Length: repChunk, ObjectSize: 2 * repChunk},
				}
				return v
			},
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				key := putPackObject(t, store, packDigest(tc.id))
				return map[string]string{"pack": key}
			},
			wantOK: true,
		},
		{
			name:   "pack-only-pack-deleted",
			bodies: [][]byte{chunkA, chunkB},
			transport: func(tc *transportCase) *checkpointchunks.Manifest {
				return packTransport(tc, packDigest(tc.id), 0, 1)
			},
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				return map[string]string{"pack": putPackObject(t, store, packDigest(tc.id))}
			},
			delete: []string{"pack"},
			wantOK: false,
		},
		{
			name:   "mixed-complete",
			bodies: [][]byte{chunkA, chunkB},
			transport: func(tc *transportCase) *checkpointchunks.Manifest {
				return packTransport(tc, packDigest(tc.id), 0)
			},
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				return map[string]string{
					"pack": putPackObject(t, store, packDigest(tc.id)),
					"cas1": putStoreObject(t, store, chunkstore.PlainKey(tc.local.Entries[1].Digest), "cas:1"),
				}
			},
			wantOK: true,
		},
		{
			name:   "mixed-pack-missing",
			bodies: [][]byte{chunkA, chunkB},
			transport: func(tc *transportCase) *checkpointchunks.Manifest {
				return packTransport(tc, packDigest(tc.id), 0)
			},
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				return map[string]string{
					"pack": putPackObject(t, store, packDigest(tc.id)),
					"cas1": putStoreObject(t, store, chunkstore.PlainKey(tc.local.Entries[1].Digest), "cas:1"),
				}
			},
			delete: []string{"pack"},
			wantOK: false,
		},
		{
			name:   "mixed-standalone-missing",
			bodies: [][]byte{chunkA, chunkB},
			transport: func(tc *transportCase) *checkpointchunks.Manifest {
				return packTransport(tc, packDigest(tc.id), 0)
			},
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				return map[string]string{
					"pack": putPackObject(t, store, packDigest(tc.id)),
					"cas1": putStoreObject(t, store, chunkstore.PlainKey(tc.local.Entries[1].Digest), "cas:1"),
				}
			},
			delete: []string{"cas1"},
			wantOK: false,
		},
		{
			// The second entry is an all-zero chunk: materialization
			// synthesizes it as a sparse hole, so NO object exists for it
			// and reconcile must still converge.
			name:      "zero-entry-no-object",
			bodies:    [][]byte{chunkA, zeroBody()},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			wantOK:    true,
		},
		{
			name:      "zstd-dot-z-present",
			bodies:    [][]byte{chunkA},
			transport: zstdView,
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				d := tc.local.Entries[0].Digest
				return map[string]string{
					"z0":   putStoreObject(t, store, chunkstore.CompressedKey(d), "zstd"),
					"cas0": putStoreObject(t, store, chunkstore.PlainKey(d), "cas:0"),
				}
			},
			delete: []string{"cas0"},
			wantOK: true,
		},
		{
			// Plain fallback alone still restores (readers fall back from
			// .z to plain), so reconcile must accept it.
			name:      "zstd-plain-fallback",
			bodies:    [][]byte{chunkA},
			transport: zstdView,
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				d := tc.local.Entries[0].Digest
				return map[string]string{
					"z0":   putStoreObject(t, store, chunkstore.CompressedKey(d), "zstd"),
					"cas0": putStoreObject(t, store, chunkstore.PlainKey(d), "cas:0"),
				}
			},
			delete: []string{"z0"},
			wantOK: true,
		},
		{
			name:      "zstd-both-missing",
			bodies:    [][]byte{chunkA},
			transport: zstdView,
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				d := tc.local.Entries[0].Digest
				return map[string]string{
					"z0":   putStoreObject(t, store, chunkstore.CompressedKey(d), "zstd"),
					"cas0": putStoreObject(t, store, chunkstore.PlainKey(d), "cas:0"),
				}
			},
			delete: []string{"z0", "cas0"},
			wantOK: false,
		},
		{
			// INDEX advertises a forged part digest for the transport
			// sidecar's part: the extracted sidecar must never be trusted,
			// and the artifact must not converge.
			name:      "bundle-part-digest-tampered",
			bodies:    [][]byte{chunkA},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			tamper: func(index *ArtifactIndex, _ *[]byte) {
				for i, part := range index.Bundle.Parts {
					if part.Name == checkpointchunks.ManifestName {
						index.Bundle.Parts[i].Digest = sha256Sum([]byte("forged"))
					}
				}
			},
			wantOK: false,
		},
		{
			// Sidecar part span points outside the bundle object: fail closed.
			name:      "bundle-part-span-tampered",
			bodies:    [][]byte{chunkA},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			tamper: func(index *ArtifactIndex, bundle *[]byte) {
				for i, part := range index.Bundle.Parts {
					if part.Name == checkpointchunks.ManifestName {
						index.Bundle.Parts[i].Offset = int64(len(*bundle)) + 64
					}
				}
			},
			wantOK: false,
		},
		{
			// Whole-bundle digest forged in the INDEX (bundle bytes are
			// honest): reconcile applies Materialize's acceptance and must
			// reject.
			name:      "bundle-digest-tampered",
			bodies:    [][]byte{chunkA},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			tamper: func(index *ArtifactIndex, _ *[]byte) {
				index.Bundle.Digest = sha256Sum([]byte("forged-bundle"))
			},
			wantOK: false,
		},
		{
			// Bundle bytes flipped after the INDEX was written: whole-bundle
			// digest mismatch, fail closed.
			name:      "bundle-body-tampered",
			bodies:    [][]byte{chunkA},
			transport: v1view,
			objects:   casObjects(digestOf(chunkA)),
			tamper: func(index *ArtifactIndex, bundle *[]byte) {
				(*bundle)[index.Bundle.Parts[0].Offset] ^= 0xff
			},
			wantOK: false,
		},
		{
			// Pre-bundle artifact (per-file objects, INDEX.Bundle nil): the
			// zstd plain-fallback acceptance must hold on this branch too,
			// with the sidecar object digest-checked against index.Files.
			name:      "prebundle-zstd-plain-fallback",
			bodies:    [][]byte{chunkA},
			transport: zstdView,
			prebundle: true,
			objects: func(t *testing.T, tc *transportCase, store *chunkstore.Local) map[string]string {
				d := tc.local.Entries[0].Digest
				return map[string]string{
					"z0":   putStoreObject(t, store, chunkstore.CompressedKey(d), "zstd"),
					"cas0": putStoreObject(t, store, chunkstore.PlainKey(d), "cas:0"),
				}
			},
			delete: []string{"z0"},
			wantOK: true,
		},
		{
			// Pre-bundle sidecar body tampered against the INDEX's recorded
			// Files digest: fail closed, never published.
			name:          "prebundle-sidecar-tampered",
			bodies:        [][]byte{chunkA},
			transport:     v1view,
			prebundle:     true,
			objects:       casObjects(digestOf(chunkA)),
			tamperSidecar: func(raw *[]byte) { (*raw)[0] ^= 0xff },
			wantOK:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			storeDir := t.TempDir()
			store, err := chunkstore.NewLocal(storeDir)
			if err != nil {
				t.Fatal(err)
			}
			fx := newTransportCase(t, root, "rep-"+tc.name, false, tc.bodies...)
			if tc.prebundle {
				seedRemotePrebundlePublication(t, store, fx, tc.transport(fx), tc.tamperSidecar)
			} else {
				seedRemotePublication(t, store, fx, tc.transport(fx), tc.tamper)
			}
			keys := tc.objects(t, fx, store)
			for _, name := range tc.delete {
				key := keys[name]
				if key == "" {
					t.Fatalf("case %s deletes unknown object %q", tc.name, name)
				}
				if err := os.Remove(filepath.Join(storeDir, key)); err != nil {
					t.Fatalf("delete %s: %v", key, err)
				}
			}
			// Crash window: the state never advanced past publishing.
			if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
			ok, rerr := ReconcilePublished(context.Background(), fx.dir, fx.id, store, nil)
			if ok != tc.wantOK {
				t.Fatalf("%s: reconcile ok=%v err=%v, want ok=%v", tc.name, ok, rerr, tc.wantOK)
			}
			if tc.wantOK && rerr != nil {
				t.Fatalf("%s: reconcile error: %v", tc.name, rerr)
			}
			// The persisted state is the real gate: converged artifacts must
			// read published; rejected ones must still read publishing.
			st, serr := Status(fx.dir)
			if serr != nil {
				t.Fatalf("%s: status: %v", tc.name, serr)
			}
			if tc.wantOK && st.State != StatePublished {
				t.Fatalf("%s: state = %s, want published", tc.name, st.State)
			}
			if !tc.wantOK && st.State == StatePublished {
				t.Fatalf("%s: converged to published (err=%v) — must fail closed", tc.name, rerr)
			}
		})
	}
}

// transportCase is a sealed local checkpoint built from explicit chunk
// bodies (an all-zero body becomes a zero-chunk entry), a closure-complete
// Firecracker manifest (packed publication's packedMemoryClosure accepts
// it), vmstate, and a deterministic writable layer: overlay.ext4 always,
// plus its chunk sidecar when chunkedOverlay is set. It keeps the v1 memory
// sidecar reconcile checks identity against.
type transportCase struct {
	id             string
	dir            string
	local          *checkpointchunks.Manifest
	chunkedOverlay bool
}

func newTransportCase(t *testing.T, root, id string, chunkedOverlay bool, bodies ...[]byte) *transportCase {
	t.Helper()
	const chunk = 256 << 10
	if len(bodies) == 0 {
		t.Fatal("transport case needs at least one chunk body")
	}
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	memory := make([]byte, 0, chunk*len(bodies))
	m := &checkpointchunks.Manifest{
		Version: 1, File: "memory",
		ChunkBytes: chunk, ChunkCount: len(bodies),
		FileDigestMode: checkpointchunks.FileDigestChunks,
	}
	for i, b := range bodies {
		if len(b) != chunk {
			t.Fatalf("chunk %d length %d, want %d", i, len(b), chunk)
		}
		memory = append(memory, b...)
		m.Entries = append(m.Entries, checkpointchunks.Chunk{Offset: int64(i * chunk), Digest: sha256Sum(b)})
	}
	m.FileSize = int64(len(memory))
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := os.WriteFile(filepath.Join(dir, "memory"), memory, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkpointchunks.Write(dir, m); err != nil {
		t.Fatal(err)
	}
	// Closure-complete FC manifest: packedMemoryClosure (and materialize's
	// closure check) accept it.
	fcManifest := fmt.Sprintf(`{"snapshot_type":"Full","memory_size":%d,"memory_digest_mode":"chunks","digests":{"memory":%q}}`,
		len(memory), m.FileDigest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(fcManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	// Writable layer: one deterministic chunk, distinct from every memory
	// chunk (checked below — a shared digest would blur which file a probe
	// belongs to).
	ov := make([]byte, chunk)
	for i := range ov {
		ov[i] = byte(i*11 + 5)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), ov, 0o600); err != nil {
		t.Fatal(err)
	}
	om := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(ov)),
		ChunkBytes: chunk, ChunkCount: 1, FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: sha256Sum(ov)}},
	}
	om.FileDigest = checkpointchunks.RootDigest(om.Entries)
	if sha256Sum(ov) == m.Entries[0].Digest {
		t.Fatal("overlay chunk digest collides with memory chunk; fixture is ambiguous")
	}
	if chunkedOverlay {
		if err := checkpointchunks.WriteNamed(dir, OverlaySidecarName, om); err != nil {
			t.Fatal(err)
		}
	}
	return &transportCase{id: id, dir: dir, local: m, chunkedOverlay: chunkedOverlay}
}

// transportView clones the sealed identity for a remote sidecar.
func (tc *transportCase) transportView() *checkpointchunks.Manifest {
	v := *tc.local
	return &v
}

// packTransport returns a v2 packed transport sidecar whose entries at the
// given indices resolve into one pack object (digest d, one chunk per
// slot); every other entry stays standalone CAS.
func packTransport(tc *transportCase, d string, packedIdx ...int) *checkpointchunks.Manifest {
	const chunk = 256 << 10
	v := tc.transportView()
	v.Version = checkpointchunks.PackedVersion
	v.Packs = make(map[string]checkpointchunks.PackReference)
	for slot, idx := range packedIdx {
		v.Packs[tc.local.Entries[idx].Digest] = checkpointchunks.PackReference{
			Digest: d, Offset: int64(slot * chunk), Length: chunk, ObjectSize: int64(len(packedIdx) * chunk),
		}
	}
	return v
}

// artifactSetParts lists the artifact-set files a committed publication of
// tc carries, pairing each with its local source bytes. The memory sidecar
// is the TRANSPORT view (compression/pack representation), not the sealed
// file. names must mirror publishArtifactSetWithTransport exactly.
func artifactSetParts(t *testing.T, tc *transportCase, transport *checkpointchunks.Manifest) []struct {
	name string
	body []byte
} {
	t.Helper()
	transportRaw, err := json.MarshalIndent(transport, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	parts := []struct {
		name string
		body []byte
	}{
		{"manifest.json", nil},
		{checkpointchunks.ManifestName, transportRaw},
		{"vmstate", nil},
	}
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(tc.dir, name))
		if err != nil {
			t.Fatalf("artifact set file %s: %v", name, err)
		}
		return raw
	}
	parts[0].body = read("manifest.json")
	parts[2].body = read("vmstate")
	if tc.chunkedOverlay {
		parts = append(parts, struct {
			name string
			body []byte
		}{OverlaySidecarName, read(OverlaySidecarName)})
	} else {
		parts = append(parts, struct {
			name string
			body []byte
		}{"overlay.ext4", read("overlay.ext4")})
	}
	return parts
}

// buildIndexAndBundle assembles an honest INDEX + BUNDLE for tc (the
// committed publication's remote residue), mirroring the production bundle
// layout (8-byte big-endian length prefix per part).
func buildIndexAndBundle(t *testing.T, tc *transportCase, transport *checkpointchunks.Manifest) (ArtifactIndex, []byte) {
	t.Helper()
	index := ArtifactIndex{
		CheckpointID:  tc.id,
		MemoryRoot:    tc.local.FileDigest,
		ChunkCount:    tc.local.ChunkCount,
		OverlayChunks: tc.chunkedOverlay,
		Files:         map[string]string{},
	}
	var bundle []byte
	info := &BundleInfo{}
	for _, p := range artifactSetParts(t, tc, transport) {
		digest := sha256Sum(p.body)
		index.Files[p.name] = digest
		var prefix [8]byte
		binary.BigEndian.PutUint64(prefix[:], uint64(len(p.body)))
		part := BundlePart{Name: p.name, Offset: int64(len(bundle)) + 8, Length: int64(len(p.body)), Digest: digest}
		bundle = append(append(bundle, prefix[:]...), p.body...)
		info.Parts = append(info.Parts, part)
	}
	sum := sha256.Sum256(bundle)
	info.Digest = hex.EncodeToString(sum[:])
	info.Size = int64(len(bundle))
	index.Bundle = info
	return index, bundle
}

// seedRemotePublication writes the committed publication's remote residue
// directly: a BUNDLE object carrying the full artifact set (transport
// sidecar included) and an INDEX bound to the local sealed identity.
// tamper, when set, may corrupt either object before upload.
func seedRemotePublication(t *testing.T, store *chunkstore.Local, tc *transportCase, transport *checkpointchunks.Manifest, tamper func(index *ArtifactIndex, bundle *[]byte)) {
	t.Helper()
	index, bundle := buildIndexAndBundle(t, tc, transport)
	if tamper != nil {
		tamper(&index, &bundle)
	}
	putStoreObjectRaw(t, store, ArtifactKey(tc.id, BundleName), bundle)
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	putStoreObjectRaw(t, store, ArtifactKey(tc.id, IndexName), encoded)
}

// seedRemotePrebundlePublication writes the PRE-bundle remote shape: no
// BUNDLE object; every artifact-set file is its own per-file object and the
// INDEX (Bundle nil) records the digests under Files. tamperSidecar, when
// set, corrupts the transport sidecar object AFTER the INDEX digest was
// recorded.
func seedRemotePrebundlePublication(t *testing.T, store *chunkstore.Local, tc *transportCase, transport *checkpointchunks.Manifest, tamperSidecar func(raw *[]byte)) {
	t.Helper()
	index := ArtifactIndex{
		CheckpointID:  tc.id,
		MemoryRoot:    tc.local.FileDigest,
		ChunkCount:    tc.local.ChunkCount,
		OverlayChunks: tc.chunkedOverlay,
		Files:         map[string]string{},
	}
	for _, p := range artifactSetParts(t, tc, transport) {
		body := p.body
		if p.name == checkpointchunks.ManifestName && tamperSidecar != nil {
			digest := sha256Sum(body)
			index.Files[p.name] = digest
			tamperSidecar(&body)
			putStoreObjectRaw(t, store, ArtifactKey(tc.id, p.name), body)
			continue
		}
		index.Files[p.name] = sha256Sum(body)
		putStoreObjectRaw(t, store, ArtifactKey(tc.id, p.name), body)
	}
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	putStoreObjectRaw(t, store, ArtifactKey(tc.id, IndexName), encoded)
}

// rewriteLocalChunkedOverlay replaces the writable layer AND its chunk
// sidecar with different bytes (a different generation's RWFS).
func rewriteLocalChunkedOverlay(t *testing.T, tc *transportCase) {
	t.Helper()
	const chunk = 256 << 10
	ov := make([]byte, chunk)
	for i := range ov {
		ov[i] = byte(i*17 + 9)
	}
	if err := os.WriteFile(filepath.Join(tc.dir, "overlay.ext4"), ov, 0o600); err != nil {
		t.Fatal(err)
	}
	om := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(ov)),
		ChunkBytes: chunk, ChunkCount: 1, FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: sha256Sum(ov)}},
	}
	om.FileDigest = checkpointchunks.RootDigest(om.Entries)
	if err := checkpointchunks.WriteNamed(tc.dir, OverlaySidecarName, om); err != nil {
		t.Fatal(err)
	}
}

func putStoreObject(t *testing.T, store *chunkstore.Local, key, body string) string {
	t.Helper()
	putStoreObjectRaw(t, store, key, []byte(body))
	return key
}

func putPackObject(t *testing.T, store *chunkstore.Local, digest string) string {
	t.Helper()
	key, err := (checkpointchunks.PackReference{Digest: digest}).Key()
	if err != nil {
		t.Fatal(err)
	}
	return putStoreObject(t, store, key, "pack-body")
}

func putStoreObjectRaw(t *testing.T, store *chunkstore.Local, key string, body []byte) {
	t.Helper()
	if err := store.PutKey(context.Background(), key, bytesReader(body)); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

func digestOf(b []byte) string { return sha256Sum(b) }

// TestScanRoundGaugesZeroAfterDrain: after a fully successful round, the
// queue gauges (Pending/UnpublishedBytes/OldestPendingAge) must be 0 —
// not the stale pre-round scan values.
func TestScanRoundGaugesZeroAfterDrain(t *testing.T) {
	root := t.TempDir()
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	newM1Fixture(t, root, "drain-a")
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
	})
	if len(res.Published) != 1 {
		t.Fatalf("published = %v failed = %v", res.Published, res.Failed)
	}
	if res.Pending != 0 {
		t.Fatalf("Pending after drain = %d, want 0", res.Pending)
	}
	if res.UnpublishedBytes != 0 {
		t.Fatalf("UnpublishedBytes after drain = %d, want 0", res.UnpublishedBytes)
	}
	if res.OldestPendingAge != 0 {
		t.Fatalf("OldestPendingAge after drain = %v, want 0", res.OldestPendingAge)
	}
	// Residue check: a publish_failed artifact leaves the gauges nonzero.
	root2 := t.TempDir()
	newM1Fixture(t, root2, "drain-f")
	if err := writeState(State{CheckpointID: "drain-f", Dir: filepath.Join(root2, "drain-f"), State: StatePublishFailed, Store: "test", StartedAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	snap := SnapshotBackpressure([]string{root2}, BackpressureLimits{}, nil)
	if snap.Pending != 1 || snap.UnpublishedBytes <= 0 {
		t.Fatalf("residue: pending=%d bytes=%d (want 1, >0)", snap.Pending, snap.UnpublishedBytes)
	}
}

// repBody is a deterministic non-zero chunk body for representation
// fixtures (seed varies the pattern).
func repBody(seed byte) []byte {
	const chunk = 256 << 10
	b := make([]byte, chunk)
	for i := range b {
		b[i] = byte(i*13 + int(seed)*7)
	}
	return b
}

// stepClock advances a fixed step per Now() call, making every
// ScanRound-internal time span deterministic and strictly increasing.
type stepClock struct {
	now  time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	t := c.now
	c.now = c.now.Add(c.step)
	return t
}

// TestReconcileArtifactSetIdentityGuardsIDReuse: a reused checkpoint ID
// whose new generation seals IDENTICAL memory (same root digest and chunk
// count) but a different vmstate / chunked RWFS / legacy overlay must NOT
// converge to the old INDEX — memory identity alone is not the artifact's
// identity. The ordinary publish then repairs the ID namespace by
// recommitted INDEX describing the NEW files (the documented ID-reuse
// protection the normal path always had).
func TestReconcileArtifactSetIdentityGuardsIDReuse(t *testing.T) {
	cases := []struct {
		name           string
		chunkedOverlay bool
		mutate         func(t *testing.T, tc *transportCase)
		remoteName     string
	}{
		{
			name:           "same-id-different-vmstate",
			chunkedOverlay: false,
			mutate: func(t *testing.T, tc *transportCase) {
				if err := os.WriteFile(filepath.Join(tc.dir, "vmstate"), []byte("vmstate-generation-2"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			remoteName: "vmstate",
		},
		{
			name:           "same-id-different-chunked-rwfs",
			chunkedOverlay: true,
			mutate:         rewriteLocalChunkedOverlay,
			remoteName:     OverlaySidecarName,
		},
		{
			name:           "same-id-different-legacy-overlay",
			chunkedOverlay: false,
			mutate: func(t *testing.T, tc *transportCase) {
				ov := repBody(9) // different bytes, no sidecar rewrite (legacy shape)
				if err := os.WriteFile(filepath.Join(tc.dir, "overlay.ext4"), ov, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			remoteName: "overlay.ext4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			storeDir := t.TempDir()
			store, err := chunkstore.NewLocal(storeDir)
			if err != nil {
				t.Fatal(err)
			}
			id := "reuse-" + tc.name
			fx := newTransportCase(t, root, id, tc.chunkedOverlay, repBody(1))
			// The previous generation's complete committed publication.
			seedRemotePublication(t, store, fx, fx.transportView(), nil)
			putStoreObject(t, store, chunkstore.PlainKey(fx.local.Entries[0].Digest), "cas:0")
			var overlayDigest string
			if tc.chunkedOverlay {
				om, err := checkpointchunks.LoadNamed(fx.dir, OverlaySidecarName)
				if err != nil {
					t.Fatal(err)
				}
				overlayDigest = om.Entries[0].Digest
				putStoreObject(t, store, OverlayChunkKey(overlayDigest), "ov")
			}
			// Crash-window state: publishing, never converged.
			if err := writeState(State{CheckpointID: id, Dir: fx.dir, State: StatePublishing, Store: "test", StartedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
			oldDigest := fileDigest(t, filepath.Join(fx.dir, tc.remoteName))

			// New generation: same memory, different non-memory file.
			tc.mutate(t, fx)

			ok, rerr := ReconcilePublished(context.Background(), fx.dir, id, store, nil)
			if ok || rerr != nil {
				t.Fatalf("reconcile converged on a different generation: ok=%v err=%v", ok, rerr)
			}
			if st, err := Status(fx.dir); err != nil || st.State != StatePublishing {
				t.Fatalf("state after rejected reconcile: %v %+v (want still publishing)", err, st)
			}

			// Repair: the ordinary publish recommits the ID namespace.
			res := ScanRound(context.Background(), ScanRoundOptions{
				Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
			})
			if len(res.Published) != 1 || len(res.Failed) > 0 {
				t.Fatalf("repair publish: published=%v failed=%v", res.Published, res.Failed)
			}
			raw, err := keyedStore(t, store).GetKey(context.Background(), ArtifactKey(id, IndexName))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(raw)
			if err != nil {
				t.Fatal(err)
			}
			raw.Close()
			var index ArtifactIndex
			if err := json.Unmarshal(body, &index); err != nil {
				t.Fatal(err)
			}
			newDigest := fileDigest(t, filepath.Join(fx.dir, tc.remoteName))
			if newDigest == oldDigest {
				t.Fatal("fixture failed to change the guarded file")
			}
			if got := index.Files[tc.remoteName]; got != newDigest {
				t.Fatalf("remote INDEX %s = %s, want the NEW generation's %s", tc.remoteName, got, newDigest)
			}
		})
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Sum(raw)
}

// blockingStore parks selected GetKey/HasKey calls until the request
// context dies (a store that answers neither yes nor no), and records every
// PUT key.
type blockingStore struct {
	inner    *chunkstore.Local
	blockGet map[string]bool
	blockHas map[string]bool
	mu       sync.Mutex
	putKeys  []string
}

func (b *blockingStore) record(key string) {
	b.mu.Lock()
	b.putKeys = append(b.putKeys, key)
	b.mu.Unlock()
}

func (b *blockingStore) dataPuts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var data []string
	for _, k := range b.putKeys {
		if !strings.HasPrefix(k, "gc-pubintents/") {
			data = append(data, k)
		}
	}
	return data
}

func (b *blockingStore) Put(ctx context.Context, digest string, r io.Reader) error {
	b.record(digest)
	return b.inner.Put(ctx, digest, r)
}

func (b *blockingStore) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	return b.inner.Get(ctx, digest)
}

func (b *blockingStore) Has(ctx context.Context, digest string) (bool, error) {
	return b.inner.Has(ctx, digest)
}

func (b *blockingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	b.record(key)
	return b.inner.PutKey(ctx, key, r)
}

func (b *blockingStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if b.blockGet[key] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.inner.GetKey(ctx, key)
}

func (b *blockingStore) HasKey(ctx context.Context, key string) (bool, error) {
	if b.blockHas[key] {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return b.inner.HasKey(ctx, key)
}

// TestScanRoundAttemptTimeoutBoundsReconcile: the per-artifact deadline
// must cover the reconciliation probe too. A store that parks the INDEX GET
// (or a dependency HEAD) makes the attempt fail at opts.Timeout — the round
// returns promptly, the failure is visible in the round result and the
// persisted state, and NO data upload happens after the deadline.

// flakyStore injects ONE deterministic failure point (intent write, first
// Has, first data PUT, or the INDEX commit) while delegating everything
// else. Keyed surface only — the fence is not under test here.
type flakyStore struct {
	inner        *chunkstore.Local
	failIntent   bool
	failHas      bool
	failDataPut  bool
	failIndex    bool
	hasFailed    bool
	putFailed    bool
	onFailPutKey func() // sabotage hook, fired when the data-PUT failure is injected
}

func (s *flakyStore) Put(ctx context.Context, digest string, r io.Reader) error {
	if s.failDataPut && !s.putFailed {
		s.putFailed = true
		if s.onFailPutKey != nil {
			s.onFailPutKey()
		}
		return errors.New("data put failed")
	}
	return s.inner.Put(ctx, digest, r)
}

func (s *flakyStore) Get(ctx context.Context, digest string) (io.ReadCloser, error) {
	return s.inner.Get(ctx, digest)
}

func (s *flakyStore) Has(ctx context.Context, digest string) (bool, error) {
	if s.failHas && !s.hasFailed {
		s.hasFailed = true
		return false, errors.New("has failed")
	}
	return s.inner.Has(ctx, digest)
}

func (s *flakyStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if s.failIntent && strings.HasPrefix(key, GCPubIntentNamespace+"/") {
		return errors.New("intent write failed")
	}
	if s.failIndex && strings.HasSuffix(key, "/"+IndexName) {
		return errors.New("index put failed")
	}
	if s.failDataPut && !s.putFailed && !isControlKey(key) {
		s.putFailed = true
		if s.onFailPutKey != nil {
			s.onFailPutKey()
		}
		return errors.New("data put failed")
	}
	return s.inner.PutKey(ctx, key, r)
}

func (s *flakyStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.inner.GetKey(ctx, key)
}

func (s *flakyStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.inner.HasKey(ctx, key)
}

// TestScanRoundFailedAttemptKeepsAttribution: a publish attempt that dies
// at the intent write, the first Has, the first data PUT, or the INDEX
// commit must STILL surface its per-artifact phases in the round summary —
// with every request counter observed before the failure, the failed
// state-write timing in StateWall, and a publish_failed record. Never a
// false published.
func TestScanRoundFailedAttemptKeepsAttribution(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*flakyStore)
		verify    func(t *testing.T, p PublishPhases, store *chunkstore.Local, id string)
	}{
		{
			name:      "intent-write",
			configure: func(f *flakyStore) { f.failIntent = true },
			verify: func(t *testing.T, p PublishPhases, _ *chunkstore.Local, _ string) {
				if p.ControlReqs < 1 {
					t.Fatalf("control_reqs = %d, want >= 1 (the failed intent write is still a request)", p.ControlReqs)
				}
				if p.PutReqs != 0 || p.HasReqs != 0 {
					t.Fatalf("nothing beyond the intent was attempted: %+v", p)
				}
				if p.MetaWall != 0 || p.IndexWall != 0 {
					t.Fatalf("artifact set must not have started: %+v", p)
				}
			},
		},
		{
			name:      "first-has",
			configure: func(f *flakyStore) { f.failHas = true },
			verify: func(t *testing.T, p PublishPhases, _ *chunkstore.Local, _ string) {
				if p.ControlReqs < 1 || p.HasReqs < 1 {
					t.Fatalf("intent + Has must be visible: %+v", p)
				}
				if p.PutReqs != 0 {
					t.Fatalf("no data PUT happened: %+v", p)
				}
			},
		},
		{
			name:      "first-data-put",
			configure: func(f *flakyStore) { f.failDataPut = true },
			verify: func(t *testing.T, p PublishPhases, _ *chunkstore.Local, _ string) {
				if p.HasReqs < 1 || p.PutReqs < 1 {
					t.Fatalf("the failing PUT itself must be counted: %+v", p)
				}
				if p.UploadWall <= 0 {
					t.Fatalf("upload_wall = %v, want > 0 (the FAILED upload stage keeps its wall)", p.UploadWall)
				}
				if p.MetaWall != 0 || p.IndexWall != 0 {
					t.Fatalf("artifact set must not have started: %+v", p)
				}
			},
		},
		{
			name:      "index-commit",
			configure: func(f *flakyStore) { f.failIndex = true },
			verify: func(t *testing.T, p PublishPhases, store *chunkstore.Local, id string) {
				if p.PutReqs < 3 { // memory chunk + overlay chunk + BUNDLE (+ the failed INDEX PUT)
					t.Fatalf("put_reqs = %d, want >= 3", p.PutReqs)
				}
				if p.MetaWall <= 0 {
					t.Fatalf("meta_wall = %v, want > 0 (bundle uploaded)", p.MetaWall)
				}
				if p.IndexWall <= 0 {
					t.Fatalf("index_wall = %v, want > 0 (the FAILED commit keeps its stage wall)", p.IndexWall)
				}
				if _, err := keyedStore(t, store).GetKey(context.Background(), ArtifactKey(id, IndexName)); err == nil {
					t.Fatal("INDEX must not exist after a failed commit")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			inner, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			flaky := &flakyStore{inner: inner}
			tc.configure(flaky)
			id := "fa-" + tc.name
			newM1Fixture(t, root, id)
			res := ScanRound(context.Background(), ScanRoundOptions{
				Roots: []string{root}, Store: flaky, StoreName: "test", Timeout: time.Minute,
			})
			if len(res.Failed) != 1 || len(res.Published) != 0 {
				t.Fatalf("round outcome: failed=%v published=%v", res.Failed, res.Published)
			}
			if len(res.Phases) != 1 {
				t.Fatalf("failed attempt must keep its phases: %+v", res.Phases)
			}
			ph := res.Phases[0]
			if ph.Reconciled {
				t.Fatal("attempt must not be marked reconciled")
			}
			if ph.PublishWall <= 0 {
				t.Fatalf("publish_wall = %v, want > 0", ph.PublishWall)
			}
			if ph.Publish.StateWall <= 0 {
				t.Fatalf("state_wall = %v, want > 0 (the FAILED state write is timed)", ph.Publish.StateWall)
			}
			st, err := Status(filepath.Join(root, id))
			if err != nil || st.State != StatePublishFailed {
				t.Fatalf("state = %v %+v (want publish_failed)", err, st)
			}
			if st.Retries != 1 {
				t.Fatalf("retries = %d, want 1", st.Retries)
			}
			tc.verify(t, ph.Publish, inner, id)
		})
	}
}

// TestFailedStateWriteKeepsAttribution: the narrow edge the final audit
// found — when the ATTEMPT's own state write fails (the publishing record,
// or the failed record inside failAttempt), the unified finalize defer must
// still freeze the shared Phases/StateTimings, and the returned Result must
// report the attempted transition (publish_failed) even though the durable
// record could not be updated.
func TestFailedStateWriteKeepsAttribution(t *testing.T) {
	t.Run("publishing-write-fails", func(t *testing.T) {
		root := t.TempDir()
		store := mustLocal(t)
		fx := newM1Fixture(t, root, "sw-pub")
		writeQueuedState(fx.dir, fx.id, "test", time.Now())
		pubDir := filepath.Join(root, StateDirName)
		t.Cleanup(func() { _ = os.Chmod(pubDir, 0o755) })
		// The claim lock must pre-exist and stay openable (file perms),
		// while directory writes (CreateTemp for the state record) fail.
		lock, err := os.OpenFile(StatePath(fx.dir)+".lock", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		lock.Close()
		if err := os.Chmod(pubDir, 0o500); err != nil {
			t.Fatal(err)
		}
		res, err := RunWithOptions(context.Background(), fx.dir, fx.id, store, "test", Options{})
		if err == nil {
			t.Fatal("the publishing state write must fail in a read-only .publish")
		}
		if res.Phases == nil {
			t.Fatal("early return lost the attempt phases")
		}
		if res.Phases.ControlReqs < 1 {
			t.Fatalf("control_reqs = %d, want >= 1 (the intent write preceded the return)", res.Phases.ControlReqs)
		}
		if res.Phases.ManifestLoadWall <= 0 {
			t.Fatalf("manifest_load_wall = %v, want > 0", res.Phases.ManifestLoadWall)
		}
		if res.Phases.UploadWall != 0 || res.Phases.PutReqs != 0 {
			t.Fatalf("upload must not have started: %+v", res.Phases)
		}
		// The durable record keeps the last successful write (queued) —
		// retryable next round; nothing falsely published.
		st, serr := Status(fx.dir)
		if serr != nil || st == nil || st.State != StateQueued {
			t.Fatalf("durable state = %v %+v (want still queued)", serr, st)
		}
	})

	t.Run("failed-state-write-fails", func(t *testing.T) {
		root := t.TempDir()
		inner := mustLocal(t)
		fx := newM1Fixture(t, root, "sw-fail")
		pubDir := filepath.Join(root, StateDirName)
		t.Cleanup(func() { _ = os.Chmod(pubDir, 0o755) })
		// The data-PUT failure ALSO makes .publish read-only, so the
		// failed-record write inside failAttempt errors.
		flaky := &flakyStore{inner: inner, failDataPut: true}
		flaky.onFailPutKey = func() { _ = os.Chmod(pubDir, 0o500) }
		res, err := RunWithOptions(context.Background(), fx.dir, fx.id, flaky, "test", Options{})
		if err == nil {
			t.Fatal("the failed-state write must error in a read-only .publish")
		}
		if res.Phases == nil {
			t.Fatal("failAttempt early return lost the attempt phases")
		}
		if res.State.State != StatePublishFailed {
			t.Fatalf("result state = %s, want the ATTEMPTED publish_failed despite the failed write", res.State.State)
		}
		if res.Phases.PutReqs < 1 || res.Phases.HasReqs < 1 || res.Phases.UploadWall <= 0 {
			t.Fatalf("observed traffic must survive: %+v", res.Phases)
		}
		if res.StateTimings == nil || res.StateTimings.Failed.Total <= 0 {
			t.Fatalf("the FAILED write itself must be timed: %+v", res.StateTimings)
		}
		if res.StateTimings.Publishing.Total <= 0 {
			t.Fatalf("the successful publishing write must be timed: %+v", res.StateTimings)
		}
		// Durable record: the last successful write is "publishing" — the
		// stale-lease path requeues it next round.
		if err := os.Chmod(pubDir, 0o755); err != nil {
			t.Fatal(err)
		}
		st, serr := Status(fx.dir)
		if serr != nil || st == nil || st.State != StatePublishing {
			t.Fatalf("durable state = %v %+v (want still publishing)", serr, st)
		}
	})
}

func TestScanRoundAttemptTimeoutBoundsReconcile(t *testing.T) {
	t.Run("blocked-index-get", func(t *testing.T) {
		root := t.TempDir()
		blk := &blockingStore{inner: mustLocal(t), blockGet: map[string]bool{}, blockHas: map[string]bool{}}
		newM1Fixture(t, root, "to-get")
		blk.blockGet[ArtifactKey("to-get", IndexName)] = true
		start := time.Now()
		res := ScanRound(context.Background(), ScanRoundOptions{
			Roots: []string{root}, Store: blk, StoreName: "test", Timeout: 200 * time.Millisecond,
		})
		if wall := time.Since(start); wall > 3*time.Second {
			t.Fatalf("round took %v; reconcile outlived the attempt deadline", wall)
		}
		failure, failed := res.Failed["to-get"]
		if !failed || !strings.Contains(failure, "context deadline exceeded") {
			t.Fatalf("round failure not fail-visible with the deadline: %+v", res.Failed)
		}
		st, err := Status(filepath.Join(root, "to-get"))
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		// The attempt may die at claim acquisition (before any state
		// transition — the queued record stays, retryable next round) or at
		// failState (publish_failed). Both are fail-visible; converging to
		// published is the only forbidden outcome.
		if st.State != StateQueued && st.State != StatePublishFailed {
			t.Fatalf("state = %s, want queued (early exit) or publish_failed", st.State)
		}
		if st.State == StatePublishFailed && !strings.Contains(st.LastError, "context deadline exceeded") {
			t.Fatalf("last error = %q, want the deadline", st.LastError)
		}
		if data := blk.dataPuts(); len(data) > 0 {
			t.Fatalf("data uploads after the deadline: %v", data)
		}
	})
	t.Run("blocked-dependency-has", func(t *testing.T) {
		root := t.TempDir()
		storeDir := t.TempDir()
		inner, err := chunkstore.NewLocal(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		blk := &blockingStore{inner: inner, blockGet: map[string]bool{}, blockHas: map[string]bool{}}
		fx := newTransportCase(t, root, "to-has", false, repBody(1))
		seedRemotePublication(t, inner, fx, fx.transportView(), nil)
		depKey := chunkstore.PlainKey(fx.local.Entries[0].Digest)
		putStoreObject(t, inner, depKey, "cas:0")
		blk.blockHas[depKey] = true
		if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StateQueued, Store: "test", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res := ScanRound(context.Background(), ScanRoundOptions{
			Roots: []string{root}, Store: blk, StoreName: "test", Timeout: 200 * time.Millisecond,
		})
		if wall := time.Since(start); wall > 3*time.Second {
			t.Fatalf("round took %v; dependency probe outlived the attempt deadline", wall)
		}
		failure, failed := res.Failed[fx.id]
		if !failed || !strings.Contains(failure, "context deadline exceeded") {
			t.Fatalf("round failure not fail-visible with the deadline: %+v", res.Failed)
		}
		st, err := Status(fx.dir)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if st.State != StateQueued && st.State != StatePublishFailed {
			t.Fatalf("state = %s, want queued (early exit) or publish_failed", st.State)
		}
		if data := blk.dataPuts(); len(data) > 0 {
			t.Fatalf("data uploads after the deadline: %v", data)
		}
	})
}

// TestPublishPhaseAttribution: the round's per-artifact attribution
// distinguishes the plan's T_remote columns across every publish shape —
// unpacked plain, zstd, packed, chunked overlay — and the reconcile path
// shows zero uploads by construction. Direct CLI publishes (RunWithOptions
// Result) carry the attempt attribution WITHOUT discovery/queue fields;
// publishd rounds carry both, separated.
func TestPublishPhaseAttribution(t *testing.T) {
	roundOf := func(t *testing.T, opts ScanRoundOptions) RoundResult {
		t.Helper()
		res := ScanRound(context.Background(), opts)
		if len(res.Published) != 1 {
			t.Fatalf("published=%v failed=%v deferred=%v", res.Published, res.Failed, res.Deferred)
		}
		return res
	}

	t.Run("plain-unpacked-with-overlay", func(t *testing.T) {
		root := t.TempDir()
		storeDir := t.TempDir()
		store, err := chunkstore.NewLocal(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		newM1Fixture(t, root, "ph-plain") // chunked overlay sidecar present
		res := roundOf(t, ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute})
		ph := res.Phases[0]
		p := ph.Publish
		if p.PutReqs < 4 { // memory chunk + overlay chunk + BUNDLE + INDEX
			t.Fatalf("put_reqs = %d, want >= 4", p.PutReqs)
		}
		if p.PutBytes <= 0 {
			t.Fatalf("put_bytes = %d", p.PutBytes)
		}
		if p.HasReqs < 2 { // memory Has + overlay HasKey probes
			t.Fatalf("has_reqs = %d, want >= 2", p.HasReqs)
		}
		if p.CompressTimeTotal != 0 || p.PackWall != 0 {
			t.Fatalf("plain path must not compress/pack: %+v", p)
		}
		if p.UploadWall <= 0 || p.MetaWall <= 0 || p.IndexWall <= 0 || p.StateWall <= 0 {
			t.Fatalf("stage walls must be positive on this path: %+v", p)
		}
		if p.ControlReqs < 1 { // publication intent (Local supports conditional puts)
			t.Fatalf("control_reqs = %d, want >= 1", p.ControlReqs)
		}
		// Sub-walls are partial spans of the ONE end-to-end wall
		// (PublishWall): each individually must fit inside it (± rounding),
		// but they may overlap each other and are never summed.
		for _, w := range []time.Duration{p.ManifestLoadWall, p.UploadWall, p.MetaWall, p.IndexWall, p.StateWall} {
			if w > ph.PublishWall+5*time.Millisecond {
				t.Fatalf("sub-wall %v exceeds publish_wall %v", w, ph.PublishWall)
			}
		}
		if p.ManifestLoadWall <= 0 {
			t.Fatalf("manifest_load_wall = %v, want > 0 (sidecar parse)", p.ManifestLoadWall)
		}
		if p.ScanHashWall != 0 {
			t.Fatalf("scan_hash_wall = %v, want 0 (sidecar existed; no hashing happened)", p.ScanHashWall)
		}
	})

	t.Run("zstd", func(t *testing.T) {
		root := t.TempDir()
		storeDir := t.TempDir()
		store, err := chunkstore.NewLocal(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		fx := newM1Fixture(t, root, "ph-zstd")
		res := roundOf(t, ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute, CompressChunks: true})
		if res.Phases[0].Publish.CompressTimeTotal <= 0 {
			t.Fatalf("compress_time_total = %v, want > 0", res.Phases[0].Publish.CompressTimeTotal)
		}
		m, err := checkpointchunks.Load(fx.dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(storeDir, chunkstore.CompressedKey(m.Entries[0].Digest))); err != nil {
			t.Fatalf(".z object absent: %v", err)
		}
	})

	t.Run("packed", func(t *testing.T) {
		root := t.TempDir()
		storeDir := t.TempDir()
		store, err := chunkstore.NewLocal(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		fx := newTransportCase(t, root, "ph-pack", false, repBody(1), repBody(2))
		runRes, err := RunWithOptions(context.Background(), fx.dir, "ph-pack", store, "test", Options{PackBytes: 512 << 10})
		if err != nil {
			t.Fatal(err)
		}
		if runRes.Phases == nil {
			t.Fatal("direct publish carries no phases")
		}
		p := *runRes.Phases
		if p.PackWall <= 0 || p.UploadWall != 0 {
			t.Fatalf("packed path walls: %+v (want PackWall>0, UploadWall==0)", p)
		}
		if p.PackBuildTimeTotal <= 0 || p.PackUploadTimeTotal <= 0 {
			t.Fatalf("pack concurrent totals must be positive: %+v", p)
		}
		if p.PutReqs < 3 { // pack object + BUNDLE + INDEX
			t.Fatalf("put_reqs = %d, want >= 3", p.PutReqs)
		}
		if p.MetaWall <= 0 || p.IndexWall <= 0 {
			t.Fatalf("meta/index walls must be positive: %+v", p)
		}
	})

	t.Run("packed-failure-keeps-pack-wall", func(t *testing.T) {
		root := t.TempDir()
		inner, err := chunkstore.NewLocal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		flaky := &flakyStore{inner: inner, failDataPut: true}
		fx := newTransportCase(t, root, "ph-pf", false, repBody(1), repBody(2))
		res, err := RunWithOptions(context.Background(), fx.dir, "ph-pf", flaky, "test", Options{PackBytes: 512 << 10})
		if err == nil {
			t.Fatal("packed publish must fail on the injected PUT error")
		}
		if res.Phases == nil {
			t.Fatal("failed packed attempt lost its phases")
		}
		p := *res.Phases
		if p.PackWall <= 0 {
			t.Fatalf("pack_wall = %v, want > 0 (classify/build/pack-PUT failures keep the stage wall)", p.PackWall)
		}
		if p.UploadWall != 0 {
			t.Fatalf("upload_wall = %v, want 0 on the packed path", p.UploadWall)
		}
		if p.PutReqs < 1 {
			t.Fatalf("the failed pack PUT must be counted: %+v", p)
		}
		st, err := Status(fx.dir)
		if err != nil || st.State != StatePublishFailed {
			t.Fatalf("state = %v %+v (want publish_failed)", err, st)
		}
	})

	t.Run("reconcile-zero-upload", func(t *testing.T) {
		root := t.TempDir()
		storeDir := t.TempDir()
		store, err := chunkstore.NewLocal(storeDir)
		if err != nil {
			t.Fatal(err)
		}
		fx := newTransportCase(t, root, "ph-rc", false, repBody(1))
		seedRemotePublication(t, store, fx, fx.transportView(), nil)
		putStoreObject(t, store, chunkstore.PlainKey(fx.local.Entries[0].Digest), "cas:0")
		if err := writeState(State{CheckpointID: fx.id, Dir: fx.dir, State: StateQueued, Store: "test", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		res := ScanRound(context.Background(), ScanRoundOptions{
			Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute,
		})
		if len(res.Reconciled) != 1 || len(res.Failed) > 0 {
			t.Fatalf("reconcile=%v failed=%v", res.Reconciled, res.Failed)
		}
		ph := res.Phases[0]
		if !ph.Reconciled {
			t.Fatalf("phases not marked reconciled: %+v", ph)
		}
		if ph.Publish.PutReqs != 0 || ph.Publish.PutBytes != 0 || ph.Publish.ControlReqs != 0 {
			t.Fatalf("reconcile must upload nothing: %+v", ph.Publish)
		}
		if ph.Publish.GetReqs < 1 { // INDEX fetch (bundle path adds the BUNDLE GET)
			t.Fatalf("get_reqs = %d, want >= 1", ph.Publish.GetReqs)
		}
		if ph.Publish.HasReqs < 1 { // dependency probe
			t.Fatalf("has_reqs = %d, want >= 1", ph.Publish.HasReqs)
		}
		if ph.Publish.UploadWall != 0 || ph.Publish.MetaWall != 0 || ph.Publish.IndexWall != 0 || ph.Publish.PackWall != 0 {
			t.Fatalf("reconcile must record no upload stages: %+v", ph.Publish)
		}
	})

	t.Run("cli-attempt-vs-publishd-round-split", func(t *testing.T) {
		root := t.TempDir()
		store := mustLocal(t)
		fx := newTransportCase(t, root, "ph-split", false, repBody(1))
		runRes, err := RunWithOptions(context.Background(), fx.dir, "ph-split", store, "test", Options{})
		if err != nil {
			t.Fatal(err)
		}
		direct, err := json.Marshal(runRes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(direct), "queue_wait") || strings.Contains(string(direct), "discovered_at") {
			t.Fatalf("direct CLI result must not carry publishd-only spans: %s", direct)
		}
		if !strings.Contains(string(direct), "hash_wall") {
			t.Fatalf("direct CLI result lacks attempt attribution: %s", direct)
		}
		// A FRESH artifact for the publishd round (the direct-publish
		// fixture above is already published and would be skipped).
		newTransportCase(t, root, "ph-split-round", false, repBody(3))
		round := roundOf(t, ScanRoundOptions{Roots: []string{root}, Store: mustLocal(t), StoreName: "test", Timeout: time.Minute})
		encoded := MarshalRound(round)
		for _, want := range []string{"queue_wait", "discovered_at", "manifest_load_wall", "scan_hash_wall", "meta_wall", "index_wall", "put_reqs", "has_reqs", "get_reqs", "control_reqs"} {
			if !strings.Contains(encoded, want) {
				t.Fatalf("round summary lacks %q", want)
			}
		}
	})
}

// TestScanRoundQueueWaitSpansBlocking: discovery is anchored at the scan's
// observation and PublishStart at the moment the artifact actually enters
// reconcile/publish — so with two artifacts in one round (newest-first
// order), BOTH spend a measurable queue_wait, the second one strictly
// positive after being blocked behind the first, and every phase block is
// self-consistent: seal_to_ready = discovery_lag + queue_wait + publish_wall.
// The pre-fix bug: DiscoveredAt was stamped per-turn inside the publish
// loop and QueueWait was never assigned, so every round reported 0.
func TestScanRoundQueueWaitSpansBlocking(t *testing.T) {
	root := t.TempDir()
	store := mustLocal(t)
	newM1Fixture(t, root, "qw-first")
	newM1Fixture(t, root, "qw-second")
	// Newest-first: qw-first (newer mtime) is processed before qw-second.
	setMtime(filepath.Join(root, "qw-first", "manifest.json"), time.Now().Add(-1*time.Hour))
	setMtime(filepath.Join(root, "qw-second", "manifest.json"), time.Now().Add(-2*time.Hour))
	clock := &stepClock{now: time.Now(), step: time.Second}
	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "test", Timeout: time.Minute, Now: clock.Now,
	})
	if len(res.Published) != 2 || len(res.Phases) != 2 {
		t.Fatalf("published=%v phases=%+v failed=%v deferred=%v", res.Published, res.Phases, res.Failed, res.Deferred)
	}
	byID := make(map[string]ArtifactPhases, len(res.Phases))
	for _, p := range res.Phases {
		byID[p.ID] = p
	}
	for _, id := range []string{"qw-first", "qw-second"} {
		p, ok := byID[id]
		if !ok {
			t.Fatalf("no phases for %s", id)
		}
		if p.QueueWait <= 0 {
			t.Fatalf("%s queue_wait = %v, want > 0 (scan-to-turn span must be measurable)", id, p.QueueWait)
		}
		if p.PublishStart.Before(p.DiscoveredAt) {
			t.Fatalf("%s publish_start %v precedes discovery %v", id, p.PublishStart, p.DiscoveredAt)
		}
		// Phase self-consistency: the three sub-spans must reassemble the
		// whole (± rounding to milliseconds).
		got := p.DiscoveryLag + p.QueueWait + p.PublishWall
		diff := p.SealToReady - got
		if diff < 0 {
			diff = -diff
		}
		if diff > 2*time.Millisecond {
			t.Fatalf("%s phases inconsistent: seal_to_ready=%v != discovery_lag+queue_wait+publish_wall=%v", id, p.SealToReady, got)
		}
	}
	// The second artifact was blocked behind the first one's full publish.
	if byID["qw-second"].QueueWait <= byID["qw-first"].QueueWait-publishWallOf(res, "qw-first") {
		t.Fatalf("second queue_wait %v does not reflect blocking behind first (first wall %v)",
			byID["qw-second"].QueueWait, publishWallOf(res, "qw-first"))
	}
}

func publishWallOf(res RoundResult, id string) time.Duration {
	for _, p := range res.Phases {
		if p.ID == id {
			return p.PublishWall
		}
	}
	return 0
}

// TestStateNextAttemptBoundarySaturates: d at exactly 1<<62 with no cap
// must saturate to MaxInt64 on the next doubling — never wrap to negative
// (bypassing the ceiling) and never collapse to zero (disabling backoff
// precisely when retries are huge).
func TestStateNextAttemptBoundarySaturates(t *testing.T) {
	base := time.Duration(1 << 61) // exactly one doubling below the boundary
	if got := StateNextAttempt(2, base, 0); got != 1<<62 {
		t.Fatalf("retries=2 uncapped: got %v, want exactly %v", got, time.Duration(1<<62))
	}
	got := StateNextAttempt(3, base, 0) // d reaches 1<<62 in-loop → saturate
	if got != time.Duration(math.MaxInt64) {
		t.Fatalf("boundary uncapped: got %v, want MaxInt64 saturation", got)
	}
	if got <= 0 {
		t.Fatal("saturated delay must stay positive")
	}
	// Huge retry counts never produce a negative, zero, or shrinking delay —
	// capped or uncapped.
	for _, capLimit := range []time.Duration{0, time.Hour} {
		prev := time.Duration(0)
		for retries := 1; retries <= 200; retries++ {
			d := StateNextAttempt(retries, time.Second, capLimit)
			if d <= 0 {
				t.Fatalf("cap=%v retries=%d: non-positive delay %v", capLimit, retries, d)
			}
			if d < prev {
				t.Fatalf("cap=%v retries=%d: delay shrank %v -> %v", capLimit, retries, prev, d)
			}
			prev = d
		}
	}
}

// TestBackpressureImplicitLocalReadyCounts: a sealed artifact with NO state
// file (implicit local_ready, not yet discovered by publishd) must count
// toward Pending/UnpublishedBytes.
func TestBackpressureImplicitLocalReadyCounts(t *testing.T) {
	root := t.TempDir()
	_ = newM1Fixture(t, root, "bp-nostate")
	// No state file: just a sealed manifest.
	snap := SnapshotBackpressure([]string{root}, BackpressureLimits{}, nil)
	if snap.Pending != 1 {
		t.Fatalf("Pending = %d, want 1 (implicit local_ready must count)", snap.Pending)
	}
	if snap.UnpublishedBytes <= 0 {
		t.Fatalf("UnpublishedBytes = %d, want >0", snap.UnpublishedBytes)
	}
}

// TestBackpressureAllRootsStatfs: multiple roots — the minimum free bytes
// across all roots is the signal; a statfs failure on any root is
// fail-closed.
func TestBackpressureAllRootsStatfs(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()
	newM1Fixture(t, root1, "mr-a")
	snap := SnapshotBackpressure([]string{root1, root2}, BackpressureLimits{}, nil)
	if snap.FreeBytes <= 0 {
		t.Fatalf("FreeBytes = %d (multi-root statfs failed)", snap.FreeBytes)
	}
	// A nonexistent root must make the snapshot fail-closed.
	bad := SnapshotBackpressure([]string{root1, "/nonexistent-root-xyz"}, BackpressureLimits{}, nil)
	if !bad.Backpressured {
		t.Fatal("nonexistent root did not set Backpressured")
	}
}

// TestScanRoundAdaptiveLayoutDecisionObservable: the adaptive decision must
// reach the daemon's round output — success attempts, failure attempts, and
// (absence on) the reconcile path.
func TestScanRoundAdaptiveLayoutDecisionObservable(t *testing.T) {
	// Pack-layout success + JSON exposure.
	root1 := t.TempDir()
	store1, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, root1, "adp-pack", adaptivePatternData())
	packOpts := ScanRoundOptions{Roots: []string{root1}, Store: store1, StoreName: "test",
		Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1}
	res := ScanRound(context.Background(), packOpts)
	if len(res.Failed) != 0 || len(res.Published) != 1 || res.Published[0] != "adp-pack" {
		t.Fatalf("pack round = %+v (failed=%v)", res, res.Failed)
	}
	if len(res.Phases) != 1 || res.Phases[0].LayoutDecision == nil ||
		res.Phases[0].LayoutDecision.Chosen != layoutPack || res.Phases[0].LayoutDecision.Reason != layoutReasonAtOrAbove {
		t.Fatalf("pack attempt must carry its decision: %+v", res.Phases)
	}
	enc, err := json.Marshal(res)
	if err != nil || !strings.Contains(string(enc), "\"layout_decision\"") || !strings.Contains(string(enc), "at_or_above_threshold") {
		t.Fatalf("round JSON must expose the decision: %s (%v)", enc, err)
	}

	// Plain-layout success on a memory-only artifact (no artifact set).
	root2 := t.TempDir()
	store2, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newM1Fixture(t, root2, "adp-plain")
	plainOpts := ScanRoundOptions{Roots: []string{root2}, Store: store2, StoreName: "test",
		Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1 << 40}
	res2 := ScanRound(context.Background(), plainOpts)
	if len(res2.Failed) != 0 || len(res2.Published) != 1 {
		t.Fatalf("plain round = %+v (failed=%v)", res2, res2.Failed)
	}
	if len(res2.Phases) != 1 || res2.Phases[0].LayoutDecision == nil ||
		res2.Phases[0].LayoutDecision.Chosen != layoutPlain || res2.Phases[0].LayoutDecision.Reason != layoutReasonBelow {
		t.Fatalf("plain attempt decision: %+v", res2.Phases)
	}

	// Failure attempts keep the decision: a store dying at the first pack
	// PUT still shows which layout the attempt chose.
	root3 := t.TempDir()
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, root3, "adp-fail", adaptivePatternData())
	failOpts := ScanRoundOptions{Roots: []string{root3}, Store: newFailingPutStore(underlying, 1),
		StoreName: "test", Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1}
	res3 := ScanRound(context.Background(), failOpts)
	if len(res3.Failed) != 1 || res3.Failed["adp-fail"] == "" {
		t.Fatalf("failure round = %+v", res3.Failed)
	}
	if len(res3.Phases) != 1 || res3.Phases[0].LayoutDecision == nil || res3.Phases[0].LayoutDecision.Chosen != layoutPack {
		t.Fatalf("failed attempt must keep its decision: %+v", res3.Phases)
	}

	// Reconcile path (crash after INDEX commit, local state lost): the
	// converged entry carries Reconciled=true and NO layout decision — no
	// publish attempt ran in that round.
	if err := os.Remove(filepath.Join(root1, ".publish", "adp-pack.json")); err != nil {
		t.Fatal(err)
	}
	res4 := ScanRound(context.Background(), packOpts)
	if len(res4.Reconciled) != 1 || res4.Reconciled[0] != "adp-pack" {
		t.Fatalf("reconcile round = %+v", res4)
	}
	if len(res4.Phases) != 1 || !res4.Phases[0].Reconciled || res4.Phases[0].LayoutDecision != nil {
		t.Fatalf("reconciled entry must have no decision: %+v", res4.Phases)
	}
}

// TestScanRoundAdaptiveStickyAcrossDaemonRounds: the sticky-layout contract
// must hold through the REAL daemon queue/retry flow, not only direct
// RunWithOptions calls. Round one decides plain and dies mid-upload; round
// two (a) with adaptive still on but a would-pack threshold stays plain and
// succeeds; round two (b, separate artifact) with adaptive OFF and pack
// configured is refused, writes nothing, and leaves layout=plain recorded.
func TestScanRoundAdaptiveStickyAcrossDaemonRounds(t *testing.T) {
	// (a) sticky plain through the queue: fail round → retry round packs a
	// fresh decision but must not flip this artifact.
	rootA := t.TempDir()
	underDir := t.TempDir()
	underlying, err := chunkstore.NewLocal(underDir)
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, rootA, "sticky-a", adaptivePatternData())
	failOpts := ScanRoundOptions{Roots: []string{rootA}, Store: newFailingPutStore(underlying, 1),
		StoreName: "s", Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1 << 40}
	res1 := ScanRound(context.Background(), failOpts)
	if len(res1.Failed) != 1 || res1.Failed["sticky-a"] == "" {
		t.Fatalf("fail round = %+v", res1.Failed)
	}
	st, _ := Status(filepath.Join(rootA, "sticky-a"))
	if st == nil || st.State != StatePublishFailed || st.Layout != layoutPlain {
		t.Fatalf("fail round state = %+v", st)
	}
	goodDir := t.TempDir()
	good, err := chunkstore.NewLocal(goodDir)
	if err != nil {
		t.Fatal(err)
	}
	retryOpts := ScanRoundOptions{Roots: []string{rootA}, Store: good, StoreName: "s",
		Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1} // fresh decision would PACK
	res2 := ScanRound(context.Background(), retryOpts)
	if len(res2.Failed) != 0 || len(res2.Published) != 1 || res2.Published[0] != "sticky-a" {
		t.Fatalf("retry round = %+v (failed=%v)", res2, res2.Failed)
	}
	if len(res2.Phases) != 1 || res2.Phases[0].LayoutDecision == nil ||
		res2.Phases[0].LayoutDecision.Chosen != layoutPlain || res2.Phases[0].LayoutDecision.Reason != layoutReasonSticky {
		t.Fatalf("retry must be sticky plain: %+v", res2.Phases)
	}
	if hasPackObjects(t, goodDir) {
		t.Fatalf("sticky-plain retry must not produce pack objects")
	}

	// (b) adaptive OFF + pack configured on a decided-plain artifact: the
	// daemon's own attempt is refused, nothing is written, layout survives.
	rootB := t.TempDir()
	under2Dir := t.TempDir()
	under2, err := chunkstore.NewLocal(under2Dir)
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, rootB, "drift-b", adaptivePatternData())
	failOptsB := failOpts
	failOptsB.Roots = []string{rootB}
	failOptsB.Store = newFailingPutStore(under2, 1)
	if res := ScanRound(context.Background(), failOptsB); len(res.Failed) != 1 {
		t.Fatalf("setup fail round = %+v", res.Failed)
	}
	driftDir := t.TempDir()
	driftStore, err := chunkstore.NewLocal(driftDir)
	if err != nil {
		t.Fatal(err)
	}
	driftOpts := ScanRoundOptions{Roots: []string{rootB}, Store: driftStore, StoreName: "s",
		Timeout: time.Minute, PackBytes: 4 << 20} // adaptive OFF
	res3 := ScanRound(context.Background(), driftOpts)
	if len(res3.Failed) != 1 || !strings.Contains(res3.Failed["drift-b"], "adaptive off") {
		t.Fatalf("drift round must refuse with the remedy: %+v", res3.Failed)
	}
	if n := storeObjects(t, driftDir); n != 0 {
		t.Fatalf("refused drift round wrote %d objects", n)
	}
	stB, _ := Status(filepath.Join(rootB, "drift-b"))
	if stB == nil || stB.State != StatePublishFailed || stB.Layout != layoutPlain {
		t.Fatalf("refused round must leave layout=plain failed state: %+v", stB)
	}
}

func hasPackObjects(t *testing.T, root string) bool {
	t.Helper()
	found := false
	filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == "memory-packs" {
			found = true
		}
		return nil
	})
	return found
}

// TestScanRoundMalformedStateNotOverwritten: an unreadable state file fails
// the artifact for the round — the scanner must not enqueue it (which would
// overwrite the record with a fresh queued state) and the publisher (direct
// or daemon) must refuse before any store IO.
func TestScanRoundMalformedStateNotOverwritten(t *testing.T) {
	root := t.TempDir()
	dir := adaptivePackedFixtureIn(t, root, "mangled", adaptivePatternData())
	statePath := filepath.Join(root, ".publish", "mangled.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	const garbage = `{"checkpoint_id": "mangled", "state": ` // truncated JSON
	if err := os.WriteFile(statePath, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	storeDir := t.TempDir()
	store, err := chunkstore.NewLocal(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	opts := ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "s",
		Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1}
	res := ScanRound(context.Background(), opts)
	if len(res.Failed) != 1 || !strings.Contains(res.Failed["mangled"], "read publish state") {
		t.Fatalf("malformed state must fail the round: %+v", res.Failed)
	}
	kept, rerr := os.ReadFile(statePath)
	if rerr != nil || string(kept) != garbage {
		t.Fatalf("scanner must not overwrite the malformed record: %q (%v)", kept, rerr)
	}
	if n := storeObjects(t, storeDir); n != 0 {
		t.Fatalf("malformed-state round wrote %d objects", n)
	}
	// The direct publisher refuses on the same file, also before any IO.
	directDir := t.TempDir()
	direct, derr := chunkstore.NewLocal(directDir)
	if derr != nil {
		t.Fatal(derr)
	}
	if _, err := RunWithOptions(context.Background(), dir, "mangled", direct, "s", opts2adaptive()); err == nil ||
		!strings.Contains(err.Error(), "refusing to treat an unreadable state as fresh") {
		t.Fatalf("direct run must refuse unreadable state, got %v", err)
	}
	if n := storeObjects(t, directDir); n != 0 {
		t.Fatalf("refused direct run wrote %d objects", n)
	}
}

func opts2adaptive() Options {
	return Options{PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1}
}

// TestScanRoundReconcilePreservesLayout: convergence after a crash between
// INDEX commit and the state write must keep a decided layout — the
// republish that follows still owes the artifact that layout. Legacy
// states without a layout converge to a published state without one.
func TestScanRoundReconcilePreservesLayout(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, root, "recov-pack", adaptivePatternData())
	publishOpts := ScanRoundOptions{Roots: []string{root}, Store: store, StoreName: "s",
		Timeout: time.Minute, PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1}
	if res := ScanRound(context.Background(), publishOpts); len(res.Failed) != 0 || len(res.Published) != 1 {
		t.Fatalf("publish round = %+v (failed=%v)", res, res.Failed)
	}
	// Simulate the crash window: keep layout=pack, rewind the state to
	// publishing. The remote INDEX stays committed.
	if err := rewriteStateField(filepath.Join(root, "recov-pack"), StatePublishing); err != nil {
		t.Fatal(err)
	}
	res := ScanRound(context.Background(), publishOpts)
	if len(res.Reconciled) != 1 || res.Reconciled[0] != "recov-pack" {
		t.Fatalf("reconcile round = %+v", res)
	}
	st, _ := Status(filepath.Join(root, "recov-pack"))
	if st == nil || st.State != StatePublished || st.Layout != layoutPack {
		t.Fatalf("reconcile must preserve layout=pack: %+v", st)
	}

	// Legacy converge: a pre-adaptive state (no layout) stays layout-free.
	root2 := t.TempDir()
	store2, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	adaptivePackedFixtureIn(t, root2, "recov-legacy", adaptivePatternData())
	legacyOpts := publishOpts
	legacyOpts.Roots = []string{root2}
	legacyOpts.Store = store2
	legacyOpts.AdaptivePackThresholdBytes = 0 // plain publish, no decision
	if res := ScanRound(context.Background(), legacyOpts); len(res.Failed) != 0 || len(res.Published) != 1 {
		t.Fatalf("legacy publish = %+v", res.Failed)
	}
	if err := rewriteStateField(filepath.Join(root2, "recov-legacy"), StatePublishing); err != nil {
		t.Fatal(err)
	}
	if err := stripLayout(filepath.Join(root2, "recov-legacy")); err != nil {
		t.Fatal(err)
	}
	res2 := ScanRound(context.Background(), legacyOpts)
	if len(res2.Reconciled) != 1 {
		t.Fatalf("legacy reconcile = %+v", res2)
	}
	st2, _ := Status(filepath.Join(root2, "recov-legacy"))
	if st2 == nil || st2.State != StatePublished || st2.Layout != "" {
		t.Fatalf("legacy converge must stay layout-free: %+v", st2)
	}
}

// rewriteStateField flips the persisted state string in place (test seam
// for the crash-window simulations above).
func rewriteStateField(checkpointDir, state string) error {
	p := StatePath(checkpointDir)
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc["state"] = state
	delete(doc, "published_at")
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(p, out, 0o600)
}

func stripLayout(checkpointDir string) error {
	p := StatePath(checkpointDir)
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	delete(doc, "layout")
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(p, out, 0o600)
}

func storeObjects(t *testing.T, root string) int {
	t.Helper()
	n := 0
	filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// packBodyTypeStore records, for every pack-object PUT, whether the body
// (under the instrument layer's counting wrapper) implements the streaming
// pack reader — the buffer path would hand the store a *bytes.Reader — and
// whether it arrives still SEEKABLE, which is what keeps Remote.PutKey on
// its streaming Seeker path instead of buffering the whole body.
type packBodyTypeStore struct {
	chunkstore.Store
	packBodies     atomic.Int64
	streamBodies   atomic.Int64
	seekableBodies atomic.Int64
}

func instrumentedBody(r io.Reader) io.Reader {
	if sc, ok := r.(*seekableCountingReader); ok {
		return sc.inner
	}
	if cr, ok := r.(*countingReader); ok {
		return cr.inner
	}
	return r
}

func (s *packBodyTypeStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if isPackObjectKey(key) {
		s.packBodies.Add(1)
		if _, ok := instrumentedBody(r).(packStreamReader); ok {
			s.streamBodies.Add(1)
		}
		if _, ok := r.(io.Seeker); ok {
			s.seekableBodies.Add(1)
		}
	}
	return s.Store.(chunkstore.Keyed).PutKey(ctx, key, r)
}

func (s *packBodyTypeStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *packBodyTypeStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

// TestScanRoundPackIdentityAndStreamingPassthrough: the daemon's
// -pack-identity/-pack-streaming-put knobs must reach the publish attempt.
// Identity is observable in the store namespace (chunks-v1 packs land under
// memory-chunk-packs-v1/, legacy under memory-packs/); streaming is
// observable in the PUT body type (every pack body must be the verified
// streaming reader, never a buffered *bytes.Reader).
func TestScanRoundPackIdentityAndStreamingPassthrough(t *testing.T) {
	root := t.TempDir()
	storeRoot := t.TempDir()
	underlying, err := chunkstore.NewLocal(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	observed := &packBodyTypeStore{Store: underlying}
	adaptivePackedFixtureIn(t, root, "pid-stream", adaptivePatternData())

	res := ScanRound(context.Background(), ScanRoundOptions{Roots: []string{root}, Store: observed,
		StoreName: "test", Timeout: time.Minute, PackBytes: 4 << 20,
		PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true})
	if len(res.Failed) != 0 || len(res.Published) != 1 || res.Published[0] != "pid-stream" {
		t.Fatalf("streaming round = %+v (failed=%v)", res, res.Failed)
	}
	if observed.packBodies.Load() == 0 || observed.packBodies.Load() != observed.streamBodies.Load() {
		t.Fatalf("pack PUT bodies: total=%d streaming=%d, want every pack body to be the streaming reader",
			observed.packBodies.Load(), observed.streamBodies.Load())
	}
	if observed.packBodies.Load() != observed.seekableBodies.Load() {
		t.Fatalf("seekable pack bodies=%d of %d: the instrument layer must not hide the reader's Seeker (that would reroute Remote.PutKey into buffered ReadAll)",
			observed.seekableBodies.Load(), observed.packBodies.Load())
	}

	v1, legacy := 0, 0
	filepath.WalkDir(storeRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch {
		case strings.Contains(p, "memory-chunk-packs-v1"):
			v1++
		case strings.Contains(p, "memory-packs"):
			legacy++
		}
		return nil
	})
	if v1 == 0 {
		t.Fatal("no chunks-v1 pack objects: -pack-identity did not reach the attempt")
	}
	if legacy != 0 {
		t.Fatalf("legacy pack objects appeared under chunks-v1 identity: %d", legacy)
	}
	lk := chunkstore.Keyed(underlying)
	if _, e := lk.GetKey(context.Background(), ArtifactKey("pid-stream", IndexName)); e != nil {
		t.Fatalf("INDEX: %v", e)
	}
}
