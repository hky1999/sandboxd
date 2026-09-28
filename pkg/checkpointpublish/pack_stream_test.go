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

package checkpointpublish

// Streaming verified-PUT tests. The pack-streaming contract these pin:
//   - byte-for-byte identical stores and normalized Results with the flag
//     off vs on, over a fixture that mixes fresh packs, parent-reused
//     packs, an all-zero chunk, and a repeated chunk;
//   - the reader streams lazily (first chunk produced before later chunks
//     are read, exactly one file read per chunk per pass) at reader level
//     AND through a full publish via the per-run reader factory;
//   - a cancelled publish stops mid-pack: no further file reads, no
//     further store writes, no INDEX, publish_failed, retry converges;
//   - a mid-body PUT failure leaves no visible half object on the real
//     local backend and retries to exact bytes;
//   - a sweep-marked pack is fenced, re-PUT under a claim, claim released;
//   - the fresh-upload guard's second PUT uses a FRESH reader whose body
//     is byte-identical to the first.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// multiPackPattern is 32MiB with every 256KiB chunk non-zero and unique:
// 8 packs of 4MiB, nothing skipped.
func multiPackPattern() []byte {
	data := make([]byte, 32<<20)
	for i := range data {
		data[i] = byte(i*31 + i/(256*1024)*17 + 1)
	}
	return data
}

func multiPackFixture(t *testing.T, dir string) *checkpointchunks.Manifest {
	t.Helper()
	m, err := checkpointchunks.Compute(context.Background(), dir, checkpointchunks.DefaultChunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, checkpointchunks.ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fc := map[string]any{
		"version": 2, "snapshot_type": "SoftDirty", "memory_size": m.FileSize,
		"memory_digest_mode": checkpointchunks.FileDigestChunks,
		"digests":            map[string]string{"memory": m.FileDigest},
	}
	fcRaw, _ := json.Marshal(fc)
	os.WriteFile(filepath.Join(dir, "manifest.json"), fcRaw, 0o600)
	os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vmstate"), 0o600)
	os.WriteFile(filepath.Join(dir, "overlay.ext4"), []byte("overlay"), 0o600)
	return m
}

// parentChildData builds a 32MiB parent and a 32MiB child whose first
// 16MiB repeats the parent (pack reuse through a base) and whose second
// 16MiB is new, containing one all-zero chunk (skipped entirely) and one
// chunk repeated from earlier in the new region (deduplicated).
func parentChildData() (parent, child []byte) {
	parent = multiPackPattern()
	child = make([]byte, 32<<20)
	copy(child, parent[:16<<20])
	for i := 16 << 20; i < len(child); i++ {
		child[i] = byte(i*29 + i/(256*1024)*13 + 7)
	}
	for i := 20 << 20; i < 20<<20+256*1024; i++ {
		child[i] = 0
	}
	copy(child[22<<20:22<<20+256*1024], child[17<<20:17<<20+256*1024])
	return parent, child
}

// expectedPackMap mirrors runPacked's job grouping (unique chunks sorted by
// digest, the all-zero chunk never packed, grouped up to packBytes) and
// returns every pack's store key and exact expected object bytes for a
// FRESH store (everything missing).
func expectedPackMap(t *testing.T, dir string, data []byte, packBytes int) map[string][]byte {
	t.Helper()
	m, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var jobs [][]checkpointchunks.Chunk
	var cur []checkpointchunks.Chunk
	size := 0
	for _, c := range uniqueSortedChunks(m) {
		n := chunkByteLen(m, c)
		if c.Digest == checkpointchunks.ZeroChunkDigest(n) {
			continue
		}
		if size+n > packBytes {
			jobs = append(jobs, cur)
			cur = nil
			size = 0
		}
		cur = append(cur, c)
		size += n
	}
	if len(cur) > 0 {
		jobs = append(jobs, cur)
	}
	out := map[string][]byte{}
	for _, chunks := range jobs {
		parts := make([]checkpointchunks.PackPart, 0, len(chunks))
		var body bytes.Buffer
		for _, c := range chunks {
			n := chunkByteLen(m, c)
			parts = append(parts, checkpointchunks.PackPart{Digest: c.Digest, Length: int64(n)})
			body.Write(data[c.Offset : int(c.Offset)+n])
		}
		digest, err := checkpointchunks.PackRootDigest(parts)
		if err != nil {
			t.Fatal(err)
		}
		key, err := (checkpointchunks.PackReference{Identity: checkpointchunks.PackIdentityChunks, Digest: digest}).Key()
		if err != nil {
			t.Fatal(err)
		}
		out[key] = body.Bytes()
	}
	if len(out) == 0 {
		t.Fatal("fixture produced no packs")
	}
	return out
}

func walkFiles(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	m := make(map[string]struct{})
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			m[rel] = struct{}{}
		}
		return nil
	})
	return m
}

func isPackObjectKey(key string) bool {
	return strings.HasPrefix(key, "memory-chunk-packs-v1/")
}

// ---------------------------------------------------------------------------
// instrumentation: per-run reader factory (never a package global)
// ---------------------------------------------------------------------------

// streamRecorder is installed as Options.packStreamFactory for one run and
// records every streaming reader instance that run created.
type streamRecorder struct {
	mu        sync.Mutex
	instances []packStreamReader
}

func (s *streamRecorder) factory() func(context.Context, io.ReaderAt, *checkpointchunks.Manifest, []checkpointchunks.Chunk) packStreamReader {
	return func(ctx context.Context, src io.ReaderAt, m *checkpointchunks.Manifest, chunks []checkpointchunks.Chunk) packStreamReader {
		r := newVerifiedPackReadSeeker(ctx, src, m, chunks)
		s.mu.Lock()
		s.instances = append(s.instances, r)
		s.mu.Unlock()
		return r
	}
}

func (s *streamRecorder) snapshot() []packStreamReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]packStreamReader(nil), s.instances...)
}

func totalLoads(instances []packStreamReader) int64 {
	var t int64
	for _, r := range instances {
		t += r.chunksLoaded()
	}
	return t
}

// countingReadAtMemory counts ReadAt calls against the memory file.
type countingReadAtMemory struct {
	*os.File
	readAts atomic.Int64
}

func (c *countingReadAtMemory) ReadAt(p []byte, off int64) (int, error) {
	c.readAts.Add(1)
	return c.File.ReadAt(p, off)
}

func waitFor(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", desc)
}

// ---------------------------------------------------------------------------
// 1. Flag-off vs flag-on: mixed reuse fixture, full key set, byte equality,
//    normalized-Result DeepEqual
// ---------------------------------------------------------------------------

// normalizeResult zeroes ONLY timing/clock/path fields so two arms of the
// same publish must agree on every REQUEST COUNTER, byte counter, and the
// payload peak — real semantic differences, not noise. PackTimings and
// StateTimings are pure timing structs and are dropped whole; Phases keeps
// its counters (Has/Get/Put/Control request and byte counts) with every
// duration field zeroed.
func normalizeResult(r Result) Result {
	n := r
	n.StateTimings = nil
	n.PackTimings = nil
	n.State.Dir = ""
	n.State.StartedAt = time.Time{}
	n.State.PublishedAt = time.Time{}
	if n.Phases != nil {
		p := *n.Phases
		p.ManifestLoadWall = 0
		p.ScanHashWall = 0
		p.UploadWall = 0
		p.MetaWall = 0
		p.IndexWall = 0
		p.PackWall = 0
		p.StateWall = 0
		p.PackBuildTimeTotal = 0
		p.PackUploadTimeTotal = 0
		p.CompressTimeTotal = 0
		p.HasTimeTotal = 0
		p.GetOpenTimeTotal = 0
		p.GetTimeTotal = 0
		p.PutTimeTotal = 0
		p.ControlTimeTotal = 0
		n.Phases = &p
	}
	return n
}

func TestStreamOffVsOnMixedReuseEquality(t *testing.T) {
	parent, childData := parentChildData()

	runArm := func(streaming bool) (storeRoot, childDir string, res Result) {
		parentDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(parentDir, "memory"), parent, 0o600); err != nil {
			t.Fatal(err)
		}
		multiPackFixture(t, parentDir)
		root := t.TempDir()
		underlying, err := chunkstore.NewLocal(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RunWithOptions(context.Background(), parentDir, "stream-parent", underlying, "s",
			Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks}); err != nil {
			t.Fatalf("parent publish: %v", err)
		}
		childDir = t.TempDir()
		if err := os.WriteFile(filepath.Join(childDir, "memory"), childData, 0o600); err != nil {
			t.Fatal(err)
		}
		multiPackFixture(t, childDir)
		res, err = RunWithOptions(context.Background(), childDir, "stream-child", underlying, "s",
			Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
				BaseID: "stream-parent", PackStreamingPut: streaming})
		if err != nil {
			t.Fatalf("child publish (streaming=%v): %v", streaming, err)
		}
		return root, childDir, res
	}

	rootOff, childOff, resOff := runArm(false)
	rootOn, _, resOn := runArm(true)

	// The fixture's content is ASSERTED, not assumed: the child manifest
	// must carry an all-zero chunk digest (skipped, never packed) and
	// duplicate digests (deduplicated to one unique chunk).
	cm, err := checkpointchunks.Load(childOff)
	if err != nil {
		t.Fatal(err)
	}
	zeros := 0
	for _, c := range cm.Entries {
		if c.Digest == checkpointchunks.ZeroChunkDigest(chunkByteLen(cm, c)) {
			zeros++
		}
	}
	if zeros == 0 {
		t.Fatal("fixture carries no all-zero chunk digest")
	}
	if dupes := len(cm.Entries) - len(uniqueSortedChunks(cm)); dupes == 0 {
		t.Fatal("fixture carries no repeated chunk digests")
	}

	// The fixture must actually mix outcomes: parent packs skipped AND
	// fresh packs uploaded.
	if resOff.PacksSkip == 0 || resOff.PacksPut == 0 {
		t.Fatalf("fixture degenerated to all-skip or all-put: %+v", resOff)
	}

	// Normalized Results must be DeepEqual: nothing but timings/paths may
	// differ between the buffer path and the streaming path.
	if !reflect.DeepEqual(normalizeResult(resOff), normalizeResult(resOn)) {
		t.Fatalf("normalized results differ:\n off=%+v\n on=%+v", normalizeResult(resOff), normalizeResult(resOn))
	}

	// Complete key set + byte-level object equality across both stores.
	keysOff, keysOn := walkFiles(t, rootOff), walkFiles(t, rootOn)
	if len(keysOff) != len(keysOn) {
		t.Fatalf("key count: off=%d on=%d", len(keysOff), len(keysOn))
	}
	for k := range keysOff {
		if _, ok := keysOn[k]; !ok {
			t.Fatalf("key %s present off but missing on", k)
		}
		bOff, _ := os.ReadFile(filepath.Join(rootOff, k))
		bOn, _ := os.ReadFile(filepath.Join(rootOn, k))
		if !bytes.Equal(bOff, bOn) {
			t.Fatalf("object %s bytes differ: off=%d on=%d", k, len(bOff), len(bOn))
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Reader unit tests: exact bytes, zero-leak, seek contract, ctx between
//    chunks
// ---------------------------------------------------------------------------

func TestStreamReadSeekerExactBytes(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, dir)
	mem, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	var packChunks []checkpointchunks.Chunk
	total := int64(0)
	for _, c := range m.Entries {
		n := int64(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
		if total+n > 4<<20 {
			break
		}
		packChunks = append(packChunks, c)
		total += n
	}
	if len(packChunks) < 4 {
		t.Fatalf("fixture too small: %d chunks", len(packChunks))
	}

	var expected bytes.Buffer
	for _, c := range packChunks {
		n := int(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
		expected.Write(data[c.Offset : int(c.Offset)+n])
	}

	r := newVerifiedPackReadSeeker(context.Background(), mem, m, packChunks)
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil || end != total {
		t.Fatalf("SeekEnd=%d err=%v want=%d", end, err, total)
	}
	start, err := r.Seek(0, io.SeekStart)
	if err != nil || start != 0 {
		t.Fatalf("SeekStart=%d err=%v", start, err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, expected.Bytes()) {
		t.Fatalf("bytes differ: got=%d expected=%d", len(got), expected.Len())
	}
}

func TestStreamBadChunkZeroLeak(t *testing.T) {
	// The manifest must describe the CLEAN bytes; corruption goes in
	// AFTER sealing, so the reader's per-chunk comparison has something
	// to disagree with.
	badDir := t.TempDir()
	clean := multiPackPattern()
	if err := os.WriteFile(filepath.Join(badDir, "memory"), clean, 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, badDir)
	corrupt := append([]byte(nil), clean...)
	corrupt[4*256*1024] ^= 0xFF
	if err := os.WriteFile(filepath.Join(badDir, "memory"), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	mem, err := os.Open(filepath.Join(badDir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	var packChunks []checkpointchunks.Chunk
	for i, c := range m.Entries {
		if i >= 16 {
			break
		}
		packChunks = append(packChunks, c)
	}

	r := newVerifiedPackReadSeeker(context.Background(), mem, m, packChunks)
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256*1024)
	var totalRead int
	for {
		n, err := r.Read(buf)
		totalRead += n
		if err != nil {
			if totalRead > 4*256*1024 {
				t.Fatalf("leaked %d bytes from bad chunk (expected ≤4×256KiB)", totalRead-4*256*1024)
			}
			if !strings.Contains(err.Error(), "changed") && !strings.Contains(err.Error(), "digest") {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if n == 0 {
			t.Fatal("unexpected EOF before hitting bad chunk")
		}
	}
}

func TestStreamSeekContract(t *testing.T) {
	seekDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(seekDir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, seekDir)
	mem, err := os.Open(filepath.Join(seekDir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	var pc []checkpointchunks.Chunk
	for i, c := range m.Entries {
		if i >= 4 {
			break
		}
		pc = append(pc, c)
	}
	r := newVerifiedPackReadSeeker(context.Background(), mem, m, pc)

	if _, err := r.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("SeekEnd: %v", err)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("SeekStart: %v", err)
	}
	if _, err := r.Seek(100, io.SeekStart); err == nil {
		t.Fatal("Seek(100,Start) must be rejected")
	}
	if _, err := r.Seek(0, io.SeekCurrent); err == nil {
		t.Fatal("Seek(0,Current) must be rejected")
	}
	if _, err := r.Seek(-1, io.SeekEnd); err == nil {
		t.Fatal("Seek(-1,End) must be rejected")
	}
}

// TestStreamSeekEndReadEOFStandard: after Seek(0,End) a Read must return
// io.EOF per standard Seeker semantics — with ZERO file reads — instead of
// silently rewinding to chunk 0. Seek(0,Start) then restores normal reads.
func TestStreamSeekEndReadEOFStandard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, dir)
	f, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cnt := &countingReadAtMemory{File: f}
	var pc []checkpointchunks.Chunk
	for i, c := range m.Entries {
		if i >= 4 {
			break
		}
		pc = append(pc, c)
	}
	r := newVerifiedPackReadSeeker(context.Background(), cnt, m, pc)
	if _, err := r.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256*1024)
	if n, err := r.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("Read after SeekEnd = (%d, %v), want (0, io.EOF)", n, err)
	}
	if got := cnt.readAts.Load(); got != 0 {
		t.Fatalf("ReadAt after SeekEnd+Read: %d, want 0", got)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	if got := cnt.readAts.Load(); got != 1 {
		t.Fatalf("ReadAt after rewind+read: %d, want 1", got)
	}
}

// TestStreamReaderContextCancelBetweenChunks: after the FIRST chunk is
// consumed, cancelling the reader's context must make the next Read fail
// with the context error while performing ZERO additional file reads —
// the check fires before the chunk buffer is even allocated.
func TestStreamReaderContextCancelBetweenChunks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, dir)
	f, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cnt := &countingReadAtMemory{File: f}
	if len(m.Entries) < 3 {
		t.Fatal("fixture too small")
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := newVerifiedPackReadSeeker(ctx, cnt, m, m.Entries[:16])

	first := make([]byte, 256*1024)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}
	if got := cnt.readAts.Load(); got != 1 {
		t.Fatalf("ReadAt after first chunk: %d, want 1", got)
	}
	cancel()

	// Zero-length read contract holds even under a dead context.
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	buf := make([]byte, 256*1024)
	n, err := r.Read(buf)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Read after cancel = (%d, %v), want (0, context.Canceled)", n, err)
	}
	if got := cnt.readAts.Load(); got != 1 {
		t.Fatalf("ReadAt after cancelled read: %d, want 1 (no file read past the cancel)", got)
	}
	// Sticky until rewind; the rewind itself succeeds but the dead context
	// still gates the next load.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read after rewind on dead ctx: %v", err)
	}
	if got := cnt.readAts.Load(); got != 1 {
		t.Fatalf("ReadAt total: %d, want 1", got)
	}
}

// TestStreamFirstChunkProducedBeforeLaterChunksRead: after consuming ONLY
// the first chunk's bytes, exactly ONE ReadAt has hit the memory file; a
// full pass lands on exactly one ReadAt per chunk (never two passes).
func TestStreamFirstChunkProducedBeforeLaterChunksRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, dir)
	f, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cnt := &countingReadAtMemory{File: f}
	if len(m.Entries) < 17 {
		t.Fatalf("fixture too small: %d entries", len(m.Entries))
	}
	packChunks := m.Entries[:16]
	r := newVerifiedPackReadSeeker(context.Background(), cnt, m, packChunks)
	if _, err := r.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 256*1024)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}
	if got := cnt.readAts.Load(); got != 1 {
		t.Fatalf("ReadAt after first chunk consumed: got %d, want 1 (later chunks must not be read yet)", got)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if got := cnt.readAts.Load(); got != int64(len(packChunks)) {
		t.Fatalf("ReadAt per full pass: got %d, want %d (exactly once per chunk)", got, len(packChunks))
	}
}

// ---------------------------------------------------------------------------
// 3. Mid-read source corruption through a real publish
// ---------------------------------------------------------------------------

func TestStreamMidReadErrorNoIndex(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	data[10*256*1024+50] ^= 0xFF
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store := adaptiveStoreSingle(t)

	_, err := RunWithOptions(context.Background(), dir, "ck", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true})
	if err == nil {
		t.Fatal("streaming with corrupt chunk must fail")
	}
	keyed := store.(chunkstore.Keyed)
	if _, e := keyed.GetKey(context.Background(), ArtifactKey("ck", IndexName)); e == nil {
		t.Fatal("INDEX must not exist after streaming failure")
	}
	st, _ := Status(dir)
	if st == nil || st.State != StatePublishFailed {
		t.Fatalf("state: %+v", st)
	}
}

// ---------------------------------------------------------------------------
// 4. In-flight context cancellation: barrier after the first chunk enters
//    PutKey, cancel, then prove the run stops reading and writing
// ---------------------------------------------------------------------------

// cancelProbeStore blocks EVERY pack-object PutKey after consuming exactly
// one chunk of its body; everything else is forwarded to the real backend.
// Pack bodies are drained but deliberately not stored — this store exists
// to pin the cancellation point, not to host pack objects.
type cancelProbeStore struct {
	chunkstore.Store
	firstChunk   chan struct{}
	gate         chan struct{}
	once         sync.Once
	putCalls     atomic.Int64
	putCommitted atomic.Int64
}

func (s *cancelProbeStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	s.putCalls.Add(1)
	k := s.Store.(chunkstore.Keyed)
	if !isPackObjectKey(key) {
		if err := k.PutKey(ctx, key, r); err != nil {
			return err
		}
		s.putCommitted.Add(1)
		return nil
	}
	buf := make([]byte, 256*1024)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	s.once.Do(func() { close(s.firstChunk) })
	<-s.gate
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	return nil
}

func (s *cancelProbeStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *cancelProbeStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

func TestStreamCtxCancelNoIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ps := &cancelProbeStore{Store: underlying, firstChunk: make(chan struct{}), gate: make(chan struct{})}
	rec := &streamRecorder{}
	opts := Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
		PackStreamingPut: true, Workers: 2, packStreamFactory: rec.factory()}

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := RunWithOptions(ctx, dir, "ck", ps, "s", opts)
		done <- outcome{res, err}
	}()

	// Wait until BOTH workers sit inside a pack PutKey with exactly one
	// chunk consumed each: instances==2 with loads==1 (workers=2, no
	// third reader can exist while both are blocked on the gate).
	<-ps.firstChunk
	waitFor(t, "both workers blocked with one loaded chunk", func() bool {
		insts := rec.snapshot()
		return len(insts) == 2 && insts[0].chunksLoaded() == 1 && insts[1].chunksLoaded() == 1
	})
	calls := ps.putCalls.Load()
	committed := ps.putCommitted.Load()

	cancel()       // the cancellation point
	close(ps.gate) // release the blocked PUTs; their bodies must now fail

	out := <-done
	if !errors.Is(out.err, context.Canceled) {
		t.Fatalf("run error = %v, want context.Canceled", out.err)
	}
	// No PutKey invocation and no committed write past the cancel point.
	if got := ps.putCalls.Load(); got != calls {
		t.Fatalf("putCalls after cancel: %d, want %d", got, calls)
	}
	if got := ps.putCommitted.Load(); got != committed {
		t.Fatalf("committed writes after cancel: %d, want %d", got, committed)
	}
	// Every reader stayed at exactly one loaded chunk: zero file reads
	// were issued after the cancel.
	for i, r := range rec.snapshot() {
		if got := r.chunksLoaded(); got != 1 {
			t.Fatalf("reader %d loaded %d chunks after cancel, want 1", i, got)
		}
	}
	// No INDEX committed; state failed closed.
	if _, e := underlying.GetKey(context.Background(), ArtifactKey("ck", IndexName)); e == nil {
		t.Fatal("INDEX must not exist after cancellation")
	}
	st, _ := Status(dir)
	if st == nil || st.State != StatePublishFailed {
		t.Fatalf("state: %+v", st)
	}
	// Retry on a clean backend converges.
	fresh, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunWithOptions(context.Background(), dir, "ck", fresh, "s", opts); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, e := fresh.GetKey(context.Background(), ArtifactKey("ck", IndexName)); e != nil {
		t.Fatalf("retry INDEX: %v", e)
	}
}

// ---------------------------------------------------------------------------
// 5. Present hit still detects mutation
// ---------------------------------------------------------------------------

func TestStreamPresentHitStillDetectsMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	store := adaptiveStoreSingle(t)

	if _, err := RunWithOptions(context.Background(), dir, "ck", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks}); err != nil {
		t.Fatal(err)
	}

	orig, _ := os.ReadFile(filepath.Join(dir, "memory"))
	corrupt := append([]byte(nil), orig...)
	corrupt[3*256*1024+7] ^= 0xFF
	if err := os.WriteFile(filepath.Join(dir, "memory"), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := RunWithOptions(context.Background(), dir, "ck", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true})
	if err == nil {
		t.Fatal("mutation must be detected even when pack is present")
	}
	if !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected mutation error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 6. Sweep-marked pack refresh: real gc-marks/<key>, fence claim lifecycle
// ---------------------------------------------------------------------------

func TestStreamGCMarkRefresh(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(underlying)
	exp := expectedPackMap(t, dir, data, 4<<20)

	opts := Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true}
	first, err := RunWithOptions(context.Background(), dir, "ck", underlying, "s", opts)
	if err != nil {
		t.Fatal(err)
	}
	if int(first.PacksPut) != len(exp) {
		t.Fatalf("first publish PacksPut=%d, want %d", first.PacksPut, len(exp))
	}

	// Write a REAL sweep mark for every pack key the artifact produced.
	for key := range exp {
		if err := keyed.PutKey(context.Background(), GCMarkKey(key), strings.NewReader("marked")); err != nil {
			t.Fatal(err)
		}
	}

	second, err := RunWithOptions(context.Background(), dir, "ck", underlying, "s", opts)
	if err != nil {
		t.Fatalf("marked re-publish: %v", err)
	}
	// Every marked pack was fenced (skip=0) and re-PUT under its claim.
	if second.PacksSkip != 0 {
		t.Fatalf("marked packs must not be skipped: %+v", second)
	}
	if int(second.PacksPut) != len(exp) {
		t.Fatalf("marked re-publish PacksPut=%d, want %d", second.PacksPut, len(exp))
	}
	// Claim lifecycle closed: every claim was released after the re-PUT.
	for key := range exp {
		ok, err := keyed.HasKey(context.Background(), GCClaimKey(key))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("claim for %s leaked", key)
		}
	}
	// Object integrity after the refresh: exact expected bytes.
	for key, want := range exp {
		rc, err := keyed.GetKey(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("refreshed pack %s: got %d bytes, want %d", key, len(got), len(want))
		}
	}
	st, _ := Status(dir)
	if st == nil || st.State != StatePublished {
		t.Fatalf("state: %+v", st)
	}
}

// ---------------------------------------------------------------------------
// 7. Mid-body PUT failure against the REAL local backend: no half object
// ---------------------------------------------------------------------------

var errInjectedMidBody = errors.New("injected mid-body error")

// errorAfterReader passes through failAfter bytes, then fails.
type errorAfterReader struct {
	r      io.Reader
	remain int64
}

func (e *errorAfterReader) Read(p []byte) (int, error) {
	if e.remain <= 0 {
		return 0, errInjectedMidBody
	}
	if int64(len(p)) > e.remain {
		p = p[:e.remain]
	}
	n, err := e.r.Read(p)
	e.remain -= int64(n)
	return n, err
}

// midFailStore forwards everything, but the FIRST pack-object PutKey's body
// dies mid-stream inside the REAL local backend's copy.
type midFailStore struct {
	chunkstore.Store
	armed     atomic.Bool
	failAfter int64
	failedKey atomic.Value // string
}

func (s *midFailStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if isPackObjectKey(key) && s.armed.CompareAndSwap(true, false) {
		s.failedKey.Store(key)
		return s.Store.(chunkstore.Keyed).PutKey(ctx, key, &errorAfterReader{r: r, remain: s.failAfter})
	}
	return s.Store.(chunkstore.Keyed).PutKey(ctx, key, r)
}

func (s *midFailStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *midFailStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

func TestStreamMidPutFailureAtomicNoIndex(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(underlying)
	exp := expectedPackMap(t, dir, data, 4<<20)

	ms := &midFailStore{Store: underlying, failAfter: 100 * 1024}
	ms.armed.Store(true)
	opts := Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true}

	_, err = RunWithOptions(context.Background(), dir, "ck", ms, "s", opts)
	if err == nil || !strings.Contains(err.Error(), errInjectedMidBody.Error()) {
		t.Fatalf("run error = %v, want injected mid-body error", err)
	}
	failedKey, _ := ms.failedKey.Load().(string)
	if failedKey == "" {
		t.Fatal("no pack PUT was failed")
	}
	if _, ok := exp[failedKey]; !ok {
		t.Fatalf("failed key %s is not an expected pack key", failedKey)
	}
	// The real backend must NOT show the half-uploaded object.
	if ok, _ := keyed.HasKey(context.Background(), failedKey); ok {
		t.Fatal("half-uploaded pack object is visible after mid-body failure")
	}
	if _, e := keyed.GetKey(context.Background(), ArtifactKey("ck", IndexName)); e == nil {
		t.Fatal("INDEX must not exist after mid-body failure")
	}
	st, _ := Status(dir)
	if st == nil || st.State != StatePublishFailed {
		t.Fatalf("state: %+v", st)
	}

	// Retry on the SAME backend (failure no longer armed) converges to the
	// exact expected objects.
	if _, err := RunWithOptions(context.Background(), dir, "ck", ms, "s", opts); err != nil {
		t.Fatalf("retry: %v", err)
	}
	for key, want := range exp {
		rc, err := keyed.GetKey(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("retried pack %s: got %d bytes, want %d", key, len(got), len(want))
		}
	}
	if _, e := keyed.GetKey(context.Background(), ArtifactKey("ck", IndexName)); e != nil {
		t.Fatalf("retry INDEX: %v", e)
	}
}

// ---------------------------------------------------------------------------
// 8. Fresh-upload guard: mark appears after the first PUT → second PUT with
//    a FRESH reader, byte-identical body
// ---------------------------------------------------------------------------

// guardInjectStore tees every pack PUT body (to compare successive
// uploads) and plants a sweep mark on the first pack key the moment the
// fresh-upload guard probes it, forcing the guarded claim + re-PUT.
type guardInjectStore struct {
	chunkstore.Store
	mu           sync.Mutex
	bodies       map[string][][]byte
	firstPackKey string
	injected     bool
}

func (s *guardInjectStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if !isPackObjectKey(key) {
		return s.Store.(chunkstore.Keyed).PutKey(ctx, key, r)
	}
	s.mu.Lock()
	if s.firstPackKey == "" {
		s.firstPackKey = key
	}
	s.mu.Unlock()
	var tee bytes.Buffer
	if err := s.Store.(chunkstore.Keyed).PutKey(ctx, key, io.TeeReader(r, &tee)); err != nil {
		return err
	}
	s.mu.Lock()
	s.bodies[key] = append(s.bodies[key], tee.Bytes())
	s.mu.Unlock()
	return nil
}

func (s *guardInjectStore) HasKey(ctx context.Context, key string) (bool, error) {
	s.mu.Lock()
	first, injected := s.firstPackKey, s.injected
	s.mu.Unlock()
	if !injected && first != "" && key == GCMarkKey(first) {
		// The guard's probe for the first pack: plant the mark now, so it
		// observes a sweep-marked fresh upload.
		if err := s.Store.(chunkstore.Keyed).PutKey(ctx, key, strings.NewReader("marked")); err != nil {
			return false, err
		}
		s.mu.Lock()
		s.injected = true
		s.mu.Unlock()
	}
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

func (s *guardInjectStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *guardInjectStore) PutKeyIfAbsent(ctx context.Context, key string, body io.Reader) (bool, error) {
	return s.Store.(chunkstore.ExclusivePutter).PutKeyIfAbsent(ctx, key, body)
}

func (s *guardInjectStore) DeleteKeyIfMatch(ctx context.Context, key, etag string) (bool, error) {
	return s.Store.(chunkstore.ExclusivePutter).DeleteKeyIfMatch(ctx, key, etag)
}

func TestStreamGuardSecondPutFreshReader(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(underlying)
	exp := expectedPackMap(t, dir, data, 4<<20)

	gs := &guardInjectStore{Store: underlying, bodies: map[string][][]byte{}}
	rec := &streamRecorder{}
	res, err := RunWithOptions(context.Background(), dir, "ck", gs, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			PackStreamingPut: true, packStreamFactory: rec.factory()})
	if err != nil {
		t.Fatal(err)
	}
	if int(res.PacksPut) != len(exp) {
		t.Fatalf("PacksPut=%d, want %d", res.PacksPut, len(exp))
	}

	gs.mu.Lock()
	fk := gs.firstPackKey
	bodies := gs.bodies
	gs.mu.Unlock()
	if fk == "" {
		t.Fatal("no pack PUT observed")
	}
	// The guarded key was uploaded exactly TWICE, both bodies complete and
	// byte-identical to the expected pack — a reused (consumed) reader
	// would produce an EMPTY second body.
	fb := bodies[fk]
	if len(fb) != 2 {
		t.Fatalf("guarded pack PUT count=%d, want 2", len(fb))
	}
	for i, b := range fb {
		if !bytes.Equal(b, exp[fk]) {
			t.Fatalf("guarded PUT %d: %d bytes, want %d identical to expected", i, len(b), len(exp[fk]))
		}
	}
	// Every other pack was uploaded exactly once with exact bytes.
	for key, bs := range bodies {
		if key == fk {
			continue
		}
		if len(bs) != 1 || !bytes.Equal(bs[0], exp[key]) {
			t.Fatalf("pack %s: %d uploads", key, len(bs))
		}
	}
	// Reader instances: one per PUT plus the guard's re-PUT, each doing a
	// FULL pass (16 chunk loads) — the second body came from a fresh
	// reader, not a rewind of the consumed one.
	insts := rec.snapshot()
	if len(insts) != len(exp)+1 {
		t.Fatalf("reader instances=%d, want %d (one per PUT + guard re-PUT)", len(insts), len(exp)+1)
	}
	for i, r := range insts {
		if got := r.chunksLoaded(); got != 16 {
			t.Fatalf("reader %d loaded %d chunks, want 16 (full pass)", i, got)
		}
	}
	// Claim released; mark remains (publishers never remove marks).
	if ok, _ := keyed.HasKey(context.Background(), GCClaimKey(fk)); ok {
		t.Fatal("guard claim leaked")
	}
	if ok, _ := keyed.HasKey(context.Background(), GCMarkKey(fk)); !ok {
		t.Fatal("injected mark should persist after the guarded re-PUT")
	}
	// Backend object integrity.
	rc, err := keyed.GetKey(context.Background(), fk)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, exp[fk]) {
		t.Fatalf("final object: %d bytes, want %d", len(got), len(exp[fk]))
	}
}

// ---------------------------------------------------------------------------
// 9. Integration no-preread: full publish blocked at the store's first
//    chunk consumption, observed through the per-run reader factory
// ---------------------------------------------------------------------------

// firstPutHoldStore holds the FIRST pack PutKey after consuming exactly one
// chunk (signaling the test), then stores the full body and lets every
// later operation through untouched.
type firstPutHoldStore struct {
	chunkstore.Store
	entered chan struct{}
	gate    chan struct{}
	once    sync.Once
	stored  atomic.Int64
}

func (s *firstPutHoldStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	k := s.Store.(chunkstore.Keyed)
	if !isPackObjectKey(key) {
		return k.PutKey(ctx, key, r)
	}
	first := make([]byte, 256*1024)
	if _, err := io.ReadFull(r, first); err != nil {
		return err
	}
	s.once.Do(func() { close(s.entered) })
	<-s.gate
	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	full := append(first, rest...)
	if err := k.PutKey(ctx, key, bytes.NewReader(full)); err != nil {
		return err
	}
	s.stored.Add(1)
	return nil
}

func (s *firstPutHoldStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *firstPutHoldStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

func TestStreamPublishNoPrereadObserver(t *testing.T) {
	dir := t.TempDir()
	data := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(underlying)
	exp := expectedPackMap(t, dir, data, 4<<20)

	hs := &firstPutHoldStore{Store: underlying, entered: make(chan struct{}), gate: make(chan struct{})}
	rec := &streamRecorder{}
	opts := Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
		PackStreamingPut: true, Workers: 1, packStreamFactory: rec.factory()}

	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := RunWithOptions(context.Background(), dir, "ck", hs, "s", opts)
		done <- outcome{res, err}
	}()

	// Race-safe barrier wait: an early publish return (any error path that
	// never reaches a pack PUT) must FAIL loudly here, not hang the test.
	select {
	case <-hs.entered: // the store is consuming the FIRST pack's first chunk
	case out := <-done:
		t.Fatalf("publish returned before any pack PUT was held: err=%v res=%+v", out.err, out.res)
	}
	// Exactly ONE reader exists (Workers=1: no later pack was touched) and
	// it has loaded exactly ONE chunk (nothing later in the pack either).
	insts := rec.snapshot()
	if len(insts) != 1 || insts[0].chunksLoaded() != 1 {
		t.Fatalf("at first-chunk consumption: %d readers with loads %d — preread detected",
			len(insts), func() []int64 {
				var l []int64
				for _, r := range insts {
					l = append(l, r.chunksLoaded())
				}
				return l
			}())
	}
	close(hs.gate)
	out := <-done
	if out.err != nil {
		t.Fatal(out.err)
	}
	if hs.stored.Load() != int64(len(exp)) {
		t.Fatalf("stored packs=%d, want %d", hs.stored.Load(), len(exp))
	}
	// After the run: one reader per actually-uploaded pack (no guard
	// re-PUTs — nothing marked), each a full 16-chunk pass.
	insts = rec.snapshot()
	if len(insts) != int(out.res.PacksPut) {
		t.Fatalf("reader instances=%d, PacksPut=%d", len(insts), out.res.PacksPut)
	}
	if totalLoads(insts) != int64(out.res.PacksPut)*16 {
		t.Fatalf("total chunk loads=%d, want %d", totalLoads(insts), out.res.PacksPut*16)
	}
	for key, want := range exp {
		rc, err := keyed.GetKey(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("pack %s: got %d bytes, want %d", key, len(got), len(want))
		}
	}
}

// TestStreamInstrumentedRemotePutKeepsSeekerPath: through the PRODUCTION
// attribution layer over a real Remote backend, the streaming pack body
// must still take Remote.PutKey's Seeker path — the reader observes exactly
// its End+Start seek pair, and the server receives the full body with an
// explicit ContentLength. (Regression: planBodyCount once hid the Seeker
// behind a read-only counting wrapper, silently rerouting every
// instrumented streaming PUT into the buffered ReadAll path.)
func TestStreamInstrumentedRemotePutKeepsSeekerPath(t *testing.T) {
	var mu sync.Mutex
	bodies := map[string][]byte{}
	chunked := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		bodies[r.URL.Path] = body
		chunked[r.URL.Path] = r.ContentLength < 0
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()
	remote, err := chunkstore.Open(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	m := multiPackFixture(t, dir)
	mem, err := os.Open(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	var pc []checkpointchunks.Chunk
	var total int64
	for i, c := range m.Entries {
		if i >= 4 {
			break
		}
		pc = append(pc, c)
		total += int64(chunkByteLen(m, c))
	}
	r := newVerifiedPackReadSeeker(context.Background(), mem, m, pc)

	counters := &phaseCounters{}
	inst := instrumentStore(remote, counters)
	keyed, ok := inst.(chunkstore.Keyed)
	if !ok {
		t.Fatal("instrumented remote lost the Keyed surface")
	}
	if err := keyed.PutKey(context.Background(), "pack-inst", r); err != nil {
		t.Fatal(err)
	}
	// The Seeker path issues exactly the End+Start pair on the reader; the
	// buffered ReadAll fallback would issue ZERO seeks.
	if got := r.seeks.Load(); got != 2 {
		t.Fatalf("reader seeks = %d, want 2 (SeekEnd+SeekStart) — the Seeker path was lost", got)
	}
	mu.Lock()
	got, saw := bodies["/pack-inst"]
	wasChunked := chunked["/pack-inst"]
	mu.Unlock()
	if !saw || int64(len(got)) != total {
		t.Fatalf("server body = %d bytes (seen=%v), want %d", len(got), saw, total)
	}
	if wasChunked {
		t.Fatal("PUT arrived chunked (no ContentLength): the Seeker path was lost")
	}
	if snap := counters.snapshot(); snap.PutReqs != 1 || snap.PutBytes != total {
		t.Fatalf("instrument counters: putReqs=%d putBytes=%d, want 1 and %d", snap.PutReqs, snap.PutBytes, total)
	}
}

// ---------------------------------------------------------------------------
// 10. Composability, legacy fallback, default off, retry convergence
// ---------------------------------------------------------------------------

func TestStreamAutoBaseAdaptiveCombo(t *testing.T) {
	root := t.TempDir()
	store := adaptiveStoreSingle(t)
	publishParentPack(t, root, "combo-parent", store)
	child := adaptivePackedFixtureIn(t, root, "combo-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "combo-parent")

	res, err := RunWithOptions(context.Background(), child, "combo-child", store, "s",
		Options{
			PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks,
			PackStreamingPut: true, PackAutoBase: true, AdaptivePackThresholdBytes: 1,
		})
	if err != nil {
		t.Fatalf("combo: %v", err)
	}
	if res.LayoutDecision == nil || res.LayoutDecision.Chosen != layoutPack {
		t.Fatalf("adaptive: %+v", res.LayoutDecision)
	}
	if res.AutoBase == nil || !res.AutoBase.Used {
		t.Fatalf("auto-base: %+v", res.AutoBase)
	}
	if res.PacksSkip == 0 {
		t.Fatalf("must reuse parent packs: %+v", res)
	}
}

func TestStreamLegacyStillBuffers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	res, err := RunWithOptions(context.Background(), dir, "ck", adaptiveStoreSingle(t), "s",
		Options{PackBytes: 4 << 20, PackStreamingPut: true}) // no identity → legacy buffer path
	if err != nil {
		t.Fatalf("legacy+flag: %v", err)
	}
	if res.PacksPut == 0 {
		t.Fatal("must create packs")
	}
}

func TestStreamDefaultOff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), multiPackPattern(), 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	res, err := RunWithOptions(context.Background(), dir, "ck", adaptiveStoreSingle(t), "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks})
	if err != nil {
		t.Fatalf("default off: %v", err)
	}
	if res.PacksPut == 0 {
		t.Fatal("must create packs")
	}
}

func TestStreamRetryConvergence(t *testing.T) {
	dir := t.TempDir()
	orig := multiPackPattern()
	if err := os.WriteFile(filepath.Join(dir, "memory"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	multiPackFixture(t, dir)
	corrupt := append([]byte(nil), orig...)
	corrupt[7*256*1024+3] ^= 0xFF
	if err := os.WriteFile(filepath.Join(dir, "memory"), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	store := adaptiveStoreSingle(t)

	_, err := RunWithOptions(context.Background(), dir, "ck", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true})
	if err == nil {
		t.Fatal("corrupted must fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunWithOptions(context.Background(), dir, "ck", store, "s",
		Options{PackBytes: 4 << 20, PackIdentity: checkpointchunks.PackIdentityChunks, PackStreamingPut: true}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}
