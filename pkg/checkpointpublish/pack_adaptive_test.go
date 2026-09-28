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

// Adaptive layout selection tests. The boundary is written down and pinned
// here: actual missing bytes BELOW the threshold -> plain, at or above ->
// pack. The decision input is the single classification's ACTUAL missing
// bytes (missing + sweep-marked refresh), never a manifest estimate.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func adaptiveStore(t *testing.T) (chunkstore.Store, string) {
	t.Helper()
	// A private store per test: state lives beside the artifact dir, so the
	// store must not collide with fixtureCheckpoint's siblings.
	dir := t.TempDir()
	root := filepath.Join(dir, "store")
	store, err := chunkstore.NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	return store, root
}

func storeHasKey(t *testing.T, store chunkstore.Store, key string) bool {
	t.Helper()
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		t.Fatalf("store is not keyed")
	}
	rc, err := keyed.GetKey(context.Background(), key)
	if err != nil {
		return false
	}
	rc.Close()
	return true
}

func adaptiveStoreSingle(t *testing.T) chunkstore.Store {
	t.Helper()
	store, _ := adaptiveStore(t)
	return store
}

func storeHasAnyPack(t *testing.T, root string) bool {
	t.Helper()
	found := false
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == "memory-packs" {
			found = true
		}
		return nil
	})
	return found
}

// adaptivePackedFixture seals a checkpoint whose sidecar is in chunks
// digest mode with a matching Firecracker manifest — the artifact shape
// the packed stage requires (packedMemoryClosure).
func adaptivePackedFixture(t *testing.T, data []byte) string {
	t.Helper()
	return adaptivePackedFixtureIn(t, t.TempDir(), "ck-"+t.Name(), data)
}

// adaptivePackedFixtureIn is the same fixture under an explicit scan root
// and artifact ID (publishd rounds discover <root>/<id>).
func adaptivePackedFixtureIn(t *testing.T, root, id string, data []byte) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := checkpointchunks.Compute(context.Background(), dir, checkpointchunks.DefaultChunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	// The LOCAL sealed sidecar stays version 1 (version 2 is the packed
	// transport view); chunks digest mode with the entries root digest is
	// what packedMemoryClosure requires.
	m.FileDigestMode = checkpointchunks.FileDigestChunks
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointchunks.ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fc := map[string]any{
		"version": 2, "snapshot_type": "SoftDirty", "memory_size": m.FileSize,
		"memory_digest_mode": checkpointchunks.FileDigestChunks,
		"digests":            map[string]string{"memory": m.FileDigest},
	}
	fcRaw, err := json.Marshal(fc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), fcRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vmstate-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), []byte("overlay-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func adaptivePatternData() []byte {
	data := make([]byte, 300<<10)
	for i := range data {
		data[i] = byte(i * 3)
	}
	return data
}

// Boundary semantics: below threshold -> plain; at or above -> pack. The
// fixture is 300KiB of non-zero data over two unique chunks, so the actual
// missing bytes on a cold store equal the file size.
func TestAdaptiveBoundaryChoosesPlainBelowAndPackAtOrAbove(t *testing.T) {
	const total = 300 << 10 // matches the fixture's unique non-zero bytes
	dir := adaptivePackedFixture(t, adaptivePatternData())

	belowStore, _ := adaptiveStore(t)
	below, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), belowStore, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: total + 1,
	})
	if err != nil {
		t.Fatalf("below-threshold run: %v", err)
	}
	if below.LayoutDecision == nil || below.LayoutDecision.Chosen != layoutPlain {
		t.Fatalf("below threshold must choose plain: %+v", below.LayoutDecision)
	}
	if below.LayoutDecision.ActualMissingBytes == nil || *below.LayoutDecision.ActualMissingBytes != total ||
		below.LayoutDecision.ActualMissingChunks == nil || *below.LayoutDecision.ActualMissingChunks != 2 {
		t.Fatalf("actual missing = %+v, want %d / 2", below.LayoutDecision, total)
	}
	if below.LayoutDecision.Reason != layoutReasonBelow {
		t.Fatalf("below-threshold reason: %+v", below.LayoutDecision)
	}
	if below.Phases != nil && below.Phases.PackWall > 0 {
		t.Fatalf("plain layout must not run the packed stage: %+v", below.Phases)
	}
	if st, _ := Status(dir); st == nil || st.Layout != layoutPlain {
		t.Fatalf("state must record the plain layout: %+v", st)
	}

	atDir := adaptivePackedFixture(t, adaptivePatternData())
	atStore, _ := adaptiveStore(t)
	at, err := RunWithOptions(context.Background(), atDir, filepath.Base(atDir), atStore, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: total, // exactly at the threshold -> pack
	})
	if err != nil {
		t.Fatalf("at-threshold run: %v", err)
	}
	if at.LayoutDecision == nil || at.LayoutDecision.Chosen != layoutPack || at.LayoutDecision.Reason != layoutReasonAtOrAbove {
		t.Fatalf("at threshold must choose pack: %+v", at.LayoutDecision)
	}
	if at.PacksPut == 0 {
		t.Fatalf("pack layout uploaded no packs: %+v", at)
	}
}

// A warm store must measure ACTUAL missing bytes, not the manifest total:
// after a plain publish every chunk is present, so even a 1-byte threshold
// keeps the plain layout and uploads nothing.
func TestAdaptiveWarmStoreMeasuresActualNotExpected(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, root := adaptiveStore(t)
	if _, err := Run(context.Background(), dir, filepath.Base(dir), store, "s"); err != nil {
		t.Fatal(err)
	}
	warm, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // any missing byte would pack
	})
	if err != nil {
		t.Fatalf("warm adaptive run: %v", err)
	}
	if warm.LayoutDecision == nil || warm.LayoutDecision.Chosen != layoutPlain ||
		warm.LayoutDecision.ActualMissingBytes == nil || *warm.LayoutDecision.ActualMissingBytes != 0 ||
		warm.LayoutDecision.ActualMissingChunks == nil || *warm.LayoutDecision.ActualMissingChunks != 0 {
		t.Fatalf("warm store must MEASURE zero missing (explicit zeros, not omitted): %+v", warm.LayoutDecision)
	}
	if warm.ChunksPut != 0 || warm.ChunksSkip == 0 {
		t.Fatalf("warm adaptive run re-uploaded: put=%d skip=%d", warm.ChunksPut, warm.ChunksSkip)
	}
	if storeHasAnyPack(t, root) {
		t.Fatalf("warm plain rerun must not produce pack objects")
	}
}

// Sweep-marked objects count as missing (they must be re-uploaded), and the
// plain layout refreshes them under the fence claim exactly like the
// non-adaptive path.
func TestAdaptivePlainRefreshesSweepMarkedReuse(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, _ := adaptiveStore(t)
	first, err := Run(context.Background(), dir, filepath.Base(dir), store, "s")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		t.Fatalf("store is not keyed")
	}
	for _, entry := range manifest.Entries {
		if err := keyed.PutKey(context.Background(), GCMarkKey(chunkstore.PlainKey(entry.Digest)), strings.NewReader("marked")); err != nil {
			t.Fatal(err)
		}
	}
	refreshed, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // far above: stays plain
	})
	if err != nil {
		t.Fatalf("marked adaptive rerun: %v", err)
	}
	if refreshed.LayoutDecision == nil || refreshed.LayoutDecision.Chosen != layoutPlain {
		t.Fatalf("marked rerun layout: %+v", refreshed.LayoutDecision)
	}
	if refreshed.LayoutDecision.ActualMissingBytes == nil || *refreshed.LayoutDecision.ActualMissingBytes != 300<<10 {
		t.Fatalf("sweep-marked chunks must count as missing: %+v", refreshed.LayoutDecision)
	}
	if refreshed.ChunksPut != first.ChunksPut || refreshed.ChunksSkip != 0 {
		t.Fatalf("marked reuse not refreshed: put=%d skip=%d want put=%d skip=0",
			refreshed.ChunksPut, refreshed.ChunksSkip, first.ChunksPut)
	}
}

// The all-zero chunk is never classified uploadable: neither layout writes
// its object, and the reader contract materializes zero blocks as holes.
func TestAdaptiveNeverUploadsZeroChunk(t *testing.T) {
	data := make([]byte, 512<<10) // one non-zero chunk + one all-zero chunk
	data[0] = 1
	dir := adaptivePackedFixture(t, data)
	store, _ := adaptiveStore(t)
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // everything missing would pack
	})
	if err != nil {
		t.Fatalf("zero-chunk adaptive run: %v", err)
	}
	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var zeroDigest string
	for _, e := range manifest.Entries {
		if e.Digest == checkpointchunks.ZeroChunkDigest(manifest.ChunkBytes) {
			zeroDigest = e.Digest
		}
	}
	if zeroDigest == "" {
		t.Fatalf("fixture lost its zero chunk")
	}
	if res.LayoutDecision == nil || res.LayoutDecision.ActualMissingBytes == nil ||
		*res.LayoutDecision.ActualMissingBytes != int64(manifest.ChunkBytes) {
		t.Fatalf("zero chunk must not count as missing: %+v", res.LayoutDecision)
	}
	if storeHasKey(t, store, chunkstore.PlainKey(zeroDigest)) {
		t.Fatalf("plain object for the all-zero chunk must not be written")
	}
}

// Inherited holes keep their fail-closed semantics at the classification
// point: a missing parent object aborts the attempt before any layout runs.
func TestAdaptiveInheritedHoleFailsClosed(t *testing.T) {
	dir := fixtureCheckpoint(t)
	if _, err := Run(context.Background(), dir, filepath.Base(dir), adaptiveStoreSingle(t), "s"); err != nil {
		t.Fatal(err)
	}
	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Turn one entry into an inherited hole whose parent object is absent.
	manifest.Entries[0].Inherited = true
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointchunks.ManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	inhStore, _ := adaptiveStore(t)
	_, err = RunWithOptions(context.Background(), dir, filepath.Base(dir), inhStore, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 20,
	})
	if err == nil || !strings.Contains(err.Error(), "parent generation's object must be republished") {
		t.Fatalf("inherited hole must fail closed, got %v", err)
	}
}

// The opt-in feature rejects (rather than silently ignores) every flag
// combination that would change or bypass its probing semantics.
func TestAdaptiveExclusionsRejected(t *testing.T) {
	dir := fixtureCheckpoint(t)
	excStore, _ := adaptiveStore(t)
	cases := []struct {
		name string
		opts Options
	}{
		{"no pack size", Options{AdaptivePackThresholdBytes: 1}},
		{"compress", Options{PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1, CompressChunks: true}},
		{"base id", Options{PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1, BaseID: "other"}},
		{"skip probe", Options{PackBytes: 4 << 20, AdaptivePackThresholdBytes: 1, PackSkipChunkProbe: true}},
	}
	for _, tc := range cases {
		if _, err := RunWithOptions(context.Background(), dir, "x", excStore, "s", tc.opts); err == nil {
			t.Fatalf("%s: combination must be rejected", tc.name)
		}
	}
}

// The decision is sticky per artifact: a retry reuses the recorded layout
// even when a different threshold would now choose the other side, so one
// artifact never mixes layouts across attempts.
func TestAdaptiveLayoutStickyAcrossRetries(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, root := adaptiveStore(t)
	first, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // plain
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.LayoutDecision.Chosen != layoutPlain {
		t.Fatalf("first decision: %+v", first.LayoutDecision)
	}
	sticky, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // would pack on a fresh decision
	})
	if err != nil {
		t.Fatalf("sticky retry: %v", err)
	}
	if sticky.LayoutDecision.Chosen != layoutPlain || sticky.LayoutDecision.Reason != layoutReasonSticky {
		t.Fatalf("retry must reuse the recorded layout: %+v", sticky.LayoutDecision)
	}
	if sticky.LayoutDecision.ActualMissingBytes != nil || sticky.LayoutDecision.ActualMissingChunks != nil {
		t.Fatalf("sticky retry did not measure — actual fields must be omitted, not zero: %+v", sticky.LayoutDecision)
	}
	if enc, err := json.Marshal(sticky.LayoutDecision); err != nil || strings.Contains(string(enc), "actual_missing") {
		t.Fatalf("sticky retry telemetry must omit actual_missing fields: %s (%v)", enc, err)
	}
	if storeHasAnyPack(t, root) {
		t.Fatalf("sticky plain retry must not produce pack objects")
	}
}

// Old state files (written before the feature, or with it off) carry no
// layout and decide afresh when the feature is enabled.
func TestAdaptiveDecidesFreshAfterLegacyState(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, _ := adaptiveStore(t)
	legacy, err := Run(context.Background(), dir, filepath.Base(dir), store, "s")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.LayoutDecision != nil {
		t.Fatalf("non-adaptive run must not record a decision")
	}
	st, err := Status(dir)
	if err != nil || st.Layout != "" {
		t.Fatalf("legacy state must carry no layout: %+v err=%v", st, err)
	}
	fresh, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // everything present -> plain
	})
	if err != nil {
		t.Fatalf("fresh adaptive decision: %v", err)
	}
	if fresh.LayoutDecision == nil || fresh.LayoutDecision.Chosen != layoutPlain ||
		fresh.LayoutDecision.ActualMissingBytes == nil || *fresh.LayoutDecision.ActualMissingBytes != 0 {
		t.Fatalf("legacy state must allow a fresh (measured) decision: %+v", fresh.LayoutDecision)
	}
}

// Feature off = byte-identical legacy behavior: explicit -pack-mib forces
// packing through the inline classification, zero keeps plain.
func TestAdaptiveOffKeepsExplicitSemantics(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	store, _ := adaptiveStore(t)
	packed, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s", Options{PackBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if packed.LayoutDecision != nil || packed.PacksPut == 0 {
		t.Fatalf("forced pack must stay forced: decision=%+v packs=%d", packed.LayoutDecision, packed.PacksPut)
	}
	if st, _ := Status(dir); st.Layout != "" {
		t.Fatalf("non-adaptive pack must not stamp a layout: %+v", st)
	}
	dir2 := fixtureCheckpoint(t)
	plain, err := Run(context.Background(), dir2, filepath.Base(dir2), adaptiveStoreSingle(t), "s")
	if err != nil {
		t.Fatal(err)
	}
	if plain.LayoutDecision != nil || plain.PacksPut != 0 || plain.ChunksPut != 2 {
		t.Fatalf("default run must be unchanged: %+v", plain)
	}
}

// A first attempt that decided plain and then failed must not be flipped
// to pack by the retry: the recorded layout is authoritative even across a
// publish_failed -> retry transition, and the retry telemetry carries
// reason=sticky_retry with the actual fields omitted.
func TestAdaptiveStickyPlainSurvivesFailedAttempt(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	failStore := newFailingPutStore(adaptiveStoreSingle(t), 1)
	_, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), failStore, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // fresh decision: plain
	})
	if err == nil {
		t.Fatalf("injected PUT failure must fail the first attempt")
	}
	st, err := Status(dir)
	if err != nil || st == nil || st.Layout != layoutPlain || st.State != StatePublishFailed {
		t.Fatalf("failed attempt must record layout=plain state=failed: %+v err=%v", st, err)
	}
	store2 := adaptiveStoreSingle(t)
	retry, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store2, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // a fresh decision would pack
	})
	if err != nil {
		t.Fatalf("sticky retry after failure: %v", err)
	}
	if retry.LayoutDecision == nil || retry.LayoutDecision.Chosen != layoutPlain || retry.LayoutDecision.Reason != layoutReasonSticky {
		t.Fatalf("retry must stay plain (sticky): %+v", retry.LayoutDecision)
	}
	if retry.LayoutDecision.ActualMissingBytes != nil {
		t.Fatalf("sticky retry must omit actual fields: %+v", retry.LayoutDecision)
	}
	if retry.PacksPut != 0 {
		t.Fatalf("sticky plain retry must not pack: %+v", retry)
	}
}

// failingPutStore fails the first N Puts after delegating everything
// else (including the Keyed capability — the publish path requires it),
// so an attempt dies mid-upload with a recorded publishing/failed state.
type failingPutStore struct {
	chunkstore.Store
	keyed    chunkstore.Keyed
	failNext atomic.Int32
}

func newFailingPutStore(inner chunkstore.Store, n int) *failingPutStore {
	s := &failingPutStore{Store: inner, keyed: inner.(chunkstore.Keyed)}
	s.failNext.Store(int32(n))
	return s
}

// Put is called from the plain upload pool and PutKey from the packed
// stage (keyed uploads): the shared atomic countdown fails the first N of
// either, so both layouts can die mid-attempt.
func (f *failingPutStore) Put(ctx context.Context, digest string, r io.Reader) error {
	if f.failNext.Add(-1) >= 0 {
		return fmt.Errorf("injected put failure %s", digest[:8])
	}
	return f.Store.Put(ctx, digest, r)
}

func (f *failingPutStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	// Only DATA keys fail: the gc- control namespace (publication intents,
	// claims, marks) is the attempt's own bookkeeping and runs BEFORE the
	// adaptive classification — failing there would kill the attempt
	// before any layout decision exists, which is not the scenario under
	// test.
	if !strings.HasPrefix(key, "gc-") && f.failNext.Add(-1) >= 0 {
		return fmt.Errorf("injected put-key failure %s", key)
	}
	return f.keyed.PutKey(ctx, key, r)
}

func (f *failingPutStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return f.keyed.GetKey(ctx, key)
}

func (f *failingPutStore) HasKey(ctx context.Context, key string) (bool, error) {
	return f.keyed.HasKey(ctx, key)
}

// Configuration drift must not silently change a decided artifact's
// layout: a failed adaptive-plain attempt followed by a run with adaptive
// OFF (but pack configured) is refused before any store IO — the artifact
// never enters the packed stage and the second store stays empty.
func TestAdaptiveLayoutDriftConfigRejected(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	failStore := newFailingPutStore(adaptiveStoreSingle(t), 1)
	_, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), failStore, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // fresh decision: plain
	})
	if err == nil {
		t.Fatalf("injected failure must fail the first attempt")
	}
	st, _ := Status(dir)
	if st == nil || st.Layout != layoutPlain || st.State != StatePublishFailed {
		t.Fatalf("first attempt must leave layout=plain failed state: %+v", st)
	}
	driftStore, driftRoot := adaptiveStore(t)
	_, err = RunWithOptions(context.Background(), dir, filepath.Base(dir), driftStore, "s", Options{
		PackBytes: 4 << 20, // adaptive OFF: the old forced-pack path
	})
	if err == nil || !strings.Contains(err.Error(), "adaptive off") {
		t.Fatalf("drift run must be refused with the remedy named, got %v", err)
	}
	if storeHasAnyPack(t, driftRoot) {
		t.Fatalf("refused drift run must not write pack objects")
	}
	if n := storeObjectCount(t, driftRoot); n != 0 {
		t.Fatalf("refused drift run must write nothing, found %d objects", n)
	}
	after, _ := Status(dir)
	if after == nil || after.Layout != layoutPlain || after.State != StatePublishFailed {
		t.Fatalf("refused run must leave the recorded state untouched: %+v", after)
	}
}

// A corrupted layout string in the persisted state is refused before any
// store IO — never silently treated as plain.
func TestAdaptiveCorruptLayoutRejected(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	stateDir := filepath.Join(filepath.Dir(dir), ".publish")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(dir)
	corrupt := map[string]any{"checkpoint_id": id, "dir": dir, "state": StatePublishFailed, "layout": "quantum"}
	raw, _ := json.Marshal(corrupt)
	if err := os.WriteFile(filepath.Join(stateDir, id+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, root := adaptiveStore(t)
	_, err := RunWithOptions(context.Background(), dir, id, store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 20,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown layout") {
		t.Fatalf("corrupt layout must be refused, got %v", err)
	}
	if n := storeObjectCount(t, root); n != 0 {
		t.Fatalf("refused corrupt-layout run must write nothing, found %d objects", n)
	}
}

// The MiB→bytes conversion bounds-checks BEFORE the shift: negative,
// above-max, and wrap-inducing values are rejected instead of silently
// becoming 0 or a negative threshold.
func TestAdaptiveMiBToBytesBounds(t *testing.T) {
	const maxMiB = maxAdaptiveThresholdBytes >> 20
	if v, err := AdaptiveMiBToBytes(0); err != nil || v != 0 {
		t.Fatalf("0 must map to off: %d %v", v, err)
	}
	if v, err := AdaptiveMiBToBytes(1); err != nil || v != 1<<20 {
		t.Fatalf("1 MiB: %d %v", v, err)
	}
	if v, err := AdaptiveMiBToBytes(maxMiB); err != nil || v != maxAdaptiveThresholdBytes {
		t.Fatalf("max: %d %v", v, err)
	}
	for _, bad := range []int64{maxMiB + 1, -1, 1 << 62} {
		if v, err := AdaptiveMiBToBytes(bad); err == nil || v != 0 {
			t.Fatalf("%d must be rejected before the shift: %d %v", bad, v, err)
		}
	}
}

func storeObjectCount(t *testing.T, root string) int {
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

// Cross-label republishing is a SUPPORTED flow (see claim_test's owner/retry
// and pack_publish_test's base/warm): one directory may be published under a
// new id, resuming the same per-directory state. This pins that the state
// machine stays directory-scoped — including for a layout an adaptive run
// recorded: the layout binds the DIRECTORY, whichever label republishes it.
func TestAdaptiveCrossLabelRepublishAllowed(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	store := adaptiveStoreSingle(t) // ONE store: relabeling is a republish, not a migration
	if _, err := RunWithOptions(context.Background(), dir, "first-label", store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // plain
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := Status(dir)
	if st == nil || st.CheckpointID != "first-label" || st.Layout != layoutPlain {
		t.Fatalf("first publish state = %+v", st)
	}
	// Republish under a new label with the same adaptive settings: allowed,
	// sticky plain, zero uploads.
	relabel, err := RunWithOptions(context.Background(), dir, "second-label", store, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40,
	})
	if err != nil {
		t.Fatalf("cross-label republish: %v", err)
	}
	if relabel.LayoutDecision == nil || relabel.LayoutDecision.Chosen != layoutPlain || relabel.LayoutDecision.Reason != layoutReasonSticky {
		t.Fatalf("cross-label republish must stay sticky plain: %+v", relabel.LayoutDecision)
	}
	if relabel.ChunksPut != 0 {
		t.Fatalf("cross-label republish re-uploaded: %+v", relabel)
	}
	// The state now names the latest label, still layout=plain.
	st2, _ := Status(dir)
	if st2 == nil || st2.CheckpointID != "second-label" || st2.Layout != layoutPlain {
		t.Fatalf("relabeled state = %+v", st2)
	}
}

// The pack side of the failure-retry contract: an attempt that decided pack
// and died mid-pack-PUT must stay pack on the retry even when the new
// threshold would pick plain — and the sticky retry re-classifies inline
// (its probes are never skipped), re-packing what the failed attempt
// managed to upload.
func TestAdaptiveStickyPackSurvivesFailedAttempt(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	underDir := t.TempDir()
	underlying, err := chunkstore.NewLocal(underDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), newFailingPutStore(underlying, 1), "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1, // fresh decision: pack
	}); err == nil {
		t.Fatalf("injected pack-put failure must fail the first attempt")
	}
	st, _ := Status(dir)
	if st == nil || st.State != StatePublishFailed || st.Layout != layoutPack {
		t.Fatalf("failed pack attempt state = %+v", st)
	}
	retry, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), underlying, "s", Options{
		PackBytes:                  4 << 20,
		AdaptivePackThresholdBytes: 1 << 40, // a fresh decision would pick plain
	})
	if err != nil {
		t.Fatalf("sticky pack retry: %v", err)
	}
	if retry.LayoutDecision == nil || retry.LayoutDecision.Chosen != layoutPack || retry.LayoutDecision.Reason != layoutReasonSticky {
		t.Fatalf("retry must stay pack (sticky): %+v", retry.LayoutDecision)
	}
	if retry.PacksPut == 0 {
		t.Fatalf("sticky pack retry must actually pack: %+v", retry)
	}
	if st2, _ := Status(dir); st2 == nil || st2.State != StatePublished || st2.Layout != layoutPack {
		t.Fatalf("published state must keep layout=pack: %+v", st2)
	}
}
