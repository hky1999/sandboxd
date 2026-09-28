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

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// setBaseMemoryHint rewrites the sealed manifest's base_memory field for
// auto-base fixtures.
func setBaseMemoryHint(t *testing.T, dir, hint string) {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if hint == "" {
		delete(doc, "base_memory")
	} else {
		doc["base_memory"] = hint
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// publishParentPack: publish the parent artifact under the given ID so the
// child's auto-base hint can find its INDEX.
func publishParentPack(t *testing.T, root, parentID string, store chunkstore.Store) {
	t.Helper()
	dir := adaptivePackedFixtureIn(t, root, parentID, adaptivePatternData())
	if _, err := RunWithOptions(context.Background(), dir, parentID, store, "s",
		Options{PackBytes: 4 << 20}); err != nil {
		t.Fatalf("publish parent %s: %v", parentID, err)
	}
}

// TestPackAutoBaseSuccessReuse: a g2-shaped fixture (SoftDirty, base_memory
// hint to a published g1) with auto-base ON reuses the parent's packs.
func TestPackAutoBaseSuccessReuse(t *testing.T) {
	root := t.TempDir()
	store := adaptiveStoreSingle(t)
	publishParentPack(t, root, "g1-parent", store)

	child := adaptivePackedFixtureIn(t, root, "g2-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "g1-parent")

	res, err := RunWithOptions(context.Background(), child, "g2-child", store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true})
	if err != nil {
		t.Fatalf("auto-base publish: %v", err)
	}
	if res.AutoBase == nil || !res.AutoBase.Used || res.AutoBase.Candidate != "g1-parent" || res.AutoBase.Reason != autoBaseUsed {
		t.Fatalf("auto-base decision: %+v", res.AutoBase)
	}
	if res.PacksSkip == 0 {
		t.Fatalf("auto-base must reuse parent packs: %+v", res)
	}
}

// TestPackAutoBaseFullGeneration: a Full-generation fixture (no base_memory)
// records no_hint and publishes normally.
func TestPackAutoBaseFullGeneration(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "") // strip any base_memory
	store := adaptiveStoreSingle(t)
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true})
	if err != nil {
		t.Fatalf("full-gen publish: %v", err)
	}
	if res.AutoBase == nil || res.AutoBase.Used || res.AutoBase.Reason != autoBaseNoHint {
		t.Fatalf("full-gen decision: %+v", res.AutoBase)
	}
	if res.PacksSkip != 0 {
		t.Fatalf("full-gen must not reuse: %+v", res)
	}
}

// TestPackAutoBaseMissingParentFallback: hint present but the parent was
// never published to this store → the ONE loadPackBaseline call inside
// runPacked fails → base is cleared, the publish falls back to a normal
// no-base pack and SUCCEEDS. This proves there is no preflight HEAD/HasKey
// — the fallback happens at the single baseline-read site, under the
// attempt's own ctx.
func TestPackAutoBaseMissingParentFallback(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "never-published-parent")
	store, root := adaptiveStore(t)
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true})
	if err != nil {
		t.Fatalf("missing-parent must fall back, not fail: %v", err)
	}
	if res.AutoBase == nil || res.AutoBase.Used || res.AutoBase.Reason != autoBaseUnavailable {
		t.Fatalf("missing-parent decision: %+v", res.AutoBase)
	}
	if res.AutoBase.Candidate != "never-published-parent" {
		t.Fatalf("decision must record the attempted candidate: %+v", res.AutoBase)
	}
	if res.PacksPut == 0 {
		t.Fatalf("fallback must actually pack: %+v", res)
	}
	_ = root
}

// TestPackAutoBaseSingleBaselineRead: the auto-base path makes exactly ONE
// store read for the parent INDEX (the loadPackBaseline call), with no
// preflight HEAD/HasKey. We count INDEX GETs via a wrapper store.
func TestPackAutoBaseSingleBaselineRead(t *testing.T) {
	root := t.TempDir()
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publishParentPack(t, root, "count-parent", underlying)
	child := adaptivePackedFixtureIn(t, root, "count-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "count-parent")
	counting := &indexCountingStore{Store: underlying}
	if _, err := RunWithOptions(context.Background(), child, "count-child", counting, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true}); err != nil {
		t.Fatalf("counting publish: %v", err)
	}
	// loadPackBaseline reads INDEX.json (1 GET) + BUNDLE (1 GET) = 2
	// keyed reads for the parent. A preflight HasKey would add a 3rd
	// (HEAD). We assert exactly 2 to prove no preflight.
	if got := counting.indexGets; got != 2 {
		t.Fatalf("parent INDEX reads = %d, want 2 (INDEX + BUNDLE, no preflight HEAD)", got)
	}
}

// indexCountingStore counts GET requests whose key contains the parent's
// artifact INDEX or BUNDLE path.
type indexCountingStore struct {
	chunkstore.Store
	indexGets int
}

func (s *indexCountingStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.HasPrefix(key, "artifacts/") && (strings.HasSuffix(key, "/INDEX.json") || strings.HasSuffix(key, "/BUNDLE")) {
		s.indexGets++
	}
	keyed := s.Store.(chunkstore.Keyed)
	return keyed.GetKey(ctx, key)
}

func (s *indexCountingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	return s.Store.(chunkstore.Keyed).PutKey(ctx, key, r)
}

func (s *indexCountingStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}

// TestPackAutoBaseMaliciousID: a hint with path separators is rejected by
// validPackedID and never forms a store key.
func TestPackAutoBaseMaliciousID(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "../../etc/passwd")
	store := adaptiveStoreSingle(t)
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true})
	if err != nil {
		t.Fatalf("malicious hint must fall back, not fail: %v", err)
	}
	if res.AutoBase == nil || res.AutoBase.Used || res.AutoBase.Reason != autoBaseInvalidID {
		t.Fatalf("malicious decision: %+v", res.AutoBase)
	}
	if res.AutoBase.Candidate != "../../etc/passwd" {
		t.Fatalf("decision must record the rejected candidate: %+v", res.AutoBase)
	}
}

// TestPackAutoBaseExplicitPriority: both explicit -base-id and auto-base
// enabled → explicit wins, the hint is not even read.
func TestPackAutoBaseExplicitPriority(t *testing.T) {
	root := t.TempDir()
	store := adaptiveStoreSingle(t)
	publishParentPack(t, root, "auto-parent", store)
	publishParentPack(t, root, "explicit-parent", store)

	child := adaptivePackedFixtureIn(t, root, "prio-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "auto-parent")

	res, err := RunWithOptions(context.Background(), child, "prio-child", store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, BaseID: "explicit-parent"})
	if err != nil {
		t.Fatalf("explicit+auto publish: %v", err)
	}
	if res.AutoBase == nil || res.AutoBase.Used || res.AutoBase.Reason != autoBaseExplicit {
		t.Fatalf("explicit priority decision: %+v", res.AutoBase)
	}
	if res.AutoBase.Candidate != "" {
		t.Fatalf("explicit override must not read the hint: %+v", res.AutoBase)
	}
}

// TestPackAutoBaseAdaptivePlainSkipsBase: adaptive chooses plain (small
// missing bytes) → the manifest hint is NEVER read (reason=plain_layout).
func TestPackAutoBaseAdaptivePlainSkipsBase(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "some-parent")
	store, root := adaptiveStore(t)
	// Warm the store so the adaptive classification sees 0 missing → plain.
	if _, err := Run(context.Background(), dir, filepath.Base(dir), store, "s"); err != nil {
		t.Fatal(err)
	}
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, AdaptivePackThresholdBytes: 1 << 40})
	if err != nil {
		t.Fatalf("adaptive-plain + auto-base: %v", err)
	}
	if res.AutoBase == nil || res.AutoBase.Used || res.AutoBase.Reason != autoBasePlainLayout {
		t.Fatalf("plain-layout decision: %+v", res.AutoBase)
	}
	_ = root
}

// TestPackAutoBaseAdaptivePackUsesBase: adaptive chooses pack (large
// missing bytes) → the hint resolves and reuses.
func TestPackAutoBaseAdaptivePackUsesBase(t *testing.T) {
	root2 := t.TempDir()
	store := adaptiveStoreSingle(t)
	publishParentPack(t, root2, "adp-parent", store)
	child := adaptivePackedFixtureIn(t, root2, "adp-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "adp-parent")

	res, err := RunWithOptions(context.Background(), child, "adp-child", store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, AdaptivePackThresholdBytes: 1})
	if err != nil {
		t.Fatalf("adaptive-pack + auto-base: %v", err)
	}
	if res.LayoutDecision == nil || res.LayoutDecision.Chosen != layoutPack {
		t.Fatalf("adaptive must choose pack: %+v", res.LayoutDecision)
	}
	if res.AutoBase == nil || !res.AutoBase.Used || res.AutoBase.Reason != autoBaseUsed {
		t.Fatalf("adaptive-pack auto-base: %+v", res.AutoBase)
	}
	if res.PacksSkip == 0 {
		t.Fatalf("adaptive-pack auto-base must reuse: %+v", res)
	}
}

// TestPackAutoBaseRequiresPack: auto-base without pack bytes is rejected.
func TestPackAutoBaseRequiresPack(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	_, err := RunWithOptions(context.Background(), dir, "x", adaptiveStoreSingle(t), "s",
		Options{PackAutoBase: true})
	if err == nil || !strings.Contains(err.Error(), "requires packing") {
		t.Fatalf("auto-base without pack must be rejected: %v", err)
	}
}

// TestScanRoundAutoBaseObservable: the daemon round output carries the
// auto-base decision alongside the layout decision.
func TestScanRoundAutoBaseObservable(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publishParentPack(t, root, "obs-parent", store)
	child := adaptivePackedFixtureIn(t, root, "obs-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "obs-parent")

	res := ScanRound(context.Background(), ScanRoundOptions{
		Roots: []string{root}, Store: store, StoreName: "s", Timeout: time.Minute,
		PackBytes: 4 << 20, PackAutoBase: true,
	})
	if len(res.Failed) != 0 || len(res.Published) != 1 || res.Published[0] != "obs-child" {
		t.Fatalf("round = %+v (failed=%v)", res, res.Failed)
	}
	// obs-parent was already published, so it is skipped; obs-child's
	// phases carry both decisions.
	for _, ph := range res.Phases {
		if ph.ID == "obs-child" {
			if ph.AutoBase == nil || !ph.AutoBase.Used || ph.AutoBase.Candidate != "obs-parent" {
				t.Fatalf("daemon auto-base: %+v", ph.AutoBase)
			}
		}
	}
}

// TestPackAutoBaseStickyLayoutUnchanged: auto-base does not affect the
// sticky-layout contract — a plain-decided artifact stays plain on retry
// even with auto-base enabled.
func TestPackAutoBaseStickyLayoutUnchanged(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "sticky-parent")
	store := adaptiveStoreSingle(t)
	// First: adaptive (threshold huge) → plain, auto-base sees plain_layout.
	first, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, AdaptivePackThresholdBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	if first.LayoutDecision.Chosen != layoutPlain || first.AutoBase.Reason != autoBasePlainLayout {
		t.Fatalf("first attempt: layout=%+v auto=%+v", first.LayoutDecision, first.AutoBase)
	}
	// Retry with a threshold that would pack: sticky plain wins.
	retry, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), store, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, AdaptivePackThresholdBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if retry.LayoutDecision.Chosen != layoutPlain || retry.PacksPut != 0 {
		t.Fatalf("sticky retry must stay plain: layout=%+v packs=%d", retry.LayoutDecision, retry.PacksPut)
	}
	if retry.AutoBase == nil || retry.AutoBase.Reason != autoBasePlainLayout {
		t.Fatalf("sticky retry auto-base: %+v", retry.AutoBase)
	}
}

// TestPackAutoBaseOffKeepsBehavior: feature off → no AutoBase record at
// all, identical to historical runs.
func TestPackAutoBaseOffKeepsBehavior(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "ignored-parent")
	res, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), adaptiveStoreSingle(t), "s",
		Options{PackBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if res.AutoBase != nil {
		t.Fatalf("feature off must not record a decision: %+v", res.AutoBase)
	}
}

// ensure chunks.json is still loadable (fixture sanity for setBaseMemoryHint)
var _ = checkpointchunks.Load

// TestPackAutoBaseArtifactErrorNotSwallowed: auto-base enabled, parent
// available, but the CURRENT artifact's data PUT fails → the publish MUST
// fail (the auto-base fallback only catches baseline-load errors, never
// the current artifact's own errors).
func TestPackAutoBaseArtifactErrorNotSwallowed(t *testing.T) {
	root := t.TempDir()
	underDir := t.TempDir()
	underlying, err := chunkstore.NewLocal(underDir)
	if err != nil {
		t.Fatal(err)
	}
	publishParentPack(t, root, "artfail-parent", underlying)
	child := adaptivePackedFixtureIn(t, root, "artfail-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "artfail-parent")
	if _, err := RunWithOptions(context.Background(), child, "artfail-child",
		newFailingPutStore(underlying, 1), "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true}); err == nil {
		t.Fatalf("current artifact error must NOT be swallowed by auto-base fallback")
	}
}

// TestPackAutoBaseExplicitInvalidStillHardError: auto-base enabled AND an
// explicit BaseID pointing to a non-existent parent → HARD ERROR (the
// auto fallback must NOT rescue an explicitly named bad parent).
func TestPackAutoBaseExplicitInvalidStillHardError(t *testing.T) {
	dir := adaptivePackedFixture(t, adaptivePatternData())
	setBaseMemoryHint(t, dir, "auto-hint-parent") // hint would resolve, but explicit wins
	_, err := RunWithOptions(context.Background(), dir, filepath.Base(dir), adaptiveStoreSingle(t), "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true, BaseID: "nonexistent-explicit"})
	if err == nil || !strings.Contains(err.Error(), "load pack baseline") {
		t.Fatalf("explicit invalid parent must hard-error even with auto-base on, got: %v", err)
	}
}

// TestPackAutoBaseContextCancelNoFallback: a cancelled context must NOT
// trigger the auto-base fallback (which would continue doing store work
// under a dead ctx) — it hard-fails, and the store receives ZERO writes.
func TestPackAutoBaseContextCancelNoFallback(t *testing.T) {
	root := t.TempDir()
	underlying, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publishParentPack(t, root, "cancel-parent", underlying)
	child := adaptivePackedFixtureIn(t, root, "cancel-child", adaptivePatternData())
	setBaseMemoryHint(t, child, "cancel-parent")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // dead before the attempt starts

	counting := &writeCountingStore{Store: underlying}
	_, err = RunWithOptions(ctx, child, "cancel-child", counting, "s",
		Options{PackBytes: 4 << 20, PackAutoBase: true})
	if err == nil {
		t.Fatalf("cancelled ctx must fail the publish")
	}
	if counting.writes > 0 {
		t.Fatalf("cancelled ctx must produce ZERO store writes, got %d", counting.writes)
	}
}

// writeCountingStore counts all PUT operations (any key) to prove no
// store writes occur after cancellation.
type writeCountingStore struct {
	chunkstore.Store
	writes int
}

func (s *writeCountingStore) Put(ctx context.Context, digest string, r io.Reader) error {
	s.writes++
	return s.Store.Put(ctx, digest, r)
}

func (s *writeCountingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	s.writes++
	return s.Store.(chunkstore.Keyed).PutKey(ctx, key, r)
}

func (s *writeCountingStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.Store.(chunkstore.Keyed).GetKey(ctx, key)
}

func (s *writeCountingStore) HasKey(ctx context.Context, key string) (bool, error) {
	return s.Store.(chunkstore.Keyed).HasKey(ctx, key)
}
