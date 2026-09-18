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

// Sweep-fence tests: a Has-hit reuse of an object carrying a gc-marks/<key>
// mark must not skip the upload. The mark says a bucket sweep judged the
// object dead and may collect it once the grace elapses; min-age cannot
// protect the reuse because the object is old by construction.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

// TestPublishRefreshesSweepMarkedReuse: an unmarked rerun skips (the
// pre-existing dedup contract), a marked rerun re-uploads — refreshing the
// object so the sweep's delete-time recheck spares it.
func TestPublishRefreshesSweepMarkedReuse(t *testing.T) {
	dir := fixtureCheckpoint(t)
	store, err := chunkstore.NewLocal(filepath.Join(filepath.Dir(dir), "store"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if first.ChunksPut == 0 {
		t.Fatalf("first publish uploaded nothing: %+v", first)
	}
	again, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("unmarked rerun: %v", err)
	}
	if again.ChunksSkip == 0 {
		t.Fatalf("unmarked rerun lost the dedup skip: %+v", again)
	}

	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(store)
	for _, entry := range manifest.Entries {
		if err := keyed.PutKey(context.Background(), GCMarkKey(chunkstore.PlainKey(entry.Digest)), strings.NewReader("marked")); err != nil {
			t.Fatal(err)
		}
	}
	fenced, err := Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err != nil {
		t.Fatalf("marked rerun: %v", err)
	}
	if fenced.ChunksPut != first.ChunksPut || fenced.ChunksSkip != 0 {
		t.Fatalf("marked reuse not refreshed: put=%d skip=%d want put=%d skip=0",
			fenced.ChunksPut, fenced.ChunksSkip, first.ChunksPut)
	}
}

// TestPublishRefusesSweepMarkedInheritedHole: a digest-inherited entry has
// no local bytes — its content lives in the store under the parent's digest.
// A marked parent object means the parent generation is on its way out;
// publishing against it must fail rather than seal zeros under the digest.
func TestPublishRefusesSweepMarkedInheritedHole(t *testing.T) {
	parent := make([]byte, 300<<10)
	for i := range parent {
		parent[i] = byte(i*7 + 1)
	}
	sum := sha256.Sum256(parent)
	parentDigest := hex.EncodeToString(sum[:])
	dir := t.TempDir()
	// Sparse local artifact: the hole IS the parent content.
	if err := os.WriteFile(filepath.Join(dir, "memory"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "memory"), int64(len(parent))); err != nil {
		t.Fatal(err)
	}
	manifest := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: int64(len(parent)),
		ChunkBytes: checkpointchunks.DefaultChunkBytes, ChunkCount: 2,
		FileDigestMode: checkpointchunks.FileDigestChunks,
	}
	manifest.Entries = append(manifest.Entries,
		checkpointchunks.Chunk{Offset: 0, Digest: parentDigest, Inherited: true},
		checkpointchunks.Chunk{Offset: checkpointchunks.DefaultChunkBytes, Digest: parentDigest, Inherited: true},
	)
	if err := checkpointchunks.Write(dir, manifest); err != nil {
		t.Fatal(err)
	}
	store, err := chunkstore.NewLocal(filepath.Join(dir, "..", "hole-store"))
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(store)
	// The parent object exists (the reuse would otherwise be a hit) and a
	// sweep marked it.
	if err := store.Put(context.Background(), parentDigest, strings.NewReader(string(parent))); err != nil {
		t.Fatal(err)
	}
	if err := keyed.PutKey(context.Background(), GCMarkKey(chunkstore.PlainKey(parentDigest)), strings.NewReader("marked")); err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), dir, filepath.Base(dir), store, "test-store")
	if err == nil || !strings.Contains(err.Error(), "marked for collection") {
		t.Fatalf("expected the marked inherited hole to fail the publish, got %v", err)
	}
}

// TestPubIntentAttemptsAreIndependent: intents are PER-ATTEMPT — every
// gcBeginPubIntent mints its own key under gc-pubintents/<id>/<nonce>, so
// overlapping attempts under the same checkpoint id never share state: an
// attempt that finishes (or fails) removes only its own intent, and a
// still-running sibling keeps its mid-publish protection regardless of
// ordering. A single shared key has the exact opposite property: whichever
// attempt ends first legally deletes the current generation and leaves
// the other attempt unprotected (reviewer 2026-09-17).
func TestPubIntentAttemptsAreIndependent(t *testing.T) {
	root := t.TempDir()
	store, err := chunkstore.NewLocal(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(store)
	ctx := context.Background()
	const id = "same-id"
	exists := func(key string) bool {
		rc, err := keyed.GetKey(ctx, key)
		if err != nil {
			return false
		}
		rc.Close()
		return true
	}
	keyA, bodyA, err := gcBeginPubIntent(ctx, keyed, id)
	if err != nil {
		t.Fatal(err)
	}
	keyB, bodyB, err := gcBeginPubIntent(ctx, keyed, id)
	if err != nil {
		t.Fatal(err)
	}
	if keyA == keyB || bodyA == bodyB {
		t.Fatal("attempts must mint unique intent keys and bodies")
	}
	if !exists(keyA) || !exists(keyB) {
		t.Fatal("both attempts' intents must coexist")
	}
	// Attempt B finishes first: its end removes only keyB.
	gcEndPubIntent(ctx, keyed, keyB, bodyB)
	if !exists(keyA) {
		t.Fatal("a finished attempt removed a still-running attempt's intent")
	}
	if exists(keyB) {
		t.Fatal("an ended attempt left its own intent behind")
	}
	// Attempt A ends on its own schedule.
	gcEndPubIntent(ctx, keyed, keyA, bodyA)
	if exists(keyA) {
		t.Fatal("owner's own end did not remove the intent")
	}
}

// intentFailingStore injects the failure the sweep protocol cannot
// tolerate: the publication intent's own PUT fails while every other
// store operation works.
type intentFailingStore struct {
	*chunkstore.Local
}

func (s intentFailingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if strings.HasPrefix(key, GCPubIntentNamespace+"/") {
		return fmt.Errorf("injected intent write failure")
	}
	return s.Local.PutKey(ctx, key, r)
}

// compProbeFailingStore fails the compressed-object probe: the plain fence
// claim has already been acquired when the compressed path errors out, so
// this is the store shape that exposes a leaked claim on the publish
// failure paths.
type compProbeFailingStore struct {
	*chunkstore.Local
}

func (s compProbeFailingStore) HasKey(ctx context.Context, key string) (bool, error) {
	if strings.HasSuffix(key, ".z") {
		return false, fmt.Errorf("injected compressed probe failure")
	}
	return s.Local.HasKey(ctx, key)
}

// TestPublishFailureReleasesHeldClaims: a publish that fails after
// acquiring a fence claim must not leak the claim — a leaked claim blocks
// every later sweep and publish on that key for up to the claim grace.
// The failure is injected at the compressed-object probe, exactly one
// step after the plain claim was acquired.
func TestPublishFailureReleasesHeldClaims(t *testing.T) {
	dir := fixtureCheckpoint(t)
	root := filepath.Dir(dir)
	local, err := chunkstore.NewLocal(filepath.Join(root, "leak-store"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := Run(ctx, dir, filepath.Base(dir), local, "seed"); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	manifest, err := checkpointchunks.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	keyed := chunkstore.Keyed(local)
	for _, entry := range manifest.Entries {
		if err := keyed.PutKey(ctx, GCMarkKey(chunkstore.PlainKey(entry.Digest)), strings.NewReader("marked")); err != nil {
			t.Fatal(err)
		}
	}
	_, err = RunWithOptions(ctx, dir, filepath.Base(dir), compProbeFailingStore{Local: local}, "fail-store", Options{CompressChunks: true})
	if err == nil {
		t.Fatal("expected the publish to fail on the injected probe error")
	}
	leaked := 0
	err = filepath.WalkDir(filepath.Join(root, "leak-store"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(path, GCClaimNamespace+"/") {
			leaked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("failed publish leaked %d gc-claims objects", leaked)
	}
}

// TestPublishFailsClosedWithoutIntent: establishing the mid-publish
// protection is a SAFETY RECORD, not telemetry. When the intent PUT
// fails, the publish must fail closed BEFORE any data upload or INDEX
// write — a publication that proceeded would run its whole
// uploads-to-INDEX window with zero protection and the sweep could
// lawfully collect its chunks mid-flight. (The intent END failing is the
// conservative direction — protection simply outlives the attempt — and
// stays best-effort.)
func TestPublishFailsClosedWithoutIntent(t *testing.T) {
	dir := fixtureCheckpoint(t)
	root := filepath.Dir(dir)
	local, err := chunkstore.NewLocal(filepath.Join(root, "intent-fail-store"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(context.Background(), dir, filepath.Base(dir), intentFailingStore{Local: local}, "test-store")
	if err == nil || !strings.Contains(err.Error(), "publication intent") {
		t.Fatalf("expected the publish to fail on the intent write, got %v", err)
	}
	// Fail-closed means fail EARLY: not one object may have landed — no
	// chunks, no artifact set, no INDEX.
	files := 0
	err = filepath.WalkDir(filepath.Join(root, "intent-fail-store"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files != 0 {
		t.Fatalf("objects were written despite the failed intent: %d files", files)
	}
}
