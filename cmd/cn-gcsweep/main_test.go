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

package main

// Sweep tests against a minimal fake S3: ListObjectsV2 XML, GET, DELETE.
// The invariants: referenced chunks survive across artifact drops, a
// chunk dies only with its last referencing artifact, in-flight young
// chunks are guarded by min-age, unknown shapes are never touched, and
// one unresolvable manifest aborts every deletion.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
)

type fakeBucket struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	gets    map[string]int
}

type fakeObject struct {
	body     []byte
	modified time.Time
}

func newFakeBucket() *fakeBucket {
	return &fakeBucket{objects: map[string]fakeObject{}, gets: map[string]int{}}
}

func (b *fakeBucket) put(key string, body []byte, age time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = fakeObject{body: body, modified: time.Now().Add(-age)}
}

func (b *fakeBucket) has(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.objects[key]
	return ok
}

func (b *fakeBucket) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.RawQuery == "":
		b.mu.Lock()
		obj, ok := b.objects[strings.TrimPrefix(r.URL.Path, "/")]
		b.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(obj.body)
	case r.Method == http.MethodGet:
		// ListObjectsV2: prefix and continuation over sorted keys.
		token := r.URL.Query().Get("continuation-token")
		keys := make([]string, 0, len(b.objects))
		b.mu.Lock()
		for k := range b.objects {
			keys = append(keys, k)
		}
		b.mu.Unlock()
		sort.Strings(keys)
		const page = 3
		start := 0
		if token != "" {
			// The token names the first key of THIS page (the one just
			// past the previous page's end); include it.
			start = sort.SearchStrings(keys, token)
		}
		end := min(start+page, len(keys))
		var pageKeys []string
		if start < len(keys) {
			pageKeys = keys[start:end]
		}
		var buf bytes.Buffer
		buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
		if end < len(keys) {
			fmt.Fprintf(&buf, "<IsTruncated>true</IsTruncated><NextContinuationToken>%s</NextContinuationToken>", keys[end])
		} else {
			buf.WriteString("<IsTruncated>false</IsTruncated>")
		}
		b.mu.Lock()
		for _, k := range pageKeys {
			fmt.Fprintf(&buf, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>",
				k, len(b.objects[k].body), b.objects[k].modified.UTC().Format(time.RFC3339))
		}
		b.mu.Unlock()
		buf.WriteString(`</ListBucketResult>`)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(buf.Bytes())
	case r.Method == http.MethodPut:
		key := strings.TrimPrefix(r.URL.Path, "/")
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.objects[key] = fakeObject{body: body, modified: time.Now()}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		key := strings.TrimPrefix(r.URL.Path, "/")
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.objects[key]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(b.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// publishArtifactAsBundle stages a bundle-era artifact: INDEX + BUNDLE
// with the memory sidecar (entries digests) inside.
func publishArtifactAsBundle(b *fakeBucket, id string, digests []string, packRefs map[string]string, overlay []string) {
	m := &checkpointchunks.Manifest{
		Version: 2, File: "memory", FileSize: int64(len(digests)) * 4096,
		ChunkBytes: 4096, ChunkCount: len(digests),
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Packs:          map[string]checkpointchunks.PackReference{},
	}
	for i, d := range digests {
		m.Entries = append(m.Entries, checkpointchunks.Chunk{Offset: int64(i) * 4096, Digest: d})
	}
	for chunkDigest, packDigest := range packRefs {
		m.Packs[chunkDigest] = checkpointchunks.PackReference{Digest: packDigest, Offset: 0, Length: 4096, ObjectSize: 8192}
	}
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	var jsonBuf bytes.Buffer
	if err := json.NewEncoder(&jsonBuf).Encode(m); err != nil {
		panic(err)
	}
	var bundle []byte
	parts := []checkpointpublish.BundlePart{}
	addPart := func(name string, body []byte) {
		sum := sha256.Sum256(body)
		var prefix [8]byte
		prefix[0] = byte(len(body) >> 56)
		parts = append(parts, checkpointpublish.BundlePart{
			Name: name, Offset: int64(len(bundle)) + 8, Length: int64(len(body)),
			Digest: hex.EncodeToString(sum[:]),
		})
		bundle = append(bundle, prefix[:]...)
		bundle = append(bundle, body...)
	}
	addPart(checkpointchunks.ManifestName, jsonBuf.Bytes())
	if len(overlay) > 0 {
		om := &checkpointchunks.Manifest{Version: 1, File: "overlay.ext4",
			FileSize: int64(len(overlay)) * 4096, ChunkBytes: 4096, ChunkCount: len(overlay),
			FileDigestMode: checkpointchunks.FileDigestChunks}
		for i, d := range overlay {
			om.Entries = append(om.Entries, checkpointchunks.Chunk{Offset: int64(i) * 4096, Digest: d})
		}
		om.FileDigest = checkpointchunks.RootDigest(om.Entries)
		var ob bytes.Buffer
		if err := json.NewEncoder(&ob).Encode(om); err != nil {
			panic(err)
		}
		addPart(checkpointpublish.OverlaySidecarName, ob.Bytes())
	}
	b.put(fmt.Sprintf("artifacts/%s/%s", id, checkpointpublish.BundleName), bundle, 2*time.Hour)
	sum := sha256.Sum256(bundle)
	index := checkpointpublish.ArtifactIndex{
		CheckpointID: id, ChunkCount: len(digests),
		Files: map[string]string{checkpointchunks.ManifestName: "x"},
		Bundle: &checkpointpublish.BundleInfo{
			Digest: hex.EncodeToString(sum[:]), Size: int64(len(bundle)), Parts: parts,
		},
		OverlayChunks: len(overlay) > 0,
	}
	var ib bytes.Buffer
	if err := json.NewEncoder(&ib).Encode(&index); err != nil {
		panic(err)
	}
	b.put(fmt.Sprintf("artifacts/%s/%s", id, checkpointpublish.IndexName), ib.Bytes(), 2*time.Hour)
}

func digestOf(seed byte) string {
	sum := sha256.Sum256([]byte{seed})
	return hex.EncodeToString(sum[:])
}

func TestSweepKeepsSharedChunksAndDropsOrphans(t *testing.T) {
	bucket := newFakeBucket()
	shared, onlyA, orphan, orphanYoung := digestOf(1), digestOf(2), digestOf(3), digestOf(4)
	publishArtifactAsBundle(bucket, "art-a", []string{shared, onlyA}, nil, nil)
	publishArtifactAsBundle(bucket, "art-b", []string{shared}, nil, nil)
	old, young := 48*time.Hour, time.Hour
	bucket.put(shared[:2]+"/"+shared, []byte("x"), old)
	bucket.put(onlyA[:2]+"/"+onlyA, []byte("x"), old)
	bucket.put(orphan[:2]+"/"+orphan+".z", []byte("x"), old)
	bucket.put(orphanYoung[:2]+"/"+orphanYoung, []byte("x"), young)
	bucket.put("operator-stuff/config", []byte("x"), old)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()

	// Dry run: nothing deleted, orphan (.z) counted, young spared.
	if err := run(context.Background(), server.URL, false, 0, nil, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(orphan[:2] + "/" + orphan + ".z") {
		t.Fatal("dry run deleted an object")
	}
	// Real run: orphan dies; shared and onlyA survive; young and foreign
	// stay; the .z key shape is recognized.
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{shared[:2] + "/" + shared, onlyA[:2] + "/" + onlyA,
		orphanYoung[:2] + "/" + orphanYoung, "operator-stuff/config",
		"artifacts/art-a/INDEX.json", "artifacts/art-b/INDEX.json"} {
		if !bucket.has(key) {
			t.Fatalf("live object deleted: %s", key)
		}
	}
	if bucket.has(orphan[:2] + "/" + orphan + ".z") {
		t.Fatal("old orphan compressed object survived")
	}
}

func TestSweepDropsArtifactAndItsLastChunk(t *testing.T) {
	bucket := newFakeBucket()
	shared, onlyA := digestOf(1), digestOf(2)
	publishArtifactAsBundle(bucket, "art-a", []string{shared, onlyA}, nil, nil)
	publishArtifactAsBundle(bucket, "art-b", []string{shared}, nil, nil)
	old := 48 * time.Hour
	bucket.put(shared[:2]+"/"+shared, []byte("x"), old)
	bucket.put(onlyA[:2]+"/"+onlyA, []byte("x"), old)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()

	// Drop art-a explicitly: onlyA loses its last reference and dies;
	// shared stays (art-b still names it); the artifact set goes.
	if err := run(context.Background(), server.URL, true, 0, []string{"art-a"}, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatal(err)
	}
	if bucket.has("artifacts/art-a/INDEX.json") || bucket.has("artifacts/art-a/BUNDLE") {
		t.Fatal("dropped artifact set survived")
	}
	if bucket.has(onlyA[:2] + "/" + onlyA) {
		t.Fatal("last-referenced chunk survived its artifact's drop")
	}
	if !bucket.has(shared[:2]+"/"+shared) || !bucket.has("artifacts/art-b/INDEX.json") {
		t.Fatal("shared chunk or surviving artifact was deleted")
	}
}

func TestSweepFailClosedOnUnresolvableIndex(t *testing.T) {
	bucket := newFakeBucket()
	orphan := digestOf(9)
	bucket.put(orphan[:2]+"/"+orphan, []byte("x"), 48*time.Hour)
	// An INDEX that cannot be decoded poisons the live set: the run must
	// fail and delete nothing, even obvious orphans.
	bucket.put("artifacts/broken/INDEX.json", []byte("not-json"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 0, 4, false); err == nil {
		t.Fatal("unresolvable INDEX accepted")
	}
	if !bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("fail-closed sweep still deleted an object")
	}
}

func TestSweepMaxArtifactAgeDropsOnlyOldSets(t *testing.T) {
	bucket := newFakeBucket()
	oldChunk, newChunk := digestOf(5), digestOf(6)
	publishArtifactAsBundle(bucket, "gen-old", []string{oldChunk}, nil, nil)
	publishArtifactAsBundle(bucket, "gen-new", []string{newChunk}, nil, nil)
	// The listing age of an artifact set comes from its INDEX; rewind the
	// old one beyond the cutoff and age both chunks old so only the
	// artifact criterion separates them.
	bucket.mu.Lock()
	for key := range bucket.objects {
		if strings.HasPrefix(key, "artifacts/gen-old/") {
			obj := bucket.objects[key]
			obj.modified = time.Now().Add(-100 * time.Hour)
			bucket.objects[key] = obj
		}
	}
	bucket.mu.Unlock()
	bucket.put(oldChunk[:2]+"/"+oldChunk, []byte("x"), 100*time.Hour)
	bucket.put(newChunk[:2]+"/"+newChunk, []byte("x"), 100*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	if err := run(context.Background(), server.URL, true, 48*time.Hour, nil, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatal(err)
	}
	if bucket.has("artifacts/gen-old/INDEX.json") || bucket.has(oldChunk[:2]+"/"+oldChunk) {
		t.Fatal("aged-out artifact or its private chunk survived")
	}
	if !bucket.has("artifacts/gen-new/INDEX.json") || !bucket.has(newChunk[:2]+"/"+newChunk) {
		t.Fatal("young artifact was dropped")
	}
}

// rewindMark ages a sweep mark past the grace window, simulating the wait
// between the marking run and the collecting run.
func rewindMark(b *fakeBucket, key string, age time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	mark := checkpointpublish.GCMarkKey(key)
	obj, ok := b.objects[mark]
	if !ok {
		panic("no mark for " + key)
	}
	obj.modified = time.Now().Add(-age)
	b.objects[mark] = obj
}

// refreshObject simulates a publisher's gc fence: the Has-hit reuse of a
// marked object re-uploaded its bytes, refreshing the store timestamp.
func refreshObject(b *fakeBucket, key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	obj, ok := b.objects[key]
	if !ok {
		panic("no object " + key)
	}
	obj.modified = time.Now()
	b.objects[key] = obj
}

// F2 regression: overlay chunks live under overlay-chunks/<aa>/<digest>;
// the sweep must count a live artifact's overlay sidecar as references for
// THOSE keys. Before the fix every overlay object was unreferenced and a
// -delete run reclaimed live blocks.
func TestSweepKeepsReferencedOverlayChunks(t *testing.T) {
	bucket := newFakeBucket()
	memChunk, overlayLive, overlayOrphan := digestOf(11), digestOf(12), digestOf(13)
	publishArtifactAsBundle(bucket, "art-o", []string{memChunk}, nil, []string{overlayLive})
	bucket.put(memChunk[:2]+"/"+memChunk, []byte("x"), 48*time.Hour)
	bucket.put(checkpointpublish.OverlayChunkKey(overlayLive), []byte("x"), 48*time.Hour)
	bucket.put(checkpointpublish.OverlayChunkKey(overlayOrphan), []byte("x"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(checkpointpublish.OverlayChunkKey(overlayLive)) {
		t.Fatal("live overlay chunk deleted (reference key mismatch)")
	}
	if bucket.has(checkpointpublish.OverlayChunkKey(overlayOrphan)) {
		t.Fatal("orphan overlay chunk survived")
	}
}

// F3 core: a fresh victim is only MARKED, never deleted in the run that
// found it; collection waits out the grace and then re-verifies.
func TestSweepMarksBeforeCollecting(t *testing.T) {
	bucket := newFakeBucket()
	orphan := digestOf(21)
	bucket.put(orphan[:2]+"/"+orphan, []byte("x"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()

	// First -delete run with a grace: mark only.
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("victim deleted before its mark aged past the grace")
	}
	if !bucket.has(checkpointpublish.GCMarkKey(orphan[:2] + "/" + orphan)) {
		t.Fatal("victim not marked")
	}
	// The grace has not elapsed: a second run still only waits.
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("victim deleted before the grace elapsed")
	}
	// Simulate the wait, then collect.
	rewindMark(bucket, orphan[:2]+"/"+orphan, 25*time.Hour)
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	if bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("stale-marked victim survived collection")
	}
	if bucket.has(checkpointpublish.GCMarkKey(orphan[:2] + "/" + orphan)) {
		t.Fatal("mark survived its object's collection")
	}
}

// F3 refresh race: the publisher fence re-uploads a marked object mid-sweep
// (between the scan listing and the delete-time recheck). The fresh listing
// sees a young timestamp, spares the object, and clears the now-obsolete
// mark — the next sweep re-evaluates it from scratch.
func TestSweepSparesRefreshedVictim(t *testing.T) {
	bucket := newFakeBucket()
	orphan := digestOf(31)
	bucket.put(orphan[:2]+"/"+orphan, []byte("x"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	rewindMark(bucket, orphan[:2]+"/"+orphan, 25*time.Hour)
	// The publisher's fence refresh lands between the second run's scan
	// listing and its delete-time relisting: the scan still sees the old
	// timestamp (a victim), the relisting sees a young one.
	var listings atomic.Int32
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The relisting (this counter's second listing: the scan came
		// first) must observe the young timestamp, so mutate pre-serve.
		if r.Method == http.MethodGet && r.URL.RawQuery != "" && listings.Add(1) == 2 {
			refreshObject(bucket, orphan[:2]+"/"+orphan)
		}
		bucket.serve(w, r)
	}))
	defer server2.Close()
	if err := run(context.Background(), server2.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("refreshed victim deleted despite the delete-time recheck")
	}
	if bucket.has(checkpointpublish.GCMarkKey(orphan[:2] + "/" + orphan)) {
		t.Fatal("obsolete mark kept after the victim was spared")
	}
}

// F3 committed-publish race: an artifact set whose INDEX appears between the
// scan and the recheck references the marked object; the sweep merges the
// new references and spares the object.
func TestSweepMergesMidRunArtifactReferences(t *testing.T) {
	bucket := newFakeBucket()
	orphan := digestOf(41)
	bucket.put(orphan[:2]+"/"+orphan, []byte("x"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	rewindMark(bucket, orphan[:2]+"/"+orphan, 25*time.Hour)
	// A publication commits after the second run's scan listing: its set
	// appears only in the delete-time relisting.
	var listings atomic.Int32
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket.serve(w, r)
		// Inject after the scan listing (this counter's first) has been
		// served: only the delete-time relisting sees the new set.
		if r.Method == http.MethodGet && r.URL.RawQuery != "" && listings.Add(1) == 1 {
			publishArtifactAsBundle(bucket, "art-late", []string{orphan}, nil, nil)
		}
	}))
	defer server2.Close()
	if err := run(context.Background(), server2.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 4, false); err != nil {
		t.Fatal(err)
	}
	if !bucket.has(orphan[:2] + "/" + orphan) {
		t.Fatal("object deleted although a mid-run publication referenced it")
	}
	if bucket.has(checkpointpublish.GCMarkKey(orphan[:2] + "/" + orphan)) {
		t.Fatal("mark kept after the mid-run reference spared the object")
	}
}
