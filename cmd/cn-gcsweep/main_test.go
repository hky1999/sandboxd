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
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

type fakeBucket struct {
	mu sync.Mutex
	// ignoreDeleteIfMatch emulates the degraded backend observed on the
	// real MinIO (2026-09-14 acceptance): a DELETE carrying If-Match
	// executes unconditionally, so GET+DELETE cannot act as an atomic
	// compare-and-delete.
	ignoreDeleteIfMatch bool
	objects             map[string]fakeObject
	gets                map[string]int
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

// hasUnderPrefix reports whether any object key starts with prefix.
func (b *fakeBucket) hasUnderPrefix(prefix string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func (b *fakeBucket) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodHead:
		b.mu.Lock()
		obj, ok := b.objects[strings.TrimPrefix(r.URL.Path, "/")]
		b.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Last-Modified", obj.modified.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.RawQuery == "":
		b.mu.Lock()
		obj, ok := b.objects[strings.TrimPrefix(r.URL.Path, "/")]
		b.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		sum := md5.Sum(obj.body)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
		w.Header().Set("Last-Modified", obj.modified.UTC().Format(http.TimeFormat))
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
		// S3 conditional write: If-None-Match:* succeeds only when the
		// object does not exist (the atomic claim primitive).
		if r.Header.Get("If-None-Match") == "*" {
			if _, exists := b.objects[key]; exists {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
		b.objects[key] = fakeObject{body: body, modified: time.Now()}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		key := strings.TrimPrefix(r.URL.Path, "/")
		b.mu.Lock()
		defer b.mu.Unlock()
		obj, ok := b.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// S3 conditional delete: If-Match only removes the observed
		// generation (the ETag of the current body) — unless the degraded
		// mode ignores the header entirely.
		if want := r.Header.Get("If-Match"); want != "" && !b.ignoreDeleteIfMatch {
			sum := md5.Sum(obj.body)
			if strings.Trim(want, `"`) != hex.EncodeToString(sum[:]) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
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

// barrierBucket wraps a fake bucket with a barrier that blocks chosen
// requests (without holding the bucket lock) until released, so a real
// publisher can run to completion while a sweep sits at the blocked step.
// A non-nil done channel is the escape hatch that keeps a failing test's
// deferred Server.Close from waiting forever on a parked handler.
type barrierBucket struct {
	inner   *fakeBucket
	block   func(method, key string) bool
	hit     chan string
	release chan struct{}
	done    <-chan struct{}
}

func (b *barrierBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/")
	if b.block(r.Method, key) {
		select {
		case b.hit <- key:
		default:
		}
		if b.done == nil {
			<-b.release
			b.inner.serve(w, r)
			return
		}
		select {
		case <-b.release:
		case <-b.done:
			return
		}
	}
	b.inner.serve(w, r)
}

// fixtureCheckpointDir builds a real-bytes checkpoint directory whose
// WRITABLE LAYER ships as one digest-keyed overlay chunk — the object class
// materialization fetches eagerly, so losing it breaks published artifacts
// observably. A real publisher can publish the fixture twice (the second
// run reuses the chunk objects).
func fixtureCheckpointDir(t *testing.T) (string, string) {
	t.Helper()
	const chunkBytes = 256 << 10
	data := make([]byte, chunkBytes)
	for i := range data {
		data[i] = byte(i*7 + 1)
	}
	digest := sha256.Sum256(data)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate"), []byte("vmstate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	overlayDigest := hex.EncodeToString(digest[:])
	om := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(data)),
		ChunkBytes: chunkBytes, ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries:        []checkpointchunks.Chunk{{Offset: 0, Digest: overlayDigest}},
	}
	om.FileDigest = checkpointchunks.RootDigest(om.Entries)
	if err := checkpointchunks.WriteNamed(dir, checkpointpublish.OverlaySidecarName, om); err != nil {
		t.Fatal(err)
	}
	m := &checkpointchunks.Manifest{
		Version: 1, File: "memory", FileSize: int64(len(data)),
		ChunkBytes: chunkBytes, ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries:        []checkpointchunks.Chunk{{Offset: 0, Digest: hex.EncodeToString(digest[:])}},
	}
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	if err := checkpointchunks.Write(dir, m); err != nil {
		t.Fatal(err)
	}
	// The checkpoint manifest is what makes the publisher ship a full
	// artifact set (INDEX last) rather than bare chunk objects.
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"snapshot_type":"Full","memory_size":`+strconv.Itoa(len(data))+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, overlayDigest
}

// sweepBarrierPublish runs the reviewer's deterministic interleave: the sweep
// is parked INSIDE its delete phase (past the re-listing), a real publisher
// then fences the marked chunk (re-upload) and commits its INDEX, and only
// then is the sweep let go. The completed publication must survive.
//
// parkedOnClaim selects which sweep write parks the run: true blocks the
// sweep's claim PUT (publisher wins the claim), false blocks the object
// DELETE itself (the sweep already owns the claim and the publisher must
// wait it out, then re-upload under its own claim).
func sweepBarrierPublish(t *testing.T, parkedOnClaim bool) {
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	// The parked object is the overlay chunk: materialization reassembles
	// the writable layer eagerly, so its loss is observable right here.
	chunkKey := checkpointpublish.OverlayChunkKey(digest)

	// The publisher's endpoint records lost claim races (412 on a
	// gc-claims PUT), which is the deterministic signal that it is now
	// contending with the parked sweep.
	claimLost := make(chan string, 8)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		if r.Method == http.MethodPut && strings.HasPrefix(key, "gc-claims/") &&
			r.Header.Get("If-None-Match") == "*" && bucket.has(key) {
			select {
			case claimLost <- key:
			default:
			}
		}
		bucket.serve(w, r)
	}))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Seed: publish p1, drop it, mark its (single) chunk, age the mark.
	if _, err := checkpointpublish.Run(context.Background(), dir, "p1", store, plain.URL); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := run(context.Background(), plain.URL, true, 0, []string{"p1"}, 0, time.Hour, 2, false); err != nil {
		t.Fatalf("mark-only sweep: %v", err)
	}
	if !bucket.has(checkpointpublish.GCMarkKey(chunkKey)) {
		t.Fatalf("chunk %s not marked", chunkKey)
	}
	rewindMark(bucket, chunkKey, 2*time.Hour)

	barrier := &barrierBucket{
		inner: bucket,
		block: func(method, key string) bool {
			if parkedOnClaim {
				// The full claim key of the target object ONLY: the preflight
				// probe also PUTs gc-claims/* before the final relisting, and
				// parking there would place the barrier before the relist.
				return method == http.MethodPut && key == checkpointpublish.GCClaimKey(chunkKey)
			}
			return method == http.MethodDelete && key == chunkKey
		},
		hit:     make(chan string, 8),
		release: make(chan struct{}),
	}
	sweepSrv := httptest.NewServer(barrier)
	defer sweepSrv.Close()
	sweepDone := make(chan error, 1)
	go func() {
		// mark-grace 1h: the freshly-marked memory chunk is NOT a candidate
		// (its mark is young), so the sweep parks holding exactly one claim
		// — the target overlay chunk's.
		sweepDone <- run(context.Background(), sweepSrv.URL, true, 0, nil, 0, time.Hour, 2, false)
	}()
	select {
	case <-barrier.hit:
	case <-time.After(30 * time.Second):
		t.Fatal("sweep never reached its parked delete-phase write")
	}

	// The publisher runs against the unimpeded endpoint: fence (mark probe,
	// claim, re-upload), artifact set, INDEX last, publish returns success.
	// A fresh directory copy per artifact id: one .publish state per id.
	p2dir := t.TempDir()
	for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p2dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pubDone := make(chan error, 1)
	go func() {
		_, err := checkpointpublish.Run(context.Background(), p2dir, "p2", store, plain.URL)
		pubDone <- err
	}()
	if !parkedOnClaim {
		// The sweep already owns the claim; the publisher must be contending
		// (412) before the barrier opens — otherwise the race was not set up.
		select {
		case <-claimLost:
		case <-time.After(30 * time.Second):
			t.Fatal("publisher never contended the parked sweep's claim")
		}
	}
	if parkedOnClaim {
		if err := <-pubDone; err != nil {
			t.Fatalf("publisher lost to a parked sweep: %v", err)
		}
	}
	close(barrier.release)
	if !parkedOnClaim {
		if err := <-pubDone; err != nil {
			t.Fatalf("publisher failed after the sweep released its claim: %v", err)
		}
	}
	select {
	case err := <-sweepDone:
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("sweep did not finish after the barrier")
	}

	// The completed publication must remain fully materializable.
	mat := filepath.Join(t.TempDir(), "mat")
	keyed, ok := store.(chunkstore.Keyed)
	if !ok {
		t.Fatal("remote store lacks the keyed surface")
	}
	if err := checkpointpublish.Materialize(context.Background(), mat, "p2", keyed); err != nil {
		t.Fatalf("published artifact lost a dependency to the sweep: %v", err)
	}
}

// F3b regression (recheck 2026-09-14 §3.2): publisher wins the claim while
// the sweep is parked past its re-listing — the sweep must spare the object.
func TestSweepBarrierPublisherWinsClaim(t *testing.T) {
	sweepBarrierPublish(t, true)
}

// F3b regression, other direction: the sweep already owns the claim and sits
// before the object DELETE; the publisher must wait the claim out, re-upload
// the chunk under its own claim, and still commit a materializable artifact.
func TestSweepBarrierSweepWinsClaim(t *testing.T) {
	sweepBarrierPublish(t, false)
}

// Ported from the 2026-09-14 recheck (Docs/checks/20260914T-b2dd1d5-
// progress-and-gc-claims-check.md): the original repro asserted the BYPASS
// (publisher claim PUTs == 0 on the Has-miss path); with the fix the same
// path must CLAIM — the count assertion flips to >= 1 while every invariant
// assertion (artifact materializable, claim generations survive) is kept.
func TestReviewTwoSweepsHasMissPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	seedDir, digest := fixtureCheckpointDir(t)
	key := checkpointpublish.OverlayChunkKey(digest)
	claimKey := checkpointpublish.GCClaimKey(key)
	markKey := checkpointpublish.GCMarkKey(key)
	var publisherClaimPuts atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.TrimPrefix(r.URL.Path, "/") == claimKey {
			publisherClaimPuts.Add(1)
		}
		bucket.serve(w, r)
	}))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointpublish.Run(ctx, seedDir, "review-seed", store, plain.URL); err != nil {
		t.Fatal(err)
	}
	bucket.mu.Lock()
	for k := range bucket.objects {
		if strings.HasPrefix(k, "artifacts/review-seed/") {
			delete(bucket.objects, k)
		}
	}
	old := bucket.objects[key]
	old.modified = time.Now().Add(-72 * time.Hour)
	bucket.objects[key] = old
	// The memory chunk shares the fixture digest: make its mark young so it
	// stays out of the candidate set (mark-grace 24h below).
	bucket.mu.Unlock()
	bucket.put(markKey, []byte("marked"), 48*time.Hour)

	bHit, releaseB := make(chan struct{}), make(chan struct{})
	var bOnce, releaseBOnce sync.Once
	sweepB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.TrimPrefix(r.URL.Path, "/") == claimKey {
			bOnce.Do(func() { close(bHit) })
			select {
			case <-releaseB:
			case <-ctx.Done():
				return
			}
		}
		bucket.serve(w, r)
	}))
	defer sweepB.Close()
	defer releaseBOnce.Do(func() { close(releaseB) })
	doneB := make(chan error, 1)
	go func() { doneB <- run(ctx, sweepB.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false) }()
	select {
	case <-bHit:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for sweep B claim PUT after final relist")
	}

	aHit, releaseA := make(chan struct{}), make(chan struct{})
	var aOnce, releaseAOnce sync.Once
	sweepA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.TrimPrefix(r.URL.Path, "/") == markKey {
			aOnce.Do(func() { close(aHit) })
			select {
			case <-releaseA:
			case <-ctx.Done():
				return
			}
		}
		bucket.serve(w, r)
	}))
	defer sweepA.Close()
	defer releaseAOnce.Do(func() { close(releaseA) })
	doneA := make(chan error, 1)
	go func() { doneA <- run(ctx, sweepA.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false) }()
	select {
	case <-aHit:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for sweep A after payload deletion")
	}
	if bucket.has(key) || !bucket.has(claimKey) || !bucket.has(markKey) {
		t.Fatal("invalid barrier: expected absent payload with A's claim and mark still present")
	}

	pubDir, pubDigest := fixtureCheckpointDir(t)
	if pubDigest != digest {
		t.Fatal("fixture digest changed")
	}
	// The publisher now contends with sweep A's held claim on the memory
	// chunk (same digest, fence engaged); run it async and release A once
	// contention is observed, so the claim-wait-then-reupload path executes.
	pubDone := make(chan error, 1)
	go func() {
		_, err := checkpointpublish.Run(ctx, pubDir, "review-new", store, plain.URL)
		pubDone <- err
	}()
	select {
	case err := <-pubDone:
		if err != nil {
			t.Fatalf("publisher failed while sweep A parked: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Still running: it must be waiting on A's claim; let A finish.
		releaseAOnce.Do(func() { close(releaseA) })
	}
	releaseAOnce.Do(func() { close(releaseA) })
	select {
	case err := <-pubDone:
		if err != nil {
			t.Fatalf("publisher: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("publisher did not finish after sweep A released")
	}
	if !bucket.has(key) {
		t.Fatal("publisher did not rebuild the payload")
	}
	if got := publisherClaimPuts.Load(); got < 1 {
		t.Fatalf("Has-miss recreate must participate in the claim protocol, got %d claim PUTs", got)
	}
	releaseBOnce.Do(func() { close(releaseB) })
	for _, done := range []chan error{doneA, doneB} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("sweep did not finish")
		}
	}
	keyed := store.(chunkstore.Keyed)
	if err := checkpointpublish.Materialize(ctx, filepath.Join(t.TempDir(), "materialized"), "review-new", keyed); err != nil {
		t.Fatalf("published artifact lost dependency after Has-miss publication between two collectors: %v", err)
	}
}

// Ported from the same recheck: a stale-claim cleanup derived from an old
// listing must not delete a replacement claim another participant created.
func TestReviewStaleCleanupDeletesReplacementClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	key := "overlay-chunks/aa/" + strings.Repeat("a", 64)
	claimKey := checkpointpublish.GCClaimKey(key)
	bucket.put(key, []byte("young payload"), 0)
	bucket.put(claimKey, []byte("old-owner-nonce"), 48*time.Hour)
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()

	hit, release := make(chan struct{}), make(chan struct{})
	var hitOnce, releaseOnce sync.Once
	parked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.TrimPrefix(r.URL.Path, "/") == claimKey {
			hitOnce.Do(func() { close(hit) })
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
		}
		bucket.serve(w, r)
	}))
	defer parked.Close()
	defer releaseOnce.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() { done <- run(ctx, parked.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false) }()
	select {
	case <-hit:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for collector B stale-claim DELETE")
	}

	if err := run(ctx, plain.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false); err != nil {
		t.Fatalf("collector A: %v", err)
	}
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.(chunkstore.ExclusivePutter).PutKeyIfAbsent(ctx, claimKey, strings.NewReader("new-owner-nonce"))
	if err != nil || !created {
		t.Fatalf("fresh publisher claim: created=%v err=%v", created, err)
	}
	acquired := time.Now()
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("collector B: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("collector B did not finish")
	}
	if !bucket.has(claimKey) {
		t.Fatalf("stale collector deleted replacement publisher claim aged only %s; mark-grace=24h", time.Since(acquired))
	}
}

// Reviewer 2026-09-15 §3.1 (degraded conditional DELETE): two collectors
// observe the same grace-old claim; collector A deletes it, a publisher
// atomically creates a replacement, and collector B's already-issued DELETE —
// bound to the OLD claim's generation — must never be able to destroy the
// replacement. On a backend that ignores If-Match on DELETE, GET+DELETE is
// not an atomic compare-and-delete, so the only safe behavior is to REFUSE
// automatic deletion on such a backend outright.
//
// On the unfixed baseline the run parks at B's stale-cleanup DELETE, the
// interleaving plays out, and B's stale DELETE destroys the fresh publisher
// claim (red). With the fix the run refuses at the preflight probe before
// any deletion and the claim is never endangered (green).
func TestReviewStaleCleanupDegradedBackendRefusesDeletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	bucket.ignoreDeleteIfMatch = true
	key := "overlay-chunks/aa/" + strings.Repeat("a", 64)
	claimKey := checkpointpublish.GCClaimKey(key)
	bucket.put(key, []byte("young payload"), 0)
	bucket.put(claimKey, []byte("old-owner-nonce"), 48*time.Hour)

	hit, release := make(chan struct{}), make(chan struct{})
	var hitOnce, releaseOnce sync.Once
	parked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.TrimPrefix(r.URL.Path, "/") == claimKey {
			hitOnce.Do(func() { close(hit) })
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
		}
		bucket.serve(w, r)
	}))
	defer parked.Close()
	defer releaseOnce.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() { done <- run(ctx, parked.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false) }()

	select {
	case <-hit:
		// Baseline interleaving: B is parked with its DELETE issued against
		// the OLD claim's generation. Collector A (unimpeded endpoint)
		// completes its own cleanup and removes the old claim; a publisher
		// then atomically acquires a fresh claim.
		plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
		defer plain.Close()
		if err := run(ctx, plain.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 2, false); err != nil {
			t.Fatalf("collector A: %v", err)
		}
		store, err := chunkstore.Open(plain.URL)
		if err != nil {
			t.Fatal(err)
		}
		created, err := store.(chunkstore.ExclusivePutter).PutKeyIfAbsent(ctx, claimKey, strings.NewReader("new-owner-nonce"))
		if err != nil || !created {
			t.Fatalf("fresh publisher claim: created=%v err=%v", created, err)
		}
		releaseOnce.Do(func() { close(release) })
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("collector B: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("collector B did not finish after the barrier")
		}
		if !bucket.has(claimKey) {
			t.Fatal("degraded backend: collector B's stale DELETE destroyed the publisher's replacement claim — GET+DELETE is not atomic when If-Match is ignored")
		}
	case err := <-done:
		// Fixed path: the store failed the conditional-delete probe, so the
		// sweep refused before any deletion (and before any mutation).
		if err == nil || !strings.Contains(err.Error(), "conditional DELETE") {
			t.Fatalf("degraded backend must refuse automatic deletion, got %v", err)
		}
		if !bucket.has(key) || !bucket.has(claimKey) {
			t.Fatal("a refusing sweep still mutated or deleted objects")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collector B neither parked at its stale DELETE nor refused")
	}
}

// Reviewer 2026-09-15 §3.2 (release before INDEX): the publisher's per-object
// claims end at each PUT while the artifact INDEX commits last, so a sweep
// that runs inside that gap — mature mark, min-age=0 — deletes the chunk the
// publication just landed; the publish still returns success and the
// published artifact is missing a block. The publication intent
// (gc-pubintents/<id>) must make the sweep skip every deletion while the
// publication is between its first store write and its INDEX commit.
//
// The publisher is parked deterministically by blocking its INDEX PUT (the
// barrier fires only after every chunk, claim, and bundle write completed),
// the collector runs to completion in that gap, and the final assertion is
// the reviewer's: a publish that returned success must be fully
// materializable.
func TestReviewPublishProtectedThroughIndexCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	overlayKey := checkpointpublish.OverlayChunkKey(digest)
	memoryKey := digest[:2] + "/" + digest
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Seed publication p1, drop it, and age its chunks' marks mature.
	if _, err := checkpointpublish.Run(ctx, dir, "p1", store, plain.URL); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := run(ctx, plain.URL, true, 0, []string{"p1"}, 0, time.Hour, 2, false); err != nil {
		t.Fatalf("mark-only sweep: %v", err)
	}
	if !bucket.has(checkpointpublish.GCMarkKey(overlayKey)) {
		t.Fatal("overlay chunk not marked")
	}
	rewindMark(bucket, overlayKey, 2*time.Hour)

	// Park the publisher's INDEX commit: every other store write of the
	// publication runs to completion first, so the barrier hit is exactly
	// the reviewer's pause point — uploads done, claims released, INDEX not
	// yet committed.
	indexKey := checkpointpublish.ArtifactKey("p2", checkpointpublish.IndexName)
	barrier := &barrierBucket{
		inner: bucket,
		block: func(method, key string) bool {
			return method == http.MethodPut && key == indexKey
		},
		hit:     make(chan string, 8),
		release: make(chan struct{}),
		done:    ctx.Done(),
	}
	pubSrv := httptest.NewServer(barrier)
	defer func() { cancel(); pubSrv.Close() }()
	pubStore, err := chunkstore.Open(pubSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p2dir := t.TempDir()
	for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p2dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pubDone := make(chan error, 1)
	go func() {
		_, err := checkpointpublish.Run(ctx, p2dir, "p2", pubStore, pubSrv.URL)
		pubDone <- err
	}()
	select {
	case <-barrier.hit:
	case <-time.After(20 * time.Second):
		t.Fatal("publisher never reached its INDEX commit")
	}

	// The collector runs while the publication is parked pre-INDEX: mature
	// mark on the overlay chunk, min-age=0 and mark-grace=0 — maximally
	// aggressive. It must not delete anything the publication needs.
	if err := run(ctx, plain.URL, true, 0, nil, 0, 0, 2, false); err != nil {
		t.Fatalf("collecting sweep: %v", err)
	}
	close(barrier.release)
	select {
	case err := <-pubDone:
		if err != nil {
			t.Fatalf("publisher: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("publisher did not finish after the barrier")
	}
	if !bucket.has(overlayKey) || !bucket.has(memoryKey) {
		t.Fatal("chunk deleted while the publication was between its uploads and the INDEX commit")
	}
	mat := filepath.Join(t.TempDir(), "mat")
	if err := checkpointpublish.Materialize(ctx, mat, "p2", store.(chunkstore.Keyed)); err != nil {
		t.Fatalf("publish returned success but the artifact lost a dependency to a mid-publish sweep: %v", err)
	}
}

// Ordering regression (reviewer 2026-09-17 follow-up): the deletion basis
// must observe publication intents BEFORE the INDEX listing of the same
// basis. The adversarial junction is a publisher that commits its INDEX
// and then deletes its intent while the sweep sits BETWEEN the two
// observations — an implementation that lists INDEX first and checks
// intents second would see NEITHER (INDEX not yet committed at listing
// time, intent already deleted at check time) and would delete the
// committed publication's chunks. The sweep is parked deterministically on
// the first full listing that follows any intent listing (the delete-time
// recheck), the publisher runs to FULL completion during the park, and
// the released sweep must then spare the chunk through the merged INDEX.
func TestReviewIntentIndexJunctionOrderedObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	overlayKey := checkpointpublish.OverlayChunkKey(digest)
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointpublish.Run(ctx, dir, "p1", store, plain.URL); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := run(ctx, plain.URL, true, 0, []string{"p1"}, 0, time.Hour, 2, false); err != nil {
		t.Fatalf("mark-only sweep: %v", err)
	}
	rewindMark(bucket, overlayKey, 2*time.Hour)

	parkHit, parkRelease := make(chan struct{}), make(chan struct{})
	var parkOnce, releaseOnce sync.Once
	var sawIntentList, parked bool
	sweepSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.RawQuery != "" {
			if r.URL.Query().Get("prefix") != "" {
				sawIntentList = true
			} else if sawIntentList && !parked {
				// First full listing after an intent listing: the
				// delete-time recheck. Park the sweep exactly between its
				// intent observation and its INDEX basis.
				parked = true
				parkOnce.Do(func() { close(parkHit) })
				select {
				case <-parkRelease:
				case <-ctx.Done():
					return
				}
			}
		}
		bucket.serve(w, r)
	}))
	defer sweepSrv.Close()
	defer releaseOnce.Do(func() { close(parkRelease) })
	sweepDone := make(chan error, 1)
	go func() { sweepDone <- run(ctx, sweepSrv.URL, true, 0, nil, 0, 0, 2, false) }()
	select {
	case <-parkHit:
	case <-time.After(20 * time.Second):
		t.Fatal("sweep never reached its delete-time recheck listing")
	}

	// The publisher runs to FULL completion during the park: chunk
	// uploads, INDEX commit, and intent deletion all land before the
	// sweep's INDEX basis is taken.
	p2dir := t.TempDir()
	for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p2dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkpointpublish.Run(ctx, p2dir, "p2", store, plain.URL); err != nil {
		t.Fatalf("publisher: %v", err)
	}
	if bucket.hasUnderPrefix(checkpointpublish.GCPubIntentNamespace + "/") {
		t.Fatal("publisher did not clean up its intent")
	}
	releaseOnce.Do(func() { close(parkRelease) })
	select {
	case err := <-sweepDone:
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("sweep did not finish after the barrier")
	}
	if !bucket.has(overlayKey) {
		t.Fatal("junction: sweep deleted a chunk of a publication whose INDEX committed and intent was deleted between the sweep's observations")
	}
	mat := filepath.Join(t.TempDir(), "mat")
	if err := checkpointpublish.Materialize(ctx, mat, "p2", store.(chunkstore.Keyed)); err != nil {
		t.Fatalf("artifact at the junction lost a dependency: %v", err)
	}
}

// Expired intents are garbage a dead publish left behind: past the grace
// they starve every later sweep, so a run with no young intent clears them
// — generation-bound (conditional delete on the freshly observed ETag) and
// only after a fresh age check, so a retrying publisher that refreshed the
// intent keeps it. A young intent makes the whole run a read-only skip
// (intents_wait): nothing is cleared, nothing deleted.
func TestSweepClearsExpiredIntents(t *testing.T) {
	bucket := newFakeBucket()
	deadKey := checkpointpublish.GCPubIntentNamespace + "/dead-publish/attempt-1"
	bucket.put(deadKey, []byte("crashed-owner"), 48*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	report, err := sweepRun(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 24*time.Hour, 24*time.Hour, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if bucket.has(deadKey) {
		t.Fatal("expired intent survived collection")
	}
	if report.IntentsCleared != 1 || report.IntentsTracked != 1 || report.IntentsWait != 0 {
		t.Fatalf("intent accounting: tracked=%d cleared=%d wait=%d, want 1/1/0",
			report.IntentsTracked, report.IntentsCleared, report.IntentsWait)
	}
	// A young intent turns the next run into a read-only skip: an expired
	// leftover from ANOTHER dead publish stays until a quiet run clears it.
	staleKey := checkpointpublish.GCPubIntentNamespace + "/older-dead/attempt-1"
	bucket.put(staleKey, []byte("older-owner"), 48*time.Hour)
	liveKey := checkpointpublish.GCPubIntentNamespace + "/live-publish/attempt-1"
	bucket.put(liveKey, []byte("live-owner"), 0)
	report, err = sweepRun(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 24*time.Hour, 24*time.Hour, 24*time.Hour, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bucket.has(liveKey) || !bucket.has(staleKey) {
		t.Fatal("an intents-wait run cleared or deleted an intent")
	}
	if report.IntentsWait != 1 {
		t.Fatalf("intents-wait accounting: wait=%d, want 1", report.IntentsWait)
	}
}

// Reviewer 2026-09-17 follow-up (overlapping attempts, same checkpoint ID):
// attempt A is parked between its uploads and its INDEX commit; attempt B
// under the SAME ID starts, completes, and legitimately removes its own
// intent. A is still alive, so its protection must NOT have been B's to
// remove: the sweep must still see a young intent and spare A's
// dependencies. A single shared intent key fails exactly here — B's
// legal conditional delete of its own generation would leave the running
// A with zero intent and collectable dependencies.
func TestReviewIntentPerAttemptOverlappingPublishers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	overlayKey := checkpointpublish.OverlayChunkKey(digest)
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointpublish.Run(ctx, dir, "p1", store, plain.URL); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := run(ctx, plain.URL, true, 0, []string{"p1"}, 0, time.Hour, 2, false); err != nil {
		t.Fatalf("mark-only sweep: %v", err)
	}
	rewindMark(bucket, overlayKey, 2*time.Hour)

	// Park ONLY the FIRST INDEX PUT under the shared ID (attempt A's);
	// attempt B's INDEX PUT must pass through and complete.
	indexKey := checkpointpublish.ArtifactKey("px", checkpointpublish.IndexName)
	var indexParks atomic.Int32
	parkHit, parkRelease := make(chan struct{}), make(chan struct{})
	var parkOnce sync.Once
	pubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.TrimPrefix(r.URL.Path, "/") == indexKey &&
			indexParks.Add(1) == 1 {
			parkOnce.Do(func() { close(parkHit) })
			select {
			case <-parkRelease:
			case <-ctx.Done():
				return
			}
		}
		bucket.serve(w, r)
	}))
	defer func() { cancel(); pubSrv.Close() }()
	pubStore, err := chunkstore.Open(pubSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	copyFixture := func() string {
		d := t.TempDir()
		for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	// Attempt A: parked between its uploads and its INDEX commit. A's
	// content is the seeded fixture, so its overlay chunk carries the
	// mature mark and is uploaded (fenced) before the park.
	aDone := make(chan error, 1)
	go func() {
		_, err := checkpointpublish.Run(ctx, copyFixture(), "px", pubStore, pubSrv.URL)
		aDone <- err
	}()
	select {
	case <-parkHit:
	case <-time.After(20 * time.Second):
		t.Fatal("attempt A never reached its INDEX commit")
	}
	// Attempt B under the SAME ID publishes DIFFERENT writable-layer
	// bytes: B's committed INDEX does not reference A's overlay chunk, so
	// the only thing standing between the collector and A's chunk is A's
	// mid-publish protection. B runs to FULL completion — including its
	// own intent cleanup — while A stays parked.
	bdir := copyFixture()
	bData := make([]byte, 256<<10)
	for i := range bData {
		bData[i] = byte(i*13 + 5)
	}
	if err := os.WriteFile(filepath.Join(bdir, "overlay.ext4"), bData, 0o600); err != nil {
		t.Fatal(err)
	}
	bSum := sha256.Sum256(bData)
	bDigest := hex.EncodeToString(bSum[:])
	bom := &checkpointchunks.Manifest{
		Version: 1, File: "overlay.ext4", FileSize: int64(len(bData)),
		ChunkBytes: 256 << 10, ChunkCount: 1,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		Entries:        []checkpointchunks.Chunk{{Offset: 0, Digest: bDigest}},
	}
	bom.FileDigest = checkpointchunks.RootDigest(bom.Entries)
	if err := checkpointchunks.WriteNamed(bdir, checkpointpublish.OverlaySidecarName, bom); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointpublish.Run(ctx, bdir, "px", store, plain.URL); err != nil {
		t.Fatalf("attempt B: %v", err)
	}

	// The collector runs now: A is still mid-publish, so a young intent
	// must remain and every deletion must be skipped.
	if err := run(ctx, plain.URL, true, 0, nil, 0, 0, 2, false); err != nil {
		t.Fatalf("collecting sweep: %v", err)
	}
	close(parkRelease)
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("attempt A: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("attempt A did not finish after the barrier")
	}
	if !bucket.has(overlayKey) {
		t.Fatal("attempt B's completion stripped the still-running attempt A's mid-publish protection")
	}
	// Both attempts' dependency chunks survive: A's (the marked, seeded
	// overlay block) through A's own still-young intent, and B's newly
	// uploaded block through the same skip. (Materializing "px" here is
	// deliberately NOT asserted: two overlapping same-ID attempts with
	// DIFFERENT content overwrite each other's ID-named BUNDLE/INDEX — an
	// unsupported topology by contract — and the collection safety of the
	// shared content-addressed chunks is what this regression pins.)
	bOverlayKey := checkpointpublish.OverlayChunkKey(bDigest)
	if !bucket.has(bOverlayKey) {
		t.Fatal("attempt B's uploaded chunk was collected while attempt A was still mid-publish")
	}
}

// Reviewer 2026-09-17 follow-up (claim liveness vs mark-grace=0): a
// publication intent protects publishers, never a RUNNING COLLECTOR's own
// claim. Collector A wins K's claim and parks mid-verdict; collector B —
// with no publisher intent in sight, since none is needed — must not be
// able to clear A's still-held claim just because -mark-grace is 0. If it
// could, a publisher would then win the freed claim, rebuild, and commit,
// and A's resumed DELETE would land on the committed generation with the
// mutual exclusion a fiction. Claim cleanup therefore has its OWN grace
// (-claim-grace), decoupled from mark-grace and positive under -delete.
func TestReviewClaimGraceDecoupledFromMarkGrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	overlayKey := checkpointpublish.OverlayChunkKey(digest)
	claimKey := checkpointpublish.GCClaimKey(overlayKey)
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointpublish.Run(ctx, dir, "p1", store, plain.URL); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if err := run(ctx, plain.URL, true, 0, []string{"p1"}, 0, time.Hour, 2, false); err != nil {
		t.Fatalf("mark-only sweep: %v", err)
	}
	rewindMark(bucket, overlayKey, 2*time.Hour)

	// Collector A: maximally aggressive (min-age 0, mark-grace 0), parked
	// at the data DELETE — holding the claim.
	barrier := &barrierBucket{
		inner: bucket,
		block: func(method, key string) bool {
			return method == http.MethodDelete && key == overlayKey
		},
		hit:     make(chan string, 8),
		release: make(chan struct{}),
		done:    ctx.Done(),
	}
	sweepSrv := httptest.NewServer(barrier)
	defer func() { cancel(); sweepSrv.Close() }()
	aDone := make(chan error, 1)
	go func() { aDone <- run(ctx, sweepSrv.URL, true, 0, nil, 0, 0, 2, false) }()
	select {
	case <-barrier.hit:
	case <-time.After(20 * time.Second):
		t.Fatal("collector A never reached its parked delete")
	}
	if !bucket.has(claimKey) {
		t.Fatal("invalid setup: collector A is not holding the claim")
	}

	// Collector B, same aggressive mark-grace of zero, runs to completion:
	// its stale-claim cleanup must spare A's held claim (claim-grace is a
	// separate, positive bound).
	if err := run(ctx, plain.URL, true, 0, nil, 0, 0, 2, false); err != nil {
		t.Fatalf("collector B: %v", err)
	}
	if !bucket.has(claimKey) {
		t.Fatal("mark-grace=0 let collector B clear a claim collector A was still holding")
	}

	// Let A finish its collection; a publisher then rebuilds the chunk and
	// commits — the whole sequence stays consistent.
	close(barrier.release)
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("collector A: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("collector A did not finish after the barrier")
	}
	p2dir := t.TempDir()
	for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p2dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkpointpublish.Run(ctx, p2dir, "p2", store, plain.URL); err != nil {
		t.Fatalf("rebuild publish: %v", err)
	}
	if !bucket.has(overlayKey) {
		t.Fatal("publisher did not rebuild the collected chunk")
	}
	mat := filepath.Join(t.TempDir(), "mat")
	if err := checkpointpublish.Materialize(ctx, mat, "p2", store.(chunkstore.Keyed)); err != nil {
		t.Fatalf("artifact after the full sequence lost a dependency: %v", err)
	}
}

// Reviewer diff recheck 2026-09-17 (unlocked mark clearing): collector A
// drops the artifacts that reference K, wins K's claim, and parks before
// its DELETE. Collector B, whose basis still sees the old INDEXes (A has
// not removed them yet), judges K live — not a victim — and its
// OBSOLETE-mark pass must not delete K's mark: a publisher arriving then
// would find no mark, reuse the object fence-less and claim-less, commit
// its INDEX, and A's resumed DELETE would land on the committed
// generation. Mark clearing therefore runs under the key's claim, exactly
// like the verdicts: B loses the claim race and leaves the mark alone.
func TestReviewMarkClearingClaimGuarded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	bucket := newFakeBucket()
	dir, digest := fixtureCheckpointDir(t)
	memoryKey := digest[:2] + "/" + digest
	overlayKey := checkpointpublish.OverlayChunkKey(digest)
	claimKey := checkpointpublish.GCClaimKey(overlayKey)
	markKey := checkpointpublish.GCMarkKey(overlayKey)
	plain := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer plain.Close()
	store, err := chunkstore.Open(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Two artifacts referencing the shared chunks; A will drop both.
	for _, id := range []string{"pa", "pb"} {
		pdir := t.TempDir()
		for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pdir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := checkpointpublish.Run(ctx, pdir, id, store, plain.URL); err != nil {
			t.Fatalf("seed publish %s: %v", id, err)
		}
	}
	// A mature mark on the overlay chunk (the candidate A will collect).
	bucket.put(markKey, []byte("mature"), 2*time.Hour)

	// Collector A: drop both artifacts, claim the overlay chunk, park at
	// its DELETE (min-age 0 / mark-grace 0; claim-grace default 24h).
	barrier := &barrierBucket{
		inner: bucket,
		block: func(method, key string) bool {
			return method == http.MethodDelete && key == overlayKey
		},
		hit:     make(chan string, 8),
		release: make(chan struct{}),
		done:    ctx.Done(),
	}
	sweepSrv := httptest.NewServer(barrier)
	defer func() { cancel(); sweepSrv.Close() }()
	aDone := make(chan error, 1)
	go func() { aDone <- run(ctx, sweepSrv.URL, true, 0, []string{"pa", "pb"}, 0, 0, 2, false) }()
	select {
	case <-barrier.hit:
	case <-time.After(20 * time.Second):
		t.Fatal("collector A never reached its parked delete")
	}
	if !bucket.has(claimKey) {
		t.Fatal("invalid setup: collector A is not holding the claim")
	}

	// Collector B sees both INDEXes (A has not deleted the sets yet), so K
	// is LIVE for B and its mark is an obsolete mark. B must lose the
	// claim race and leave the mark in place.
	if err := run(ctx, plain.URL, true, 0, nil, 0, 0, 2, false); err != nil {
		t.Fatalf("collector B: %v", err)
	}
	if !bucket.has(markKey) {
		t.Fatal("collector B cleared a mark whose object's claim a parked collector was still holding")
	}

	// Let A finish (collect the chunk, clear the mark, release), then a
	// publisher rebuilds and commits — the sequence stays consistent.
	close(barrier.release)
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("collector A: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("collector A did not finish after the barrier")
	}
	p2dir := t.TempDir()
	for _, name := range []string{"memory", "vmstate", "overlay.ext4", "manifest.json", checkpointchunks.ManifestName, checkpointpublish.OverlaySidecarName} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p2dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkpointpublish.Run(ctx, p2dir, "pc", store, plain.URL); err != nil {
		t.Fatalf("rebuild publish: %v", err)
	}
	if !bucket.has(overlayKey) || !bucket.has(memoryKey) {
		t.Fatal("publisher did not rebuild the collected chunks")
	}
	mat := filepath.Join(t.TempDir(), "mat")
	if err := checkpointpublish.Materialize(ctx, mat, "pc", store.(chunkstore.Keyed)); err != nil {
		t.Fatalf("artifact after the unlocked-mark sequence lost a dependency: %v", err)
	}
}
