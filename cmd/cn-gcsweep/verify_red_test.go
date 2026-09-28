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

package main

// GC extraction-chain verification red tests (P1). The AUTHORITY (INDEX,
// Files digests, Bundle digest/Size/parts) is always generated from the
// ORIGINAL legitimate 2-entry sidecar; the corruption is applied AFTERWARD
// as a STORED-OBJECT (or INDEX-field) mutation only:
//
//   - bundle path: the stored BUNDLE object is rebuilt around a DIFFERENT,
//     internally valid, decodable sidecar that references fewer chunks —
//     the INDEX still describes the original, so its digests are stale;
//   - legacy path: the stored chunks.json OBJECT is replaced by that same
//     decodable reference-poorer sidecar — its bytes no longer hash to
//     index.Files[...];
//   - hostile part spans (int64 overflow), a foreign CheckpointID, a
//     MemoryRoot/ChunkCount closure mismatch, and a bundle one byte longer
//     than its declared Size.
//
// Every corrupted variant must make the WHOLE sweep fail with every live
// object surviving; the green control proves the pre-fix sweep accepts the
// untouched original. NOTE: on the pre-fix code the span-overflow test
// PANICS (the overflowed span reaches the slice expression) — run it in a
// separate invocation when collecting red evidence.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

const (
	vmstateBody = "vmstate-bytes"
	overlayBody = "overlay-bytes"
)

type stagedArtifact struct {
	bucket  *fakeBucket
	id      string
	digests []string
	sidecar []byte // the ORIGINAL, internally closed memory sidecar
	fc      []byte // the Firecracker manifest, CLOSED against the sidecar
	index   checkpointpublish.ArtifactIndex
	bundle  []byte // the ORIGINAL bundle object
}

func sidecarFor(digests []string, edit func(*checkpointchunks.Manifest)) []byte {
	m := &checkpointchunks.Manifest{
		Version: 2, File: "memory", FileSize: int64(len(digests)) * 4096,
		ChunkBytes: 4096, ChunkCount: len(digests),
		FileDigestMode: checkpointchunks.FileDigestChunks,
	}
	for i, d := range digests {
		m.Entries = append(m.Entries, checkpointchunks.Chunk{Offset: int64(i) * 4096, Digest: d})
	}
	if edit != nil {
		edit(m)
	}
	m.FileDigest = checkpointchunks.RootDigest(m.Entries)
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return raw
}

func buildBundle(sidecar, fc, overlaySidecar []byte) ([]byte, []checkpointpublish.BundlePart, map[string]string) {
	files := map[string]string{}
	var bundle []byte
	parts := []checkpointpublish.BundlePart{}
	addPart := func(name string, body []byte) {
		sum := sha256.Sum256(body)
		var prefix [8]byte
		length := uint64(len(body))
		for i := 0; i < 8; i++ {
			prefix[7-i] = byte(length >> (8 * i))
		}
		parts = append(parts, checkpointpublish.BundlePart{
			Name: name, Offset: int64(len(bundle)) + 8, Length: int64(len(body)),
			Digest: hex.EncodeToString(sum[:]),
		})
		bundle = append(append(bundle, prefix[:]...), body...)
		files[name] = hex.EncodeToString(sum[:])
	}
	addPart("manifest.json", fc)
	addPart(checkpointchunks.ManifestName, sidecar)
	addPart("vmstate", []byte(vmstateBody))
	// The writable layer ships either as one whole-file object
	// (OverlayChunks=false) or as an overlay sidecar part whose chunk
	// objects live in the global overlay-chunks namespace — the exact-set
	// verification expects whichever shape the INDEX declares.
	if overlaySidecar == nil {
		addPart("overlay.ext4", []byte(overlayBody))
	} else {
		addPart(checkpointpublish.OverlaySidecarName, overlaySidecar)
	}
	return bundle, parts, files
}

// stageOriginal computes a complete legitimate artifact WITHOUT writing it.
func stageOriginal(b *fakeBucket, id string, digests []string) *stagedArtifact {
	sidecar := sidecarFor(digests, nil)
	m := &checkpointchunks.Manifest{}
	if err := json.Unmarshal(sidecar, m); err != nil {
		panic(err)
	}
	// The Firecracker manifest CLOSES against the sidecar (same memory
	// size, chunks digest mode, and root) — a "placeholder" digest would
	// make the shape fail the very closure under test.
	fcObj := map[string]any{
		"version": 2, "memory_size": m.FileSize,
		"memory_digest_mode": checkpointchunks.FileDigestChunks,
		"digests":            map[string]string{"memory": m.FileDigest},
	}
	fcRaw, err := json.Marshal(fcObj)
	if err != nil {
		panic(err)
	}
	bundle, parts, files := buildBundle(sidecar, fcRaw, nil)
	return &stagedArtifact{
		bucket: b, id: id, digests: digests, sidecar: sidecar, fc: fcRaw, bundle: bundle,
		index: checkpointpublish.ArtifactIndex{
			CheckpointID: id, ChunkCount: len(digests), MemoryRoot: m.FileDigest,
			Files: files,
			Bundle: &checkpointpublish.BundleInfo{
				Digest: hexDigest(bundle), Size: int64(len(bundle)), Parts: parts,
			},
		},
	}
}

// spliceSidecar replaces the memory-sidecar part's bytes IN PLACE with an
// edited sidecar padded to the same length (JSON tolerates the trailing
// newlines): bundle size and every part span stay exactly as declared.
func (s *stagedArtifact) spliceSidecar(edited []byte) []byte {
	var span checkpointpublish.BundlePart
	for _, p := range s.index.Bundle.Parts {
		if p.Name == checkpointchunks.ManifestName {
			span = p
		}
	}
	if len(edited) > int(span.Length) {
		panic("edited sidecar longer than the original part — test setup bug")
	}
	padded := append(append([]byte(nil), edited...), bytes.Repeat([]byte("\n"), int(span.Length)-len(edited))...)
	out := append([]byte(nil), s.bundle...)
	copy(out[span.Offset:], padded)
	return out
}

func (s *stagedArtifact) legacyIndex() checkpointpublish.ArtifactIndex {
	idx := s.index
	idx.Bundle = nil
	return idx
}

func (s *stagedArtifact) putIndex(idx checkpointpublish.ArtifactIndex) {
	ib, err := json.Marshal(&idx)
	if err != nil {
		panic(err)
	}
	s.bucket.put(fmt.Sprintf("artifacts/%s/%s", s.id, checkpointpublish.IndexName), ib, 2*time.Hour)
}

func (s *stagedArtifact) put(key string, body []byte) {
	s.bucket.put(key, body, 2*time.Hour)
}

func (s *stagedArtifact) putLiveChunks() {
	for _, d := range s.digests {
		s.bucket.put(d[:2]+"/"+d, []byte("x"), 48*time.Hour)
	}
}

func (s *stagedArtifact) liveKeys() []string {
	keys := make([]string, len(s.digests))
	for i, d := range s.digests {
		keys[i] = d[:2] + "/" + d
	}
	return keys
}

// stagedFC builds the Firecracker manifest closed against the sidecar the
// EDITED artifact actually ships (self-consistent tamper: only the ORIGINAL
// INDEX authority stays stale).
func stagedFC(digests []string) []byte {
	edited := &checkpointchunks.Manifest{}
	if err := json.Unmarshal(sidecarFor(digests, dropLastEntry()), edited); err != nil {
		panic(err)
	}
	fcObj := map[string]any{
		"version": 2, "memory_size": edited.FileSize,
		"memory_digest_mode": checkpointchunks.FileDigestChunks,
		"digests":            map[string]string{"memory": edited.FileDigest},
	}
	raw, err := json.Marshal(fcObj)
	if err != nil {
		panic(err)
	}
	return raw
}

// dropLastEntry edits a sidecar into a fully VALID sidecar that describes
// only the FIRST chunk: consistent entries/ChunkCount/FileSize/root — it
// decodes cleanly and simply references fewer live objects.
func dropLastEntry() func(*checkpointchunks.Manifest) {
	return func(m *checkpointchunks.Manifest) {
		m.Entries = m.Entries[:1]
		m.ChunkCount = 1
		m.FileSize = 4096
	}
}

// mustSweepFailClosed requires the whole sweep round to ERROR with the
// expected failure CATEGORY (so a fix cannot pass by failing for an
// unrelated reason) and every live object to survive.
func mustSweepFailClosed(t *testing.T, b *fakeBucket, url, wantErr string, live ...string) {
	t.Helper()
	err := run(context.Background(), url, true, 0, nil, 24*time.Hour, 0, 4, false)
	if err == nil {
		t.Fatal("sweep accepted corrupted artifact metadata — must fail the whole round")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("sweep failed with the wrong category: want %q, got: %v", wantErr, err)
	}
	for _, key := range live {
		if !b.has(key) {
			t.Fatalf("live object deleted under corrupted metadata: %s", key)
		}
	}
}

func hexDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestSweepAcceptsRealShapeArtifact(t *testing.T) {
	bucket := newFakeBucket()
	// REALITY CHECK FIRST: the same fake HTTP store must satisfy the REAL
	// shared acceptance chain — materialize one artifact's full set (memory
	// chunks are not part of the set) before any GC claim about "real
	// shape" is made.
	mat := stageOriginal(bucket, "art-m", []string{digestOf(5), digestOf(6)})
	mat.put(fmt.Sprintf("artifacts/%s/%s", mat.id, checkpointpublish.BundleName), mat.bundle)
	mat.putIndex(mat.index)
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mStore, err := chunkstore.Open(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	mKeyed, ok := mStore.(chunkstore.Keyed)
	if !ok {
		t.Fatal("store lacks the keyed surface")
	}
	// Materialize's contract: the target LEAF must not pre-exist (a
	// non-empty target is refused rather than overwritten).
	dst := filepath.Join(t.TempDir(), "mat")
	if err := checkpointpublish.Materialize(context.Background(), dst, "art-m", mKeyed); err != nil {
		t.Fatalf("real-shape artifact must pass the shared materialize chain: %v", err)
	}
	for _, name := range []string{"manifest.json", checkpointchunks.ManifestName, "vmstate", "overlay.ext4"} {
		if _, err := os.Stat(dst + "/" + name); err != nil {
			t.Fatalf("materialized set missing %s: %v", name, err)
		}
	}
	// A SECOND same-shape artifact for the GC sweep itself.
	st := stageOriginal(bucket, "art-a", []string{digestOf(1), digestOf(2)})
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), st.bundle)
	st.putIndex(st.index)
	st.putLiveChunks()
	if err := run(context.Background(), server.URL, true, 0, nil, 24*time.Hour, 0, 4, false); err != nil {
		t.Fatalf("legitimate real-shape artifact must sweep cleanly: %v", err)
	}
	for _, key := range st.liveKeys() {
		if !bucket.has(key) {
			t.Fatalf("legitimate live chunk deleted: %s", key)
		}
	}
	if !bucket.has("artifacts/art-a/INDEX.json") || !bucket.has("artifacts/art-m/INDEX.json") {
		t.Fatal("live artifact set deleted")
	}
}

func TestSweepFailsClosedOnTamperedBundleSidecar(t *testing.T) {
	bucket := newFakeBucket()
	digests := []string{digestOf(1), digestOf(2)}
	st := stageOriginal(bucket, "art-a", digests)
	// STORED-OBJECT mutation only, LENGTH-PRESERVING: the edited sidecar is
	// padded with newlines to the ORIGINAL part length and spliced in place,
	// so every INDEX span still fits exactly (a shorter rebuild would trip
	// the existing span check and prove nothing). The INDEX authority still
	// describes the ORIGINAL artifact: its Bundle.Digest and Files are stale,
	// and the spliced sidecar decodes cleanly while referencing fewer chunks.
	tampered := st.spliceSidecar(sidecarFor(digests, dropLastEntry()))
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), tampered)
	st.putIndex(st.index)
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "digest mismatch", st.liveKeys()...)
}

func TestSweepFailsClosedOnLegacySidecarDigestMismatch(t *testing.T) {
	bucket := newFakeBucket()
	digests := []string{digestOf(1), digestOf(2)}
	st := stageOriginal(bucket, "art-a", digests)
	// STORED-OBJECT mutation only: the legacy chunks.json OBJECT is replaced
	// by a decodable reference-poorer sidecar — its bytes no longer hash to
	// the ORIGINAL index.Files[...] the authority still carries.
	st.put(fmt.Sprintf("artifacts/%s/manifest.json", st.id), st.fc)
	st.put(fmt.Sprintf("artifacts/%s/vmstate", st.id), []byte(vmstateBody))
	st.put(fmt.Sprintf("artifacts/%s/overlay.ext4", st.id), []byte(overlayBody))
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointchunks.ManifestName),
		sidecarFor(digests, dropLastEntry()))
	st.putIndex(st.legacyIndex())
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "digest mismatch", st.liveKeys()...)
}

func TestSweepFailsClosedOnIndexIDMismatch(t *testing.T) {
	bucket := newFakeBucket()
	st := stageOriginal(bucket, "art-a", []string{digestOf(1), digestOf(2)})
	idx := st.index
	idx.CheckpointID = "someone-else"
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), st.bundle)
	st.putIndex(idx)
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "names checkpoint", st.liveKeys()...)
}

func TestSweepFailsClosedOnSidecarIndexClosureMismatch(t *testing.T) {
	bucket := newFakeBucket()
	digests := []string{digestOf(1), digestOf(2)}
	st := stageOriginal(bucket, "art-a", digests)
	// Bundle, part digests and Files are all rebuilt consistently around a
	// DIFFERENT sidecar — only the INDEX's MemoryRoot/ChunkCount still
	// describe the original one (the closure the sweep must check).
	other := sidecarFor(digests, dropLastEntry())
	bundle, parts, files := buildBundle(other, stagedFC(digests), nil)
	idx := st.index
	idx.Bundle.Digest = hexDigest(bundle)
	idx.Bundle.Size = int64(len(bundle))
	idx.Bundle.Parts = parts
	idx.Files = files
	idx.ChunkCount = len(digests) // still the original count (2 vs shipped 1)
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), bundle)
	st.putIndex(idx)
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "identity mismatch", st.liveKeys()...)
}

func TestSweepFailsClosedOnBundleLengthDrift(t *testing.T) {
	bucket := newFakeBucket()
	st := stageOriginal(bucket, "art-a", []string{digestOf(1), digestOf(2)})
	// STORED-OBJECT mutation only: one byte longer than the declared
	// Bundle.Size — every span still fits, only an exact-length check sees it.
	drifted := append(append([]byte(nil), st.bundle...), 0)
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), drifted)
	st.putIndex(st.index)
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "declared", st.liveKeys()...)
}

func TestSweepFailsClosedOnBundleSpanOverflow(t *testing.T) {
	bucket := newFakeBucket()
	st := stageOriginal(bucket, "art-a", []string{digestOf(1), digestOf(2)})
	idx := st.index
	// Keep EVERY original part (the whitelist must pass) and rewrite only
	// the memory sidecar's span: Offset+Length overflows int64, so the
	// naive additive bound check passes and the pre-fix slice expression
	// goes out of range (a PANIC — see the file comment on red evidence).
	parts := append([]checkpointpublish.BundlePart(nil), st.index.Bundle.Parts...)
	for i := range parts {
		if parts[i].Name == checkpointchunks.ManifestName {
			parts[i].Offset = math.MaxInt64 - 4
			parts[i].Length = 8
		}
	}
	idx.Bundle.Parts = parts
	st.put(fmt.Sprintf("artifacts/%s/%s", st.id, checkpointpublish.BundleName), st.bundle)
	st.putIndex(idx)
	st.putLiveChunks()
	server := httptest.NewServer(http.HandlerFunc(bucket.serve))
	defer server.Close()
	mustSweepFailClosed(t, bucket, server.URL, "span out of range", st.liveKeys()...)
}
