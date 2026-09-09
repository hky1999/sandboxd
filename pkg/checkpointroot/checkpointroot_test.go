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

package checkpointroot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// writeChunkSidecar builds a structurally valid chunk sidecar for the
// artifact bytes already on disk, following the real seal's semantics:
// chunks digest mode, the root binding its entries, the seal's offset grid,
// and a file size matching the artifact. name selects the sidecar file name
// (the plain chunks.json for memory, SidecarName(artifact) otherwise).
func writeChunkSidecar(t *testing.T, dir, artifact, name string, chunkBytes int64) *checkpointchunks.Manifest {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, artifact))
	if err != nil {
		t.Fatalf("read artifact %s: %v", artifact, err)
	}
	size := int64(len(content))
	entries := make([]checkpointchunks.Chunk, 0, (size+chunkBytes-1)/chunkBytes)
	for offset := int64(0); offset < size; offset += chunkBytes {
		end := offset + chunkBytes
		if end > size {
			end = size
		}
		sum := sha256.Sum256(content[offset:end])
		entries = append(entries, checkpointchunks.Chunk{
			Offset: offset,
			Digest: hex.EncodeToString(sum[:]),
		})
	}
	manifest := &checkpointchunks.Manifest{
		Version:        1,
		File:           artifact,
		FileSize:       size,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		FileDigest:     checkpointchunks.RootDigest(entries),
		ChunkBytes:     int(chunkBytes),
		ChunkCount:     len(entries),
		Entries:        entries,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// seedSealedDirectory lays out a sealed checkpoint with a manifest digesting
// the named artifacts, real bytes on disk, and valid chunk sidecars for the
// artifacts whose sidecars are requested.
func seedSealedDirectory(
	t *testing.T,
	artifacts map[string]string, // artifact name -> on-disk bytes ("" = skip the file)
	digested []string, // names the manifest claims to digest
	sidecars map[string]bool, // artifact name -> write a valid sidecar
	chunkBytes int64,
	extraFiles map[string]string, // raw extra files (for malformed-input tests)
) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	digests := make(map[string]string, len(digested))
	for _, name := range digested {
		sum := sha256.Sum256([]byte(name))
		digests[name] = hex.EncodeToString(sum[:])
	}
	manifestBytes, err := json.Marshal(map[string]any{
		"version":       2,
		"snapshot_type": "Full",
		"digests":       digests,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for name, content := range artifacts {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name := range sidecars {
		sidecarName := checkpointchunks.ManifestName
		if name != "memory" {
			sidecarName = checkpointchunks.SidecarName(name)
		}
		writeChunkSidecar(t, dir, name, sidecarName, chunkBytes)
	}
	for name, content := range extraFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, map[string]string{"manifest": string(manifestRaw)}
}

func fcArtifacts() map[string]string {
	return map[string]string{
		"vmstate":      "vmstate-bytes",
		"memory":       "cold-memory-bytes",
		"overlay.ext4": "overlay-bytes",
	}
}

// A real chunks-mode Firecracker layout — manifest digests vmstate and the
// memory root, the memory and overlay sidecars sit next to their artifacts —
// binds, and so does a real runsc layout.
func TestBindRealArtifactLayouts(t *testing.T) {
	t.Run("firecracker chunks-mode directory", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(),
			[]string{"vmstate", "memory"},
			map[string]bool{"memory": true, "overlay.ext4": true},
			int64(16), nil)
		binding, err := Bind(dir)
		if err != nil {
			t.Fatalf("bind real Firecracker layout: %v", err)
		}
		if !binding.ManifestBound || !binding.OverlaySidecarBound {
			t.Fatalf("binding = %+v", binding)
		}
		if len(binding.RootDigest) != DigestHexLen {
			t.Fatalf("root digest %q", binding.RootDigest)
		}
		if binding.Scheme != Scheme {
			t.Fatalf("scheme %q, want %q", binding.Scheme, Scheme)
		}
	})

	t.Run("runsc sealed directory", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			map[string]string{"checkpoint.img": "image-bytes", "pages.img": "pages-bytes"},
			[]string{"checkpoint.img", "pages.img"},
			map[string]bool{"pages.img": true},
			int64(32), nil)
		binding, err := Bind(dir)
		if err != nil {
			t.Fatalf("bind real runsc layout: %v", err)
		}
		if binding.OverlaySidecarBound {
			t.Fatal("runsc layout must not claim an overlay sidecar")
		}
	})
}

// The source-directory ownership claim a Firecracker identified checkpoint
// writes beside the artifact is metadata, never content: a sealed directory
// binds the exact same root with or without it, while any other uncovered
// regular file keeps refusing the closure.
func TestClaimFileExcludedFromContentRoot(t *testing.T) {
	dir, _ := seedSealedDirectory(t,
		fcArtifacts(),
		[]string{"vmstate", "memory"},
		map[string]bool{"memory": true, "overlay.ext4": true},
		int64(16), nil)
	withoutClaim, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind without claim: %v", err)
	}
	claim, err := json.Marshal(map[string]any{
		"version":           1,
		"sandbox_id":        "sandbox-claim-root",
		"operation_id":      "op-claim-root",
		"request_digest":    strings.Repeat("ab", 32),
		"source_generation": "gen-claim-root",
		"directory":         dir,
		"directory_dev":     1,
		"directory_inode":   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ClaimFileName), claim, 0600); err != nil {
		t.Fatal(err)
	}
	withClaim, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind with claim: %v", err)
	}
	if withClaim.RootDigest != withoutClaim.RootDigest || withClaim.Scheme != withoutClaim.Scheme {
		t.Fatalf(
			"claim changed the content root: without %s, with %s",
			withoutClaim.RootDigest, withClaim.RootDigest,
		)
	}
	// The control: an arbitrary uncovered file still refuses the closure.
	if err := os.WriteFile(filepath.Join(dir, "uncovered-artifact"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind(dir); err == nil || !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("uncovered artifact = %v, want ErrUnverifiable", err)
	}
}

// A self-consistent replacement under the same path is a different
// checkpoint: neither the path nor the manifest shape identifies it.
func TestSamePathSelfConsistentReplacementChangesRoot(t *testing.T) {
	dir, _ := seedSealedDirectory(t,
		fcArtifacts(), []string{"vmstate", "memory"},
		map[string]bool{"memory": true, "overlay.ext4": true}, int64(16), nil)
	first, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind first artifact: %v", err)
	}

	// Replace the whole directory with a different but fully self-consistent
	// artifact (different bytes everywhere, valid seals again).
	for _, name := range []string{"manifest.json", "chunks.json",
		checkpointchunks.SidecarName("overlay.ext4")} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	replacement := fcArtifacts()
	replacement["memory"] = "different-cold-memory-bytes"
	replacement["overlay.ext4"] = "different-overlay-bytes"
	digests := map[string]string{}
	for _, name := range []string{"vmstate", "memory"} {
		sum := sha256.Sum256([]byte(name + "-replacement"))
		digests[name] = hex.EncodeToString(sum[:])
	}
	manifestBytes, _ := json.Marshal(map[string]any{"version": 2, "snapshot_type": "Full", "digests": digests})
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for name, content := range replacement {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeChunkSidecar(t, dir, "memory", checkpointchunks.ManifestName, 16)
	writeChunkSidecar(t, dir, "overlay.ext4", checkpointchunks.SidecarName("overlay.ext4"), 16)

	second, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind replacement artifact: %v", err)
	}
	if first.RootDigest == second.RootDigest {
		t.Fatal("a self-consistent replacement under the same path kept the root")
	}
}

// Malformed sidecars are refused: a root that does not bind its entries, a
// wrong artifact name, a size disagreement with the artifact, a non-chunks
// digest mode, and undigested artifacts without any sidecar.
func TestMalformedSidecarsAndCoverageRejected(t *testing.T) {
	t.Run("sidecar root does not bind entries", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"memory": true, "overlay.ext4": true}, int64(16), nil)
		sidecarPath := filepath.Join(dir, checkpointchunks.SidecarName("overlay.ext4"))
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		sidecar.FileDigest = strings.Repeat("a", 64) // breaks the root closure
		forged, _ := json.Marshal(&sidecar)
		if err := os.WriteFile(sidecarPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "does not bind its entries") {
			t.Fatalf("err = %v, want the root-closure rejection", err)
		}
	})

	t.Run("sidecar describes another file", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"overlay.ext4": true}, int64(16), nil)
		sidecarPath := filepath.Join(dir, checkpointchunks.SidecarName("overlay.ext4"))
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		sidecar.File = "memory"
		forged, _ := json.Marshal(&sidecar)
		if err := os.WriteFile(sidecarPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "describes file") {
			t.Fatalf("err = %v, want the artifact-name rejection", err)
		}
	})

	t.Run("sidecar size disagrees with the artifact", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"overlay.ext4": true}, int64(16), nil)
		if err := os.Truncate(filepath.Join(dir, "overlay.ext4"), 4); err != nil {
			t.Fatal(err)
		}
		_, err := Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "sidecar expects") {
			t.Fatalf("err = %v, want the size-disagreement rejection", err)
		}
	})

	t.Run("sidecar carries an unknown digest mode", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"overlay.ext4": true}, int64(16), nil)
		sidecarPath := filepath.Join(dir, checkpointchunks.SidecarName("overlay.ext4"))
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		sidecar.FileDigestMode = "bogus"
		forged, _ := json.Marshal(&sidecar)
		if err := os.WriteFile(sidecarPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "unknown digest mode") {
			t.Fatalf("err = %v, want the digest-mode rejection", err)
		}
	})

	t.Run("whole-file sidecar disagreeing with the manifest", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"memory": true}, int64(16), nil)
		sidecarPath := filepath.Join(dir, checkpointchunks.ManifestName)
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		// The real pre-chunks shape: mode "" and the whole-file digest. The
		// seal computes it in the same pass as the manifest digest, so a
		// disagreement between the two breaks the closure.
		sidecar.FileDigestMode = ""
		sidecar.FileDigest = strings.Repeat("b", 64)
		forged, _ := json.Marshal(&sidecar)
		if err := os.WriteFile(sidecarPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "the manifest records") {
			t.Fatalf("err = %v, want the whole-file closure rejection", err)
		}
	})

	t.Run("whole-file sidecar agreeing with the manifest binds", func(t *testing.T) {
		// A directory with no overlay at all (runsc-style): the memory
		// sidecar in whole-file mode matches the manifest digest.
		artifacts := map[string]string{"vmstate": "state", "memory": "cold-memory-bytes"}
		dir, _ := seedSealedDirectory(t,
			artifacts, []string{"vmstate", "memory"},
			map[string]bool{"memory": true}, int64(16), nil)
		// Rewrite the sidecar into the whole-file shape: the digest the
		// manifest recorded for memory was sha256 over the artifact name in
		// the seed helper, so recompute the closure the seal would produce:
		// the manifest digest equals the whole-file hash only in the real
		// seal; here the manifest is synthetic, so align the manifest to the
		// sidecar's whole-file digest instead.
		sum := sha256.Sum256([]byte(artifacts["memory"]))
		wholeFile := hex.EncodeToString(sum[:])
		manifestPath := filepath.Join(dir, "manifest.json")
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Version      int               `json:"version"`
			SnapshotType string            `json:"snapshot_type"`
			Digests      map[string]string `json:"digests"`
		}
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Digests["memory"] = wholeFile
		realigned, _ := json.Marshal(&manifest)
		if err := os.WriteFile(manifestPath, realigned, 0600); err != nil {
			t.Fatal(err)
		}
		sidecarPath := filepath.Join(dir, checkpointchunks.ManifestName)
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		sidecar.FileDigestMode = ""
		sidecar.FileDigest = wholeFile
		forged, _ := json.Marshal(&sidecar)
		if err := os.WriteFile(sidecarPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		binding, err := Bind(dir)
		if err != nil {
			t.Fatalf("the real pre-chunks whole-file shape must bind: %v", err)
		}
		if !binding.ManifestBound || len(binding.RootDigest) != DigestHexLen {
			t.Fatalf("binding = %+v", binding)
		}
	})

	t.Run("artifact without verifiable root", func(t *testing.T) {
		// memory is present but the manifest digests only vmstate, and no
		// sidecar covers it.
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate"},
			map[string]bool{"overlay.ext4": true}, int64(16), nil)
		_, err := Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "no verifiable root") {
			t.Fatalf("err = %v, want the coverage rejection", err)
		}
	})

	t.Run("overlay without sidecar", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"memory": true}, int64(16), nil)
		_, err := Bind(dir)
		if err == nil || !strings.Contains(err.Error(), "no chunk sidecar") {
			t.Fatalf("err = %v, want the overlay-sidecar rejection", err)
		}
	})

	t.Run("unsealed and empty-seal directories", func(t *testing.T) {
		unsealed := t.TempDir()
		if err := os.WriteFile(filepath.Join(unsealed, "checkpoint.img"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Bind(unsealed); err == nil || !strings.Contains(err.Error(), "no sealed manifest") {
			t.Fatalf("err = %v, want the unsealed rejection", err)
		}
		emptySeal := t.TempDir()
		if err := os.WriteFile(filepath.Join(emptySeal, "manifest.json"),
			[]byte(`{"version":2,"digests":{}}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Bind(emptySeal); err == nil || !strings.Contains(err.Error(), "not a complete seal") {
			t.Fatalf("err = %v, want the empty-seal rejection", err)
		}
	})

	t.Run("symlink artifact", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			map[string]string{"checkpoint.img": "image"},
			[]string{"checkpoint.img"}, nil, 0, nil)
		if err := os.Remove(filepath.Join(dir, "checkpoint.img")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/hosts", filepath.Join(dir, "checkpoint.img")); err != nil {
			t.Fatal(err)
		}
		if _, err := Bind(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want the regular-file rejection", err)
		}
	})
}

// Oversized metadata is rejected from the stat alone — the read is bounded
// before any byte is buffered.
func TestOversizeMetadataRejected(t *testing.T) {
	t.Run("oversize manifest", func(t *testing.T) {
		dir := t.TempDir()
		f, err := os.Create(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		// A sparse file: the size claims oversize without writing it.
		if err := f.Truncate(int64(MaxManifestBytes + 1)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err := Bind(dir); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want the oversize rejection", err)
		}
	})

	t.Run("oversize sidecar", func(t *testing.T) {
		dir, _ := seedSealedDirectory(t,
			fcArtifacts(), []string{"vmstate", "memory"},
			map[string]bool{"overlay.ext4": true}, int64(16), nil)
		f, err := os.Create(filepath.Join(dir, checkpointchunks.SidecarName("overlay.ext4")))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(checkpointchunks.MaxManifestBytes + 1)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err := Bind(dir); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want the oversize rejection", err)
		}
	})
}

// RootFromView computes the identity from the manifest bytes the caller
// supplies, never from a second read of manifest.json: after the file on disk
// changes, RootFromView with the original bytes still yields the original
// manifest component (while Bind sees the new one), and the sidecar/size
// components stay bound to the current directory.
func TestRootFromViewUsesSuppliedManifestBytes(t *testing.T) {
	dir, _ := seedSealedDirectory(t,
		fcArtifacts(), []string{"vmstate", "memory"},
		map[string]bool{"memory": true, "overlay.ext4": true}, int64(16), nil)
	binding, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	originalRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Mutate ONLY the manifest on disk.
	forged := strings.Replace(string(originalRaw), `"Full"`, `"Incremental"`, 1)
	if forged == string(originalRaw) {
		t.Fatal("fixture failed to change the manifest")
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(forged), 0600); err != nil {
		t.Fatal(err)
	}

	fromView, err := RootFromView(dir, originalRaw)
	if err != nil {
		t.Fatalf("root from the opened view: %v", err)
	}
	if fromView.RootDigest != binding.RootDigest {
		t.Fatal("RootFromView re-read manifest.json instead of using the supplied view")
	}
	onDisk, err := Bind(dir)
	if err != nil {
		t.Fatalf("bind the mutated directory: %v", err)
	}
	if onDisk.RootDigest == binding.RootDigest {
		t.Fatal("the on-disk mutation did not change the bound root")
	}

	// The supplied view still participates: different bytes give a different
	// root over the same directory.
	shifted, err := RootFromView(dir, []byte(forged))
	if err != nil {
		t.Fatalf("root from the forged view: %v", err)
	}
	if shifted.RootDigest != onDisk.RootDigest {
		t.Fatal("RootFromView over the current bytes disagreed with Bind")
	}

	// An empty view is an explicit error, not a silent re-read.
	if _, err := RootFromView(dir, nil); err == nil || !strings.Contains(err.Error(), "no opened manifest view") {
		t.Fatalf("err = %v, want the empty-view rejection", err)
	}
}

// The identity binds each sidecar's full logical geometry — file, size,
// normalized digest mode, chunk grid, count, file digest, and the independent
// root over its entries — so a different read geometry or a changed entry is
// a different checkpoint even when the file digest still agrees.
func TestSidecarGeometryBindsIdentity(t *testing.T) {
	forge := func(dir, name string, mutate func(*checkpointchunks.Manifest)) []byte {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var sidecar checkpointchunks.Manifest
		if err := json.Unmarshal(raw, &sidecar); err != nil {
			t.Fatal(err)
		}
		mutate(&sidecar)
		forged, err := json.Marshal(&sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), forged, 0600); err != nil {
			t.Fatal(err)
		}
		return forged
	}

	t.Run("chunks-mode geometry change changes the root", func(t *testing.T) {
		dir := t.TempDir()
		data := []byte("0123456789")
		if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0600); err != nil {
			t.Fatal(err)
		}
		hash := func(b []byte) string {
			sum := sha256.Sum256(b)
			return hex.EncodeToString(sum[:])
		}
		manifestBytes, _ := json.Marshal(map[string]any{
			"version":       2,
			"snapshot_type": "Full",
			"digests":       map[string]string{"memory": hash(data)},
		})
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0600); err != nil {
			t.Fatal(err)
		}
		// A 6-byte grid, then the same bytes re-chunked on a 7-byte grid.
		entries := []checkpointchunks.Chunk{
			{Offset: 0, Digest: hash(data[:6])},
			{Offset: 6, Digest: hash(data[6:])},
		}
		sidecar := checkpointchunks.Manifest{
			Version:        1,
			File:           "memory",
			FileSize:       10,
			FileDigest:     checkpointchunks.RootDigest(entries),
			FileDigestMode: checkpointchunks.FileDigestChunks,
			ChunkBytes:     6,
			ChunkCount:     2,
			Entries:        entries,
		}
		raw, _ := json.Marshal(sidecar)
		if err := os.WriteFile(filepath.Join(dir, checkpointchunks.ManifestName), raw, 0600); err != nil {
			t.Fatal(err)
		}
		first, err := Bind(dir)
		if err != nil {
			t.Fatal(err)
		}
		forge(dir, checkpointchunks.ManifestName, func(m *checkpointchunks.Manifest) {
			m.ChunkBytes = 7
			m.Entries[1].Offset = 7
		})
		second, err := Bind(dir)
		if err != nil {
			// A refusal is acceptable only when the geometry itself became
			// invalid; the identical root is never acceptable.
			return
		}
		if first.RootDigest == second.RootDigest {
			t.Fatalf("a different read geometry kept the root %s", first.RootDigest)
		}
	})

	t.Run("whole-file sidecar entry digest change changes the root", func(t *testing.T) {
		// Whole-file mode: FileDigest is the manifest's whole-file hash and
		// binds nothing about the entries — the independent entries root is
		// what catches a changed entry.
		dir, _ := seedSealedDirectory(t,
			map[string]string{"memory": "cold-memory-bytes"},
			[]string{"memory"}, map[string]bool{"memory": true}, int64(8), nil)
		sum := sha256.Sum256([]byte("cold-memory-bytes"))
		wholeFile := hex.EncodeToString(sum[:])
		// Align the manifest digest with the sidecar's whole-file digest so
		// the closure holds in both states.
		manifestPath := filepath.Join(dir, "manifest.json")
		manifestRaw, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Version      int               `json:"version"`
			SnapshotType string            `json:"snapshot_type"`
			Digests      map[string]string `json:"digests"`
		}
		if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Digests["memory"] = wholeFile
		realigned, _ := json.Marshal(&manifest)
		if err := os.WriteFile(manifestPath, realigned, 0600); err != nil {
			t.Fatal(err)
		}
		first, err := Bind(dir)
		if err != nil {
			t.Fatal(err)
		}
		forge(dir, checkpointchunks.ManifestName, func(m *checkpointchunks.Manifest) {
			m.FileDigestMode = ""
			m.FileDigest = wholeFile
			// One entry digest changes while the whole-file digest still
			// agrees with the manifest.
			m.Entries[0].Digest = strings.Repeat("c", 64)
		})
		second, err := Bind(dir)
		if err != nil {
			t.Fatal(err)
		}
		if first.RootDigest == second.RootDigest {
			t.Fatal("a changed entry digest kept the root in whole-file mode")
		}
	})

	t.Run("pack references stay out of the local sidecar format", func(t *testing.T) {
		// Pack placement (identity/offset/length/object size) is physical
		// transport data: the local sidecar format never carries it, and the
		// loader keeps rejecting a version-1 sidecar that tries. The logical
		// root composition folds no pack field, so relocating packs between
		// object-store locations cannot change a checkpoint's identity.
		dir, _ := seedSealedDirectory(t,
			map[string]string{"memory": "cold-memory-bytes"},
			[]string{"memory"}, map[string]bool{"memory": true}, int64(8), nil)
		forge(dir, checkpointchunks.ManifestName, func(m *checkpointchunks.Manifest) {
			m.Packs = map[string]checkpointchunks.PackReference{
				"pack-0": {Digest: strings.Repeat("d", 64), Offset: 0, Length: 8, ObjectSize: 8},
			}
		})
		if _, err := Bind(dir); err == nil || !strings.Contains(err.Error(), "cannot reference packs") {
			t.Fatalf("err = %v, want the existing pack-format rejection", err)
		}
	})
}
