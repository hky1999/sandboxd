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

package checkpointcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeCheckpoint lays down a minimal v2 checkpoint directory whose
// manifest records real digests for the components it is given.
func writeCheckpoint(t *testing.T, root, name string, components map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	digests := make(map[string]string, len(components))
	for comp, content := range components {
		path := filepath.Join(dir, comp)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		sum := sha256.Sum256([]byte(content))
		digests[comp] = hex.EncodeToString(sum[:])
	}
	manifest := map[string]any{
		"version":       2,
		"snapshot_type": "full",
		"memory_size":   512 << 20,
		"created_at":    "2026-09-03T17:00:00Z",
		"compat": map[string]any{
			"arch":        "x86_64",
			"firecracker": "fc123",
			"kernel":      "k456",
			"initrd":      "i789",
			"vcpus":       2,
		},
		"digests": digests,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), raw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}

func TestListScansConfiguredRoots(t *testing.T) {
	root := t.TempDir()
	writeCheckpoint(t, root, "C1", map[string]string{
		"vmstate": "state-bytes",
		"memory":  "memory-bytes",
	})
	writeCheckpoint(t, root, "C2", map[string]string{"vmstate": "s2"})

	// A directory without a manifest is not a checkpoint and must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "half-written"), 0o700); err != nil {
		t.Fatal(err)
	}
	// So is a manifest with an unsupported version.
	bad := filepath.Join(root, "legacy")
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, manifestName), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	writeCheckpoint(t, other, "C3", map[string]string{"vmstate": "s3"})

	cfg := Config{Dirs: []string{root, other, filepath.Join(other, "missing")}}
	entries, err := List(context.Background(), cfg)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 (got %+v)", len(entries), entries)
	}
	byID := make(map[string]Entry, len(entries))
	for _, e := range entries {
		byID[e.ID] = e
	}
	for _, id := range []string{"C1", "C2", "C3"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("entry %s missing", id)
		}
	}
	if got := byID["C1"].MemoryMiB; got != 512 {
		t.Fatalf("C1 memory_mib = %d, want 512", got)
	}
	if byID["C1"].Compat == nil || byID["C1"].Compat.Firecracker != "fc123" || byID["C1"].Compat.Vcpus != 2 {
		t.Fatalf("C1 compat not projected: %+v", byID["C1"].Compat)
	}
	if _, ok := byID["half-written"]; ok {
		t.Fatal("unsealed directory listed")
	}
	if _, ok := byID["legacy"]; ok {
		t.Fatal("v1 manifest listed")
	}
}

func TestListQualifiesDuplicateIDs(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	writeCheckpoint(t, rootA, "C1", map[string]string{"vmstate": "a"})
	writeCheckpoint(t, rootB, "C1", map[string]string{"vmstate": "b"})

	entries, err := List(context.Background(), Config{Dirs: []string{rootA, rootB}})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	ids := map[string]bool{}
	for _, e := range entries {
		ids[e.ID] = true
	}
	if !ids["C1"] || len(ids) != 2 {
		t.Fatalf("duplicate ids not qualified: %v", ids)
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	writeCheckpoint(t, root, "good", map[string]string{
		"vmstate": "state",
		"memory":  "memory",
	})
	corrupt := writeCheckpoint(t, root, "bad", map[string]string{
		"vmstate": "original",
		"memory":  "original",
	})
	if err := os.WriteFile(filepath.Join(corrupt, "memory"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Dirs: []string{root}}

	good, err := Verify(context.Background(), cfg, "good")
	if err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if !good.DigestOK {
		t.Fatalf("good checkpoint failed verification: %+v", good.Components)
	}

	bad, err := Verify(context.Background(), cfg, "bad")
	if err != nil {
		t.Fatalf("verify bad: %v", err)
	}
	if bad.DigestOK {
		t.Fatal("tampered memory passed verification")
	}
	for _, c := range bad.Components {
		if c.Name == "memory" && c.OK {
			t.Fatal("tampered component reported ok")
		}
	}

	if _, err := Verify(context.Background(), cfg, "missing"); err == nil {
		t.Fatal("verify of unknown id succeeded")
	}
}

func TestModuleServesEndpoints(t *testing.T) {
	root := t.TempDir()
	writeCheckpoint(t, root, "C1", map[string]string{"vmstate": "s", "memory": "m"})
	sock := filepath.Join(t.TempDir(), "catalog.sock")
	mod, err := NewModule(Config{SockPath: sock, Dirs: []string{root}})
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	srv := httptest.NewServer(mod.handler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/v1/checkpoints")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	var listed struct {
		Checkpoints []Entry `json:"checkpoints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Checkpoints) != 1 || listed.Checkpoints[0].ID != "C1" {
		t.Fatalf("listed = %+v", listed.Checkpoints)
	}

	resp2, err := srv.Client().Get(srv.URL + "/api/v1/checkpoints/C1/verify")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer resp2.Body.Close()
	var verified VerifyResult
	if err := json.NewDecoder(resp2.Body).Decode(&verified); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if !verified.DigestOK {
		t.Fatalf("verify result = %+v", verified)
	}

	resp3, err := srv.Client().Get(srv.URL + "/api/v1/checkpoints/nope/verify")
	if err != nil {
		t.Fatalf("verify miss: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id status = %d", resp3.StatusCode)
	}
}
