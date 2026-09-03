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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeTemplate lays down a template directory exactly as the manufacture
// pipeline does — content-addressed by the ordered concatenation of
// manifest, vmstate, memory, overlay — and registers it in templates.json.
func writeTemplate(t *testing.T, root, name string, files map[string]string) (id, dir string) {
	t.Helper()
	dir = filepath.Join(root, "pending-"+name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for fname, content := range files {
		if err := os.WriteFile(filepath.Join(dir, fname), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{
		"version":       2,
		"snapshot_type": "full",
		"memory_size":   256 << 20,
		"compat":        map[string]any{"arch": "amd64", "firecracker": "fc", "kernel": "k"},
		"digests": map[string]string{
			"vmstate": mustSHA(files["vmstate"]),
			"memory":  mustSHA(files["memory"]),
		},
	}
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	for _, fname := range templateComponentOrder {
		b, err := os.ReadFile(filepath.Join(dir, fname))
		if err != nil {
			t.Fatalf("template file %s: %v", fname, err)
		}
		h.Write(b)
	}
	id = hex.EncodeToString(h.Sum(nil))[:16]
	final := filepath.Join(root, id)
	if err := os.Rename(dir, final); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, root, id, name, final, manifest)
	return id, final
}

func registerTemplate(t *testing.T, root, id, name, dir string, manifest map[string]any) {
	t.Helper()
	regPath := filepath.Join(root, registryName)
	reg := map[string]any{"templates": []any{}}
	if raw, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(raw, &reg)
	}
	entries := reg["templates"].([]any)
	entries = append(entries, map[string]any{
		"id": id, "name": name, "dir": dir,
		"created_at":    "2026-09-03T19:00:00Z",
		"snapshot_type": manifest["snapshot_type"],
		"memory_size":   manifest["memory_size"],
		"compat":        manifest["compat"],
		"digests":       manifest["digests"],
	})
	reg["templates"] = entries
	raw, _ := json.MarshalIndent(reg, "", "  ")
	if err := os.WriteFile(regPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSHA(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestListTemplatesLiveView(t *testing.T) {
	root := t.TempDir()
	id, _ := writeTemplate(t, root, "warm", map[string]string{
		"vmstate": "s", "memory": "m", "overlay.ext4": "o",
	})

	// A registry entry whose directory vanished is not listed.
	registerTemplate(t, root, "ghost0000000000000", "ghost",
		filepath.Join(root, "ghost0000000000000"),
		map[string]any{"snapshot_type": "full", "memory_size": 1 << 20,
			"compat": map[string]any{}, "digests": map[string]string{}})

	entries, err := ListTemplates(context.Background(), Config{TemplateRoots: []string{root}})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != id || entries[0].MemoryMiB != 256 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Compat == nil || entries[0].Compat.Firecracker != "fc" {
		t.Fatalf("compat not projected: %+v", entries[0].Compat)
	}
}

func TestVerifyTemplateContentAddress(t *testing.T) {
	root := t.TempDir()
	id, dir := writeTemplate(t, root, "warm", map[string]string{
		"vmstate": "s", "memory": "m", "overlay.ext4": "o",
	})
	cfg := Config{TemplateRoots: []string{root}}

	result, err := VerifyTemplate(context.Background(), cfg, id)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.IDOK || !result.DigestOK {
		t.Fatalf("verify = %+v", result)
	}

	// Mutate a byte: the content address must drift and the digest must fail.
	if err := os.WriteFile(filepath.Join(dir, "memory"), []byte("m2"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = VerifyTemplate(context.Background(), cfg, id)
	if err != nil {
		t.Fatalf("verify drifted: %v", err)
	}
	if result.IDOK || result.DigestOK {
		t.Fatalf("mutated template passed: %+v", result)
	}
	if result.Error == "" {
		t.Fatal("content-address drift unreported")
	}
}

func TestModuleServesTemplates(t *testing.T) {
	root := t.TempDir()
	id, _ := writeTemplate(t, root, "warm", map[string]string{
		"vmstate": "s", "memory": "m", "overlay.ext4": "o",
	})
	sock := filepath.Join(t.TempDir(), "catalog.sock")
	mod, err := NewModule(Config{SockPath: sock, TemplateRoots: []string{root}})
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	srv := httptest.NewServer(mod.handler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/v1/templates")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed struct {
		Templates []TemplateEntry `json:"templates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Templates) != 1 || listed.Templates[0].ID != id {
		t.Fatalf("templates = %+v", listed.Templates)
	}

	resp2, err := srv.Client().Get(srv.URL + "/api/v1/templates/" + id + "/verify")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var verified TemplateVerifyResult
	if err := json.NewDecoder(resp2.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified.IDOK || !verified.DigestOK {
		t.Fatalf("verify = %+v", verified)
	}
}
