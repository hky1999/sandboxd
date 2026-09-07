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

package checkpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectPairedCheckpointRejectsFilesystemDamage(t *testing.T) {
	for _, mode := range []string{"intact", "same-size-corruption", "missing-file", "wrong-identity"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "published")
			fact, err := PublishAt(dir, SourceIdentity{CheckpointID: "pair-test", SourceID: "sbox-source", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64), IncludeFilesystem: true}, func(image string) error {
				fs := filepath.Join(filepath.Dir(image), FsArtifactDirName)
				if err := os.MkdirAll(fs, 0700); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(fs, "pages.img"), []byte("before"), 0600); err != nil {
					return err
				}
				return os.WriteFile(image, []byte("memory"), 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			page := filepath.Join(dir, FsArtifactDirName, "pages.img")
			identity := fact.Manifest.CheckpointID
			switch mode {
			case "same-size-corruption":
				err = os.WriteFile(page, []byte("after!"), 0600)
			case "missing-file":
				err = os.Remove(page)
			case "wrong-identity":
				identity = "different"
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = InspectAt(dir, identity)
			if (err == nil) != (mode == "intact") {
				t.Fatalf("mode=%s validation error=%v", mode, err)
			}
		})
	}
}

func TestResourceLimitsAreBoundToPublishedManifest(t *testing.T) {
	for _, mode := range []string{"intact", "modified", "missing", "symlink", "oversized", "legacy-absent"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "checkpoint")
			fact, err := PublishAt(dir, SourceIdentity{CheckpointID: "limits", SourceID: "sandbox", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}, func(image string) error {
				if mode != "legacy-absent" {
					if err := os.WriteFile(filepath.Join(filepath.Dir(image), ResourceLimitsName), []byte(`{"memory_limit_bytes":536870912}`), 0600); err != nil {
						return err
					}
				}
				return os.WriteFile(image, []byte("memory-image"), 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			if mode != "legacy-absent" && (fact.Manifest.ResourceLimitsSize == 0 || fact.Manifest.ResourceLimitsSHA256 == "") {
				t.Fatal("sidecar digest missing")
			}
			path := filepath.Join(dir, ResourceLimitsName)
			switch mode {
			case "modified":
				err = os.WriteFile(path, []byte(`{"memory_limit_bytes":536870913}`), 0600)
			case "missing":
				err = os.Remove(path)
			case "symlink":
				target := filepath.Join(t.TempDir(), "limits")
				if err = os.Rename(path, target); err == nil {
					err = os.Symlink(target, path)
				}
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat("x", (64<<10)+1)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = InspectAt(dir, "limits")
			want := mode == "intact" || mode == "legacy-absent"
			if (err == nil) != want {
				t.Fatalf("inspect error=%v want valid=%v", err, want)
			}
			if err := VerifyResourceLimitsAt(dir); (err == nil) != want {
				t.Fatalf("restore sidecar verification=%v want valid=%v", err, want)
			}
		})
	}
}

func TestCheckpointReplayBindsPhysicalGeneration(t *testing.T) {
	source := SourceIdentity{CheckpointID: "physical", SourceID: "same-id", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64), SourceGeneration: "generation-one"}
	dir := filepath.Join(t.TempDir(), "published")
	build := func(image string) error { return os.WriteFile(image, []byte("checkpoint image"), 0600) }
	if _, err := PublishAt(dir, source, build); err != nil {
		t.Fatal(err)
	}
	fact, err := InspectAt(dir, source.CheckpointID)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Manifest.SourceGeneration != source.SourceGeneration {
		t.Fatal("physical generation not persisted")
	}
	if _, err := MatchSource(fact, source); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"generation-two", ""} {
		other := source
		other.SourceGeneration = changed
		if _, err := MatchSource(fact, other); err == nil {
			t.Fatalf("accepted changed generation %q", changed)
		}
		called := false
		if _, err := PublishAt(dir, other, func(string) error { called = true; return nil }); err == nil || called {
			t.Fatal("replay overwrote another physical generation")
		}
	}
}
