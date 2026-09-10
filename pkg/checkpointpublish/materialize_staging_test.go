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

package checkpointpublish

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

func stagingFixtureStore(t *testing.T) (string, *chunkstore.Local) {
	t.Helper()
	source := fixtureCheckpoint(t)
	writeFullArtifact(t, source)
	store, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), source, filepath.Base(source), store, "test-local"); err != nil {
		t.Fatal(err)
	}
	return source, store
}

func TestMaterializeWithExternalPublishState(t *testing.T) {
	source, store := stagingFixtureStore(t)
	parent := t.TempDir()
	control, err := os.MkdirTemp("/dev/shm", "sandboxd-materialize-state-")
	if err != nil {
		t.Skipf("second writable filesystem unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(control) })
	pInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	cInfo, err := os.Stat(control)
	if err != nil {
		t.Fatal(err)
	}
	pStat, pOK := pInfo.Sys().(*syscall.Stat_t)
	cStat, cOK := cInfo.Sys().(*syscall.Stat_t)
	if !pOK || !cOK || pStat.Dev == cStat.Dev {
		t.Skip("cross-filesystem fixture unavailable")
	}
	t.Logf("target device=%d state device=%d", pStat.Dev, cStat.Dev)
	if err := os.Symlink(control, filepath.Join(parent, StateDirName)); err != nil {
		t.Fatal(err)
	}
	retained := filepath.Join(control, "staging-retained")
	if err := os.Mkdir(retained, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(retained, "keep")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "restored")
	if err := Materialize(context.Background(), target, filepath.Base(source), store); err != nil {
		t.Fatalf("materialize with external publication state: %v", err)
	}
	for _, name := range []string{"manifest.json", "chunks.json", "vmstate", "overlay.ext4"} {
		want, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("materialized %s mismatch: %v", name, err)
		}
	}
	memory, err := os.Stat(filepath.Join(target, "memory"))
	if err != nil || memory.Size() != int64(len(mustMemoryBytes(t, source))) {
		t.Fatalf("placeholder: %v %v", memory, err)
	}
	if _, err := os.Stat(filepath.Join(target, MaterializedMarker)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("old staging changed: %q %v", got, err)
	}
	entries, err := os.ReadDir(control)
	if err != nil || len(entries) != 1 {
		t.Fatalf("control directory modified: %v %v", entries, err)
	}
	entries, err = os.ReadDir(filepath.Join(parent, ".materialize"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("completed staging leaked: %v %v", entries, err)
	}
}

type stagingObservationStore struct {
	chunkstore.Keyed
	beforeGet func(string) error
}

func (s stagingObservationStore) GetKey(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := s.beforeGet(key); err != nil {
		return nil, err
	}
	return s.Keyed.GetKey(ctx, key)
}

func TestMaterializeStagingVisibilityAndFailureCleanup(t *testing.T) {
	source, store := stagingFixtureStore(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "failed")
	retained := filepath.Join(parent, ".materialize", "staging-retained")
	if err := os.MkdirAll(retained, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(retained, "keep")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected overlay chunk fetch failure")
	observed := false
	wrapped := stagingObservationStore{Keyed: store, beforeGet: func(key string) error {
		// The bundle era lands every small file in one GET, so the probe's
		// "partially materialized" moment is the overlay reassembly that
		// follows: the sidecar is staged, later chunks are not. Match both
		// the global namespace and the legacy per-ID fallback prefix.
		if !strings.Contains(key, "overlay-chunks/") {
			return nil
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("target visible before commit: %v", err)
		}
		if err := filepath.WalkDir(parent, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Name() == "manifest.json" {
				rel, err := filepath.Rel(parent, path)
				if err != nil {
					return err
				}
				parts := strings.Split(rel, string(filepath.Separator))
				if len(parts) < 3 || !strings.HasPrefix(parts[0], ".") {
					t.Fatalf("partial manifest visible at scan level: %s", rel)
				}
				observed = true
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !observed {
			t.Fatal("probe did not reach a partially materialized manifest")
		}
		return injected
	}}
	if err := Materialize(context.Background(), target, filepath.Base(source), wrapped); !errors.Is(err, injected) {
		t.Fatalf("wrong failure: %v", err)
	}
	if !observed {
		t.Fatal("fetch boundary not observed")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed target committed: %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("unrelated staging changed: %q %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(parent, ".materialize"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "staging-retained" {
		t.Fatalf("failed staging leaked: %v %v", entries, err)
	}
}
