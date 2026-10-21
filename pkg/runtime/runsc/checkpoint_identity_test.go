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

package runsc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

func a1RunscCheckpoint(t *testing.T, split bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range runscArtifactNames(split) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("sealed-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := sealRunscCheckpoint(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	binding, err := checkpointroot.Bind(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, binding.RootDigest
}

func a1RunscOpenRaw(t *testing.T, dir string, split bool) []*os.File {
	t.Helper()
	var files []*os.File
	for _, name := range runscArtifactNames(split) {
		f, err := openRegularRunscFile(filepath.Join(dir, name))
		if err != nil {
			closeFiles(files)
			t.Fatal(err)
		}
		files = append(files, f)
	}
	t.Cleanup(func() { closeFiles(files) })
	return files
}

func TestA1RunscSealedCheckpointRoundTrip(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "single"
		if split {
			name = "split"
		}
		t.Run(name, func(t *testing.T) {
			dir, root := a1RunscCheckpoint(t, split)
			files, havePages, err := openVerifiedRestoreFiles(context.Background(), filepath.Join(dir, checkpointImageName), root)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFiles(files)
			if havePages != split || len(files) != len(runscArtifactNames(split)) {
				t.Fatal("descriptor coverage differs")
			}
			for i, f := range files {
				offset, err := f.Seek(0, io.SeekCurrent)
				if err != nil || offset != 0 {
					t.Fatalf("verification consumed descriptor %d: offset=%d err=%v", i, offset, err)
				}
				got, err := io.ReadAll(f)
				if err != nil || string(got) != "sealed-"+runscArtifactNames(split)[i] {
					t.Fatalf("unexpected opened content: %q %v", got, err)
				}
			}
		})
	}
}

func TestA1RunscPinnedRestoreRefusesLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, checkpointImageName)
	if err := os.WriteFile(path, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	files, _, err := openVerifiedRestoreFiles(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	closeFiles(files)
	files, _, err = openVerifiedRestoreFiles(context.Background(), path, strings.Repeat("a", 64))
	if err == nil {
		closeFiles(files)
		t.Fatal("pinned restore accepted no seal")
	}
}

func TestA1RunscRejectsSameSizePayloadReplacement(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, true)
	path := filepath.Join(dir, checkpointPagesName)
	original := []byte("sealed-" + checkpointPagesName)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(original)), 0600); err != nil {
		t.Fatal(err)
	}
	binding, err := checkpointroot.Bind(dir)
	if err != nil || binding.RootDigest != root {
		t.Fatalf("test requires unchanged metadata identity: %v", err)
	}
	files, _, err := openVerifiedRestoreFiles(context.Background(), filepath.Join(dir, checkpointImageName), root)
	if err == nil {
		closeFiles(files)
		t.Fatal("metadata identity blessed wrong actual payload")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatal(err)
	}
}

func TestA1RunscUsesOpenedDescriptorNotReopenedPath(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, true)
	view, err := readRunscManifestView(context.Background(), dir, root)
	if err != nil {
		t.Fatal(err)
	}
	files := a1RunscOpenRaw(t, dir, true)
	path := filepath.Join(dir, checkpointPagesName)
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(replacement, bytes.Repeat([]byte{'x'}, len("sealed-"+checkpointPagesName)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenedRunscFiles(context.Background(), view, files); err != nil {
		t.Fatalf("valid held descriptor rejected: %v", err)
	}
	got, err := io.ReadAll(files[2])
	if err != nil || string(got) != "sealed-"+checkpointPagesName {
		t.Fatalf("held descriptor changed: %q %v", got, err)
	}
	newer, _, err := openVerifiedRestoreFiles(context.Background(), filepath.Join(dir, checkpointImageName), root)
	if err == nil {
		closeFiles(newer)
		t.Fatal("newly opened wrong descriptor accepted")
	}
}

func TestA1RunscBindsParsedManifestBytes(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, false)
	view, err := readRunscManifestView(context.Background(), dir, root)
	if err != nil {
		t.Fatal(err)
	}
	files := a1RunscOpenRaw(t, dir, false)
	changed := append(append([]byte{}, view.Raw...), []byte(" \n")...)
	if err := os.WriteFile(filepath.Join(dir, runscCheckpointManifestName), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyOpenedRunscFiles(context.Background(), view, files); err != nil {
		t.Fatalf("pinned opened manifest view was replaced by a path reread: %v", err)
	}
	if _, err := readRunscManifestView(context.Background(), dir, root); err == nil {
		t.Fatal("new manifest path view has old expected identity")
	}
}

func TestA1RunscManifestCoverageRefusals(t *testing.T) {
	for _, tc := range []string{"version", "runtime", "missing-digest", "extra-digest", "duplicate", "traversal", "page-pair", "bad-digest"} {
		t.Run(tc, func(t *testing.T) {
			dir, _ := a1RunscCheckpoint(t, true)
			raw, err := checkpointroot.ReadManifestBounded(dir)
			if err != nil {
				t.Fatal(err)
			}
			var manifest runscCheckpointManifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "version":
				manifest.Version = 1
			case "runtime":
				manifest.SnapshotType = "firecracker"
			case "missing-digest":
				delete(manifest.Digests, checkpointPagesName)
			case "extra-digest":
				manifest.Digests["extra.img"] = strings.Repeat("a", 64)
			case "duplicate":
				manifest.Artifacts[1] = manifest.Artifacts[0]
			case "traversal":
				manifest.Artifacts[0] = "../outside"
				manifest.Digests["../outside"] = manifest.Digests[checkpointImageName]
				delete(manifest.Digests, checkpointImageName)
			case "page-pair":
				manifest.Artifacts = []string{checkpointImageName, checkpointPagesName}
				delete(manifest.Digests, checkpointPagesMetadataName)
			case "bad-digest":
				manifest.Digests[checkpointImageName] = "not-a-sha256"
			}
			raw, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, runscCheckpointManifestName), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRunscManifestView(context.Background(), dir, ""); err == nil {
				t.Fatal("malformed manifest accepted")
			}
		})
	}
}

func TestA1RunscRejectsOversizeManifest(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, runscCheckpointManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(checkpointroot.MaxManifestBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, err := readRunscManifestView(context.Background(), dir, ""); err == nil {
		t.Fatal("oversized sparse manifest accepted")
	}
}

func TestA1RunscRejectsSymlinkAndFIFO(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir, root := a1RunscCheckpoint(t, false)
		path := filepath.Join(dir, checkpointImageName)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("sealed-"+checkpointImageName), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		files, _, err := openVerifiedRestoreFiles(context.Background(), path, root)
		if err == nil {
			closeFiles(files)
			t.Fatal("symlink accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fifo")
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := openRegularRunscFile(path)
		if err == nil {
			f.Close()
			t.Fatal("FIFO accepted")
		}
	})
}

func TestA1RunscSealRefusesPartialAndUnknownOutput(t *testing.T) {
	for _, tc := range []string{"empty", "page-pair", "unknown"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			if tc != "empty" {
				if err := os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("state"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch tc {
			case "page-pair":
				if err := os.WriteFile(filepath.Join(dir, checkpointPagesName), []byte("page"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "uncovered"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := sealRunscCheckpoint(context.Background(), dir); err == nil {
				t.Fatal("bad output sealed")
			}
			if _, err := os.Stat(filepath.Join(dir, runscCheckpointManifestName)); !os.IsNotExist(err) {
				t.Fatalf("bad output has commit marker: %v", err)
			}
		})
	}
}

func TestA1RunscVerificationCancellation(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	files, _, err := openVerifiedRestoreFiles(ctx, filepath.Join(dir, checkpointImageName), root)
	if !errors.Is(err, context.Canceled) {
		closeFiles(files)
		t.Fatalf("error=%v", err)
	}
}

func TestA1RunscClientVerifiesBeforeStateOrNetwork(t *testing.T) {
	dir, root := a1RunscCheckpoint(t, false)
	path := filepath.Join(dir, checkpointImageName)
	if err := os.WriteFile(path, []byte("wrong-checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	client := NewClient("/not-executed", t.TempDir())
	err := client.Restore(context.Background(), StartArgs{ID: "pinned", ExpectedCheckpointRoot: root}, path)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("restore failed at wrong boundary: %v", err)
	}
}

type a1RunscSealingClient struct {
	successfulRunscClient
	failure error
}

func (c a1RunscSealingClient) Checkpoint(_ context.Context, _ string, dir string, _ bool, _ bool) error {
	if c.failure != nil {
		return c.failure
	}
	return os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("checkpoint-output"), 0600)
}

func TestA1RunscHandlerSealsSuccessfulCheckpointOnly(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "runtime-failure"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			client := a1RunscSealingClient{}
			if fail {
				client.failure = errors.New("runtime failed")
			}
			handler := &Handler{runsc: client}
			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: "source", Directory: dir})
			if fail {
				if err == nil {
					t.Fatal("runtime failure swallowed")
				}
				if _, err := os.Stat(filepath.Join(dir, runscCheckpointManifestName)); !os.IsNotExist(err) {
					t.Fatal("failed runtime checkpoint sealed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := checkpointroot.Bind(dir); err != nil {
					t.Fatalf("successful checkpoint has no complete root: %v", err)
				}
			}
		})
	}
}
