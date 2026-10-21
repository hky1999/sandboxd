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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"golang.org/x/sys/unix"
)

const runscCheckpointManifestName = "manifest.json"

type runscCheckpointManifest struct {
	Version      int               `json:"version"`
	SnapshotType string            `json:"snapshot_type"`
	CreatedAt    time.Time         `json:"created_at"`
	Artifacts    []string          `json:"artifacts"`
	Digests      map[string]string `json:"digests"`
}

type runscManifestView struct {
	Dir      string
	Raw      []byte
	Manifest runscCheckpointManifest
	Root     string
}

func runscArtifactNames(split bool) []string {
	if split {
		return []string{checkpointImageName, checkpointPagesMetadataName, checkpointPagesName}
	}
	return []string{checkpointImageName}
}

func validateRunscManifest(manifest *runscCheckpointManifest) error {
	if manifest.Version != 2 || manifest.SnapshotType != "runsc" {
		return fmt.Errorf("unsupported runsc checkpoint manifest")
	}
	if len(manifest.Artifacts) != len(manifest.Digests) {
		return fmt.Errorf("runsc manifest artifact/digest coverage differs")
	}
	seen := make(map[string]bool)
	for _, name := range manifest.Artifacts {
		switch name {
		case checkpointImageName, checkpointPagesMetadataName, checkpointPagesName:
		default:
			return fmt.Errorf("unsupported runsc artifact %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate runsc artifact %q", name)
		}
		seen[name] = true
		digest := manifest.Digests[name]
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(digest) != 64 || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid runsc digest for %s", name)
		}
	}
	if !seen[checkpointImageName] || seen[checkpointPagesMetadataName] != seen[checkpointPagesName] {
		return fmt.Errorf("incomplete runsc checkpoint artifact set")
	}
	return nil
}

// readRunscManifestView parses exactly the bounded bytes fed to the shared
// root algorithm. Only legacy, unpinned restores may omit the seal.
func readRunscManifestView(ctx context.Context, dir, expected string) (*runscManifestView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, err := os.Lstat(filepath.Join(dir, runscCheckpointManifestName))
	if errors.Is(err, os.ErrNotExist) && expected == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect runsc manifest: %w", err)
	}
	raw, err := checkpointroot.ReadManifestBounded(dir)
	if err != nil {
		return nil, err
	}
	var manifest runscCheckpointManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode runsc manifest: %w", err)
	}
	if err := validateRunscManifest(&manifest); err != nil {
		return nil, err
	}
	binding, err := checkpointroot.RootFromView(dir, raw)
	if err != nil {
		return nil, err
	}
	if expected != "" && binding.RootDigest != expected {
		return nil, fmt.Errorf("runsc checkpoint content root %s does not match expected root %s", binding.RootDigest, expected)
	}
	return &runscManifestView{Dir: dir, Raw: raw, Manifest: manifest, Root: binding.RootDigest}, nil
}

func openRegularRunscFile(path string) (*os.File, error) {
	// O_NONBLOCK prevents a substituted FIFO/device from blocking the type
	// check. O_NOFOLLOW refuses a substituted symbolic link.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("runsc artifact %s is not regular", path)
	}
	return f, nil
}

type runscContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r runscContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Hash only the already opened descriptor, without moving its offset. The same
// descriptor is later transferred through URPC; path reopening cannot bless a
// different payload. The caller still guarantees directory/file immutability
// throughout the reader lifetime (not arbitrary concurrent in-place writes).
func digestOpenedRunscFile(ctx context.Context, f *os.File) (string, error) {
	if f == nil {
		return "", fmt.Errorf("nil runsc artifact descriptor")
	}
	before, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("runsc artifact is not regular")
	}
	h := sha256.New()
	section := io.NewSectionReader(f, 0, before.Size())
	if _, err := io.Copy(h, runscContextReader{ctx: ctx, reader: section}); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil {
		return "", err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", fmt.Errorf("runsc artifact changed during verification")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyOpenedRunscFiles(ctx context.Context, view *runscManifestView, files []*os.File) error {
	if view == nil {
		return fmt.Errorf("missing opened runsc manifest view")
	}
	binding, err := checkpointroot.RootFromView(view.Dir, view.Raw)
	if err != nil {
		return err
	}
	if binding.RootDigest != view.Root {
		return fmt.Errorf("runsc checkpoint view changed before consumption")
	}
	names := runscArtifactNames(len(view.Manifest.Artifacts) == 3)
	if len(files) != len(names) {
		return fmt.Errorf("opened runsc descriptor coverage differs")
	}
	for i, name := range names {
		got, err := digestOpenedRunscFile(ctx, files[i])
		if err != nil {
			return fmt.Errorf("verify opened %s: %w", name, err)
		}
		if got != view.Manifest.Digests[name] {
			return fmt.Errorf("runsc artifact %s digest mismatch", name)
		}
	}
	return nil
}

func openVerifiedRestoreFiles(ctx context.Context, imagePath, expected string) ([]*os.File, bool, error) {
	dir := filepath.Dir(imagePath)
	view, err := readRunscManifestView(ctx, dir, expected)
	if err != nil {
		return nil, false, err
	}
	if view == nil {
		return openRestoreFiles(imagePath)
	}
	if filepath.Base(imagePath) != checkpointImageName {
		return nil, false, fmt.Errorf("sealed runsc image name is not canonical")
	}
	split := len(view.Manifest.Artifacts) == 3
	var files []*os.File
	for _, name := range runscArtifactNames(split) {
		f, err := openRegularRunscFile(filepath.Join(dir, name))
		if err != nil {
			closeFiles(files)
			return nil, false, fmt.Errorf("open sealed %s: %w", name, err)
		}
		files = append(files, f)
	}
	if err := verifyOpenedRunscFiles(ctx, view, files); err != nil {
		closeFiles(files)
		return nil, false, err
	}
	return files, split, nil
}

// sealRunscCheckpoint is a correctness-first whole-file seal. It intentionally
// does not copy the old best-effort chunk sidecar, whose incomplete geometry
// cannot satisfy checkpointroot. Whole-file verification pre-reads cold pages;
// lazy per-chunk verification is a separate performance milestone.
func sealRunscCheckpoint(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	manifest := runscCheckpointManifest{Version: 2, SnapshotType: "runsc", CreatedAt: time.Now().UTC(), Digests: make(map[string]string)}
	for _, entry := range entries {
		name := entry.Name()
		if name == checkpointroot.ClaimFileName {
			continue
		}
		switch name {
		case checkpointImageName, checkpointPagesMetadataName, checkpointPagesName:
		default:
			return fmt.Errorf("unexpected runsc checkpoint entry %q", name)
		}
		f, err := openRegularRunscFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		digest, hashErr := digestOpenedRunscFile(ctx, f)
		if hashErr == nil {
			hashErr = f.Sync()
		}
		closeErr := f.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		manifest.Artifacts = append(manifest.Artifacts, name)
		manifest.Digests[name] = digest
	}
	sort.Strings(manifest.Artifacts)
	if err := validateRunscManifest(&manifest); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := checkpointroot.RootFromView(dir, raw); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := util.AtomicWriteFile(filepath.Join(dir, runscCheckpointManifestName), raw, 0600); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
