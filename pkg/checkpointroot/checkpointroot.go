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

// Package checkpointroot derives the content-root identity of a checkpoint
// directory. It is deliberately free of runtime dependencies so that the
// server's restore-operation admission and the runtime's restore consumption
// boundary compute the identity with ONE algorithm — the server binds what
// the caller pinned, the runtime verifies what it actually opens, and the two
// can never drift into hashing different views of the same directory.
package checkpointroot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

const (
	// Scheme names the identity composition: the sealed manifest bytes, each
	// validated chunk sidecar's full logical geometry (file, file size,
	// normalized digest mode, chunk grid, count, file digest, and the
	// independent root over its entries — pack placement excluded), and the
	// size of uncovered regular files.
	Scheme = "v2:manifest+sidecar-roots"

	// DigestHexLen is the length of every hex digest this package produces
	// or compares.
	DigestHexLen = 64

	manifestName       = "manifest.json"
	overlayName        = "overlay.ext4"
	materializedMarker = ".materialized"

	// MaxManifestBytes is the shared bound on one sealed manifest.json read.
	// Every consumer — the server's admission Bind and the runtimes feeding
	// RootFromView — reads the manifest through ReadManifestBounded so an
	// oversized (possibly sparse) manifest is refused by its stat before any
	// byte is buffered, and the bytes a runtime parses are exactly the bytes
	// its identity check recomputes the root from.
	MaxManifestBytes = 1 << 20
)

// ErrUnverifiable marks a directory whose artifacts admit no verifiable
// content root (no seal, an uncovered artifact, a malformed sidecar); callers
// map it to their refusal errors.
var ErrUnverifiable = errors.New("checkpoint content root is not verifiable")

// Binding is the derived content-root identity of one checkpoint directory.
type Binding struct {
	// RootDigest is the hex sha-256 over the canonical composition; two
	// directories with different roots are different checkpoints even when
	// they share a path (or manifest bytes).
	RootDigest string
	// Scheme repeats the composition scheme recorded beside the digest.
	Scheme string
	// ManifestBound reports that a sealed manifest.json was read and folded
	// in. Admissions reject unsealed directories, so bindings produced by
	// this package always carry true; the field keeps the evidence explicit.
	ManifestBound bool
	// OverlaySidecarBound reports that the Firecracker writable overlay's
	// chunk sidecar was present, validated, and folded in.
	OverlaySidecarBound bool
}

// Bind derives the admission binding of a checkpoint directory: it reads the
// sealed manifest itself (stat-bounded) and enforces the full strictness
// closure — manifest shape, sidecar schema/version/mode/file/size/grid/root
// validation, and coverage of every regular file. It never reads artifact
// payloads: cold guest memory stays lazy and the overlay's actual bytes are
// verified by the runtime's own restore-time content check, not here.
func Bind(checkpointDir string) (*Binding, error) {
	raw, err := readManifestBounded(checkpointDir)
	if err != nil {
		return nil, err
	}
	return bindFromView(checkpointDir, raw)
}

// RootFromView recomputes the content root from the manifest bytes the caller
// already opened and parsed — the same view the runtime is about to consume,
// never a second independent read of manifest.json. The full strictness
// closure still runs over the directory, so a directory that changed since
// admission yields a different root (or an explicit error) instead of a
// silently accepted identity.
func RootFromView(checkpointDir string, manifestRaw []byte) (*Binding, error) {
	if len(manifestRaw) == 0 {
		return nil, fmt.Errorf("no opened manifest view for %s: %w", checkpointDir, ErrUnverifiable)
	}
	if len(manifestRaw) > MaxManifestBytes {
		return nil, fmt.Errorf("opened manifest view of %s exceeds %d bytes: %w", checkpointDir, MaxManifestBytes, ErrUnverifiable)
	}
	return bindFromView(checkpointDir, manifestRaw)
}

// sealedManifest is the generic shape of the seals runsc and Firecracker both
// write as manifest.json. The digests map names the artifact files the seal
// covers; the Firecracker writable overlay is deliberately outside it and is
// bound through its chunk sidecar instead.
type sealedManifest struct {
	Version      int               `json:"version"`
	SnapshotType string            `json:"snapshot_type"`
	Digests      map[string]string `json:"digests"`
}

// ReadManifestBounded reads a sealed manifest.json with its size checked by
// Lstat before any allocation and the read itself bounded, so a file growing
// between the check and the read cannot force an unbounded buffer. It is the
// single shared reader behind Bind and of the runtimes' restore boundary.
func ReadManifestBounded(dir string) ([]byte, error) {
	return readManifestBounded(dir)
}

func readManifestBounded(dir string) ([]byte, error) {
	path := filepath.Join(dir, manifestName)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("checkpoint directory %s carries no sealed manifest: %w", dir, ErrUnverifiable)
		}
		return nil, fmt.Errorf("inspect checkpoint manifest in %s: %w", dir, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("checkpoint manifest in %s is not a regular file: %w", dir, ErrUnverifiable)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("checkpoint manifest in %s is %d bytes, exceeds %d: %w", dir, info.Size(), MaxManifestBytes, ErrUnverifiable)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint manifest in %s: %w", dir, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint manifest in %s: %w", dir, err)
	}
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("checkpoint manifest in %s exceeds %d bytes: %w", dir, MaxManifestBytes, ErrUnverifiable)
	}
	return raw, nil
}

func bindFromView(dir string, manifestRaw []byte) (*Binding, error) {
	var manifest sealedManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("decode checkpoint manifest in %s: %w: %v", dir, ErrUnverifiable, err)
	}
	if manifest.Version < 1 || len(manifest.Digests) == 0 {
		return nil, fmt.Errorf(
			"checkpoint manifest in %s is not a complete seal (version %d, %d digests): %w",
			dir, manifest.Version, len(manifest.Digests), ErrUnverifiable,
		)
	}

	binding := &Binding{Scheme: Scheme, ManifestBound: true}
	root := map[string]any{
		"scheme":   Scheme,
		"manifest": digestBytes(manifestRaw),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint directory %s: %w", dir, err)
	}

	// Validate every chunk sidecar and fold its root into the identity. The
	// sidecar loader is strict (version, digest shapes, entry count, offset
	// grid, tail size); this loop adds the identity semantics. The seal
	// writes two real shapes and both must close:
	//   - chunks mode: FileDigest is the root over the entries, so the root
	//     must bind them;
	//   - whole-file mode ("" or "sha256", the pre-chunks default): the
	//     sidecar's FileDigest is the same whole-file sha256 the manifest
	//     records for the artifact — both come from one seal pass — so the
	//     two must agree.
	// The sidecar's artifact must exist as a regular file of exactly the
	// declared size, and a named sidecar must describe its own artifact.
	for _, entry := range entries {
		name := entry.Name()
		if name == manifestName || !isSidecarName(name) {
			continue
		}
		var sidecar *checkpointchunks.Manifest
		var err error
		if name == checkpointchunks.ManifestName {
			// Materialized memory keeps its validated packed transport metadata.
			// Physical pack placement does not change the logical content root.
			sidecar, err = checkpointchunks.LoadTransport(dir)
		} else {
			sidecar, err = checkpointchunks.LoadNamedBounded(dir, name, checkpointchunks.MaxManifestBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("load checkpoint sidecar %s in %s: %w: %v", name, dir, ErrUnverifiable, err)
		}
		artifact := strings.TrimSuffix(name, "."+checkpointchunks.ManifestName)
		if artifact == name { // the plain memory sidecar chunks.json
			artifact = sidecar.File
		} else if sidecar.File != artifact {
			return nil, fmt.Errorf(
				"checkpoint sidecar %s in %s describes file %q: %w",
				name, dir, sidecar.File, ErrUnverifiable,
			)
		}
		switch sidecar.FileDigestMode {
		case checkpointchunks.FileDigestChunks:
			if root := checkpointchunks.RootDigest(sidecar.Entries); root != sidecar.FileDigest {
				return nil, fmt.Errorf(
					"checkpoint sidecar %s in %s records root %s but does not bind its entries (%s): %w",
					name, dir, sidecar.FileDigest, root, ErrUnverifiable,
				)
			}
		case "", checkpointchunks.FileDigestSha256:
			if manifest.Digests[artifact] != sidecar.FileDigest {
				return nil, fmt.Errorf(
					"checkpoint sidecar %s in %s records whole-file digest %s but the manifest records %s for %s: %w",
					name, dir, sidecar.FileDigest, manifest.Digests[artifact], artifact, ErrUnverifiable,
				)
			}
		default:
			return nil, fmt.Errorf(
				"checkpoint sidecar %s in %s carries unknown digest mode %q: %w",
				name, dir, sidecar.FileDigestMode, ErrUnverifiable,
			)
		}
		info, err := os.Lstat(filepath.Join(dir, artifact))
		if err != nil {
			return nil, fmt.Errorf("checkpoint sidecar %s references missing artifact %s: %w: %v", name, artifact, ErrUnverifiable, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("checkpoint sidecar artifact %s in %s is not a regular file: %w", artifact, dir, ErrUnverifiable)
		}
		if info.Size() != sidecar.FileSize {
			return nil, fmt.Errorf(
				"checkpoint artifact %s in %s is %d bytes, sidecar expects %d: %w",
				artifact, dir, info.Size(), sidecar.FileSize, ErrUnverifiable,
			)
		}
		if name == checkpointchunks.SidecarName(overlayName) {
			binding.OverlaySidecarBound = true
		}
		// The identity binds the sidecar's full logical geometry — file,
		// size, normalized digest mode, chunk grid, count, and file digest —
		// AND the independent root over its entries. The entries root is
		// essential in whole-file/sha256 mode, where FileDigest is the
		// whole-file hash and binds nothing about the entries: a changed
		// entry digest, chunk_bytes, or offset grid must change the identity
		// even when FileDigest still agrees with the manifest. Pack
		// references are deliberately EXCLUDED: they name the physical
		// placement of packed objects (identity, offset, length, object
		// size), and relocating a pack between object-store locations does
		// not change which bytes the checkpoint logically is. Their format
		// keeps being validated by the shared loader.
		mode := sidecar.FileDigestMode
		if mode == "" {
			mode = checkpointchunks.FileDigestSha256
		}
		root["sidecar:"+name] = map[string]any{
			"file":         sidecar.File,
			"file_size":    sidecar.FileSize,
			"digest_mode":  mode,
			"chunk_bytes":  sidecar.ChunkBytes,
			"chunk_count":  sidecar.ChunkCount,
			"file_digest":  sidecar.FileDigest,
			"entries_root": checkpointchunks.RootDigest(sidecar.Entries),
		}
	}

	// Coverage closure: every remaining regular file must be verifiable —
	// digested by the manifest, or the Firecracker overlay (bound through its
	// sidecar above plus its size here), or a sidecar/materialization marker.
	// Anything else has no verifiable root and the whole binding is refused.
	for _, entry := range entries {
		name := entry.Name()
		if name == manifestName || isSidecarName(name) || name == materializedMarker {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect checkpoint entry %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("checkpoint entry %s in %s is not a regular file: %w", name, dir, ErrUnverifiable)
		}
		if digest, covered := manifest.Digests[name]; covered && digest != "" {
			continue
		}
		if name == overlayName {
			if !binding.OverlaySidecarBound {
				return nil, fmt.Errorf(
					"checkpoint overlay %s in %s has no chunk sidecar; its content cannot be bound: %w",
					overlayName, dir, ErrUnverifiable,
				)
			}
			// The overlay's bytes are content-verified at restore time
			// against its sidecar; the identity here binds the sidecar root
			// plus the on-disk size.
			root["uncovered:"+name] = info.Size()
			continue
		}
		return nil, fmt.Errorf(
			"checkpoint artifact %s in %s has no verifiable root (not digested by the manifest, no sidecar): %w",
			name, dir, ErrUnverifiable,
		)
	}

	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	binding.RootDigest = digestBytes(encoded)
	return binding, nil
}

// isSidecarName matches the real chunk sidecar names: the plain memory
// sidecar chunks.json and the per-artifact <artifact>.chunks.json.
func isSidecarName(name string) bool {
	return name == checkpointchunks.ManifestName ||
		strings.HasSuffix(name, "."+checkpointchunks.ManifestName)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
