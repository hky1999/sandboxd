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

package checkpointchunks

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const PackedVersion = 2
const RootPackedVersion = 3
const PackIdentityChunks = "chunks-v1"
const MaxPackBytes = 8 << 20

// PackReference locates a chunk inside a content-addressed immutable pack.
// The chunk digest remains the cache identity and must be verified after reading.
type PackReference struct {
	Identity   string `json:"identity,omitempty"`
	Digest     string `json:"digest"`
	Offset     int64  `json:"offset"`
	Length     int64  `json:"length"`
	ObjectSize int64  `json:"object_size"`
}

// PackKey is used only after the digest has passed manifest validation.
func PackKey(digest string) string { return "memory-packs/" + digest }

// Key validates the namespace and digest, including for callers without a manifest.
func (r PackReference) Key() (string, error) {
	if !validDigest(r.Digest) {
		return "", fmt.Errorf("invalid pack digest %q", r.Digest)
	}
	switch r.Identity {
	case "":
		return PackKey(r.Digest), nil
	case PackIdentityChunks:
		return "memory-chunk-packs-v1/" + r.Digest, nil
	default:
		return "", fmt.Errorf("unsupported pack identity %q", r.Identity)
	}
}

// PackPart describes one verified payload segment in its exact object order.
type PackPart struct {
	Digest string
	Length int64
}

// PackRootDigest hashes a domain-separated, fixed-width sequence. Callers must
// verify each payload segment against its digest before publishing the object.
// It does not compute or assert the SHA256 of the concatenated payload.
func PackRootDigest(parts []PackPart) (string, error) {
	if len(parts) == 0 || len(parts) > MaxPackBytes {
		return "", fmt.Errorf("invalid pack part count")
	}
	h := sha256.New()
	h.Write([]byte("akernel.memory-chunk-pack\x00v1\x00"))
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(len(parts)))
	h.Write(word[:])
	var total int64
	for _, p := range parts {
		if p.Length <= 0 || p.Length > MaxPackBytes-total || !validDigest(p.Digest) {
			return "", fmt.Errorf("invalid pack part")
		}
		total += p.Length
		digest, err := hex.DecodeString(p.Digest)
		if err != nil {
			return "", err
		}
		binary.BigEndian.PutUint64(word[:], uint64(p.Length))
		h.Write(word[:])
		h.Write(digest)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// LoadTransport is for consumers that implement both CAS and packed reads.
// Load and LoadNamed deliberately continue to reject transport versions 2 and 3.
func LoadTransport(dir string) (*Manifest, error) {
	return loadNamedBounded(dir, ManifestName, MaxManifestBytes, true)
}

func DecodeTransport(raw []byte) (*Manifest, error) { return decodeManifest(raw, true) }

func decodeManifest(raw []byte, packed bool) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode chunk manifest: %w", err)
	}
	if m.Version != 1 && (!packed || (m.Version != PackedVersion && m.Version != RootPackedVersion)) {
		return nil, fmt.Errorf("unsupported chunk manifest version %d", m.Version)
	}
	if err := ValidateTransport(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ValidateTransport checks logical identity and transport references before
// they can reach an object store. Version 1 never carries packed references.
func ValidateTransport(m *Manifest) error {
	if m.Version != 1 && m.Version != PackedVersion && m.Version != RootPackedVersion {
		return fmt.Errorf("unsupported chunk manifest version %d", m.Version)
	}
	if m.Version == 1 && len(m.Packs) > 0 {
		return fmt.Errorf("version 1 manifest cannot reference packs")
	}
	if m.Version != 1 && (m.File != "memory" || m.ChunkBytes <= 0 || m.ChunkBytes > MaxPackBytes) {
		return fmt.Errorf("packed manifest requires memory and chunk_bytes in [1,%d]", MaxPackBytes)
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	for i, c := range m.Entries {
		// Only reuse a preceding digest after it has passed validation.
		// Sparse overlays commonly repeat the same zero-chunk digest.
		if i > 0 && c.Digest == m.Entries[i-1].Digest {
			continue
		}
		if !validDigest(c.Digest) {
			return fmt.Errorf("chunk manifest entry %d has invalid digest %q", i, c.Digest)
		}
	}
	if m.Version == 1 {
		return nil
	}
	if !validDigest(m.FileDigest) {
		return fmt.Errorf("packed manifest has invalid file digest")
	}
	switch m.FileDigestMode {
	case FileDigestChunks:
		if RootDigest(m.Entries) != m.FileDigest {
			return fmt.Errorf("packed manifest root digest mismatch")
		}
	case FileDigestSha256:
	default:
		return fmt.Errorf("packed manifest has unsupported digest mode %q", m.FileDigestMode)
	}
	lengths := make(map[string]int64, len(m.Entries))
	for _, c := range m.Entries {
		n := min(int64(m.ChunkBytes), m.FileSize-c.Offset)
		if old, ok := lengths[c.Digest]; ok && old != n {
			return fmt.Errorf("digest %s has inconsistent chunk lengths", c.Digest)
		}
		lengths[c.Digest] = n
	}
	byPack := make(map[string][]PackReference)
	for digest, r := range m.Packs {
		length, ok := lengths[digest]
		if !ok {
			return fmt.Errorf("pack reference for absent chunk %s", digest)
		}
		key, err := r.Key()
		if err != nil {
			return err
		}
		if m.Version == PackedVersion && r.Identity != "" {
			return fmt.Errorf("version 2 cannot use pack identity %q", r.Identity)
		}
		if r.Length != length || r.Offset < 0 || r.ObjectSize <= 0 || r.ObjectSize > MaxPackBytes || r.Offset > r.ObjectSize || r.Length > r.ObjectSize-r.Offset {
			return fmt.Errorf("invalid pack range for chunk %s", digest)
		}
		byPack[key] = append(byPack[key], r)
	}
	for digest, refs := range byPack {
		sort.Slice(refs, func(i, j int) bool { return refs[i].Offset < refs[j].Offset })
		for i, r := range refs {
			if r.ObjectSize != refs[0].ObjectSize {
				return fmt.Errorf("pack %s has conflicting object sizes", digest)
			}
			if i > 0 && r.Offset < refs[i-1].Offset+refs[i-1].Length {
				return fmt.Errorf("pack %s has overlapping chunk ranges", digest)
			}
		}
	}
	return nil
}
