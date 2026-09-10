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
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func transportFixture() *Manifest {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	m := &Manifest{Version: 2, File: "memory", FileSize: 10, ChunkBytes: 4, ChunkCount: 3, FileDigestMode: FileDigestChunks, Entries: []Chunk{{Offset: 0, Digest: a}, {Offset: 4, Digest: a}, {Offset: 8, Digest: b}}, Packs: map[string]PackReference{a: {Digest: strings.Repeat("c", 64), Offset: 2, Length: 4, ObjectSize: 10}, b: {Digest: strings.Repeat("c", 64), Offset: 8, Length: 2, ObjectSize: 10}}}
	m.FileDigest = RootDigest(m.Entries)
	return m
}
func TestTransportRoundTripAndLegacyRejection(t *testing.T) {
	m := transportFixture()
	raw, _ := json.Marshal(m)
	got, err := DecodeTransport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.FileDigest != m.FileDigest || len(got.Packs) != 2 {
		t.Fatal("lost mapping or identity")
	}
	dir := t.TempDir()
	if err := Write(dir, m); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("legacy memory reader accepted v2")
	}
	if _, err := LoadNamed(dir, ManifestName); err == nil {
		t.Fatal("legacy named reader accepted v2")
	}
	if _, err := LoadTransport(dir); err != nil {
		t.Fatal(err)
	}
	delete(m.Packs, m.Entries[2].Digest)
	if err := ValidateTransport(m); err != nil {
		t.Fatalf("mixed CAS and pack: %v", err)
	}
	m.Version = 1
	m.Packs = nil
	if err := Write(dir, m); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTransport(dir); err != nil {
		t.Fatal(err)
	}
}
func TestTransportRejectsMalformedReferences(t *testing.T) {
	cases := map[string]func(*Manifest){
		"version":           func(m *Manifest) { m.Version = 4 },
		"legacy-with-packs": func(m *Manifest) { m.Version = 1 },
		"wrong-file":        func(m *Manifest) { m.File = "overlay.ext4" },
		"huge-chunk":        func(m *Manifest) { m.ChunkBytes = math.MaxInt },
		"wrong-root":        func(m *Manifest) { m.FileDigest = strings.Repeat("d", 64) },
		"unknown-mode":      func(m *Manifest) { m.FileDigestMode = "unchecked" },
		"extra-reference":   func(m *Manifest) { m.Packs[strings.Repeat("d", 64)] = m.Packs[m.Entries[0].Digest] },
		"invalid-pack-key": func(m *Manifest) {
			r := m.Packs[m.Entries[0].Digest]
			r.Digest = "../../bad"
			m.Packs[m.Entries[0].Digest] = r
		},
		"negative-offset": func(m *Manifest) { r := m.Packs[m.Entries[0].Digest]; r.Offset = -1; m.Packs[m.Entries[0].Digest] = r },
		"overflow": func(m *Manifest) {
			r := m.Packs[m.Entries[0].Digest]
			r.Offset = math.MaxInt64
			r.ObjectSize = math.MaxInt64
			m.Packs[m.Entries[0].Digest] = r
		},
		"short-reference": func(m *Manifest) { r := m.Packs[m.Entries[0].Digest]; r.Length = 3; m.Packs[m.Entries[0].Digest] = r },
		"overlap":         func(m *Manifest) { r := m.Packs[m.Entries[2].Digest]; r.Offset = 5; m.Packs[m.Entries[2].Digest] = r },
		"conflicting-size": func(m *Manifest) {
			r := m.Packs[m.Entries[2].Digest]
			r.ObjectSize = 11
			m.Packs[m.Entries[2].Digest] = r
		},
		"tail-length":                  func(m *Manifest) { r := m.Packs[m.Entries[2].Digest]; r.Length = 4; m.Packs[m.Entries[2].Digest] = r },
		"same-digest-different-length": func(m *Manifest) { m.Entries[2].Digest = m.Entries[0].Digest; m.FileDigest = RootDigest(m.Entries) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := transportFixture()
			change(m)
			raw, _ := json.Marshal(m)
			if _, err := DecodeTransport(raw); err == nil {
				t.Fatal("accepted invalid transport")
			}
		})
	}
}

func TestPackRootCanonicalEncoding(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	parts := []PackPart{{a, 4096}, {b, 3}}
	got, err := PackRootDigest(parts)
	// Independently encoded with Python struct.pack('>Q', ...) + bytes.fromhex.
	const golden = "9e7b5f91b17e29acf13a3e9458c8ae0675ff17039af53edb73ccfa0e6be2b9af"
	if err != nil || got != golden {
		t.Fatalf("digest %s: %v", got, err)
	}
	for _, other := range [][]PackPart{{{b, 3}, {a, 4096}}, {{a, 4095}, {b, 4}}, {{a, 4099}}, {{a, 4096}, {a, 3}}} {
		d, e := PackRootDigest(other)
		if e != nil || d == got {
			t.Fatalf("sequence not distinguished: %v %s %v", other, d, e)
		}
	}
	for _, bad := range [][]PackPart{nil, {{a, 0}}, {{a, -1}}, {{a, MaxPackBytes + 1}}, {{a, MaxPackBytes}, {b, 1}}, {{"../bad", 1}}, {{strings.Repeat("A", 64), 1}}} {
		if _, err := PackRootDigest(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestRootPackTransportCompatibility(t *testing.T) {
	m := transportFixture()
	m.Version = RootPackedVersion
	first := m.Entries[0].Digest
	r := m.Packs[first]
	r.Identity = PackIdentityChunks
	m.Packs[first] = r
	// Equal digest strings in different namespaces are distinct objects, even
	// when ranges overlap or object sizes differ.
	r = m.Packs[m.Entries[2].Digest]
	r.Offset = 0
	r.ObjectSize = 2
	m.Packs[m.Entries[2].Digest] = r
	if err := ValidateTransport(m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	if _, err := DecodeTransport(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeManifest(raw, false); err == nil {
		t.Fatal("legacy reader accepted v3")
	}
	m.Version = PackedVersion
	if err := ValidateTransport(m); err == nil {
		t.Fatal("v2 accepted root identity")
	}
	m.Version = RootPackedVersion
	r = m.Packs[first]
	r.Identity = "unknown"
	m.Packs[first] = r
	if err := ValidateTransport(m); err == nil {
		t.Fatal("accepted unknown namespace")
	}
	if _, err := r.Key(); err == nil {
		t.Fatal("key allowed unknown namespace")
	}
}
