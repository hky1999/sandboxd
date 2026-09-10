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
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
)

var originalDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The old regexp is an independent acceptance oracle. All other fields in
// these manifests are valid, so only entry digest shape can reject them.
func TestManifestDigestAcceptance(t *testing.T) {
	valid := strings.Repeat("a", 64)
	for _, digest := range []string{"", valid, strings.Repeat("0", 64), strings.Repeat("F", 64), valid + "\n", valid[:63], valid + "0", strings.Repeat("é", 32), strings.Repeat("\xff", 64)} {
		for _, entries := range [][]Chunk{{{Offset: 0, Digest: digest}, {Offset: 4, Digest: digest}}, {{Offset: 0, Digest: valid}, {Offset: 4, Digest: digest}}, {{Offset: 0, Digest: digest}, {Offset: 4, Digest: valid}}} {
			m := &Manifest{Version: 1, File: "overlay.ext4", FileSize: 8, ChunkBytes: 4, ChunkCount: 2, Entries: entries}
			want := originalDigestPattern.MatchString(digest)
			if err := ValidateTransport(m); (err == nil) != want {
				t.Fatalf("entries=%v: err=%v want valid=%v", entries, err, want)
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeTransport(raw); (err == nil) != want {
				t.Fatalf("decode %q: err=%v want valid=%v", digest, err, want)
			}
		}
	}
}

func benchmarkDigestManifest(unique bool) *Manifest {
	m := &Manifest{Version: 1, File: "overlay.ext4", ChunkBytes: DefaultChunkBytes, ChunkCount: 32768, FileSize: 32768 * DefaultChunkBytes}
	m.Entries = make([]Chunk, m.ChunkCount)
	zero := ZeroChunkDigest(DefaultChunkBytes)
	for i := range m.Entries {
		digest := zero
		if unique {
			sum := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
			digest = hex.EncodeToString(sum[:])
		}
		m.Entries[i] = Chunk{Offset: int64(i) * DefaultChunkBytes, Digest: digest}
	}
	m.FileDigestMode = FileDigestChunks
	m.FileDigest = RootDigest(m.Entries)
	return m
}

// An external captured manifest is optional so CI has no fixture dependency.
// Both Validate and Decode use identical input bytes across revisions.
func BenchmarkDigestManifest(b *testing.B) {
	manifests := map[string]*Manifest{"Repeated": benchmarkDigestManifest(false), "Unique": benchmarkDigestManifest(true)}
	if path := os.Getenv("CHECKPOINT_OVERLAY_FIXTURE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		m, err := DecodeTransport(raw)
		if err != nil {
			b.Fatal(err)
		}
		manifests["Captured"] = m
	}
	for name, m := range manifests {
		b.Run(name, func(b *testing.B) {
			raw, err := json.Marshal(m)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Validate", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if err := ValidateTransport(m); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Decode", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for i := 0; i < b.N; i++ {
					if _, err := DecodeTransport(raw); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestDigestShapeMatchesOriginalRegexp(t *testing.T) {
	check := func(s string) {
		t.Helper()
		if got, want := validDigest(s), originalDigestPattern.MatchString(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	}
	valid := strings.Repeat("0123456789abcdef", 4)
	for n := 0; n <= 129; n++ {
		check(strings.Repeat("a", n))
	}
	// Every byte at every position includes valid hex, uppercase, NUL,
	// newlines, non-ASCII, and invalid UTF-8 in otherwise valid digests.
	for i := 0; i < 64; i++ {
		for c := 0; c < 256; c++ {
			raw := []byte(valid)
			raw[i] = byte(c)
			check(string(raw))
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		raw := make([]byte, rng.Intn(130))
		if _, err := rng.Read(raw); err != nil {
			t.Fatal(err)
		}
		check(string(raw))
	}
	for _, s := range []string{valid + "\n", "\n" + valid, strings.Repeat("é", 32), strings.Repeat("ａ", 64)} {
		check(s)
	}
}

func FuzzDigestShapeMatchesOriginalRegexp(f *testing.F) {
	for _, s := range []string{"", strings.Repeat("a", 64), strings.Repeat("0", 64), strings.Repeat("F", 64), strings.Repeat("a", 63) + "\n", strings.Repeat("\xff", 64)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validDigest(s) != originalDigestPattern.MatchString(s) {
			t.Fatalf("acceptance mismatch: %q", s)
		}
	})
}
