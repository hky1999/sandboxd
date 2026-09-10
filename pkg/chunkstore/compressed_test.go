// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chunkstore

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompressedKeyLayout(t *testing.T) {
	digest := strings.Repeat("ab", 32) // 64 hex chars
	if got := CompressedKey(digest); got != "ab/"+digest+".z" {
		t.Fatalf("compressed key = %q", got)
	}
	// Both the bare object name and the full two-level key map back to
	// the digest; anything else is not a compressed chunk object.
	for _, key := range []string{digest + ".z", "ab/" + digest + ".z"} {
		plain, ok := CompressedKeyDigest(key)
		if !ok || plain != digest {
			t.Fatalf("CompressedKeyDigest(%q) = %q, %v", key, plain, ok)
		}
	}
	for _, key := range []string{digest, digest + ".zy", digest[:63] + ".z", "ab/" + digest + ".z/" + digest} {
		if plain, ok := CompressedKeyDigest(key); ok {
			t.Fatalf("CompressedKeyDigest(%q) accepted as %q", key, plain)
		}
	}
}

func TestCompressDecompressChunkBody(t *testing.T) {
	// One compressible and one incompressible body, plus a short tail:
	// every one must roundtrip to identical bytes at the exact length.
	bodies := [][]byte{
		bytes.Repeat([]byte{0x5a}, 256<<10),
		func() []byte { // pseudo-random enough to defeat matching
			out := make([]byte, 4096)
			for i := range out {
				out[i] = byte(i*7 + i/251)
			}
			return out
		}(),
		[]byte("short-tail"),
	}
	for _, plain := range bodies {
		compressed, err := CompressChunkBody(plain)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(compressed)) > MaxCompressedChunkBytes(int64(len(plain))) {
			t.Fatalf("compressed body %d exceeds the accepted bound", len(compressed))
		}
		got, err := DecompressChunkBody(compressed, len(plain))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("roundtrip bytes differ")
		}
	}
}

func TestDecompressRejectsWrongLengths(t *testing.T) {
	plain := bytes.Repeat([]byte{0x11}, 4096)
	compressed, err := CompressChunkBody(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecompressChunkBody(compressed, len(plain)+1); err == nil {
		t.Fatal("oversized expectation accepted a shorter body")
	}
	if _, err := DecompressChunkBody(compressed, len(plain)-1); err == nil {
		t.Fatal("short expectation accepted a longer body")
	}
	if _, err := DecompressChunkBody([]byte("not-zstd"), len(plain)); err == nil {
		t.Fatal("garbage accepted as a zstd stream")
	}
}

func TestReadBoundedRejectsOversized(t *testing.T) {
	body := bytes.Repeat([]byte{9}, 100)
	got, err := ReadBounded(bytes.NewReader(body), 100)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("exact bound failed: %v", err)
	}
	if _, err := ReadBounded(bytes.NewReader(body), 99); err == nil {
		t.Fatal("oversized body accepted")
	}
}
