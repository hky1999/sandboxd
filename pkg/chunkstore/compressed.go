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
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// CompressedKey is the store key of a chunk's compressed transport body:
// the content key with a ".z" suffix. The digest still names the
// UNCOMPRESSED bytes — a reader decodes the zstd stream and verifies the
// digest against the decoded content, so addressing and verification
// semantics are unchanged. The suffix lives in this one helper so writers,
// readers, and any sweeper agree on the layout.
func CompressedKey(digest string) string {
	return digest[:2] + "/" + digest + ".z"
}

// CompressedKeyDigest strips the ".z" suffix back to the content digest,
// reporting whether the key named a compressed chunk object at all.
func CompressedKeyDigest(key string) (string, bool) {
	const suffix = ".z"
	if len(key) < 66 || key[len(key)-len(suffix):] != suffix {
		return "", false
	}
	digest := key[len(key)-len(suffix)-64 : len(key)-len(suffix)]
	for _, c := range digest {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return digest, true
}

// encoderPool reuses zstd encoders across chunk compressions: one-shot
// EncodeAll calls from many publish workers share window buffers instead
// of paying encoder setup per chunk.
var encoderPool = sync.Pool{
	New: func() any {
		enc, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1),
			zstd.WithZeroFrames(true))
		if err != nil {
			panic(err) // options are compile-time constants; cannot fail
		}
		return enc
	},
}

// CompressChunkBody returns the zstd transport body of one chunk. The
// plain bytes still define the digest; this body is opaque transport and
// no digest of it is recorded.
func CompressChunkBody(plain []byte) ([]byte, error) {
	enc := encoderPool.Get().(*zstd.Encoder)
	defer encoderPool.Put(enc)
	return enc.EncodeAll(plain, nil), nil
}

// statelessDecoder serves bounded DecodeAll calls; stateless decodes are
// documented as concurrency-safe on a shared decoder.
var statelessDecoder = func() *zstd.Decoder {
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		panic(err)
	}
	return dec
}()

// DecompressChunkBody decodes one chunk's zstd transport body and requires
// the result to be exactly want bytes — short and oversized streams are
// rejected before the caller sees any byte, so a malformed object cannot
// smuggle length confusion past the (unchanged) plaintext digest check.
// The compressed input must itself be bounded by the caller.
func DecompressChunkBody(compressed []byte, want int) ([]byte, error) {
	// DecodeAll appends to dst: pass a zero-length slice with a capacity
	// hint of one byte over the expectation, so an oversized stream is
	// detected without ever buffering more than want+1 bytes.
	dst := make([]byte, 0, want+1)
	out, err := statelessDecoder.DecodeAll(compressed, dst)
	if err != nil {
		return nil, err
	}
	switch {
	case len(out) > want:
		return nil, errors.New("decompressed chunk exceeds its recorded length")
	case len(out) < want:
		return nil, errors.New("decompressed chunk shorter than its recorded length")
	}
	return out, nil
}

// MaxCompressedChunkBytes bounds one compressed transport body accepted
// from a store: zstd's incompressible worst case grows the input only
// slightly, so anything beyond that is corruption or abuse, and rejecting
// it caps decompression input before any allocation.
func MaxCompressedChunkBytes(plainLen int64) int64 {
	return plainLen + plainLen/64 + 64
}

// ReadBounded drains r up to limit bytes, rejecting anything longer.
func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, errors.New("object exceeds its size bound")
	}
	return out, nil
}
