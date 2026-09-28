// Copyright 2026 Ant Group Corporation.
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

package checkpointpublish

// Streaming verified PUT: replaces the "assemble full pack buffer then
// PutKey" path with a verified io.ReadSeeker that streams chunks directly
// from the memory file to the store, hashing and validating each chunk
// before exposing its bytes to the HTTP client. Only active when
// Options.PackStreamingPut && PackIdentity == chunks-v1.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// packStreamReader is the test-visible surface of a streaming pack reader:
// the ReadSeeker the store consumes, the cumulative ReadAt+hash time that
// feeds BuildTotal, and the count of chunk loads (one ReadAt+hash pass per
// chunk) the per-run instrumentation hook observes.
type packStreamReader interface {
	io.ReadSeeker
	buildTime() int64
	chunksLoaded() int64
}

// verifiedPackReadSeeker streams a pack's chunks from the memory file,
// verifying each chunk's sha256 against the manifest digest BEFORE
// exposing its bytes. Restricted Seek: only Seek(0,End) and Seek(0,Start).
// The source is an io.ReaderAt (the publish path passes the memory file;
// tests inject counting wrappers to prove per-chunk read structure).
// The reader carries the attempt's context: every chunk load checks it
// BEFORE the chunk buffer is allocated, after ReadAt, and after the hash,
// so a cancelled publish stops issuing file reads mid-pack and the PUT
// body fails with the context error.
type verifiedPackReadSeeker struct {
	ctx       context.Context
	memory    io.ReaderAt
	manifest  *checkpointchunks.Manifest
	chunks    []checkpointchunks.Chunk
	totalSize int64

	chunkIdx int    // current chunk index
	chunkOff int    // offset within current chunk's verified buffer
	verified []byte // verified bytes of the current chunk
	failed   error  // sticky error
	pos      int64
	reads    atomic.Int64
	seeks    atomic.Int64
	loads    atomic.Int64 // completed chunk loads (ReadAt + hash + digest check)
	buildNs  atomic.Int64 // cumulative ReadAt+hash nanoseconds
}

func newVerifiedPackReadSeeker(ctx context.Context, memory io.ReaderAt, m *checkpointchunks.Manifest, chunks []checkpointchunks.Chunk) *verifiedPackReadSeeker {
	return &verifiedPackReadSeeker{
		ctx:       ctx,
		memory:    memory,
		manifest:  m,
		chunks:    chunks,
		totalSize: totalPackBytes(m, chunks),
	}
}

func chunkByteLen(m *checkpointchunks.Manifest, c checkpointchunks.Chunk) int {
	return int(min(int64(m.ChunkBytes), m.FileSize-c.Offset))
}

func totalPackBytes(m *checkpointchunks.Manifest, chunks []checkpointchunks.Chunk) int64 {
	var t int64
	for _, c := range chunks {
		t += int64(chunkByteLen(m, c))
	}
	return t
}

func (r *verifiedPackReadSeeker) Seek(offset int64, whence int) (int64, error) {
	r.seeks.Add(1)
	switch whence {
	case io.SeekEnd:
		if offset != 0 {
			return 0, fmt.Errorf("verifiedPackReadSeeker: Seek(%d,End) rejected (only 0)", offset)
		}
		r.pos = r.totalSize
		return r.totalSize, nil
	case io.SeekStart:
		if offset != 0 {
			return 0, fmt.Errorf("verifiedPackReadSeeker: Seek(%d,Start) rejected (only 0)", offset)
		}
		r.pos = 0
		r.chunkIdx = 0
		r.chunkOff = 0
		r.verified = nil
		r.failed = nil
		return 0, nil
	default:
		return 0, fmt.Errorf("verifiedPackReadSeeker: SeekCurrent rejected")
	}
}

func (r *verifiedPackReadSeeker) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.reads.Add(1)
	if r.failed != nil {
		return 0, r.failed
	}
	// Standard Seeker semantics: after Seek(0, End) the position sits at
	// totalSize and Read must report EOF — the reader is not "usable by
	// accident" only for Remote.PutKey's exact End-then-Start sequence.
	if r.pos >= r.totalSize || r.chunkIdx >= len(r.chunks) {
		return 0, io.EOF
	}
	if r.verified == nil || r.chunkOff >= len(r.verified) {
		if err := r.loadAndVerifyChunk(); err != nil {
			r.failed = err
			return 0, err
		}
	}
	avail := r.verified[r.chunkOff:]
	n := copy(p, avail)
	r.chunkOff += n
	r.pos += int64(n)
	if r.chunkOff >= len(r.verified) {
		r.verified = nil
		r.chunkOff = 0
		r.chunkIdx++
	}
	if n == 0 && len(p) > 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return n, nil
}

// interrupted wraps the reader's context error so callers can test it with
// errors.Is(err, context.Canceled) and friends.
func (r *verifiedPackReadSeeker) interrupted() error {
	if err := r.ctx.Err(); err != nil {
		return fmt.Errorf("stream pack interrupted: %w", err)
	}
	return nil
}

func (r *verifiedPackReadSeeker) loadAndVerifyChunk() error {
	// Before the allocation: a cancelled attempt must not even build the
	// next chunk buffer.
	if err := r.interrupted(); err != nil {
		return err
	}
	c := r.chunks[r.chunkIdx]
	n := chunkByteLen(r.manifest, c)
	buf := make([]byte, n)
	start := time.Now()
	if _, err := r.memory.ReadAt(buf, c.Offset); err != nil {
		return fmt.Errorf("stream read chunk %s: %w", c.Digest[:12], err)
	}
	// After the file read: the bytes are in hand but a cancelled attempt
	// must not spend the hash (and must not expose the bytes).
	if err := r.interrupted(); err != nil {
		return err
	}
	sum := sha256.Sum256(buf)
	r.buildNs.Add(int64(time.Since(start)))
	// After the hash: same cancellation gate before the digest comparison
	// would make the chunk eligible for exposure.
	if err := r.interrupted(); err != nil {
		return err
	}
	if hex.EncodeToString(sum[:]) != c.Digest {
		return fmt.Errorf("source chunk %s changed before pack publication", c.Digest[:12])
	}
	r.loads.Add(1)
	r.verified = buf
	r.chunkOff = 0
	return nil
}

func (r *verifiedPackReadSeeker) buildTime() int64 {
	return r.buildNs.Load()
}

func (r *verifiedPackReadSeeker) chunksLoaded() int64 {
	return r.loads.Load()
}
