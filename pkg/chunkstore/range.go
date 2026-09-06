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

package chunkstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
)

// MaxRangeReadBytes bounds allocations for a single packed-object read.
const MaxRangeReadBytes = 8 << 20

// ObjectRange identifies a bounded slice of an immutable object. ObjectSize
// is required so a response from a different object layout cannot pass.
type ObjectRange struct {
	Offset     int64
	Length     int64
	ObjectSize int64
}

// RangeReader is an optional surface for packed-object consumers. It verifies
// the response range and exact length; callers must also verify content digests.
type RangeReader interface {
	ReadKeyRange(context.Context, string, ObjectRange) ([]byte, error)
}

func (s ObjectRange) validate(key string) error {
	if key == "" || key == "." || strings.HasPrefix(key, "/") || path.Clean(key) != key || key == ".." || strings.HasPrefix(key, "../") || strings.ContainsAny(key, "\\?#%") {
		return fmt.Errorf("invalid range object key %q", key)
	}
	// Subtraction avoids overflowing Offset+Length on untrusted metadata.
	if s.Offset < 0 || s.Length <= 0 || s.Length > MaxRangeReadBytes || s.ObjectSize <= 0 || s.Offset > s.ObjectSize || s.Length > s.ObjectSize-s.Offset {
		return fmt.Errorf("invalid object range: offset=%d length=%d size=%d", s.Offset, s.Length, s.ObjectSize)
	}
	return nil
}

func (r *Remote) ReadKeyRange(ctx context.Context, key string, span ObjectRange) ([]byte, error) {
	if err := span.validate(key); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/"+key, nil)
	if err != nil {
		return nil, err
	}
	end := span.Offset + span.Length - 1
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", span.Offset, end))
	// Ranges address stored bytes, never transparently decompressed bytes.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("range GET %s: status %d", key, resp.StatusCode)
	}
	want := fmt.Sprintf("bytes %d-%d/%d", span.Offset, end, span.ObjectSize)
	if resp.Header.Get("Content-Range") != want {
		return nil, fmt.Errorf("range GET %s: Content-Range %q, want %q", key, resp.Header.Get("Content-Range"), want)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return nil, fmt.Errorf("range GET %s: unexpected content encoding %q", key, enc)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != span.Length {
		return nil, fmt.Errorf("range GET %s: Content-Length %d, want %d", key, resp.ContentLength, span.Length)
	}
	// The validated size is known: avoid ReadAll's repeated growth and
	// copying on each page-fault fetch, while still rejecting extra bytes.
	data := make([]byte, span.Length)
	if _, err := io.ReadFull(resp.Body, data); err != nil {
		return nil, fmt.Errorf("range GET %s: %w", key, err)
	}
	var extra [1]byte
	if n, err := io.ReadFull(resp.Body, extra[:]); n != 0 || err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("range GET %s trailing body: %w", key, err)
		}
		return nil, fmt.Errorf("range GET %s: body exceeds expected length %d", key, span.Length)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func (l *Local) ReadKeyRange(ctx context.Context, key string, span ObjectRange) ([]byte, error) {
	if err := span.validate(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path.Join(l.root, key))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != span.ObjectSize {
		return nil, fmt.Errorf("range object %s: require regular file of size %d, got %s size %d", key, span.ObjectSize, info.Mode(), info.Size())
	}
	data := make([]byte, span.Length)
	if _, err := f.ReadAt(data, span.Offset); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}
