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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

type countedBackingReader struct {
	io.ReaderAt
	bytes int64
}

func (r *countedBackingReader) ReadAt(b []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(b, off)
	r.bytes += int64(n)
	return n, err
}

func TestBackingHoleReadsMatchLogicalContent(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	f, err := openMemory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	query, err := openMemory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer query.Close()
	counted := &countedBackingReader{ReaderAt: f}
	r := &memoryHoleReader{SectionReader: io.NewSectionReader(counted, 0, m.FileSize), seekData: func(off int64) (int64, error) { return unix.Seek(int(query.Fd()), off, unix.SEEK_DATA) }}
	if err = verifyContents(context.Background(), r, m); err != nil {
		t.Fatal(err)
	}
	first, queryErr := unix.Seek(int(query.Fd()), 0, unix.SEEK_DATA)
	if queryErr == nil && first >= 4096 && counted.bytes >= m.FileSize {
		t.Fatal("confirmed hole was read")
	}
	t.Logf("logical=%d read=%d first_data=%d query_error=%v", m.FileSize, counted.bytes, first, queryErr)
	// A changed root must still fail even if some or all chunks can be skipped.
	m.FileDigest = ZeroChunkDigest(17)
	r.SectionReader = io.NewSectionReader(counted, 0, m.FileSize)
	if verifyContents(context.Background(), r, m) == nil {
		t.Fatal("accepted wrong root")
	}
}

func TestBackingHoleQueryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name              string
		start             int64
		err               error
		wantSkip, wantErr bool
	}{
		{"no-data", 0, unix.ENXIO, true, false},
		{"data-in-range", 7, nil, false, false},
		{"data-after-range", 8192, nil, true, false},
		{"unsupported", 0, unix.EINVAL, false, false},
		{"not-supported", 0, unix.ENOTSUP, false, false},
		{"not-implemented", 0, unix.ENOSYS, false, false},
		{"io-error", 0, unix.EIO, false, true},
		{"backwards", -1, nil, false, true},
		{"past-eof", 20000, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &memoryHoleReader{SectionReader: io.NewSectionReader(bytes.NewReader(make([]byte, 16384)), 0, 16384), seekData: func(int64) (int64, error) { return tc.start, tc.err }}
			skipped, err := r.skipZeroHole(4096)
			if skipped != tc.wantSkip || (err != nil) != tc.wantErr {
				t.Fatalf("skip=%v err=%v", skipped, err)
			}
			pos, _ := r.Seek(0, io.SeekCurrent)
			want := int64(0)
			if skipped {
				want = 4096
			}
			if pos != want {
				t.Fatalf("position %d want %d", pos, want)
			}
		})
	}
}

func TestBackingHoleNonzeroAndLegacyNeverSkip(t *testing.T) {
	for _, mode := range []string{FileDigestChunks, FileDigestSha256} {
		dir, m := backingFixture(t, mode)
		// An all-hole file cannot satisfy this manifest's nonzero pages.
		f, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err = f.Truncate(m.FileSize); err != nil {
			t.Fatal(err)
		}
		calls := 0
		r := &memoryHoleReader{SectionReader: io.NewSectionReader(f, 0, m.FileSize), seekData: func(int64) (int64, error) { calls++; return 0, unix.ENXIO }}
		if verifyContents(context.Background(), r, m) == nil {
			t.Fatal("accepted missing nonzero data")
		}
		if mode == FileDigestSha256 && calls != 0 {
			t.Fatal("legacy mode queried/skipped holes")
		}
	}
}

func TestBackingHoleUnsupportedReadsAndDetectsMutation(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	f, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	for _, queryErr := range []error{unix.EINVAL, unix.EIO} {
		counted := &countedBackingReader{ReaderAt: f}
		r := &memoryHoleReader{SectionReader: io.NewSectionReader(counted, 0, m.FileSize), seekData: func(int64) (int64, error) { return 0, queryErr }}
		err = verifyContents(context.Background(), r, m)
		if err == nil {
			t.Fatal("accepted corrupted zero chunk")
		}
		if errors.Is(queryErr, unix.EIO) && !errors.Is(err, unix.EIO) {
			t.Fatalf("lost query error: %v", err)
		}
		if errors.Is(queryErr, unix.EINVAL) && counted.bytes == 0 {
			t.Fatal("unsupported query did not read")
		}
	}
}

func TestBackingHoleProofRechecksNewData(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	p := requireProof(t, dir, m)
	f, err := p.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// Deliberately refresh the saved identity to isolate content verification
	// from timestamp invalidation, including same-clock-tick writes.
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	p.memory, err = backingID(info)
	if err != nil {
		t.Fatal(err)
	}
	if p.Check(context.Background(), f) == nil {
		t.Fatal("reused a previous hole answer after data was written")
	}
}
