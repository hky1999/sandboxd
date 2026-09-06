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
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func backingFixture(t *testing.T, mode string) (string, *Manifest) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "memory"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(4*4096 + 17); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{4096 + 5, 4*4096 + 16} {
		if _, err = f.WriteAt([]byte{0xA7}, off); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := Compute(context.Background(), dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if mode == FileDigestChunks {
		m.FileDigestMode = mode
		m.FileDigest = RootDigest(m.Entries)
		if err = Write(dir, m); err != nil {
			t.Fatal(err)
		}
	}
	return dir, m
}
func requireProof(t *testing.T, dir string, m *Manifest) *BackingProof {
	t.Helper()
	p, err := VerifyMemoryBacking(context.Background(), dir, m.FileDigest, m.FileDigestMode)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestBackingProofSparseComplete(t *testing.T) {
	for _, mode := range []string{FileDigestChunks, FileDigestSha256} {
		t.Run(mode, func(t *testing.T) {
			dir, m := backingFixture(t, mode)
			p := requireProof(t, dir, m)
			f, err := p.Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err = p.Check(context.Background(), f); err != nil {
				t.Fatal(err)
			}
			other, err := os.CreateTemp(t.TempDir(), "other")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if p.Check(context.Background(), other) == nil {
				t.Fatal("proof accepted another inode")
			}
		})
	}
}
func TestBackingProofInvalidation(t *testing.T) {
	mutations := map[string]func(*testing.T, string){
		"replace-inode": func(t *testing.T, dir string) {
			b, e := os.ReadFile(filepath.Join(dir, "memory"))
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(dir, "new")
			if e = os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(p, filepath.Join(dir, "memory")); e != nil {
				t.Fatal(e)
			}
		},
		"write-reset-mtime": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "memory")
			info, e := os.Stat(p)
			if e != nil {
				t.Fatal(e)
			}
			f, e := os.OpenFile(p, os.O_WRONLY, 0)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.WriteAt([]byte{1}, 0)
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Chtimes(p, info.ModTime(), info.ModTime()); e != nil {
				t.Fatal(e)
			}
		},
		"sidecar-rewrite": func(t *testing.T, dir string) {
			p := filepath.Join(dir, ManifestName)
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			b = []byte(`{"invalid":true}`)
			if e = os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
		},
		"marker": func(t *testing.T, dir string) {
			if e := os.WriteFile(filepath.Join(dir, ".materialized"), nil, 0600); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir, m := backingFixture(t, FileDigestChunks)
			p := requireProof(t, dir, m)
			f, e := p.Open(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			mutate(t, dir)
			if p.Check(context.Background(), f) == nil {
				t.Fatal("old descriptor retained valid proof after mutation")
			}
			if f, e := p.Open(context.Background()); e == nil {
				f.Close()
				t.Fatal("reopened mutated backing")
			}
		})
	}
}
func TestBackingProofRejectsFalseCompleteness(t *testing.T) {
	for _, kind := range []string{"missing-content", "preallocated", "marker", "wrong-root", "wrong-mode", "extra-tail", "symlink", "wrong-file"} {
		t.Run(kind, func(t *testing.T) {
			dir, m := backingFixture(t, FileDigestChunks)
			digest, mode := m.FileDigest, m.FileDigestMode
			p := filepath.Join(dir, "memory")
			switch kind {
			case "missing-content", "preallocated":
				f, e := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Truncate(m.FileSize); e != nil {
					t.Fatal(e)
				}
				if kind == "preallocated" {
					if e = unix.Fallocate(int(f.Fd()), 0, 0, m.FileSize); e != nil {
						f.Close()
						t.Fatal(e)
					}
				}
				f.Close()
			case "marker":
				if e := os.WriteFile(filepath.Join(dir, ".materialized"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "wrong-root":
				digest = ZeroChunkDigest(1)
			case "wrong-mode":
				mode = FileDigestSha256
			case "extra-tail":
				if e := os.Truncate(p, m.FileSize+1); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(p, p+"-real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(p+"-real", p); e != nil {
					t.Fatal(e)
				}
			case "wrong-file":
				m.File = "../memory"
				if e := Write(dir, m); e != nil {
					t.Fatal(e)
				}
			}
			if proof, e := VerifyMemoryBacking(context.Background(), dir, digest, mode); e == nil {
				t.Fatalf("issued proof for %s: %+v", kind, proof)
			}
		})
	}
}
func TestBackingProofCancelledAndEmpty(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyMemoryBacking(ctx, dir, m.FileDigest, m.FileDigestMode); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, p := range []*BackingProof{nil, {}} {
		if f, e := p.Open(context.Background()); e == nil {
			f.Close()
			t.Fatal("empty proof opened")
		}
	}
}
func TestVerifyRejectsTrailingBytes(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	if err := os.Truncate(filepath.Join(dir, "memory"), m.FileSize+1); err != nil {
		t.Fatal(err)
	}
	if Verify(context.Background(), dir) == nil {
		t.Fatal("accepted unverified trailing byte")
	}
}

type markDuringReadContext struct {
	context.Context
	calls int
	mark  func()
}

func (c *markDuringReadContext) Err() error {
	c.calls++
	if c.calls == 3 {
		c.mark()
	}
	return c.Context.Err()
}
func TestBackingProofRejectsMarkerCreatedDuringScan(t *testing.T) {
	// This original injection targets the serial verifier's Err checks.
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	dir, m := backingFixture(t, FileDigestChunks)
	ctx := &markDuringReadContext{Context: context.Background(), mark: func() {
		if err := os.WriteFile(filepath.Join(dir, ".materialized"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if p, err := VerifyMemoryBacking(ctx, dir, m.FileDigest, m.FileDigestMode); err == nil {
		t.Fatalf("accepted marker created during scan: %+v", p)
	}
}
func TestBackingProofCheckPreservesOffset(t *testing.T) {
	dir, m := backingFixture(t, FileDigestChunks)
	p := requireProof(t, dir, m)
	f, err := p.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Seek(17, 0); err != nil {
		t.Fatal(err)
	}
	if err = p.Check(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	off, err := f.Seek(0, 1)
	if err != nil || off != 17 {
		t.Fatalf("check moved descriptor offset: %d %v", off, err)
	}
}

func TestBackingProofZeroDigestRequiresZeroBytes(t *testing.T) {
	for _, off := range []int64{0, 4095, 8192, 12287} {
		dir, m := backingFixture(t, FileDigestChunks)
		f, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteAt([]byte{1}, off)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = VerifyMemoryBacking(context.Background(), dir, m.FileDigest, m.FileDigestMode); err == nil {
			t.Fatalf("accepted nonzero byte at %d against zero digest", off)
		}
	}
}

func TestZeroVerificationChecksWholeChunkAndTail(t *testing.T) {
	for _, off := range []int64{0, 32 << 10, DefaultChunkBytes - 1, DefaultChunkBytes + 2} {
		dir := t.TempDir()
		path := filepath.Join(dir, "memory")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(DefaultChunkBytes + 3); err != nil {
			t.Fatal(err)
		}
		f.Close()
		m, err := Compute(context.Background(), dir, DefaultChunkBytes)
		if err != nil {
			t.Fatal(err)
		}
		m.FileDigestMode = FileDigestChunks
		m.FileDigest = RootDigest(m.Entries)
		if err = Write(dir, m); err != nil {
			t.Fatal(err)
		}
		if err = Verify(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		f, err = os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteAt([]byte{1}, off)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if Verify(context.Background(), dir) == nil {
			t.Fatalf("zero verification missed corrupt byte at %d", off)
		}
	}
}

// WithCancel subscribes to the parent only when parallel content verification
// starts, after the proof's initial marker/identity checks. Inject there rather
// than counting Err calls made by a child context.
type markDuringParallelContext struct {
	context.Context
	once sync.Once
	mark func()
}

func (c *markDuringParallelContext) Done() <-chan struct{} {
	c.once.Do(c.mark)
	return c.Context.Done()
}
func TestBackingProofRejectsMarkerCreatedDuringParallelScan(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	dir, m := backingFixture(t, FileDigestChunks)
	triggered := false
	ctx := &markDuringParallelContext{Context: context.Background(), mark: func() {
		triggered = true
		if err := os.WriteFile(filepath.Join(dir, ".materialized"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if p, err := VerifyMemoryBacking(ctx, dir, m.FileDigest, m.FileDigestMode); err == nil {
		t.Fatalf("accepted marker created during parallel scan: %+v", p)
	}
	if !triggered {
		t.Fatal("marker injection did not run")
	}
}
