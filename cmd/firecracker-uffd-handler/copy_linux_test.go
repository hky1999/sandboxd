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

package main

import (
	"bytes"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// Exercise the real kernel's partial-copy/EEXIST contract, including a guest
// write in the middle of the proposed population span. USER_MODE_ONLY does
// not cover KVM faults; those require the separate VM acceptance run.
func TestForwardCopyPreservesResidentPage(t *testing.T) {
	for _, cached := range []bool{false, true} {
		name := "backing"
		if cached {
			name = "verified-cache"
		}
		t.Run(name, func(t *testing.T) { testForwardCopy(t, cached, false) })
	}
}

func TestForwardZeroPreservesResidentPage(t *testing.T) {
	testForwardCopy(t, false, true)
}

func testForwardCopy(t *testing.T, cached, zero bool) {
	if os.Getpagesize() != 4096 {
		t.Skip("requires 4KiB pages")
	}
	fd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC|unix.O_NONBLOCK|1), 0, 0)
	if errno == unix.EPERM || errno == unix.ENOSYS {
		t.Skipf("userfaultfd unavailable: %v", errno)
	}
	if errno != 0 {
		t.Fatal(errno)
	}
	defer unix.Close(int(fd))
	api := [3]uint64{0xAA, 0, 0}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, 0xC018AA3F, uintptr(unsafe.Pointer(&api))); e != 0 {
		t.Fatal(e)
	}
	memory, err := unix.Mmap(-1, 0, 16*4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(memory)
	base := uint64(uintptr(unsafe.Pointer(&memory[0])))
	reg := [4]uint64{base, uint64(len(memory)), 1, 0}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, fd, 0xC020AA00, uintptr(unsafe.Pointer(&reg))); e != 0 {
		t.Fatal(e)
	}
	data := make([]byte, len(memory))
	for i := range data {
		if !zero {
			data[i] = byte(i*131 + (i/4096)*17)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "memory")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	s := faultServer{regions: []regionMapping{{BaseHostVirtAddr: base, Size: uint64(len(memory))}}, chunk: 8 * 4096, uffdFd: int(fd), source: &pageSource{file: f}}
	if cached {
		s.chunk = 256 << 10 // CLI hint differs from the effective source chunk
		s.source = &pageSource{cache: f, chunk: 8 * 4096, fetched: map[uint64]struct{}{0: {}, 1: {}}}
	}
	if zero {
		if reg[3]&(1<<4) == 0 {
			t.Skip("range does not support ZEROPAGE")
		}
		s.zeroPage = true
		s.source = &pageSource{chunk: 8 * 4096, chunkManifest: &checkpointchunks.Manifest{
			Version: 1, File: "memory", FileSize: int64(len(memory)), ChunkBytes: 8 * 4096, ChunkCount: 2,
			Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: checkpointchunks.ZeroChunkDigest(8 * 4096)}, {Offset: 8 * 4096, Digest: checkpointchunks.ZeroChunkDigest(8 * 4096)}},
		}}
		done, err := s.tryZeroPage(s.regions[0], 2*4096, 4096, base+2*4096)
		if err != nil || !done {
			t.Fatalf("real ZEROPAGE done=%v err=%v", done, err)
		}
	}
	// Default fills only page 2; a later guest write must survive all COPYs.
	if err = s.resolve(base + 2*4096); err != nil {
		t.Fatal(err)
	}
	memory[2*4096] = 0xA7
	data[2*4096] = 0xA7
	s.copyBytes = 256 << 10
	if err = s.resolve(base); err != nil {
		t.Fatal(err)
	} // partial prefix, EAGAIN
	if err = s.resolve(base + 2*4096); err != nil {
		t.Fatal(err)
	} // EEXIST at first page
	resident := make([]byte, len(memory)/4096)
	if _, _, e := unix.Syscall(unix.SYS_MINCORE, uintptr(base), uintptr(len(memory)), uintptr(unsafe.Pointer(&resident[0]))); e != 0 {
		t.Fatal(e)
	}
	for i, v := range resident {
		if (v&1 != 0) != (i < 3) {
			t.Fatalf("unexpected resident page %d: %d", i, v)
		}
	}
	if err = s.resolve(base + 3*4096); err != nil {
		t.Fatal(err)
	} // fills suffix to chunk end
	if _, _, e := unix.Syscall(unix.SYS_MINCORE, uintptr(base), uintptr(len(memory)), uintptr(unsafe.Pointer(&resident[0]))); e != 0 {
		t.Fatal(e)
	}
	for i, v := range resident {
		if (v&1 != 0) != (i < 8) {
			t.Fatalf("copy crossed effective chunk at page %d: %d", i, v)
		}
	}
	if err = s.resolve(base + 8*4096); err != nil {
		t.Fatal(err)
	} // next chunk, capped at region end
	if !bytes.Equal(memory, data) {
		t.Fatal("forward population changed guest data")
	}
	runtime.KeepAlive(memory)
}

// A bad descriptor makes accidental zero supply observable without risking
// a blocked reader. Only authenticated, page-contained remote zero spans qualify.
func TestZeroSupplyEligibilityAndFallback(t *testing.T) {
	fixture := func() *faultServer {
		return &faultServer{zeroPage: true, uffdFd: -1, source: &pageSource{chunk: 8192, chunkManifest: &checkpointchunks.Manifest{
			FileSize: 8192, ChunkBytes: 8192, Entries: []checkpointchunks.Chunk{{Offset: 0, Digest: checkpointchunks.ZeroChunkDigest(8192)}},
		}}}
	}
	for _, tc := range []struct {
		name                  string
		change                func(*faultServer)
		off, length, pageSize uint64
	}{
		{"disabled", func(s *faultServer) { s.zeroPage = false }, 0, 4096, 4096},
		{"local backing", func(s *faultServer) { s.source.file = os.Stdin }, 0, 4096, 4096},
		{"unverified manifest", func(s *faultServer) { s.source.chunkManifest = nil }, 0, 4096, 4096},
		{"nonzero digest", func(s *faultServer) { s.source.chunkManifest.Entries[0].Digest = "bad" }, 0, 4096, 4096},
		{"crosses tail", func(s *faultServer) {}, 4096, 8192, 4096},
		{"past end", func(s *faultServer) {}, 8192, 4096, 4096},
		{"hugepage", func(s *faultServer) {}, 0, 4096, 2 << 20},
		{"wrong grid", func(s *faultServer) { s.source.chunkManifest.Entries[0].Offset = 1 }, 0, 4096, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			tc.change(s)
			done, err := s.tryZeroPage(regionMapping{PageSize: tc.pageSize}, tc.off, tc.length, 0)
			if done || err != nil {
				t.Fatalf("ineligible range attempted ioctl: done=%v err=%v", done, err)
			}
		})
	}
	s := fixture()
	if done, err := s.tryZeroPage(regionMapping{}, 0, 4096, 0); done || err == nil {
		t.Fatalf("bad descriptor must fail: %v %v", done, err)
	}
	f, err := os.CreateTemp(t.TempDir(), "unsupported")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s.uffdFd = int(f.Fd())
	if done, err := s.tryZeroPage(regionMapping{}, 0, 4096, 0); done || err != nil {
		t.Fatalf("ENOTTY must fall back: %v %v", done, err)
	}
}
