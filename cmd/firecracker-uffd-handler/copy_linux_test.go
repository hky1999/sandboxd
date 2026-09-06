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
		t.Run(name, func(t *testing.T) { testForwardCopy(t, cached) })
	}
}

func testForwardCopy(t *testing.T, cached bool) {
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
		data[i] = byte(i*131 + (i/4096)*17)
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
