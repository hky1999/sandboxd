//go:build linux

package sha256batch

import (
	"os"
	"syscall"
	"testing"
)

func TestGuardPages(t *testing.T) {
	page := os.Getpagesize()
	sizes := []int{0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 1023, 2048, page - 1, page}
	var mappings [][]byte
	defer func() {
		for _, m := range mappings {
			if err := syscall.Munmap(m); err != nil {
				t.Error(err)
			}
		}
	}()
	inputs := make([][]byte, 16)
	for i, n := range sizes {
		m, err := syscall.Mmap(-1, 0, 3*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
		if err != nil {
			t.Fatal(err)
		}
		mappings = append(mappings, m)
		if err := syscall.Mprotect(m[:page], syscall.PROT_NONE); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mprotect(m[2*page:], syscall.PROT_NONE); err != nil {
			t.Fatal(err)
		}
		inputs[i] = m[2*page-n : 2*page]
		for j := range inputs[i] {
			inputs[i][j] = byte(j + i)
		}
	}
	for n := 0; n <= 16; n++ {
		check(t, inputs[:n])
	}
	// Also exercise reads starting immediately after an inaccessible page.
	for i, m := range mappings {
		inputs[i] = m[page : page+sizes[i]]
	}
	check(t, inputs)
}
