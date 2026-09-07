//go:build amd64 && gc && !noasm && !appengine

package sha256batch

import (
	"encoding/binary"
	"golang.org/x/sys/cpu"
)

// Accelerated reports CPU and OS support; x/sys/cpu also honors GODEBUG CPU
// disables. The conservative feature set includes the upstream requirements.
func Accelerated() bool {
	return cpu.X86.HasAVX2 && cpu.X86.HasAVX512F && cpu.X86.HasAVX512DQ && cpu.X86.HasAVX512CD && cpu.X86.HasAVX512BW && cpu.X86.HasAVX512VL
}

//go:noescape
func sha256X16Avx512(digests *[512]byte, scratch *[512]byte, table *[512]uint64, mask []uint64, inputs [16][]byte)

// sumAccelerated is synchronous; caller must check Accelerated first.
func sumAccelerated(inputs [][]byte, out *[16][32]byte) {
	const window = 64 << 10
	var state, scratch [512]byte
	initial := [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	for word, v := range initial {
		for lane := 0; lane < 16; lane++ {
			binary.LittleEndian.PutUint32(state[word*64+lane*4:], v)
		}
	}
	var remaining, blocks [16][]byte
	for i, b := range inputs {
		remaining[i] = b[:len(b)&^63]
	}
	// At most 1024 compression rounds per assembly call, regardless of input size.
	var masks [window / 64]uint64
	compress := func() {
		rounds := 0
		for i, b := range blocks {
			n := len(b) / 64
			for r := 0; r < n; r++ {
				masks[r] |= uint64(1) << i
			}
			rounds = max(rounds, n)
		}
		if rounds > 0 {
			sha256X16Avx512(&state, &scratch, &table, masks[:rounds], blocks)
			clear(masks[:rounds])
		}
	}
	for {
		any := false
		for i, b := range remaining {
			n := min(len(b), window)
			blocks[i] = b[:n]
			remaining[i] = b[n:]
			any = any || n > 0
		}
		if !any {
			break
		}
		compress()
	}
	var padding [16][128]byte
	blocks = [16][]byte{}
	for i, b := range inputs {
		tail := len(b) & 63
		copy(padding[i][:], b[len(b)-tail:])
		padding[i][tail] = 0x80
		n := 64
		if tail >= 56 {
			n = 128
		}
		binary.BigEndian.PutUint64(padding[i][n-8:n], uint64(len(b))*8)
		blocks[i] = padding[i][:n]
	}
	compress()
	for i := range inputs {
		for word := 0; word < 8; word++ {
			binary.BigEndian.PutUint32(out[i][word*4:], binary.LittleEndian.Uint32(state[word*64+i*4:]))
		}
	}
}
