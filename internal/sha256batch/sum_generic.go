//go:build !amd64 || !gc || noasm || appengine

package sha256batch

import "crypto/sha256"

// Accelerated reports whether the synchronous AVX512 backend is available.
func Accelerated() bool { return false }
func sumAccelerated(inputs [][]byte, out *[16][32]byte) {
	for i, b := range inputs {
		out[i] = sha256.Sum256(b)
	}
}
