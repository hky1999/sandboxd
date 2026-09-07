// Package sha256batch computes independent SHA-256 digests synchronously.
package sha256batch

import "crypto/sha256"

// Sum256 hashes at most 16 independent messages. Unused output slots are zero.
// Inputs must remain immutable during the call; no references are retained after
// return. Scratch space is bounded independently of message length. Output may
// overlap input storage, because all digests are computed before output is set.
// It panics if more than 16 messages or a nil output pointer are supplied.
func Sum256(inputs [][]byte, out *[16][32]byte) {
	if len(inputs) > 16 || out == nil {
		panic("sha256batch: invalid batch")
	}
	var result [16][32]byte
	if len(inputs) >= 4 && Accelerated() {
		sumAccelerated(inputs, &result)
	} else {
		for i, b := range inputs {
			result[i] = sha256.Sum256(b)
		}
	}
	*out = result
}
