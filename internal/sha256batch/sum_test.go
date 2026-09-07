package sha256batch

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func check(t *testing.T, inputs [][]byte) {
	t.Helper()
	var want [16][32]byte
	for i, b := range inputs {
		want[i] = sha256.Sum256(b)
	}
	var got [16][32]byte
	for i := range got {
		for j := range got[i] {
			got[i][j] = 0xff
		}
	}
	Sum256(inputs, &got)
	if got != want {
		t.Fatalf("digest mismatch: batch %d", len(inputs))
	}
	if Accelerated() {
		var direct [16][32]byte
		sumAccelerated(inputs, &direct)
		if direct != want {
			t.Fatalf("accelerated mismatch: batch %d", len(inputs))
		}
	}
}

func TestOracle(t *testing.T) {
	t.Logf("AVX512 backend available: %v", Accelerated())
	sizes := []int{0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 4095, 4096, 65535, 65536, 65537, 262143, 262144, 262145, 1048579}
	r := rand.New(rand.NewSource(2010))
	for n := 0; n <= 16; n++ {
		for shift := range sizes {
			inputs := make([][]byte, n)
			for i := range inputs {
				size := sizes[(i+shift)%len(sizes)]
				b := make([]byte, size+3)
				r.Read(b)
				inputs[i] = b[3:]
			}
			check(t, inputs)
		}
	}
}

func TestOwnershipAndConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(w + 1)))
			inputs := make([][]byte, 16)
			for i := range inputs {
				inputs[i] = make([]byte, 4096+i)
			}
			for round := 0; round < 20; round++ {
				for _, b := range inputs {
					r.Read(b)
				}
				check(t, inputs)
			}
		}(w)
	}
	wg.Wait()
	// Output aliases an input. Computation must complete before setting output.
	var output [16][32]byte
	for i := range output[0] {
		output[0][i] = byte(i)
	}
	inputs := [][]byte{output[0][:], []byte("a"), []byte("b"), []byte("c")}
	var want [16][32]byte
	for i, b := range inputs {
		want[i] = sha256.Sum256(b)
	}
	Sum256(inputs, &output)
	if output != want {
		t.Fatal("overlapping output mismatch")
	}
}

func TestInvalid(t *testing.T) {
	for _, n := range []int{17, 32} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("missing panic")
				}
			}()
			var out [16][32]byte
			Sum256(make([][]byte, n), &out)
		})
	}
	t.Run("nil-output", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("missing panic")
			}
		}()
		Sum256(nil, nil)
	})
}

func BenchmarkBatch(b *testing.B) {
	inputs := make([][]byte, 16)
	r := rand.New(rand.NewSource(1))
	for i := range inputs {
		inputs[i] = make([]byte, 256<<10)
		r.Read(inputs[i])
	}
	for _, mode := range []string{"standard", "batch"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(4 << 20)
			var out [16][32]byte
			for i := 0; i < b.N; i++ {
				if mode == "batch" {
					Sum256(inputs, &out)
				} else {
					for lane, p := range inputs {
						out[lane] = sha256.Sum256(p)
					}
				}
			}
			if out[0] != sha256.Sum256(inputs[0]) {
				b.Fatal("benchmark digest")
			}
		})
	}
}
