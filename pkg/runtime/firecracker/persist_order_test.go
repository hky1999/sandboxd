package firecracker

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentPersistsRetainLatestInstanceState(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	i := &firecrackerInstance{state: firecrackerPersistedState{ID: "persist-order", BundlePath: root, MemoryMiB: 128}}
	h := &Handler{}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for round := 0; round < 4; round++ {
				i.setMemoryMiB(uint32(128 + n*4 + round))
				if err := h.persistInstance(i); err != nil {
					errs <- err
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	disk, err := readFirecrackerState(root)
	if err != nil {
		t.Fatal(err)
	}
	if disk != i.snapshot() {
		t.Fatalf("durable state differs from final instance: disk=%+v memory=%+v", disk, i.snapshot())
	}
}
