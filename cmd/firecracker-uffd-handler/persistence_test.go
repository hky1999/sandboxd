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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistenceBoundsIOWithoutDroppingQueuedWork(t *testing.T) {
	for _, workers := range []int{1, 4, 16, 64} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) { testPersistenceBoundsIO(t, workers) })
	}
}

func testPersistenceBoundsIO(t *testing.T, workers int) {
	const count = 512
	gate := make(chan struct{})
	var release sync.Once
	entered := make(chan struct{}, count)
	finished := make(chan struct{}, count)
	var active, maxActive atomic.Int64
	p := newChunkPersister(count, workers, func(job persistRef) error {
		n := active.Add(1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-gate
		active.Add(-1)
		finished <- struct{}{}
		return nil
	})
	t.Cleanup(func() { release.Do(func() { close(gate) }); p.stop(); p.wg.Wait() })
	submitted := make(chan bool, 1)
	go func() {
		accepted := true
		for i := 0; i < count; i++ {
			if !p.enqueue(persistRef{digest: fmt.Sprintf("%064x", i), offset: uint64(i * 4096), length: 4096}) {
				accepted = false
			}
		}
		submitted <- accepted
	}()
	select {
	case ok := <-submitted:
		if !ok {
			t.Fatal("live work dropped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submission blocked on IO")
	}
	for i := 0; i < workers; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("workers not started")
		}
	}
	if got := active.Load(); got != int64(workers) {
		t.Fatalf("active=%d", got)
	}
	release.Do(func() { close(gate) })
	for i := 0; i < count; i++ {
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("queued warm-cache work lost")
		}
	}
	if got := maxActive.Load(); got > int64(workers) {
		t.Fatalf("IO concurrency %d exceeds budget", got)
	}
}

func TestPersistenceShutdownDropsOnlyUnstartedWork(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	entered := make(chan struct{}, 128)
	var writes atomic.Int64
	p := newChunkPersister(128, persistenceWorkers, func(job persistRef) error { writes.Add(1); entered <- struct{}{}; <-gate; return nil })
	t.Cleanup(func() { release.Do(func() { close(gate) }); p.stop(); p.wg.Wait() })
	for i := 0; i < 100; i++ {
		if !p.enqueue(persistRef{digest: fmt.Sprintf("%064x", i)}) {
			t.Fatal("unexpected rejection")
		}
	}
	for i := 0; i < persistenceWorkers; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("workers not started")
		}
	}
	p.stop()
	if p.enqueue(persistRef{}) {
		t.Fatal("accepted work after shutdown")
	}
	release.Do(func() { close(gate) })
	p.wg.Wait()
	if got := writes.Load(); got != persistenceWorkers {
		t.Fatalf("shutdown started pending IO: %d", got)
	}
}

func TestPersistVerifiedCacheExtent(t *testing.T) {
	cache, err := os.CreateTemp(t.TempDir(), "cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	body := bytes.Repeat([]byte{3, 5, 7}, 137)
	if _, err := cache.WriteAt(body, 8192); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	local := t.TempDir()
	job := persistRef{digest: digest, offset: 8192, length: uint64(len(body))}
	if err := persistCacheExtent(cache, local, job); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(local, digest[:2], digest))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("persisted extent differs")
	}
	job.offset = 8193
	other := t.TempDir()
	if err := persistCacheExtent(cache, other, job); err == nil {
		t.Fatal("short cache extent accepted")
	}
	entries, err := os.ReadDir(other)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed read left persistent artifacts")
	}
}
