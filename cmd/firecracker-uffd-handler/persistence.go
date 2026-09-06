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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const persistenceWorkers = 4

// A pending job holds metadata only. Verified cache bytes are immutable for
// the handler lifetime, so buffering payloads while waiting for fsync is wasted.
type persistRef struct {
	digest string
	offset uint64
	length uint64
}

type chunkPersister struct {
	mu      sync.Mutex
	ready   *sync.Cond
	pending []persistRef
	limit   int
	stopped bool
	wg      sync.WaitGroup
	write   func(persistRef) error
}

func newChunkPersister(limit, workers int, write func(persistRef) error) *chunkPersister {
	p := &chunkPersister{limit: limit, write: write}
	p.ready = sync.NewCond(&p.mu)
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.run()
	}
	return p
}

func (p *chunkPersister) enqueue(job persistRef) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || len(p.pending) >= p.limit {
		return false
	}
	p.pending = append(p.pending, job)
	p.ready.Signal()
	return true
}

func (p *chunkPersister) run() {
	defer p.wg.Done()
	for {
		p.mu.Lock()
		for len(p.pending) == 0 && !p.stopped {
			p.ready.Wait()
		}
		if p.stopped {
			p.mu.Unlock()
			return
		}
		job := p.pending[0]
		p.pending[0] = persistRef{}
		p.pending = p.pending[1:]
		if len(p.pending) == 0 {
			p.pending = nil
		}
		p.mu.Unlock()
		if err := p.write(job); err != nil {
			log.Printf("persist chunk %s: %v", job.digest, err)
		}
	}
}

// stop never waits for filesystem IO. Pending cache work is rebuildable and
// irrelevant once the VMM exits; at most the configured worker count writes remain.
func (p *chunkPersister) stop() {
	p.mu.Lock()
	p.stopped = true
	p.pending = nil
	p.ready.Broadcast()
	p.mu.Unlock()
}

func (src *pageSource) schedulePersistence(job persistRef) {
	src.persistenceMu.Lock()
	defer src.persistenceMu.Unlock()
	if src.persistenceStopped {
		return
	}
	if src.persister == nil {
		// Digest reuse enqueues each successful unique digest at most once.
		// Thus the manifest count bounds metadata without dropping live work
		// or blocking faults behind a full payload queue.
		workers := src.persistenceWorkerCount
		if workers == 0 {
			workers = persistenceWorkers
		}
		src.persister = newChunkPersister(len(src.chunkManifest.Entries), workers, func(job persistRef) error {
			return persistCacheExtent(src.cache, src.chunkLocal, job)
		})
	}
	if !src.persister.enqueue(job) {
		log.Printf("persist chunk %s: queue closed or manifest task bound exceeded", job.digest)
	}
}

func (src *pageSource) stopPersistence() *chunkPersister {
	src.persistenceMu.Lock()
	defer src.persistenceMu.Unlock()
	src.persistenceStopped = true
	if src.persister != nil {
		src.persister.stop()
	}
	return src.persister
}

func persistCacheExtent(cache *os.File, local string, job persistRef) error {
	body := make([]byte, job.length)
	if _, err := cache.ReadAt(body, int64(job.offset)); err != nil {
		return fmt.Errorf("read verified cache: %w", err)
	}
	path := filepath.Join(local, job.digest[:2], job.digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
