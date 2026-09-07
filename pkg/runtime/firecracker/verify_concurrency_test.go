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

package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

type pausedVerificationContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *pausedVerificationContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Err()
}

func TestRestoreVerificationIndependentPaths(t *testing.T) {
	for _, kind := range []string{"materialized", "cancelled-local"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			memory := filepath.Join(dir, "memory")
			if err := os.WriteFile(memory, []byte("verified local memory"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := digestMemoryWithChunkScan(context.Background(), memory, checkpointchunks.FileDigestChunks)
			if err != nil {
				t.Fatal(err)
			}
			local := &firecrackerCheckpointArtifact{Files: firecrackerCheckpointFiles{Memory: memory}, Manifest: &firecrackerCheckpointManifest{MemorySize: 21, MemoryDigestMode: checkpointchunks.FileDigestChunks, Digests: map[string]string{"memory": root}}}
			remoteDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(remoteDir, materializedMarkerName), []byte("remote"), 0600); err != nil {
				t.Fatal(err)
			}
			remote := &firecrackerCheckpointArtifact{Files: firecrackerCheckpointFiles{Memory: filepath.Join(remoteDir, "memory")}, Manifest: &firecrackerCheckpointManifest{MemoryDigestMode: checkpointchunks.FileDigestChunks, Digests: map[string]string{"memory": root}}}
			paused := &pausedVerificationContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
			var cache checkpointDigestCache
			first := make(chan error, 1)
			go func() { first <- cache.verifyFirecrackerCheckpointDigests(paused, local) }()
			released := false
			defer func() {
				if !released {
					close(paused.release)
				}
				if err := <-first; err != nil {
					t.Errorf("first verification: %v", err)
				}
			}()
			select {
			case <-paused.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("local verifier never reached content check")
			}
			result := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			artifact := remote
			if kind == "cancelled-local" {
				artifact = local
				cancel()
			}
			go func() { result <- cache.verifyFirecrackerCheckpointDigests(ctx, artifact) }()
			var got error
			select {
			case got = <-result:
			case <-time.After(2 * time.Second):
				t.Error("independent/cancelled restore blocked by local memory verification")
				close(paused.release)
				released = true
				got = <-result
			}
			if kind == "cancelled-local" {
				if !errors.Is(got, context.Canceled) {
					t.Errorf("cancelled verification: %v", got)
				}
			} else if got != nil {
				t.Errorf("materialized verification: %v", got)
			}
		})
	}
}
