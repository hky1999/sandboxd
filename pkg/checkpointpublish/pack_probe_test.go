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

package checkpointpublish

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

type probeCountingStore struct {
	*chunkstore.Local
	probes    atomic.Int64
	packBytes atomic.Int64
}

func (s *probeCountingStore) Has(ctx context.Context, digest string) (bool, error) {
	s.probes.Add(1)
	return s.Local.Has(ctx, digest)
}
func (s *probeCountingStore) PutKey(ctx context.Context, key string, r io.Reader) error {
	if strings.HasPrefix(key, "memory-packs/") || strings.HasPrefix(key, "memory-chunk-packs-v1/") {
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		s.packBytes.Add(int64(len(data)))
		r = bytes.NewReader(data)
	}
	return s.Local.PutKey(ctx, key, r)
}
func TestPackSkipChunkProbeTradeoff(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("identity=%s/skip=%t", identity, skip), func(t *testing.T) {
				ctx := context.Background()
				data := packData(2, 4096)
				data = append(data, data[:4096]...) // duplicate logical page
				data = append(data, make([]byte, 4096)...)
				data = append(data, []byte("tail")...)
				source := packSource(t, data, 4096)
				local, err := chunkstore.NewLocal(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				m, err := checkpointchunks.Load(source)
				if err != nil {
					t.Fatal(err)
				}
				for _, c := range m.Entries {
					end := min(c.Offset+int64(m.ChunkBytes), int64(len(data)))
					if err := local.Put(ctx, c.Digest, bytes.NewReader(data[c.Offset:end])); err != nil {
						t.Fatal(err)
					}
				}
				store := &probeCountingStore{Local: local}
				opts := Options{PackSkipChunkProbe: skip, PackIdentity: identity, Workers: 4, PackBytes: 8192}
				result, err := RunWithOptions(ctx, source, "probe", store, "local", opts)
				if err != nil {
					t.Fatal(err)
				}
				transport := assertPackedBytes(t, local, "probe", data)
				if skip {
					if store.probes.Load() != 0 || store.packBytes.Load() != 8196 || len(transport.Packs) != 3 || result.PacksPut != 2 {
						t.Fatalf("skip probes=%d bytes=%d refs=%d packs=%d", store.probes.Load(), store.packBytes.Load(), len(transport.Packs), result.PacksPut)
					}
				} else if store.probes.Load() != 3 || store.packBytes.Load() != 0 || len(transport.Packs) != 0 {
					t.Fatalf("default probes=%d bytes=%d refs=%d", store.probes.Load(), store.packBytes.Load(), len(transport.Packs))
				}
				t.Logf("skip=%t standalone_probes=%d pack_upload_bytes=%d", skip, store.probes.Load(), store.packBytes.Load())
				before := store.packBytes.Load()
				if _, err := RunWithOptions(ctx, source, "probe", store, "local", opts); err != nil {
					t.Fatal(err)
				}
				if store.packBytes.Load() != before {
					t.Fatal("retry reuploaded packs")
				}
				assertPackedBytes(t, local, "probe", data)
			})
		}
	}
}
func TestPackSkipChunkProbeRejectsInvalidAndChangedSource(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	if _, err := RunWithOptions(ctx, source, "bad", nil, "none", Options{PackSkipChunkProbe: true}); err == nil {
		t.Fatal("nonpacked accepted")
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) != 0 {
		t.Fatalf("source changed: %v %v", entries, err)
	}
	if _, err := os.Stat(StatePath(source) + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("claim created: %v", err)
	}
	if _, err := os.Stat(StatePath(source)); !os.IsNotExist(err) {
		t.Fatalf("state created: %v", err)
	}
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		t.Run(identity, func(t *testing.T) {
			data := packData(2, 4096)
			dir := packSource(t, data, 4096)
			data[0] ^= 1
			if err := os.WriteFile(filepath.Join(dir, "memory"), data, 0600); err != nil {
				t.Fatal(err)
			}
			local, err := chunkstore.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RunWithOptions(ctx, dir, "changed", local, "local", Options{PackSkipChunkProbe: true, PackBytes: 8192, PackIdentity: identity}); err == nil {
				t.Fatal("changed source accepted")
			}
			if ok, err := local.HasKey(ctx, ArtifactKey("changed", IndexName)); err != nil || ok {
				t.Fatalf("INDEX exists=%v err=%v", ok, err)
			}
		})
	}
}
