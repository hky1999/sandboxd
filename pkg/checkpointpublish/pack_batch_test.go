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
	"context"
	"fmt"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPackBatchHashArtifacts(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		for _, packChunks := range []int{1, 4, 16, 17, 32} {
			t.Run(fmt.Sprintf("%s/%d", identity, packChunks), func(t *testing.T) {
				data := packData(35, 4096)
				data = append(data, data[:4096]...)
				data = append(data, make([]byte, 4096)...)
				data = append(data, []byte("tail")...)
				var expected *checkpointchunks.Manifest
				for _, batch := range []bool{false, true} {
					source := packSource(t, data, 4096)
					store, err := chunkstore.NewLocal(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					opts := Options{PackBatchHash: batch, PackIdentity: identity, Workers: 4, PackBytes: packChunks * 4096}
					if _, err := RunWithOptions(context.Background(), source, "batch", store, "local", opts); err != nil {
						t.Fatal(err)
					}
					actual := assertPackedBytes(t, store, "batch", data)
					if expected == nil {
						expected = actual
					} else if !reflect.DeepEqual(expected, actual) {
						t.Fatal("batch flag changed transport identity")
					}
				}
			})
		}
	}
}

// Inject after the sealed source manifest is loaded, while classifying chunks.
// This exercises the actual pack content verification, not metadata validation.
type batchMutationStore struct {
	*chunkstore.Local
	mutate func() error
}

func (s *batchMutationStore) Has(ctx context.Context, digest string) (bool, error) {
	if s.mutate != nil {
		f := s.mutate
		s.mutate = nil
		if err := f(); err != nil {
			return false, err
		}
	}
	return false, nil
}
func TestPackBatchHashRejectsMutationAndCancellation(t *testing.T) {
	for _, identity := range []string{"", checkpointchunks.PackIdentityChunks} {
		for _, batch := range []bool{false, true} {
			for _, cancelled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/batch=%t/cancel=%t", identity, batch, cancelled), func(t *testing.T) {
					data := packData(35, 4096)
					source := packSource(t, data, 4096)
					local, err := chunkstore.NewLocal(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					store := &batchMutationStore{Local: local}
					store.mutate = func() error {
						if cancelled {
							cancel()
							return nil
						}
						data[17*4096] ^= 1
						return os.WriteFile(filepath.Join(source, "memory"), data, 0600)
					}
					_, err = RunWithOptions(ctx, source, "bad", store, "local", Options{PackBatchHash: batch, PackIdentity: identity, Workers: 1, PackBytes: 32 * 4096})
					if err == nil {
						t.Fatal("invalid source/context accepted")
					}
					if !cancelled && !strings.Contains(err.Error(), "changed before pack publication") {
						t.Fatalf("wrong failure: %v", err)
					}
					ok, e := local.HasKey(context.Background(), ArtifactKey("bad", IndexName))
					if e != nil || ok {
						t.Fatalf("INDEX present=%t err=%v", ok, e)
					}
					state, e := Status(source)
					if e != nil || state == nil || state.State != StatePublishFailed {
						t.Fatalf("state=%+v err=%v", state, e)
					}
				})
			}
		}
	}
}

func TestPackBatchHashRequiresPacking(t *testing.T) {
	source := t.TempDir()
	if _, err := RunWithOptions(context.Background(), source, "invalid", nil, "", Options{PackBatchHash: true}); err == nil {
		t.Fatal("accepted without packing")
	}
	for _, name := range []string{StatePath(source), StatePath(source) + ".lock"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("created %s: %v", name, err)
		}
	}
}
