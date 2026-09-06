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

package checkpointchunks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalContentsTransportWithoutLineage(t *testing.T) {
	for _, version := range []int{1, PackedVersion, RootPackedVersion} {
		dir, m := backingFixture(t, FileDigestChunks)
		m.Version = version
		// Mixed CAS/pack transports permit an empty pack mapping; content
		// validation reads the complete local file, not any remote pack.
		if err := Write(dir, m); err != nil {
			t.Fatal(err)
		}
		if err := VerifyLocalMemoryContents(context.Background(), dir, m.FileDigest, FileDigestChunks); err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if version != 1 {
			if _, err := VerifyMemoryBacking(context.Background(), dir, m.FileDigest, FileDigestChunks); err == nil {
				t.Fatal("transport gained lineage authority")
			}
		}
		f, err := os.OpenFile(filepath.Join(dir, "memory"), os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.WriteAt([]byte{1}, 0); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if VerifyLocalMemoryContents(context.Background(), dir, m.FileDigest, FileDigestChunks) == nil {
			t.Fatalf("version %d accepted corruption", version)
		}
	}
}

func TestLocalContentsRejectsMarkersAndCancellation(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		dir, m := backingFixture(t, FileDigestChunks)
		path := filepath.Join(dir, ".materialized")
		var err error
		switch kind {
		case "file":
			err = os.WriteFile(path, nil, 0600)
		case "directory":
			err = os.Mkdir(path, 0700)
		case "symlink":
			err = os.Symlink("missing", path)
		}
		if err != nil {
			t.Fatal(err)
		}
		if VerifyLocalMemoryContents(context.Background(), dir, m.FileDigest, FileDigestChunks) == nil {
			t.Fatalf("accepted marker %s", kind)
		}
	}
	dir, m := backingFixture(t, FileDigestChunks)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyLocalMemoryContents(ctx, dir, m.FileDigest, FileDigestChunks); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
