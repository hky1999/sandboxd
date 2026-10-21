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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func operationIdentityCheckpoint(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	contents := map[string][]byte{
		firecrackerCheckpointStateName:   []byte("vmstate"),
		firecrackerCheckpointMemoryName:  []byte("memory00"),
		firecrackerCheckpointOverlayName: []byte("overlay0"),
	}
	digests := make(map[string]string)
	for name, data := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(sum[:])
	}
	manifest := firecrackerCheckpointManifest{
		Version: firecrackerCheckpointVersion2, SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize: int64(len(contents[firecrackerCheckpointMemoryName])),
		CreatedAt:  time.Now().UTC(), Digests: digests,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, firecrackerCheckpointManifestName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	binding, err := checkpointroot.Bind(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, binding.RootDigest
}

func TestFirecrackerOperationContractStrictCapability(t *testing.T) {
	if _, ok := any(&Handler{}).(runtimecore.StrictDeleteHandler); !ok {
		t.Fatal("actual Firecracker runtime does not provide exact-generation retirement")
	}
}

func TestFirecrackerOperationContractRootCapability(t *testing.T) {
	verifier, ok := any(&Handler{}).(runtimecore.CheckpointRootVerifier)
	if !ok || !verifier.SupportsCheckpointRootVerification() {
		t.Fatal("actual Firecracker runtime does not verify an admission-bound restore root")
	}
}

func TestFirecrackerOperationContractWrongRootRejectedBeforeCreation(t *testing.T) {
	dir, _ := operationIdentityCheckpoint(t)
	handler := &Handler{}
	err := handler.Restore(context.Background(), runtimecore.StartConfig{
		CheckpointDir: dir, ExpectedCheckpointRoot: strings.Repeat("0", checkpointroot.DigestHexLen),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match expected root") {
		t.Fatalf("wrong root must be refused before OCI/storage/VMM creation, got %v", err)
	}
}

func TestFirecrackerOperationContractArchiveCannotIgnoreExpectedRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("legacy archive"), 0600); err != nil {
		t.Fatal(err)
	}
	err := (&Handler{}).Restore(context.Background(), runtimecore.StartConfig{
		CheckpointDir: dir, ExpectedCheckpointRoot: strings.Repeat("0", checkpointroot.DigestHexLen),
	})
	if err == nil || !strings.Contains(err.Error(), "sealed v2") {
		t.Fatalf("legacy archive must not silently ignore an expected root, got %v", err)
	}
}
