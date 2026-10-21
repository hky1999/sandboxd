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

package runsc

// This file deliberately compiles on the actual pre-change source. It is
// overlaid alone for behavioral RED, then retained in the final green suite.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func a1RunscContractSnapshot(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	payload := []byte("expected-checkpoint")
	if err := os.WriteFile(filepath.Join(dir, checkpointImageName), payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	manifest := map[string]any{
		"version": 2, "snapshot_type": "runsc", "artifacts": []string{checkpointImageName},
		"digests": map[string]string{checkpointImageName: hex.EncodeToString(sum[:])},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	binding, err := checkpointroot.Bind(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, binding.RootDigest
}

func TestA1RunscContractRootBeforeAllocation(t *testing.T) {
	dir, _ := a1RunscContractSnapshot(t)
	handler := &Handler{runsc: NewClient("/not-executed", t.TempDir())}
	err := handler.Restore(context.Background(), runtimecore.StartConfig{
		ID: "target", CheckpointDir: dir, ExpectedCheckpointRoot: strings.Repeat("0", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "expected root") {
		t.Fatalf("expected root was not enforced before allocation: %v", err)
	}
}

func TestA1RunscContractOpenedPayloadBeforeNetwork(t *testing.T) {
	dir, root := a1RunscContractSnapshot(t)
	if err := os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("wrong!-checkpoint!!"), 0600); err != nil {
		t.Fatal(err)
	}
	// Unknown JSON fields are ignored by the old StartArgs, so the old code
	// compiles but fails this behavior assertion instead of a compile gate.
	raw, err := json.Marshal(map[string]string{"ID": "target", "ExpectedCheckpointRoot": root})
	if err != nil {
		t.Fatal(err)
	}
	var args StartArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	client := NewClient("/not-executed", t.TempDir())
	err = client.Restore(context.Background(), args, filepath.Join(dir, checkpointImageName))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("opened payload was not checked before state/network: %v", err)
	}
}

type a1RunscContractCheckpointClient struct{ successfulRunscClient }

func (a1RunscContractCheckpointClient) Checkpoint(_ context.Context, _ string, dir string, _ bool, _ bool) error {
	return os.WriteFile(filepath.Join(dir, checkpointImageName), []byte("output"), 0600)
}

func TestA1RunscContractSuccessfulCheckpointIsSealed(t *testing.T) {
	dir := t.TempDir()
	handler := &Handler{runsc: a1RunscContractCheckpointClient{}}
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: "source", Directory: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointroot.Bind(dir); err != nil {
		t.Fatalf("successful checkpoint has no verifiable seal: %v", err)
	}
}

func TestA1RunscContractStrictDeleteCannotUseLegacyClient(t *testing.T) {
	handler := &Handler{runsc: successfulRunscClient{}, sandboxRoot: t.TempDir()}
	strict, ok := any(handler).(runtimecore.StrictDeleteHandler)
	if !ok {
		t.Fatal("actual handler has no strict generation retirement capability")
	}
	if err := strict.DeleteStrict(context.Background(), "target", "generation"); err == nil || !strings.Contains(err.Error(), "strict") || !strings.Contains(err.Error(), errord.ErrFailedPrecondition.Error()) {
		t.Fatalf("unproven legacy deletion accepted: %v", err)
	}
}
