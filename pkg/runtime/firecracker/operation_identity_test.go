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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestFirecrackerStrictDeleteRejectsWrongGenerationBeforeEffects(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	instance.state.Generation = "current-generation"
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	fd := a1FCPidfd(t, instance.state.PID)
	err := handler.DeleteStrict(context.Background(), instance.state.ID, "another-generation")
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("wrong generation: %v", err)
	}
	if instance.deleting {
		t.Fatal("mismatched generation mutated deleting state")
	}
	if a1FCExited(t, fd) {
		t.Fatal("mismatched generation stopped the live process")
	}
	a1FCAssertRetained(t, handler, instance.state.ID, instance.state.BundlePath)
	if err := handler.DeleteStrict(context.Background(), instance.state.ID, instance.state.Generation); err != nil {
		t.Fatal(err)
	}
	if !a1FCExited(t, fd) {
		t.Fatal("strict deletion returned before kernel exit")
	}
	a1FCAssertReleased(t, handler, instance.state.ID, instance.state.BundlePath)
}

func TestFirecrackerStrictDeleteUnboundLegacyRecordIsNotProof(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	fd := a1FCPidfd(t, instance.state.PID)
	err := handler.DeleteStrict(context.Background(), instance.state.ID, "expected-generation")
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("unbound legacy generation: %v", err)
	}
	if instance.deleting || a1FCExited(t, fd) {
		t.Fatal("unbound rejection changed the live incarnation")
	}
	if err := handler.Delete(context.Background(), instance.state.ID); err != nil {
		t.Fatal(err)
	}
}

func TestFirecrackerStrictDeleteMissingStateIsNotProof(t *testing.T) {
	handler, _ := a1FCDeleteFixture(t)
	handler.sandboxRoot = t.TempDir()
	const id = "sbox-no-runtime-state"
	if err := handler.DeleteStrict(context.Background(), id, "generation"); !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("missing state must refuse strict deletion, got %v", err)
	}
	if err := handler.Delete(context.Background(), id); err != nil {
		t.Fatalf("legacy idempotent behavior changed: %v", err)
	}
}

func TestFirecrackerStrictDeleteReloadDoesNotRunRecoveryBeforeGenerationGate(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	fd := a1FCPidfd(t, instance.state.PID)
	handler.sandboxRoot = t.TempDir()
	newBundle := filepath.Join(handler.sandboxRoot, instance.state.ID)
	if err := os.Rename(instance.state.BundlePath, newBundle); err != nil {
		t.Fatal(err)
	}
	instance.state.BundlePath = newBundle
	instance.state.Generation = "persisted-generation"
	// Legacy recoverState would try to stop this still-live process because the
	// record says Exited. A strict mismatch must never invoke that recovery.
	instance.state.Exited = true
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	handler.mu.Lock()
	delete(handler.instances, instance.state.ID)
	handler.mu.Unlock()
	err := handler.DeleteStrict(context.Background(), instance.state.ID, "stale-generation")
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("reloaded mismatch: %v", err)
	}
	if a1FCExited(t, fd) {
		t.Fatal("passive mismatch lookup signalled the process")
	}
	handler.mu.RLock()
	_, adopted := handler.instances[instance.state.ID]
	handler.mu.RUnlock()
	if adopted {
		t.Fatal("mismatched lookup must not publish a recovered instance")
	}
	if err := handler.DeleteStrict(context.Background(), instance.state.ID, "persisted-generation"); err != nil {
		t.Fatal(err)
	}
	if !a1FCExited(t, fd) {
		t.Fatal("reloaded strict delete lacks kernel exit proof")
	}
	a1FCAssertReleased(t, handler, instance.state.ID, instance.state.BundlePath)
}

func TestFirecrackerRestoreIdentityUsesOpenedManifestView(t *testing.T) {
	dir, oldRoot := operationIdentityCheckpoint(t)
	artifact, err := openFirecrackerCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, firecrackerCheckpointManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, artifact.ManifestRaw) {
		t.Fatal("manifest raw differs from parsed view")
	}
	// An equivalent JSON re-encoding changes the manifest identity. Checking the
	// opened artifact must still use its original raw bytes, not reread this path.
	if err := os.WriteFile(filepath.Join(dir, firecrackerCheckpointManifestName), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	newer, err := checkpointroot.Bind(dir)
	if err != nil {
		t.Fatal(err)
	}
	if newer.RootDigest == oldRoot {
		t.Fatal("fixture did not change the path's identity")
	}
	cfg := runtimecore.StartConfig{CheckpointDir: dir, ExpectedCheckpointRoot: oldRoot}
	if err := verifyFirecrackerExpectedRoot(cfg, artifact); err != nil {
		t.Fatal(err)
	}
	err = (&Handler{}).Restore(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "does not match expected root") {
		t.Fatalf("fresh restore must bind its newly opened view, got %v", err)
	}
}

func TestFirecrackerRestoreMatchingRootReachesExistingRuntimeValidation(t *testing.T) {
	dir, root := operationIdentityCheckpoint(t)
	err := (&Handler{}).Restore(context.Background(), runtimecore.StartConfig{CheckpointDir: dir, ExpectedCheckpointRoot: root})
	if err == nil || !strings.Contains(err.Error(), "requires a managed cgroup") {
		t.Fatalf("correct root should pass identity gate, got %v", err)
	}
}

func TestFirecrackerManifestReadIsBoundedAndLegacyReaderCompatible(t *testing.T) {
	dir, _ := operationIdentityCheckpoint(t)
	parsed, err := readFirecrackerCheckpointManifest(dir)
	if err != nil || parsed.Version != firecrackerCheckpointVersion2 {
		t.Fatalf("legacy reader compatibility: %v", err)
	}
	path := filepath.Join(dir, firecrackerCheckpointManifestName)
	if err := os.Truncate(path, checkpointroot.MaxManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readFirecrackerCheckpointManifest(dir); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized manifest must be refused before buffering it: %v", err)
	}
}
