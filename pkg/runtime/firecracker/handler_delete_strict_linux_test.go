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
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

var _ interface {
	DeleteStrict(context.Context, string, string) error
} = (*Handler)(nil)

func TestDeleteStrictRejectsUnknownSandboxWhileLegacyStaysIdempotent(t *testing.T) {
	handler, _ := deleteExitFixture(t)
	// Drop every trace of the sandbox: no mapped instance and no persisted
	// state file below a clean sandbox root.
	sandboxID := "delete-exit-test"
	handler.sandboxRoot = t.TempDir()
	handler.mu.Lock()
	delete(handler.instances, sandboxID)
	handler.mu.Unlock()
	if _, err := os.Stat(filepath.Join(handler.sandboxRoot, sandboxID)); err == nil {
		t.Fatalf("unexpected pre-existing state for %s", sandboxID)
	}

	// Strict delete must not convert absence into a retirement proof.
	err := handler.DeleteStrict(context.Background(), sandboxID, "generation")
	if !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("strict delete of unknown sandbox = %v, want ErrNotFound", err)
	}

	// The legacy Delete contract is unchanged: absence is a successful no-op.
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("legacy delete of unknown sandbox = %v, want nil", err)
	}
}

// assertLiveOwnedChild fails when the recorded child process has exited or
// lost the identity the delete flow keys on.
func assertLiveOwnedChild(
	t *testing.T,
	instance *firecrackerInstance,
	fd int,
	binary, apiPath, sandboxID string,
) {
	t.Helper()
	if checkpointTestExitReady(t, fd) {
		t.Fatal("live owned child exited during a rejected strict delete")
	}
	if !firecrackerProcessMatches(instance.state.PID, binary, apiPath, sandboxID) {
		t.Fatal("live owned child lost its native identity")
	}
}

func TestDeleteStrictGenerationMismatchLeavesLiveChildAndArtifactsIntact(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	handler.sandboxRoot = t.TempDir()
	instance.state.BundlePath = filepath.Join(handler.sandboxRoot, instance.state.ID)
	instance.state.Generation = "gen-live"
	if err := os.MkdirAll(
		filepath.Join(instance.state.BundlePath, firecrackerArtifactsDir),
		0700,
	); err != nil {
		t.Fatal(err)
	}
	startDeleteExitChild(t, handler, instance)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	binary := handler.binary
	apiPath := instance.state.APIPath
	pid := instance.state.PID
	fd := checkpointTestPidfd(t, pid)

	// A mismatched expectation must be rejected by the runtime's own
	// persisted identity before any state change, guest request, or signal.
	err := handler.DeleteStrict(context.Background(), sandboxID, "gen-other")
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("mismatched strict delete = %v, want ErrFailedPrecondition", err)
	}
	assertLiveOwnedChild(t, instance, fd, binary, apiPath, sandboxID)
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)

	// The rejected attempt must not wedge the incarnation: a strict delete
	// with the matching generation still retires it, and the same live child
	// is the one that exits.
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-live"); err != nil {
		t.Fatalf("matching strict delete after rejection = %v", err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("matching delete returned before the kernel exit notification")
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

func TestDeleteStrictRejectsUnboundGenerationRecord(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	handler.sandboxRoot = t.TempDir()
	instance.state.BundlePath = filepath.Join(handler.sandboxRoot, instance.state.ID)
	// A record written before the identity binding existed carries no
	// generation; strict deletion is unsupported for it, not merely unequal.
	instance.state.Generation = ""
	if err := os.MkdirAll(
		filepath.Join(instance.state.BundlePath, firecrackerArtifactsDir),
		0700,
	); err != nil {
		t.Fatal(err)
	}
	startDeleteExitChild(t, handler, instance)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	binary := handler.binary
	apiPath := instance.state.APIPath
	fd := checkpointTestPidfd(t, instance.state.PID)

	err := handler.DeleteStrict(context.Background(), sandboxID, "")
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("unbound strict delete = %v, want ErrFailedPrecondition", err)
	}
	assertLiveOwnedChild(t, instance, fd, binary, apiPath, sandboxID)
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)

	// The pre-generation record keeps its legacy compatibility: an
	// unconditional Delete still retires it.
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("legacy delete of unbound record = %v", err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("legacy delete returned before the kernel exit notification")
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

func TestDeleteStrictRetiresRecoveredPersistedState(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	handler.sandboxRoot = t.TempDir()
	instance.state.BundlePath = filepath.Join(handler.sandboxRoot, instance.state.ID)
	instance.state.Generation = "gen-a"
	if err := os.MkdirAll(
		filepath.Join(instance.state.BundlePath, firecrackerArtifactsDir),
		0700,
	); err != nil {
		t.Fatal(err)
	}
	startDeleteExitChild(t, handler, instance)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath

	// Forget the in-memory mapping: a disk reload must retain the bound
	// generation, because the strict comparison reads the persisted identity.
	handler.mu.Lock()
	delete(handler.instances, sandboxID)
	handler.mu.Unlock()
	recovered, err := handler.lookupInstance(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if got := recovered.snapshot().Generation; got != "gen-a" {
		t.Fatalf("recovered state generation = %q, want %q", got, "gen-a")
	}

	// Strict delete still finds, verifies, and retires the persisted
	// incarnation rather than reporting it missing.
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-a"); err != nil {
		t.Fatal(err)
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)

	// After a confirmed retirement nothing is left, so a repeated strict
	// delete must fail instead of fabricating a second proof.
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-a"); !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("repeat strict delete = %v, want ErrNotFound", err)
	}
}
