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
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// The tests in this file pin the zero-witness abort retirement and the
// instance-state-driven abort handback: a validated state whose checkpoint
// operation witness is exactly zero retires an identified operation with NO
// source effect when — and only when — every positive gate holds, and the
// intent/aborting handback resumes exactly a Paused source exactly once.

// zeroWitnessAbortFixture builds a live configured fixture whose durable
// witness is exactly zero — the shape a crash between the directory claim and
// the intent persistence (or a failed intent write) leaves — plus the binding
// carrying the canonical output directory the service now supplies.
func zeroWitnessAbortFixture(
	t *testing.T,
	generation string,
) (*Handler, *firecrackerInstance, *fakeFirecrackerAPI, *fakeCheckpointAgent, string, string, runtimecore.CheckpointOperationBinding) {
	t.Helper()
	handler, instance, api, sandboxID := checkpointOperationFixture(t, generation)
	agent := pointFixtureVsockAtAgent(t, handler, instance)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	binding := testCheckpointOperationBinding(generation)
	binding.CheckpointDir = directory
	return handler, instance, api, agent, sandboxID, directory, binding
}

// nowitnessStateFile is the durable state file of the fixture's incarnation.
func nowitnessStateFile(state firecrackerPersistedState) string {
	return filepath.Join(state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
}

// makeZeroWitnessCold models the restarted daemon: the fixture's durable
// state is republished under a sandbox root the handler actually consults,
// the in-memory instance map is dropped, and the cold bundle path is
// returned for durable-state reads and byte-exact refusal proofs.
func makeZeroWitnessCold(
	t *testing.T,
	handler *Handler,
	instance *firecrackerInstance,
) string {
	t.Helper()
	state := instance.snapshot()
	root := t.TempDir()
	bundle := filepath.Join(root, state.ID)
	if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	coldState := state
	coldState.BundlePath = bundle
	if err := writeFirecrackerState(coldState); err != nil {
		t.Fatal(err)
	}
	handler.sandboxRoot = root
	handler.mu.Lock()
	handler.instances = make(map[string]*firecrackerInstance)
	handler.mu.Unlock()
	return bundle
}

// assertZeroWitnessRetired proves the complete no-effect retirement contract:
// a schema-valid version-3 aborted witness bound to the live birth and the
// exact claimed directory, zero resumes, pauses, snapshots, guest messages,
// and lineage mutations, and the retained claim tombstone.
func assertZeroWitnessRetired(
	t *testing.T,
	handler *Handler,
	api *fakeFirecrackerAPI,
	agent *fakeCheckpointAgent,
	binding runtimecore.CheckpointOperationBinding,
	directory string,
	before firecrackerPersistedState,
	bundlePath string,
	includeLineage bool,
) {
	t.Helper()
	disk, readErr := readFirecrackerState(bundlePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	record := disk.CheckpointOperation
	if record.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after zero-witness abort = %q, want aborted", record.Phase)
	}
	if record.Version != firecrackerCheckpointOperationRecordVersion3 {
		t.Fatalf("retired witness version = %d, want 3", record.Version)
	}
	if record.SandboxID != before.ID ||
		record.OperationID != binding.OperationID ||
		record.RequestDigest != binding.RequestDigest ||
		record.SourceGeneration != before.Generation {
		t.Fatalf("retired witness binds the wrong identity: %+v", record)
	}
	if record.VMMPID != before.PID || record.VMMAPIPath != before.APIPath {
		t.Fatalf("retired witness froze the wrong source birth: %+v", record)
	}
	if record.Directory != directory {
		t.Fatalf("retired witness records directory %q, want %q", record.Directory, directory)
	}
	if record.RootDigest != "" || record.RootScheme != "" {
		t.Fatalf("retired witness must carry no root: %+v", record)
	}
	dev, inode := claimTestDirectoryStats(t, directory)
	if record.DirectoryDev != dev || record.DirectoryInode != inode {
		t.Fatalf("retired witness directory identity drifted: record (%d,%d) live (%d,%d)",
			record.DirectoryDev, record.DirectoryInode, dev, inode)
	}
	assertClaimBeside(t, directory, before.ID, binding, dev, inode)
	// No source or guest effect of any kind.
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("zero-witness abort resumed the source %d times", resumes)
	}
	if pauses := api.countVMState("Paused"); pauses != 0 {
		t.Fatalf("zero-witness abort paused the source %d times", pauses)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 0 {
		t.Fatalf("zero-witness abort took %d snapshots", snapshots)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("zero-witness abort released the guest: %+v", observations)
	}
	if includeLineage && disk.BaseMemoryLineageLost {
		t.Fatal("zero-witness abort mutated the incremental lineage")
	}
}

// TestAbortCheckpointOperationZeroWitnessRetiresMissingDirectory proves the
// hot zero-witness retirement over a MISSING output directory: the exact
// claim is established, the aborted fact is durable, nothing else happens,
// and the evidence gate releases only through the abort acknowledgment.
func TestAbortCheckpointOperationZeroWitnessRetiresMissingDirectory(t *testing.T) {
	handler, instance, api, agent, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("zero-witness abort over a missing directory = %v", err)
	}
	assertZeroWitnessRetired(t, handler, api, agent, binding, directory, before, before.BundlePath, true)
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)

	// The success recovery must not turn a zero-witness shape into success:
	// an aborted operation is a phase of the abort protocol.
	if _, err := handler.RecoverCheckpointOperation(context.Background(), sandboxID, binding); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("recover after zero-witness abort = %v, want ErrFailedPrecondition", err)
	}
	// The evidence gate holds: no new checkpoint, no delete, until the
	// abort-side acknowledgment releases it.
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint-retry"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("checkpoint after zero-witness abort = %v, want the evidence gate", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after zero-witness abort = %v, want the evidence gate", err)
	}
	// The idempotent retry re-persists the same fact and stays effect-free.
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("idempotent zero-witness abort replay = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("abort replay resumed the source %d times", resumes)
	}
	if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort acknowledgment = %v", err)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAbortAcked {
		t.Fatalf("durable phase after abort ack = %+v %v", disk.CheckpointOperation, readErr)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete after abort ack = %v", err)
	}
}

// TestAbortCheckpointOperationZeroWitnessRetiresEmptyAndClaimOnly proves the
// same retirement over an EMPTY reserved directory and over an EXACT
// claim-only directory — the re-entry keeps the existing tombstone untouched
// — including from a cold daemon.
func TestAbortCheckpointOperationZeroWitnessRetiresEmptyAndClaimOnly(t *testing.T) {
	for _, shape := range []struct {
		name string
		cold bool
		seed func(t *testing.T, directory, sandboxID string, binding runtimecore.CheckpointOperationBinding)
	}{
		{name: "empty directory hot"},
		{name: "empty directory cold", cold: true, seed: func(t *testing.T, directory, _ string, _ runtimecore.CheckpointOperationBinding) {
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "exact claim-only hot", seed: func(t *testing.T, directory, sandboxID string, binding runtimecore.CheckpointOperationBinding) {
			if _, _, err := claimFirecrackerCheckpointDirectory(directory, sandboxID, binding); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "exact claim-only cold", cold: true, seed: func(t *testing.T, directory, sandboxID string, binding runtimecore.CheckpointOperationBinding) {
			if _, _, err := claimFirecrackerCheckpointDirectory(directory, sandboxID, binding); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			handler, instance, api, agent, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
			before := instance.snapshot()
			bundlePath := before.BundlePath
			if shape.seed != nil {
				shape.seed(t, directory, sandboxID, binding)
			}
			if shape.cold {
				bundlePath = makeZeroWitnessCold(t, handler, instance)
			}
			if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
				t.Fatalf("zero-witness abort (%s) = %v", shape.name, err)
			}
			// The cold path's instance recovery legitimately resets the
			// incremental lineage before the retirement runs; the retirement
			// itself must add nothing beyond the aborted fact.
			assertZeroWitnessRetired(t, handler, api, agent, binding, directory, before, bundlePath, !shape.cold)
			if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
				t.Fatalf("abort acknowledgment = %v", err)
			}
		})
	}
}

// TestZeroWitnessSuccessPathsStayUnavailable proves the new retirement is
// exclusive to Abort: an operation with no runtime witness can never be
// recovered as a success or success-acknowledged, even when its service
// binding carries a canonical checkpoint directory.
func TestZeroWitnessSuccessPathsStayUnavailable(t *testing.T) {
	handler, instance, api, agent, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
	before := instance.snapshot()

	if _, err := handler.RecoverCheckpointOperation(context.Background(), sandboxID, binding); !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("recover of a zero-witness operation = %v, want NotFound", err)
	}
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, binding); !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("success acknowledgment of a zero-witness operation = %v, want NotFound", err)
	}
	if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("success paths touched the output directory: %v", statErr)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || !disk.CheckpointOperation.isZero() {
		t.Fatalf("success paths wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
	}
	if api.countSnapshotCreates() != 0 || api.countVMState("Paused") != 0 ||
		api.countVMState("Resumed") != 0 || len(agent.abortObservations()) != 0 {
		t.Fatal("a zero-witness success path produced a source or guest effect")
	}
}

// TestAbortCheckpointOperationZeroWitnessRefusals pins every refusal shape:
// each refuses WITHOUT writing a witness, and the directory-touching gates
// leave the output untouched when they fire before the claim.
func TestAbortCheckpointOperationZeroWitnessRefusals(t *testing.T) {
	t.Run("empty binding directory keeps the historical NotFound", func(t *testing.T) {
		handler, instance, api, _, sandboxID, _, binding := zeroWitnessAbortFixture(t, "gen-live")
		binding.CheckpointDir = ""
		before := instance.snapshot()

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrNotFound) ||
			!containsAll(err.Error(), "retains no checkpoint operation witness") {
			t.Fatalf("abort without a binding directory = %v, want the historical NotFound", err)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
		if resumes := api.countVMState("Resumed"); resumes != 0 {
			t.Fatalf("refusal resumed the source %d times", resumes)
		}
	})
	t.Run("noncanonical binding directory keeps the historical NotFound", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		for _, dir := range []string{"relative/checkpoint", directory + "/../elsewhere"} {
			binding.CheckpointDir = dir
			if canonicalCheckpointOperationBindingDir(dir) != "" {
				t.Fatalf("test directory %q unexpectedly canonical", dir)
			}
			err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
			if !errors.Is(err, errord.ErrNotFound) {
				t.Fatalf("abort with noncanonical binding directory %q = %v, want NotFound", dir, err)
			}
		}
		disk, readErr := readFirecrackerState(instance.snapshot().BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
	t.Run("cold generation mismatch refuses without any recovery side effect", func(t *testing.T) {
		handler, instance, _, _, sandboxID, _, binding := zeroWitnessAbortFixture(t, "gen-live")
		binding.SourceGeneration = "gen-other"
		statePath := filepath.Join(makeZeroWitnessCold(t, handler, instance), firecrackerArtifactsDir, firecrackerStateFilename)
		beforeBytes, readErr := os.ReadFile(statePath)
		if readErr != nil {
			t.Fatal(readErr)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("cold abort with a mismatched generation = %v, want ErrFailedPrecondition", err)
		}
		// Pure refusal: the durable bytes are untouched and the handler map
		// stays empty — no lineage reset, no monitors, no recorded-process
		// stop from recoverState.
		afterBytes, readErr := os.ReadFile(statePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(beforeBytes) != string(afterBytes) {
			t.Fatal("generation-mismatch refusal rewrote the durable state")
		}
		handler.mu.RLock()
		mapped := len(handler.instances)
		handler.mu.RUnlock()
		if mapped != 0 {
			t.Fatalf("generation-mismatch refusal mapped %d instances", mapped)
		}
	})
	t.Run("missing runtime state is NotFound", func(t *testing.T) {
		handler, instance, _, _, sandboxID, _, binding := zeroWitnessAbortFixture(t, "gen-live")
		statePath := filepath.Join(makeZeroWitnessCold(t, handler, instance), firecrackerArtifactsDir, firecrackerStateFilename)
		if err := os.Remove(statePath); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrNotFound) || !containsAll(err.Error(), "has no runtime state") {
			t.Fatalf("abort without runtime state = %v, want NotFound", err)
		}
	})
	t.Run("corrupt runtime state refuses", func(t *testing.T) {
		handler, instance, _, _, sandboxID, _, binding := zeroWitnessAbortFixture(t, "gen-live")
		statePath := filepath.Join(makeZeroWitnessCold(t, handler, instance), firecrackerArtifactsDir, firecrackerStateFilename)
		if err := os.WriteFile(statePath, []byte("{not json"), 0600); err != nil {
			t.Fatal(err)
		}

		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err == nil {
			t.Fatal("abort with corrupt runtime state unexpectedly retired")
		}
	})
	t.Run("dead source refuses before touching the directory", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		killCheckpointChild(t, before.PID)

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("abort with a dead source = %v, want ErrFailedPrecondition", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("dead-source refusal touched the output directory: %v", statErr)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
	t.Run("paused source refuses before touching the directory", func(t *testing.T) {
		handler, instance, api, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		if err := api.pause(); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "is Paused, not Running") {
			t.Fatalf("abort with a paused source = %v, want the not-Running refusal", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("paused-source refusal touched the output directory: %v", statErr)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
	t.Run("not-started source refuses", func(t *testing.T) {
		handler, _, api, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		api.forceVMState(firecrackerInstanceInfoStateNotStarted)

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "is Not started, not Running") {
			t.Fatalf("abort with a not-started source = %v, want the not-Running refusal", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("not-started refusal touched the output directory: %v", statErr)
		}
	})
	t.Run("unreadable instance state refuses", func(t *testing.T) {
		handler, _, api, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		api.setInstanceInfoFailure(true)

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "refusing to decide from an unreadable source state") {
			t.Fatalf("abort with an unreadable instance state = %v", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("unreadable-state refusal touched the output directory: %v", statErr)
		}
	})
	t.Run("foreign instance id refuses", func(t *testing.T) {
		handler, instance, api, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		api.setInstanceID("a-different-sandbox")

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "reports instance id a-different-sandbox") {
			t.Fatalf("abort with a foreign instance id = %v, want identity refusal", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("foreign-id refusal touched the output directory: %v", statErr)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("foreign-id refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
	t.Run("foreign claim refuses and is retained", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		foreign := testCheckpointOperationBinding("gen-live")
		foreign.OperationID = "op-foreign"
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, sandboxID, foreign); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "a different binding never re-enters it") {
			t.Fatalf("abort over a foreign claim = %v, want the foreign-claim refusal", err)
		}
		claim, readErr := readFirecrackerCheckpointClaim(directory)
		if readErr != nil || claim.OperationID != "op-foreign" {
			t.Fatalf("foreign claim was not retained: %+v %v", claim, readErr)
		}
		disk, stateErr := readFirecrackerState(before.BundlePath)
		if stateErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, stateErr)
		}
	})
	t.Run("corrupt claim refuses and is retained", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, firecrackerCheckpointClaimName()),
			[]byte("{half-written"), 0600,
		); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("abort over a corrupt claim = %v, want ErrFailedPrecondition", err)
		}
		disk, stateErr := readFirecrackerState(before.BundlePath)
		if stateErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, stateErr)
		}
	})
	t.Run("symlinked claim refuses", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "claim-target")
		if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, firecrackerCheckpointClaimName())); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "symbolic link") {
			t.Fatalf("abort over a symlinked claim = %v, want the symlink refusal", err)
		}
		disk, stateErr := readFirecrackerState(before.BundlePath)
		if stateErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, stateErr)
		}
	})
	t.Run("claim with stray entries refuses and is retained", func(t *testing.T) {
		handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
		before := instance.snapshot()
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, sandboxID, binding); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "memory.img"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) ||
			!containsAll(err.Error(), "not exactly claim-only") {
			t.Fatalf("abort over a stray-holding claim = %v, want the claim-only refusal", err)
		}
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 2 {
			t.Fatalf("refusal changed the directory contents: %d %v", len(entries), readErr)
		}
		disk, stateErr := readFirecrackerState(before.BundlePath)
		if stateErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, stateErr)
		}
	})
}

// TestAbortCheckpointOperationZeroWitnessPersistFailureRetries proves the
// ambiguous-persist discipline of the retirement: a failed witness write
// leaves the durable record empty, the claim tombstone retained, and this
// daemon's evidence gate in force; the retry re-persists before success.
func TestAbortCheckpointOperationZeroWitnessPersistFailureRetries(t *testing.T) {
	handler, instance, _, _, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
	before := instance.snapshot()
	makeStateDirUnwritable(t, instance)

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if err == nil || !containsAll(err.Error(), "persist the aborted witness") {
		t.Fatalf("zero-witness abort must fail on the durable write: %v", err)
	}
	if !containsAll(err.Error(), "the directory claim is retained") {
		t.Fatalf("failure must report the retained claim honestly: %v", err)
	}
	// The claim is durable; the witness is not.
	if _, statErr := os.Stat(filepath.Join(directory, firecrackerCheckpointClaimName())); statErr != nil {
		t.Fatalf("claim tombstone missing after a failed persist: %v", statErr)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || !disk.CheckpointOperation.isZero() {
		t.Fatalf("failed persist still wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
	}
	if !instance.snapshot().CheckpointOperation.retainsEvidence() {
		t.Fatal("failed persist released the in-memory evidence gate")
	}

	makeStateDirWritable(instance)
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("zero-witness abort retry after repair = %v", err)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after retry = %+v %v", disk.CheckpointOperation, readErr)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 ||
		entries[0].Name() != firecrackerCheckpointClaimName() {
		t.Fatalf("retry left %d entries beside the claim: %v", len(entries), readErr)
	}
}

// TestAbortCheckpointOperationZeroWitnessConcurrentSingleFact proves the
// operation lock serializes concurrent retirements into exactly one aborted
// fact with one claim and no duplicated effect.
func TestAbortCheckpointOperationZeroWitnessConcurrentSingleFact(t *testing.T) {
	handler, instance, api, agent, sandboxID, directory, binding := zeroWitnessAbortFixture(t, "gen-live")
	before := instance.snapshot()

	const callers = 4
	done := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() { done <- handler.AbortCheckpointOperation(context.Background(), sandboxID, binding) }()
	}
	for i := 0; i < callers; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent zero-witness abort = %v", err)
		}
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after concurrent aborts = %+v %v", disk.CheckpointOperation, readErr)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("concurrent aborts resumed the source %d times", resumes)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("concurrent aborts released the guest: %+v", observations)
	}
	if entries, readErr := os.ReadDir(directory); readErr != nil || len(entries) != 1 {
		t.Fatalf("concurrent aborts left %d entries: %v", len(entries), readErr)
	}
}

// --- the binding-directory contract of the initial checkpoint ---

// TestCheckpointOperationBindingDirectoryContract pins the initial-checkpoint
// agreement check: the empty binding directory of older internal callers
// constrains nothing, and a nonempty disagreement is refused before the claim
// or any side effect.
func TestCheckpointOperationBindingDirectoryContract(t *testing.T) {
	t.Run("empty binding directory stays unconstrained", func(t *testing.T) {
		handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		binding := testCheckpointOperationBinding("gen-live")

		if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
			ID:        sandboxID,
			Directory: directory,
			Operation: binding,
		}); err != nil {
			t.Fatalf("identified checkpoint with an empty binding directory = %v", err)
		}
		disk, readErr := readFirecrackerState(instance.snapshot().BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted {
			t.Fatalf("durable phase = %+v %v", disk.CheckpointOperation, readErr)
		}
		if pauses := api.countVMState("Paused"); pauses != 1 {
			t.Fatalf("empty binding directory changed the checkpoint flow: %d pauses", pauses)
		}
	})
	t.Run("disagreeing binding directory is refused before any effect", func(t *testing.T) {
		handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		binding := testCheckpointOperationBinding("gen-live")
		binding.CheckpointDir = filepath.Join(t.TempDir(), "the-admitted-directory")

		err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
			ID:        sandboxID,
			Directory: directory,
			Operation: binding,
		})
		if !errors.Is(err, errord.ErrInvalidArgument) ||
			!containsAll(err.Error(), "binds checkpoint directory") {
			t.Fatalf("checkpoint with a disagreeing binding directory = %v", err)
		}
		for _, dir := range []string{directory, binding.CheckpointDir} {
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("refusal touched %s: %v", dir, statErr)
			}
		}
		if pauses := api.countVMState("Paused"); pauses != 0 {
			t.Fatalf("refusal paused the source %d times", pauses)
		}
		disk, readErr := readFirecrackerState(instance.snapshot().BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
	t.Run("noncanonical binding directory is refused before any effect", func(t *testing.T) {
		handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		binding := testCheckpointOperationBinding("gen-live")
		binding.CheckpointDir = filepath.Dir(directory) + "/./checkpoint"

		err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
			ID:        sandboxID,
			Directory: directory,
			Operation: binding,
		})
		if !errors.Is(err, errord.ErrInvalidArgument) ||
			!containsAll(err.Error(), "not the canonical output") {
			t.Fatalf("checkpoint with a noncanonical binding directory = %v", err)
		}
		if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
			t.Fatalf("refusal touched %s: %v", directory, statErr)
		}
		if pauses := api.countVMState("Paused"); pauses != 0 {
			t.Fatalf("refusal paused the source %d times", pauses)
		}
		disk, readErr := readFirecrackerState(instance.snapshot().BundlePath)
		if readErr != nil || !disk.CheckpointOperation.isZero() {
			t.Fatalf("refusal wrote a witness: %+v %v", disk.CheckpointOperation, readErr)
		}
	})
}

// --- the instance-state-driven handback of the intent/aborting phases ---

// TestAbortCheckpointOperationRunningIntentSkipsResume pins the pre-pause
// crash window: a durable intent whose source is STILL Running is released
// with no resume request at all — resuming a running MicroVM is an error —
// through the same idempotent guest abort and durable aborted fact.
func TestAbortCheckpointOperationRunningIntentSkipsResume(t *testing.T) {
	// The fixture models the post-pause crash (intent + Paused); force the
	// Running state to model the window between the intent persistence and
	// the pause request instead.
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	api.forceVMState(firecrackerInstanceInfoStateRunning)
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort of a running-source intent = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("running-source abort resumed %d times, want 0", resumes)
	}
	if state := api.currentVMState(); state != firecrackerInstanceInfoStateRunning {
		t.Fatalf("instance state after abort = %q, want Running", state)
	}
	assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase = %+v %v", disk.CheckpointOperation, readErr)
	}
	if !disk.BaseMemoryLineageLost {
		t.Fatal("intent abort did not invalidate the incremental lineage")
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
}

// TestAbortCheckpointOperationUnknownVMStateRefuses proves a MicroVM state
// outside Paused/Running refuses the handback with the aborting evidence
// retained, and the retry completes once the state becomes legal again.
func TestAbortCheckpointOperationUnknownVMStateRefuses(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	api.forceVMState("Halting")

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if err == nil || !containsAll(err.Error(), "unknown MicroVM state") {
		t.Fatalf("abort with an unknown MicroVM state = %v, want the unknown-state refusal", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("unknown-state abort resumed %d times", resumes)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("unknown-state abort released the guest: %+v", observations)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
		t.Fatalf("durable phase after refusal = %+v %v", disk.CheckpointOperation, readErr)
	}

	// The same decision retries to completion once the state is legal.
	api.forceVMState(firecrackerInstanceInfoStatePaused)
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort retry after the state cleared = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("abort retry resumed %d times, want exactly 1", resumes)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after retry = %+v %v", disk.CheckpointOperation, readErr)
	}
}

// TestAbortCheckpointOperationInstanceInfoFailureRefuses proves a GET /
// failure refuses the handback the same fail-closed way, with the evidence
// retained and a working retry.
func TestAbortCheckpointOperationInstanceInfoFailureRefuses(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	api.setInstanceInfoFailure(true)

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if err == nil || !containsAll(err.Error(), "read the Firecracker instance state") {
		t.Fatalf("abort with a failing GET / = %v, want the state-read refusal", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("failing-GET abort resumed %d times", resumes)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("failing-GET abort released the guest: %+v", observations)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
		t.Fatalf("durable phase after refusal = %+v %v", disk.CheckpointOperation, readErr)
	}

	api.setInstanceInfoFailure(false)
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort retry after GET / recovered = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("abort retry resumed %d times, want exactly 1", resumes)
	}
}

// TestAbortCheckpointOperationForeignInstanceIDRefuses proves an API socket
// belonging to another MicroVM cannot authorize handback of an intent-bound
// source, even when the recorded PID birth is still live.
func TestAbortCheckpointOperationForeignInstanceIDRefuses(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	api.setInstanceID("a-different-sandbox")

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if !errors.Is(err, errord.ErrFailedPrecondition) ||
		!containsAll(err.Error(), "reports instance id a-different-sandbox") {
		t.Fatalf("intent abort with a foreign instance id = %v, want identity refusal", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("foreign-id abort resumed the source %d times", resumes)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("foreign-id abort released the guest: %+v", observations)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
		t.Fatalf("durable phase after identity refusal = %+v %v", disk.CheckpointOperation, readErr)
	}
}
