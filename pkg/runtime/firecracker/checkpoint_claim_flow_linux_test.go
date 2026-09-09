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
	"syscall"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// assertClaimBeside checks the output directory holds exactly the sealed
// artifact plus the claim tombstone, and the tombstone binds the exact
// operation and directory identity the witness records.
func assertClaimBeside(
	t *testing.T,
	directory string,
	sandboxID string,
	binding runtimecore.CheckpointOperationBinding,
	dev, inode uint64,
) {
	t.Helper()
	claim, err := readFirecrackerCheckpointClaim(directory)
	if err != nil {
		t.Fatalf("output directory carries no usable claim: %v", err)
	}
	if claim.SandboxID != sandboxID || claim.OperationID != binding.OperationID ||
		claim.RequestDigest != binding.RequestDigest ||
		claim.SourceGeneration != binding.SourceGeneration ||
		claim.Directory != directory ||
		claim.DirectoryDev != dev || claim.DirectoryInode != inode {
		t.Fatalf("claim drifted from the operation binding: %+v", claim)
	}
}

// TestCheckpointOperationClaimPrecedesIntentAndAllSideEffects is the
// observable ordering proof of the claim boundary: with the intent
// persistence made to fail, the durable claim is already complete on disk
// while NO side effect has run — no pause, no snapshot, no guest interaction,
// no component file, no durable witness. The flow is sequential, so claim <
// intent persistence < every later side effect follows from this observation
// without any timing.
func TestCheckpointOperationClaimPrecedesIntentAndAllSideEffects(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	agent := pointFixtureVsockAtAgent(t, handler, instance)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	makeStateDirUnwritable(t, instance)

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if !containsAll(err.Error(), "persist checkpoint operation intent") {
		t.Fatalf("failure must land on the intent write, after the claim: %v", err)
	}
	// The claim is complete and durable: exactly one entry, the full exact
	// binding, and the directory birth identity it records is real.
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != firecrackerCheckpointClaimName() {
		t.Fatalf("claimed output must hold exactly the claim before the intent: %d entries %v", len(entries), readErr)
	}
	dev, inode := claimTestDirectoryStats(t, directory)
	assertClaimBeside(t, directory, sandboxID, testCheckpointOperationBinding("gen-live"), dev, inode)
	// Zero side effects of any kind: no pause, no snapshot, no guest message.
	if pauses := api.countVMState("Paused"); pauses != 0 {
		t.Fatalf("claim acquisition paused the source %d times", pauses)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 0 {
		t.Fatalf("claim acquisition took %d snapshots", snapshots)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("claim acquisition touched the guest: %+v", observations)
	}
	if outcomes := agent.checkpointOutcomes(); len(outcomes) != 0 {
		t.Fatalf("claim acquisition sent a legacy guest message: %v", outcomes)
	}
	// No witness reached the disk, and the source is untouched.
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || !disk.CheckpointOperation.isZero() {
		t.Fatalf("failed intent write left a durable witness: %+v %v", disk.CheckpointOperation, readErr)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
	makeStateDirWritable(instance)
}

// TestCheckpointOperationLayoutGateRefusesDriftedClaimBeforeComponents is the
// finding-7 regression: the ownership gate runs immediately before the first
// layout/component side effect, so a claim deleted, replaced by a foreign
// binding, or a directory replaced between the durable intent and the layout
// refuses the checkpoint with ZERO components written, zero pauses, and zero
// snapshots. The window is injected through the deterministic
// post-intent seam; the gate's protection is TOCTOU-bounded to the window
// before the component writes, which are name-based O_EXCL creations.
func TestCheckpointOperationLayoutGateRefusesDriftedClaimBeforeComponents(t *testing.T) {
	binding := testCheckpointOperationBinding("gen-live")
	for _, tc := range []struct {
		name     string
		mutate   func(t *testing.T, directory string)
		fragment string
	}{
		{
			name: "claim deleted",
			mutate: func(t *testing.T, directory string) {
				if err := os.Remove(filepath.Join(directory, firecrackerCheckpointClaimName())); err != nil {
					t.Fatal(err)
				}
			},
			fragment: "claim cannot be verified",
		},
		{
			name: "claim replaced by a foreign binding",
			mutate: func(t *testing.T, directory string) {
				dev, inode := claimTestDirectoryStats(t, directory)
				writeClaimJSON(t, directory, firecrackerCheckpointClaim{
					Version:          firecrackerCheckpointClaimVersion,
					SandboxID:        "sandbox-usurper",
					OperationID:      "op-usurper",
					RequestDigest:    claimTestDigest("op-usurper"),
					SourceGeneration: binding.SourceGeneration,
					Directory:        directory,
					DirectoryDev:     dev,
					DirectoryInode:   inode,
				})
			},
			fragment: "is now claimed by",
		},
		{
			name: "directory replaced",
			mutate: func(t *testing.T, directory string) {
				if err := os.Rename(directory, directory+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			},
			fragment: "a replaced output directory is never reconciled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
			directory := filepath.Join(t.TempDir(), "checkpoint")
			before := instance.snapshot()
			fd := checkpointTestPidfd(t, before.PID)
			handler.onCheckpointIntentDurable = func(string) { tc.mutate(t, directory) }
			t.Cleanup(func() { handler.onCheckpointIntentDurable = nil })

			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
				ID:        sandboxID,
				Directory: directory,
				Operation: binding,
			})
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("drifted claim at the layout gate = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), "before layout", tc.fragment) {
				t.Fatalf("refusal must name the layout gate and the boundary: %v", err)
			}
			// The gate precedes every component side effect.
			if pauses := api.countVMState("Paused"); pauses != 0 {
				t.Fatalf("refused layout paused the source %d times", pauses)
			}
			if snapshots := api.countSnapshotCreates(); snapshots != 0 {
				t.Fatalf("refused layout took %d snapshots", snapshots)
			}
			for _, component := range []string{
				firecrackerCheckpointStateName,
				firecrackerCheckpointMemoryName,
				firecrackerCheckpointOverlayName,
			} {
				if _, statErr := os.Lstat(filepath.Join(directory, component)); statErr == nil {
					t.Fatalf("refused layout created component %s", component)
				}
			}
			// The durable intent exists (the gate runs after it), and the
			// source is untouched.
			disk, readErr := readFirecrackerState(before.BundlePath)
			if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
				t.Fatalf("durable witness = %+v %v, want the intent", disk.CheckpointOperation, readErr)
			}
			assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
		})
	}
}

// TestCheckpointOperationClaimTombstoneSurvivesSuccessAndRetirement proves
// the claim is ownership metadata of the SOURCE directory, not artifact
// content: it survives the completed operation, the success acknowledgment,
// and the sandbox's retirement unchanged, and the sealed artifact beside it
// still binds its content root through the shared algorithm that excludes
// the claim.
func TestCheckpointOperationClaimTombstoneSurvivesSuccessAndRetirement(t *testing.T) {
	handler, _, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	binding := testCheckpointOperationBinding("gen-live")

	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: directory,
		Operation: binding,
	}); err != nil {
		t.Fatal(err)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("checkpoint took %d snapshots, want 1", snapshots)
	}
	dev, inode := claimTestDirectoryStats(t, directory)
	assertClaimBeside(t, directory, sandboxID, binding, dev, inode)
	tombstone, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatal(err)
	}
	// The claim is outside the content root: the sealed directory binds.
	if _, err := checkpointroot.Bind(directory); err != nil {
		t.Fatalf("sealed artifact with its claim tombstone no longer binds: %v", err)
	}

	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("ack = %v", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatalf("claim tombstone did not survive success, ack, and retirement: %v", err)
	}
	if string(after) != string(tombstone) {
		t.Fatalf("retirement rewrote the claim tombstone:\nbefore: %s\nafter:  %s", tombstone, after)
	}
}

// TestCheckpointOperationClaimTombstoneSurvivesAbortAndAbortAck proves the
// same tombstone semantics on the abort side: an aborted operation leaves its
// claim in place through the abort and the abort acknowledgment.
func TestCheckpointOperationClaimTombstoneSurvivesAbortAndAbortAck(t *testing.T) {
	handler, _, _, agent, sandboxID, directory := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	tombstone, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatal(err)
	}

	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort = %v", err)
	}
	if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("ack aborted = %v", err)
	}
	if observations := agent.abortObservations(); len(observations) != 1 {
		t.Fatalf("abort observations = %+v, want exactly one", observations)
	}
	after, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatalf("claim tombstone did not survive the abort path: %v", err)
	}
	if string(after) != string(tombstone) {
		t.Fatalf("abort rewrote the claim tombstone:\nbefore: %s\nafter:  %s", tombstone, after)
	}
}

// coldClaimIntentFixture persists an incarnation with a durable VERSION-3
// claim-bound intent witness under a handler whose in-memory map is empty.
// The recorded directory must hold the same-operation seal (and its claim)
// produced by the real flow, so the cold reconciliation exercises exactly the
// claim-bound recovery path; mutateRecord lets a test drift the record.
func coldClaimIntentFixture(
	t *testing.T,
	sealedDirectory string,
	mutateRecord func(*firecrackerCheckpointOperationRecord),
) (*Handler, string, func() []byte, firecrackerPersistedState) {
	t.Helper()
	handler := &Handler{
		sandboxRoot: t.TempDir(),
		storageRoot: t.TempDir(),
		instances:   make(map[string]*firecrackerInstance),
	}
	// A short runtime root keeps the sandbox-derived socket paths under the
	// kernel's unix name limit regardless of the test's temporary root.
	shortRuntimeRoot, err := os.MkdirTemp(os.TempDir(), "fcop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortRuntimeRoot) })
	handler.runtimeRoot = shortRuntimeRoot
	kernel := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.kernelPath = kernel
	// The sealing fixture's sandbox identity: the claim inside the sealed
	// directory binds it, and a version-3 witness must restate it.
	const sandboxID = "persist-test"
	runtimeDir := handler.runtimeDirectory(sandboxID)
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	overlayDir := filepath.Join(handler.storageRoot, sandboxID)
	if err := os.Mkdir(overlayDir, 0700); err != nil {
		t.Fatal(err)
	}
	apiPath := filepath.Join(runtimeDir, firecrackerAPISocket)
	command := startColdCheckpointChild(t, handler, apiPath, sandboxID)
	startTime, err := readFirecrackerProcessStartTime(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := readFirecrackerBootID()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(sealedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no unix directory identity")
	}
	binding := testCheckpointOperationBinding("gen-live")
	state := firecrackerPersistedState{
		ID:          sandboxID,
		PID:         command.Process.Pid,
		BundlePath:  filepath.Join(handler.sandboxRoot, sandboxID),
		APIPath:     apiPath,
		VsockPath:   filepath.Join(runtimeDir, firecrackerVsock),
		OverlayPath: filepath.Join(overlayDir, "overlay.ext4"),
		Generation:  binding.SourceGeneration,
		MemoryMiB:   512,
		Vcpus:       2,
		Configured:  true,
		CheckpointOperation: firecrackerCheckpointOperationRecord{
			Version:          firecrackerCheckpointOperationRecordVersion3,
			Phase:            firecrackerCheckpointOperationPhaseIntent,
			OperationID:      binding.OperationID,
			RequestDigest:    binding.RequestDigest,
			SourceGeneration: binding.SourceGeneration,
			SandboxID:        sandboxID,
			Directory:        sealedDirectory,
			DirectoryDev:     uint64(stat.Dev),
			DirectoryInode:   stat.Ino,
			VMMPID:           command.Process.Pid,
			VMMStartTime:     startTime,
			VMMBootID:        bootID,
			VMMAPIPath:       apiPath,
		},
	}
	if mutateRecord != nil {
		mutateRecord(&state.CheckpointOperation)
	}
	if err := os.MkdirAll(
		filepath.Join(state.BundlePath, firecrackerArtifactsDir), 0700,
	); err != nil {
		t.Fatal(err)
	}
	if err := handler.persistInstance(&firecrackerInstance{
		state: state, done: make(chan struct{}),
	}); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(
		state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	return handler, sandboxID, func() []byte {
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}, state
}

// TestRecoverCheckpointOperationClaimBoundIntentPromotesFromOwnSeal drives
// the cold reconciliation of a version-3 claim-bound intent whose recorded
// directory holds the same operation's sealed artifact and claim: the
// promotion completes the original stop with the claim verified on the cold
// path, and the completion keeps the claim-bound identity.
func TestRecoverCheckpointOperationClaimBoundIntentPromotesFromOwnSeal(t *testing.T) {
	sealedDir, _, _ := sealIdentifiedCheckpointArtifactBinding(t, "gen-live")
	handler, sandboxID, readState, state := coldClaimIntentFixture(t, sealedDir, nil)
	before := readState()

	completion, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err != nil {
		t.Fatalf("cold claim-bound recovery = %v", err)
	}
	root, bindErr := checkpointroot.Bind(sealedDir)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	if completion.RootDigest != root.RootDigest || completion.RootScheme != root.Scheme {
		t.Fatalf("recovered root %s (%s), want the sealed root %s (%s)",
			completion.RootDigest, completion.RootScheme, root.RootDigest, root.Scheme)
	}
	disk, readErr := readFirecrackerState(state.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted {
		t.Fatalf("durable phase after claim-bound recovery = %+v %v", disk.CheckpointOperation, readErr)
	}
	completed := disk.CheckpointOperation
	if completed.Version != firecrackerCheckpointOperationRecordVersion3 ||
		completed.SandboxID != state.CheckpointOperation.SandboxID {
		t.Fatalf("completion dropped the claim-bound identity: %+v", completed)
	}
	if after := readState(); string(before) == string(after) {
		t.Fatal("recovery did not durably promote the intent")
	}
	handler.mu.RLock()
	recovered := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if recovered != nil {
		recovered.markDeleting()
	}
}

// TestRecoverCheckpointOperationClaimBoundIntentRefusesDriftedClaim proves
// the cold claim-bound reconciliation fails closed on a deleted, replaced,
// or foreign claim before any recovery side effect — the durable record is
// untouched and nothing is mapped or signalled.
func TestRecoverCheckpointOperationClaimBoundIntentRefusesDriftedClaim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutateDir func(t *testing.T, sealedDir string)
		fragments []string
	}{
		{
			name: "claim deleted",
			mutateDir: func(t *testing.T, sealedDir string) {
				if err := os.Remove(filepath.Join(sealedDir, firecrackerCheckpointClaimName())); err != nil {
					t.Fatal(err)
				}
			},
			fragments: []string{"claim cannot be verified"},
		},
		{
			name: "claim replaced by a usurper",
			mutateDir: func(t *testing.T, sealedDir string) {
				dev, inode := claimTestDirectoryStats(t, sealedDir)
				writeClaimJSON(t, sealedDir, firecrackerCheckpointClaim{
					Version:          firecrackerCheckpointClaimVersion,
					SandboxID:        "sandbox-usurper",
					OperationID:      "op-usurper",
					RequestDigest:    claimTestDigest("op-usurper"),
					SourceGeneration: "gen-live",
					Directory:        sealedDir,
					DirectoryDev:     dev,
					DirectoryInode:   inode,
				})
			},
			fragments: []string{"is now claimed by"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealedDir, _, _ := sealIdentifiedCheckpointArtifactBinding(t, "gen-live")
			tc.mutateDir(t, sealedDir)
			handler, sandboxID, readState, _ := coldClaimIntentFixture(t, sealedDir, nil)
			before := readState()

			_, err := handler.RecoverCheckpointOperation(
				context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("cold recovery with a drifted claim = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the claim boundary: %v", err)
			}
			if after := readState(); string(before) != string(after) {
				t.Fatalf("refused recovery rewrote durable state")
			}
			handler.mu.RLock()
			_, mapped := handler.instances[sandboxID]
			handler.mu.RUnlock()
			if mapped {
				t.Fatal("refused recovery mapped the instance")
			}
		})
	}
}

// TestCheckpointOperationClaimExcludedFromContentRoot proves the tombstone is
// never artifact content at the root level the runtime consumes: adding the
// claim to an ALREADY sealed directory leaves the content root byte-for-byte
// identical, and a foreign extra file keeps being refused.
func TestCheckpointOperationClaimExcludedFromContentRoot(t *testing.T) {
	sealedDir, root, binding := sealIdentifiedCheckpointArtifactBinding(t, "gen-root")
	after, err := checkpointroot.Bind(sealedDir)
	if err != nil {
		t.Fatalf("sealed directory no longer binds once it carries its claim: %v", err)
	}
	if after.RootDigest != root.RootDigest || after.Scheme != root.Scheme {
		t.Fatalf("the claim changed the content root: %s -> %s", root.RootDigest, after.RootDigest)
	}
	claim, err := readFirecrackerCheckpointClaim(sealedDir)
	if err != nil || claim.OperationID != binding.OperationID {
		t.Fatalf("sealed directory carries no usable claim of its own operation: %+v %v", claim, err)
	}
	// The control: an arbitrary extra file is still refused by the closure.
	if err := os.WriteFile(filepath.Join(sealedDir, "foreign-artifact"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointroot.Bind(sealedDir); err == nil {
		t.Fatal("an uncovered foreign artifact must keep refusing the root")
	}
}
