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
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// checkpointGenerationFixture builds the state Checkpoint gates on: a mapped,
// configured instance with a live owned VMM child, a persisted state file
// binding the given generation, and a digestible kernel so the fixture's only
// barrier to proceeding into layout and pause is the generation expectation.
func checkpointGenerationFixture(
	t *testing.T,
	generation string,
) (*Handler, *firecrackerInstance, string) {
	t.Helper()
	handler, instance := checkpointPersistenceFixture(t)
	instance.state.Generation = generation
	handler.instances = map[string]*firecrackerInstance{instance.state.ID: instance}
	kernel := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.kernelPath = kernel
	startCheckpointPersistenceChild(t, handler, instance)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	return handler, instance, instance.state.ID
}

// TestCheckpointGenerationMismatchRejectedBeforeSideEffects pins the runtime
// half of the conditional checkpoint contract: the expected generation is
// compared against the runtime's own persisted identity under the operation
// lock, before layout, pause, snapshot, or any state mutation, so a rejection
// leaves the incarnation and its artifacts exactly as they were.
func TestCheckpointGenerationMismatchRejectedBeforeSideEffects(t *testing.T) {
	handler, instance, sandboxID := checkpointGenerationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:                 sandboxID,
		Directory:          directory,
		ExpectedGeneration: "gen-other",
	})
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("mismatched generation checkpoint = %v, want ErrFailedPrecondition", err)
	}
	// The exact recorded and expected values are reported, never trimmed.
	if !containsAll(err.Error(), `"gen-live"`, `"gen-other"`) {
		t.Fatalf("rejection must report both exact values: %v", err)
	}
	// Zero side effects: no output directory, no state mutation in memory or
	// on disk, and the live child keeps its recorded identity untouched.
	if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("rejected checkpoint touched the output directory: %v", statErr)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
	if after := instance.snapshot(); after != before {
		t.Fatalf("rejected checkpoint mutated runtime state: %+v", after)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk != before {
		t.Fatalf("rejected checkpoint mutated persisted state: %+v %v", disk, readErr)
	}
}

// TestCheckpointGenerationMissingRecordRejected proves a record with no bound
// generation attests no incarnation: a generation-checked checkpoint against
// it is unsupported rather than a wildcard match, mirroring DeleteStrict.
func TestCheckpointGenerationMissingRecordRejected(t *testing.T) {
	handler, instance, sandboxID := checkpointGenerationFixture(t, "")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:                 sandboxID,
		Directory:          directory,
		ExpectedGeneration: "gen-live",
	})
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("unbound generation checkpoint = %v, want ErrFailedPrecondition", err)
	}
	if !containsAll(err.Error(), "carries no resource generation") {
		t.Fatalf("rejection must name the unbound record: %v", err)
	}
	if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("rejected checkpoint touched the output directory: %v", statErr)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
	if after := instance.snapshot(); after != before {
		t.Fatalf("rejected checkpoint mutated runtime state: %+v", after)
	}
}

// TestCheckpointGenerationAdmittedContinuesIntoCheckpointPath proves the gate
// is a pass-through for an admitted identity: with the matching generation —
// and for the legacy empty expectation even against a different recorded
// generation — the same fixture proceeds into the ordinary checkpoint path,
// reaching layout and the VMM pause boundary, and the failure observed is the
// fixture's absent API socket rather than a generation refusal.
func TestCheckpointGenerationAdmittedContinuesIntoCheckpointPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorded string
		expected string
	}{
		{name: "matching generation", recorded: "gen-live", expected: "gen-live"},
		{name: "legacy empty expectation", recorded: "gen-live", expected: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, instance, sandboxID := checkpointGenerationFixture(t, tc.recorded)
			directory := filepath.Join(t.TempDir(), "checkpoint")
			before := instance.snapshot()
			fd := checkpointTestPidfd(t, before.PID)

			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
				ID:                 sandboxID,
				Directory:          directory,
				ExpectedGeneration: tc.expected,
			})
			if err == nil {
				t.Fatal("fixture checkpoint unexpectedly succeeded without a VMM API socket")
			}
			if errors.Is(err, errord.ErrFailedPrecondition) ||
				containsAll(err.Error(), "does not match expected", "carries no resource generation") {
				t.Fatalf("admitted identity was refused by the generation gate: %v", err)
			}
			if !containsAll(err.Error(), "pause Firecracker sandbox") {
				t.Fatalf("checkpoint did not reach the existing pause boundary: %v", err)
			}
			// Layout already laid out the caller-owned output directory: the
			// ordinary path ran, and only the unpaused fixture child stopped it.
			if info, statErr := os.Stat(directory); statErr != nil || !info.IsDir() {
				t.Fatalf("checkpoint did not lay out its output directory: %v", statErr)
			}
			if checkpointTestExitReady(t, fd) {
				t.Fatal("fixture child exited during an admitted checkpoint attempt")
			}
			if after := instance.snapshot(); after.Exited || after.Generation != before.Generation {
				t.Fatalf("admitted attempt mutated the recorded incarnation: %+v", after)
			}
		})
	}
}

// coldIncarnation records what a cold-lookup test needs to observe about a
// durable incarnation: its identity fields and the on-disk state file.
type coldIncarnation struct {
	id        string
	pid       int
	apiPath   string
	binary    string
	statePath string
}

func (cold *coldIncarnation) readState(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(cold.statePath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// checkpointColdStateFixture persists a recoverable incarnation under a
// handler whose in-memory map is EMPTY: bundle, socket directory, and
// writable-layer paths all inside handler-owned roots, a configured live owned
// VMM child, and an incremental base lineage that recovery would reset. Any
// cold lookup that reaches recoverState therefore betrays itself: the state
// file is rewritten, the instance becomes mapped, and recovery monitors spawn.
func checkpointColdStateFixture(t *testing.T, generation string) (*Handler, *coldIncarnation) {
	t.Helper()
	handler := &Handler{
		sandboxRoot: t.TempDir(),
		storageRoot: t.TempDir(),
		runtimeRoot: t.TempDir(),
		instances:   make(map[string]*firecrackerInstance),
	}
	kernel := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.kernelPath = kernel
	const sandboxID = "cold-generation-source"
	runtimeDir := handler.runtimeDirectory(sandboxID)
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	overlayDir := filepath.Join(handler.storageRoot, sandboxID)
	if err := os.Mkdir(overlayDir, 0700); err != nil {
		t.Fatal(err)
	}
	cold := &coldIncarnation{
		id:      sandboxID,
		apiPath: filepath.Join(runtimeDir, firecrackerAPISocket),
	}
	command := startColdCheckpointChild(t, handler, cold.apiPath, sandboxID)
	cold.binary = handler.binary
	cold.pid = command.Process.Pid
	state := firecrackerPersistedState{
		ID:                    sandboxID,
		PID:                   cold.pid,
		BundlePath:            filepath.Join(handler.sandboxRoot, sandboxID),
		APIPath:               cold.apiPath,
		VsockPath:             filepath.Join(runtimeDir, firecrackerVsock),
		OverlayPath:           filepath.Join(overlayDir, "overlay.ext4"),
		Generation:            generation,
		MemoryMiB:             512,
		Vcpus:                 2,
		BaseMemoryPath:        filepath.Join(overlayDir, "base-memory"),
		BaseMemoryIncremental: true,
		Configured:            true,
	}
	if err := os.MkdirAll(
		filepath.Join(state.BundlePath, firecrackerArtifactsDir), 0700,
	); err != nil {
		t.Fatal(err)
	}
	if err := handler.persistInstance(&firecrackerInstance{
		state: state,
		done:  make(chan struct{}),
	}); err != nil {
		t.Fatal(err)
	}
	cold.statePath = filepath.Join(
		state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	return handler, cold
}

// startColdCheckpointChild starts the owned VMM-identity child bound to the
// sandbox-derived socket directory the persisted state must carry. Like the
// other fixtures' children it supplies native argv/exe identity, not KVM
// behavior.
func startColdCheckpointChild(
	t *testing.T,
	handler *Handler,
	apiPath, sandboxID string,
) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	handler.binary = binary
	command := handler.vmmCommand(apiPath, sandboxID)
	command.Args = append([]string{binary, "-test.run=^TestVMMCommandProcessIdentity$", "--"}, command.Args[1:]...)
	command.Env = append(os.Environ(), "AKERNEL_VMM_COMMAND_CHILD=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child readiness %q: %v", line, err)
	}
	return command
}

// TestCheckpointColdStateGenerationRefusedBeforeRecovery pins the cold-path
// contract: when the checkpoint resolves a sandbox absent from the in-memory
// map, a mismatched or unbound durable generation is refused before recovery
// runs, so the incarnation's durable record, its mapping, and its recorded
// process stay exactly as they were.
func TestCheckpointColdStateGenerationRefusedBeforeRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		recorded  string
		expected  string
		fragments []string
	}{
		{
			name:      "mismatched generation",
			recorded:  "gen-live",
			expected:  "gen-other",
			fragments: []string{`"gen-live"`, `"gen-other"`},
		},
		{
			name:      "unbound record",
			recorded:  "",
			expected:  "gen-live",
			fragments: []string{"carries no resource generation"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, cold := checkpointColdStateFixture(t, tc.recorded)
			before := cold.readState(t)
			fd := checkpointTestPidfd(t, cold.pid)
			directory := filepath.Join(t.TempDir(), "checkpoint")

			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
				ID:                 cold.id,
				Directory:          directory,
				ExpectedGeneration: tc.expected,
			})
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("cold-state checkpoint = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("rejection must report the exact identity: %v", err)
			}
			// The durable incarnation record is byte-for-byte unchanged: the
			// refusal never reached recoverState, so no lineage reset, exit
			// rewrite, or monitor-spawning persistence happened.
			if after := cold.readState(t); !bytes.Equal(before, after) {
				t.Fatalf("refused cold checkpoint rewrote durable state:\nbefore: %s\nafter:  %s", before, after)
			}
			handler.mu.RLock()
			_, mapped := handler.instances[cold.id]
			handler.mu.RUnlock()
			if mapped {
				t.Fatal("refused cold checkpoint recovered an instance")
			}
			// The recorded process was neither stopped nor signalled, and its
			// recorded identity still resolves to the live child.
			if checkpointTestExitReady(t, fd) {
				t.Fatal("recorded process exited during a refused cold checkpoint")
			}
			if !firecrackerProcessMatches(cold.pid, cold.binary, cold.apiPath, cold.id) {
				t.Fatal("recorded process lost its native identity")
			}
			if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
				t.Fatalf("refused cold checkpoint touched the output directory: %v", statErr)
			}
		})
	}
}

// TestCheckpointColdStateMatchingGenerationRecoversAndProceeds proves the
// cold-path gate is a pass-through for an admitted identity: the durable state
// is recovered into the map (with recovery's ordinary lineage reset), and the
// checkpoint then runs the ordinary path up to the pause boundary.
func TestCheckpointColdStateMatchingGenerationRecoversAndProceeds(t *testing.T) {
	handler, cold := checkpointColdStateFixture(t, "gen-live")
	fd := checkpointTestPidfd(t, cold.pid)
	directory := filepath.Join(t.TempDir(), "checkpoint")

	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:                 cold.id,
		Directory:          directory,
		ExpectedGeneration: "gen-live",
	})
	if err == nil {
		t.Fatal("fixture checkpoint unexpectedly succeeded without a VMM API socket")
	}
	if errors.Is(err, errord.ErrFailedPrecondition) ||
		containsAll(err.Error(), "does not match expected", "carries no resource generation") {
		t.Fatalf("admitted cold identity was refused by the generation gate: %v", err)
	}
	if !containsAll(err.Error(), "pause Firecracker sandbox") {
		t.Fatalf("cold checkpoint did not reach the existing pause boundary: %v", err)
	}
	// The admitted incarnation was recovered — the instance is mapped and the
	// restart lineage reset is recovery's ordinary durable contract.
	handler.mu.RLock()
	instance, mapped := handler.instances[cold.id]
	handler.mu.RUnlock()
	if !mapped || instance == nil {
		t.Fatal("admitted cold checkpoint did not recover the instance")
	}
	recovered := instance.snapshot()
	if recovered.Generation != "gen-live" ||
		recovered.BaseMemoryPath != "" || !recovered.BaseMemoryLineageLost {
		t.Fatalf("recovered state not admitted-and-reset as expected: %+v", recovered)
	}
	// The ordinary path laid out the caller-owned output directory before the
	// fixture's absent API socket stopped it at the pause boundary.
	if info, statErr := os.Stat(directory); statErr != nil || !info.IsDir() {
		t.Fatalf("cold checkpoint did not lay out its output directory: %v", statErr)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("fixture child exited during an admitted cold checkpoint")
	}
	// Quiet the recovery monitor so test cleanup can remove the temporary
	// roots without racing an exit-state rewrite.
	instance.markDeleting()
}
