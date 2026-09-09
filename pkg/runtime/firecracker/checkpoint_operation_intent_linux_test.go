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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

var _ runtimecore.CheckpointOperationAborter = (*Handler)(nil)

// killCheckpointChild kills the owned fixture child without reaping it, so
// its recorded PID remains a zombie whose pidfd reports the completed exit —
// the honest "source already gone" shape.
func killCheckpointChild(t *testing.T, pid int) {
	t.Helper()
	fd := checkpointTestPidfd(t, pid)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	exited, err := waitProcessExitNotification(fd, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !exited {
		t.Fatalf("owned child pid %d did not report a kernel exit notification", pid)
	}
}

// fakeAbortObservation records one MessageCheckpointAbort the fake agent
// received: the exact binding the runtime sent and the durable witness phase
// the state file held at that moment, so tests can prove both the request
// identity and the durable-aborting-before-resume ordering without polling.
type fakeAbortObservation struct {
	request firecrackerproto.CheckpointAbortRequest
	phase   string
}

// fakeCheckpointAgent stands in for the guest agent on the checkpoint vsock:
// it completes the CONNECT handshake, parses the retryable abort message with
// its full binding, and answers host messages. Hooks run on the connection
// goroutine and therefore never touch testing.T; they report errors through
// recorded fields the test goroutine inspects, and may drop the reply to
// simulate a lost one. It is a fake socket protocol peer, not a VM: real-VM
// abort acceptance is separate.
type fakeCheckpointAgent struct {
	mu                  sync.Mutex
	outcomes            []string // legacy MessageCheckpoint outcomes
	aborts              []fakeAbortObservation
	refuseLegacyMessage bool
	// refuseAbortMessage mimics a guest agent that predates the retryable
	// abort message: it answers the new message with an error and no handoff
	// side effect, which the host must not answer with a legacy fallback.
	refuseAbortMessage bool
	// onAbort runs when an abort request arrives, before the reply. A true
	// first return drops the reply — the lost-reply shape.
	onAbort         func(request firecrackerproto.CheckpointAbortRequest) (bool, error)
	hookErr         error
	stateBundlePath string
}

func startFakeCheckpointAgent(t *testing.T, socketPath string) *fakeCheckpointAgent {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	agent := &fakeCheckpointAgent{}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.serve(connection)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("fake checkpoint agent did not stop")
		}
	})
	return agent
}

func (agent *fakeCheckpointAgent) serve(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	handshake, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(handshake, "CONNECT ") {
		return
	}
	if _, err := fmt.Fprintf(connection, "OK %d\n", firecrackerproto.AgentPort); err != nil {
		return
	}
	messageType, payload, err := firecrackerproto.ReadMessage(reader)
	if err != nil {
		return
	}
	switch messageType {
	case firecrackerproto.MessageCheckpointAbort:
		var request firecrackerproto.CheckpointAbortRequest
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			return
		}
		agent.mu.Lock()
		// Every received request is recorded — a refused one included — so
		// tests can prove the runtime sent the retryable message even when
		// the agent answers it with an error.
		observation := fakeAbortObservation{request: request}
		if agent.stateBundlePath != "" {
			if state, readErr := readFirecrackerState(agent.stateBundlePath); readErr == nil {
				observation.phase = state.CheckpointOperation.Phase
			}
		}
		refuse := agent.refuseAbortMessage
		hook, drop := agent.onAbort, false
		var hookErr error
		if !refuse && hook != nil {
			drop, hookErr = hook(request)
		}
		agent.hookErr = hookErr
		agent.aborts = append(agent.aborts, observation)
		agent.mu.Unlock()
		if refuse {
			_ = firecrackerproto.WriteMessage(
				connection, firecrackerproto.MessageResponse,
				firecrackerproto.Response{OK: false, Error: "unknown message type 11"},
			)
			return
		}
		if drop {
			return // lost reply: the host must retry the identical request
		}
		_ = firecrackerproto.WriteMessage(
			connection, firecrackerproto.MessageResponse, firecrackerproto.Response{OK: true},
		)
	case firecrackerproto.MessageCheckpoint:
		var request firecrackerproto.CheckpointRequest
		if err := firecrackerproto.Decode(payload, &request); err != nil {
			return
		}
		agent.mu.Lock()
		agent.outcomes = append(agent.outcomes, request.Outcome)
		refuse := agent.refuseLegacyMessage
		agent.mu.Unlock()
		if refuse {
			// An abort path must never fall back to the legacy one-shot
			// message: refuse it loudly so a wrong sender fails its test.
			_ = firecrackerproto.WriteMessage(
				connection, firecrackerproto.MessageResponse,
				firecrackerproto.Response{OK: false, Error: "legacy checkpoint message refused"},
			)
			return
		}
		_ = firecrackerproto.WriteMessage(
			connection, firecrackerproto.MessageResponse, firecrackerproto.Response{OK: true},
		)
	default:
		_ = firecrackerproto.WriteMessage(
			connection, firecrackerproto.MessageResponse,
			firecrackerproto.Response{OK: false, Error: "unknown message type"},
		)
	}
}

func (agent *fakeCheckpointAgent) checkpointOutcomes() []string {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return append([]string(nil), agent.outcomes...)
}

func (agent *fakeCheckpointAgent) abortObservations() []fakeAbortObservation {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return append([]fakeAbortObservation(nil), agent.aborts...)
}

func (agent *fakeCheckpointAgent) abortHookError() error {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	return agent.hookErr
}

// blockStateWriteFromHook is the background-safe form of blockStateWrite for
// the agent's connection goroutine: it replaces the state file with a
// directory so the next durable write fails, and reports its own errors
// instead of touching testing.T. The test goroutine restores the file.
func blockStateWriteFromHook(
	state firecrackerPersistedState,
) func(firecrackerproto.CheckpointAbortRequest) (bool, error) {
	return func(firecrackerproto.CheckpointAbortRequest) (bool, error) {
		path := filepath.Join(
			state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
		if err := os.Rename(path, path+".blocked"); err != nil {
			return false, err
		}
		if err := os.Mkdir(path, 0700); err != nil {
			return false, err
		}
		return false, nil
	}
}

// unblockStateWriteFromHook reverses blockStateWriteFromHook on the test
// goroutine, restoring the file set aside by the hook.
func unblockStateWriteFromHook(t *testing.T, state firecrackerPersistedState) {
	t.Helper()
	path := filepath.Join(
		state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".blocked", path); err != nil {
		t.Fatal(err)
	}
}

// assertAbortObservations proves the runtime released the guest through the
// retryable abort message exactly want times, every request carrying the exact
// full operation binding, and — when phases are given — the durable witness
// phase the state file held at each request (the ordering proof that the
// aborting decision was durable before the resume could reach the release).
func assertAbortObservations(
	t *testing.T,
	agent *fakeCheckpointAgent,
	want int,
	binding runtimecore.CheckpointOperationBinding,
	phases ...string,
) {
	t.Helper()
	observations := agent.abortObservations()
	if len(observations) != want {
		t.Fatalf("abort requests = %d, want %d: %+v", len(observations), want, observations)
	}
	for i, observation := range observations {
		if err := observation.request.Validate(); err != nil {
			t.Fatalf("abort request %d is not a valid bounded request: %v", i, err)
		}
		if observation.request.OperationID != binding.OperationID ||
			observation.request.RequestDigest != binding.RequestDigest ||
			observation.request.SourceGeneration != binding.SourceGeneration {
			t.Fatalf("abort request %d carried the wrong binding: %+v", i, observation.request)
		}
		if i < len(phases) && observation.phase != phases[i] {
			t.Fatalf("abort request %d observed durable phase %q, want %q", i, observation.phase, phases[i])
		}
	}
}

// pointFixtureVsockAtAgent rebinds the fixture instance's vsock path to the
// sandbox-derived socket the persisted-state validation expects and serves a
// fake guest agent there, durably.
func pointFixtureVsockAtAgent(
	t *testing.T,
	handler *Handler,
	instance *firecrackerInstance,
) *fakeCheckpointAgent {
	t.Helper()
	vsockPath := filepath.Join(filepath.Dir(instance.snapshot().APIPath), firecrackerVsock)
	agent := startFakeCheckpointAgent(t, vsockPath)
	agent.mu.Lock()
	agent.stateBundlePath = instance.snapshot().BundlePath
	agent.mu.Unlock()
	instance.mu.Lock()
	instance.state.VsockPath = vsockPath
	instance.mu.Unlock()
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	return agent
}

// checkpointIntentFixture builds a hot instance holding a DURABLE version-2
// intent witness — reserved, captured, and persisted through the production
// helpers against the live fixture child — with a fake guest agent so the
// abort handback can complete. The recorded output directory starts empty and
// unsealed.
func checkpointIntentFixture(
	t *testing.T,
	generation string,
) (*Handler, *firecrackerInstance, *fakeFirecrackerAPI, *fakeCheckpointAgent, string, string) {
	t.Helper()
	handler, instance, api, sandboxID := checkpointOperationFixture(t, generation)
	agent := pointFixtureVsockAtAgent(t, handler, instance)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	binding := testCheckpointOperationBinding(generation)
	dev, inode, err := claimFirecrackerCheckpointDirectory(directory, sandboxID, binding)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture models the post-pause crash: the durable intent exists and
	// the source MicroVM is Paused, exactly the state an abort must resume
	// exactly once. The pre-pause window — a durable intent with the source
	// still Running — is forced explicitly by the tests that cover it.
	if err := api.pause(); err != nil {
		t.Fatal(err)
	}
	state := instance.snapshot()
	birth, err := captureFirecrackerVMMBirthIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	instance.setCheckpointOperation(buildFirecrackerCheckpointOperationIntent(
		binding, state, birth, directory, dev, inode,
	))
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	return handler, instance, api, agent, sandboxID, directory
}

// sealIdentifiedCheckpointArtifactBinding drives the real identified flow on a
// disposable fixture and returns the sealed artifact directory, its bound
// root, and the exact operation binding the seal's manifest carries.
func sealIdentifiedCheckpointArtifactBinding(
	t *testing.T,
	generation string,
) (string, *checkpointroot.Binding, runtimecore.CheckpointOperationBinding) {
	t.Helper()
	handler, _, api, sandboxID := checkpointOperationFixture(t, generation)
	binding := testCheckpointOperationBinding(generation)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: directory,
		Operation: binding,
	}); err != nil {
		t.Fatal(err)
	}
	if api.countVMState("Resumed") != 0 {
		t.Fatal("identified stop-and-copy checkpoint resumed the source")
	}
	root, err := checkpointroot.Bind(directory)
	if err != nil {
		t.Fatal(err)
	}
	return directory, root, binding
}

// sealLegacyCheckpointArtifact seals through the legacy leave-running flow —
// no operation binding in the manifest, no witness record — producing the
// "old seal" a durable intent must never claim.
func sealLegacyCheckpointArtifact(t *testing.T) string {
	t.Helper()
	handler, _, _, sandboxID := checkpointOperationFixture(t, "gen-legacy")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:           sandboxID,
		Directory:    directory,
		LeaveRunning: true,
	}); err != nil {
		t.Fatal(err)
	}
	return directory
}

// coldCheckpointIntentFixture persists an incarnation with a durable v2
// intent witness under a handler whose in-memory map is EMPTY. Any cold path
// that reaches recoverState betrays itself by rewriting the state file and
// mapping the instance. The recorded directory defaults to an existing empty
// directory (an unsealed reservation) unless the caller supplies a sealed one.
func coldCheckpointIntentFixture(
	t *testing.T,
	sealedDirectory string,
	mutateWitness func(*firecrackerCheckpointOperationRecord),
) (*Handler, string, func() []byte, *exec.Cmd, firecrackerPersistedState) {
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
	const sandboxID = "cold-intent-source"
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
	directory := sealedDirectory
	if directory == "" {
		directory = t.TempDir()
	}
	info, err := os.Lstat(directory)
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
			Version:          firecrackerCheckpointOperationRecordVersion2,
			Phase:            firecrackerCheckpointOperationPhaseIntent,
			OperationID:      binding.OperationID,
			RequestDigest:    binding.RequestDigest,
			SourceGeneration: binding.SourceGeneration,
			Directory:        directory,
			DirectoryDev:     uint64(stat.Dev),
			DirectoryInode:   stat.Ino,
			VMMPID:           command.Process.Pid,
			VMMStartTime:     startTime,
			VMMBootID:        bootID,
			VMMAPIPath:       apiPath,
		},
	}
	if mutateWitness != nil {
		mutateWitness(&state.CheckpointOperation)
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
	}, command, state
}

// TestCheckpointOperationIntentWriteFailureHasZeroSourceEffects proves the
// earliest durable boundary: a failed or ambiguous intent write runs no
// source side effect at all, keeps the conservative in-memory gate, and
// leaves a cleanly abortable operation behind.
func TestCheckpointOperationIntentWriteFailureHasZeroSourceEffects(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	agent := pointFixtureVsockAtAgent(t, handler, instance)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	makeStateDirUnwritable(t, instance)

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if !containsAll(err.Error(), "persist checkpoint operation intent") {
		t.Fatalf("failure must name the intent write: %v", err)
	}
	// Zero source effects: no pause, no snapshot, no guest interaction, and
	// the source is untouched.
	if pauses := api.countVMState("Paused"); pauses != 0 {
		t.Fatalf("intent write failure paused the source %d times", pauses)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 0 {
		t.Fatalf("intent write failure took %d snapshots", snapshots)
	}
	if observations := agent.abortObservations(); len(observations) != 0 {
		t.Fatalf("intent write failure released the guest: %+v", observations)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
	// The claimed output directory holds exactly the durable claim — its full
	// binding was persisted before the intent write was attempted — and no
	// checkpoint component was written into it.
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != firecrackerCheckpointClaimName() {
		t.Fatalf("claimed output must hold only the claim: %d entries %v", len(entries), readErr)
	}
	claim, claimErr := readFirecrackerCheckpointClaim(directory)
	if claimErr != nil {
		t.Fatalf("claim left by the failed intent write is unusable: %v", claimErr)
	}
	if claim.SandboxID != sandboxID || claim.OperationID != "op-source-1" ||
		claim.RequestDigest != strings.Repeat("ab", 32) ||
		claim.SourceGeneration != "gen-live" || claim.Directory != directory {
		t.Fatalf("claim binding drifted: %+v", claim)
	}
	// The durable record never landed; the in-memory intent keeps the gate.
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || !disk.CheckpointOperation.isZero() {
		t.Fatalf("durable witness state = %+v %v, want none", disk.CheckpointOperation, readErr)
	}
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhaseIntent {
		t.Fatalf("in-memory witness phase = %q, want intent", phase)
	}
	// The conservative gate blocks every new checkpoint and delete.
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint-retry"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("legacy checkpoint after failed intent write = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after failed intent write = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-live"); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("strict delete after failed intent write = %v, want ErrFailedPrecondition", err)
	}

	// Repaired storage: the same operation aborts cleanly. The source was
	// NEVER paused — the intent write failed before any side effect — so the
	// abort observes a Running instance through GET / and must send NO
	// resume: one guest error release, one durable aborted fact, and only
	// the abort acknowledgment releases the evidence gate.
	makeStateDirWritable(instance)
	binding := testCheckpointOperationBinding("gen-live")
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort after repaired intent-write failure = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("abort resumed the never-paused source %d times, want 0", resumes)
	}
	assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after abort = %+v %v", disk.CheckpointOperation, readErr)
	}
	if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("ack aborted = %v", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete after abort acknowledgment = %v", err)
	}
}

// TestCheckpointOperationPreparedWriteGapAfterDurableIntent is the 1405
// counterexample rebuilt against the early-intent flow: the injection lands
// precisely AFTER the intent is durable and BEFORE the prepared promotion
// write, so the ambiguity the original probe proved is still exercised — and
// the durable intent now closes the cold gap: after mapping loss the same
// binding reconciles from the intent plus its own sealed artifact with one
// snapshot, zero resumes, and the exact recorded identity.
func TestCheckpointOperationPreparedWriteGapAfterDurableIntent(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	// A consistent durable vsock path so the cold read after mapping loss
	// passes persisted-state validation; no agent is needed — the recovery
	// performs no guest interaction.
	pointFixtureVsockAtAgent(t, handler, instance)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	// Deterministic injection inside the FIRST snapshot request: the intent
	// is already durable, the prepared promotion write has not run.
	api.onSnapshotCreate = makeStateDirUnwritableFromHook(instance)
	t.Cleanup(func() { makeStateDirWritable(instance) })

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if hookErr := api.snapshotHookError(); hookErr != nil {
		t.Fatalf("snapshot injection failed: %v", hookErr)
	}
	if !containsAll(err.Error(), "persist prepared checkpoint operation witness") {
		t.Fatalf("failure must still name the ambiguous prepared write, not an earlier boundary: %v", err)
	}
	// The ambiguity the original probe asserted: the source is never resumed,
	// the sealed artifact is retained, the durable record exists but proves
	// no prepared witness, and the in-memory record binds this daemon.
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("ambiguous prepared write resumed the source %d times", resumes)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("source was stopped after an ambiguous prepared write")
	}
	if _, statErr := os.Stat(filepath.Join(directory, firecrackerCheckpointManifestName)); statErr != nil {
		t.Fatalf("sealed artifact was discarded: %v", statErr)
	}
	root, bindErr := checkpointroot.Bind(directory)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
		t.Fatalf("durable witness state = %+v %v, want the durable intent", disk.CheckpointOperation, readErr)
	}
	durableIntent := disk.CheckpointOperation
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("in-memory witness phase = %q, want prepared", phase)
	}
	// The gates hold exactly as before.
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint-retry"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("checkpoint during ambiguous prepared write = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete during ambiguous prepared write = %v, want ErrFailedPrecondition", err)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)

	// Simulate the daemon losing the mapping: relocate the durable state
	// under a sandbox root the cold lookup resolves, then drop the map entry.
	// A wrong binding is refused cold without any side effect first.
	makeStateDirWritable(instance)
	coldRoot := t.TempDir()
	coldBundle := filepath.Join(coldRoot, sandboxID)
	coldStateDir := filepath.Join(coldBundle, firecrackerArtifactsDir)
	if err := os.MkdirAll(coldStateDir, 0700); err != nil {
		t.Fatal(err)
	}
	stateBytes, readErr := os.ReadFile(filepath.Join(
		before.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename))
	if readErr != nil {
		t.Fatal(readErr)
	}
	// The relocated record must name its new bundle path, exactly as a real
	// daemon restart would find it.
	relocated := disk
	relocated.BundlePath = coldBundle
	if err := writeFirecrackerState(relocated); err != nil {
		t.Fatal(err)
	}
	stateBytes, readErr = os.ReadFile(filepath.Join(
		coldStateDir, firecrackerStateFilename))
	if readErr != nil {
		t.Fatal(readErr)
	}
	handler.sandboxRoot = coldRoot
	handler.mu.Lock()
	delete(handler.instances, sandboxID)
	handler.mu.Unlock()
	wrong := testCheckpointOperationBinding("gen-live")
	wrong.OperationID = "op-other"
	if _, err := handler.RecoverCheckpointOperation(context.Background(), sandboxID, wrong); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("cold recovery with wrong binding = %v, want ErrFailedPrecondition", err)
	}
	if after, err := os.ReadFile(filepath.Join(
		coldStateDir, firecrackerStateFilename)); err != nil || string(after) != string(stateBytes) {
		t.Fatalf("refused cold recovery rewrote durable state: %v", err)
	}
	handler.mu.RLock()
	_, mapped := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("refused cold recovery mapped the instance")
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)

	// The same binding now reconciles from the durable intent plus the sealed
	// artifact: the promotion keeps the intent's captured identity, completes
	// the original stop, and reports the sealed root — with no new snapshot
	// and no resume.
	completion, recoverErr := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if recoverErr != nil {
		t.Fatalf("cold recovery from durable intent = %v", recoverErr)
	}
	if completion.RootDigest != root.RootDigest || completion.RootScheme != root.Scheme {
		t.Fatalf("recovered root %s (%s), want the sealed root %s (%s)",
			completion.RootDigest, completion.RootScheme, root.RootDigest, root.Scheme)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("cold recovery returned before the source's kernel exit notification")
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("cold recovery re-took snapshots: %d", snapshots)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("cold recovery resumed the source %d times", resumes)
	}
	disk, readErr = readFirecrackerState(coldBundle)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted || !disk.Exited {
		t.Fatalf("durable completion after intent promotion = %+v %v", disk.CheckpointOperation, readErr)
	}
	completed := disk.CheckpointOperation
	if completed.Version != firecrackerCheckpointOperationRecordVersion3 ||
		completed.DirectoryDev != durableIntent.DirectoryDev ||
		completed.DirectoryInode != durableIntent.DirectoryInode ||
		completed.VMMPID != durableIntent.VMMPID ||
		completed.VMMStartTime != durableIntent.VMMStartTime ||
		completed.VMMBootID != durableIntent.VMMBootID {
		t.Fatalf("promotion recaptured or replaced the intent identity: %+v", completed)
	}
	handler.mu.RLock()
	recovered := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if recovered == nil {
		t.Fatal("cold recovery did not map the instance")
	}
	recovered.markDeleting()
}

// TestRecoverCheckpointOperationColdIntentRefusesWithoutOwnSeal pins the
// fail-closed boundary of the intent promotion: an unsealed reservation, a
// replaced output directory, a foreign or legacy seal, and a foreign boot are
// all refused before any recovery side effect, and a reused birth is never
// signalled.
func TestRecoverCheckpointOperationColdIntentRefusesWithoutOwnSeal(t *testing.T) {
	// otherOpDir holds a complete seal of a DIFFERENT operation; sameOpDir
	// holds one of the exact gen-live binding the cold records carry.
	otherOpDir, _, _ := sealIdentifiedCheckpointArtifactBinding(t, "gen-seal")
	sameOpDir, _, _ := sealIdentifiedCheckpointArtifactBinding(t, "gen-live")
	legacySealedDir := sealLegacyCheckpointArtifact(t)
	for _, tc := range []struct {
		name      string
		directory func() string
		mutate    func(*firecrackerCheckpointOperationRecord)
		fragments []string
	}{
		{
			name:      "unsealed reservation",
			directory: func() string { return "" },
			fragments: []string{"seal is not a complete verifiable artifact"},
		},
		{
			name:      "replaced output directory",
			directory: func() string { return "" },
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.DirectoryInode++
			},
			fragments: []string{"now carries"},
		},
		{
			name:      "foreign seal",
			directory: func() string { return otherOpDir },
			fragments: []string{"not the intent's own operation"},
		},
		{
			name:      "legacy seal without binding",
			directory: func() string { return legacySealedDir },
			fragments: []string{"carrying no operation binding"},
		},
		{
			name:      "foreign host boot",
			directory: func() string { return sameOpDir },
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.VMMBootID = "99999999-8888-4777-8666-555555555555"
			},
			fragments: []string{"refuses to reconcile across a host reboot"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, sandboxID, readState, command, _ := coldCheckpointIntentFixture(
				t, tc.directory(), tc.mutate,
			)
			before := readState()

			_, err := handler.RecoverCheckpointOperation(
				context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("cold intent recovery = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the boundary: %v", err)
			}
			assertColdRefusal(t, handler, sandboxID, before, readState, command.Process.Pid)
		})
	}

	// A reused birth against a verifiable same-op seal: the promotion lands
	// (it proves only the artifact), but the recorded process is never
	// signalled and the evidence is retained at prepared.
	t.Run("reused source birth", func(t *testing.T) {
		handler, sandboxID, _, command, state := coldCheckpointIntentFixture(
			t, sameOpDir,
			func(record *firecrackerCheckpointOperationRecord) {
				record.VMMStartTime++
			},
		)
		fd := checkpointTestPidfd(t, command.Process.Pid)

		_, err := handler.RecoverCheckpointOperation(
			context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
		)
		if err == nil || !containsAll(err.Error(), "refusing to signal a reused pid") {
			t.Fatalf("recovery with a recycled birth = %v, want the reused-pid refusal", err)
		}
		if checkpointTestExitReady(t, fd) {
			t.Fatal("recovery signalled a process the witness did not record")
		}
		disk, readErr := readFirecrackerState(state.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
			t.Fatalf("refused stop must retain the promoted prepared evidence: %+v %v", disk.CheckpointOperation, readErr)
		}
		handler.mu.RLock()
		recovered := handler.instances[sandboxID]
		handler.mu.RUnlock()
		if recovered != nil {
			recovered.markDeleting()
		}
	})
}

// TestCheckpointOperationReservationRefusals proves the reservation contract
// of the canonical output directory: absolute, non-root, not a symlink, and
// empty or new — every refusal predating the intent write, so nothing is
// recorded and the source is untouched. A preexisting EMPTY directory is a
// valid reservation and the flow completes.
func TestCheckpointOperationReservationRefusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prepare   func(t *testing.T) string
		fragments []string
		wantErr   error
	}{
		{
			name: "preexisting nonempty directory",
			prepare: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			fragments: []string{"not an empty reserved directory"},
			wantErr:   errord.ErrFailedPrecondition,
		},
		{
			name: "preexisting file",
			prepare: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "output")
				if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			fragments: []string{"is not a directory"},
		},
		{
			name: "relative path",
			prepare: func(t *testing.T) string {
				return filepath.Join("relative", "checkpoint")
			},
			fragments: []string{"not an absolute non-root"},
		},
		{
			name: "filesystem root",
			prepare: func(t *testing.T) string {
				return string(filepath.Separator)
			},
			fragments: []string{"not an absolute non-root"},
		},
		{
			name: "symbolic link",
			prepare: func(t *testing.T) string {
				target := t.TempDir()
				link := filepath.Join(filepath.Dir(target), "checkpoint-link")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			fragments: []string{"symbolic link"},
			wantErr:   errord.ErrFailedPrecondition,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
			before := instance.snapshot()
			fd := checkpointTestPidfd(t, before.PID)
			directory := tc.prepare(t)

			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
				ID:        sandboxID,
				Directory: directory,
				Operation: testCheckpointOperationBinding("gen-live"),
			})
			if err == nil {
				t.Fatal("reservation refusal expected")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("reservation refusal = %v, want %v", err, tc.wantErr)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the boundary: %v", err)
			}
			// The refusal predates the intent: no pause, no state change, no
			// witness, and the preexisting path is left exactly as it was.
			if pauses := api.countVMState("Paused"); pauses != 0 {
				t.Fatalf("refused reservation paused the source %d times", pauses)
			}
			if checkpointTestExitReady(t, fd) {
				t.Fatal("refused reservation stopped the source")
			}
			if after := instanceState(t, handler, before.ID); after != before {
				t.Fatalf("refused reservation mutated runtime state: %+v", after)
			}
			disk, readErr := readFirecrackerState(before.BundlePath)
			if readErr != nil || disk != before {
				t.Fatalf("refused reservation mutated persisted state: %+v %v", disk, readErr)
			}
		})
	}

	// A preexisting EMPTY directory is a valid reservation: the flow runs to
	// completion and the sealed manifest carries the operation binding.
	t.Run("preexisting empty directory", func(t *testing.T) {
		handler, _, api, sandboxID := checkpointOperationFixture(t, "gen-live")
		directory := t.TempDir()
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
		manifestRaw, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointManifestName))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Operation *struct {
				OperationID      string `json:"operation_id"`
				RequestDigest    string `json:"request_digest"`
				SourceGeneration string `json:"source_generation"`
			} `json:"operation"`
		}
		if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Operation == nil ||
			manifest.Operation.OperationID != binding.OperationID ||
			manifest.Operation.RequestDigest != binding.RequestDigest ||
			manifest.Operation.SourceGeneration != binding.SourceGeneration {
			t.Fatalf("sealed manifest carries wrong operation binding: %s", manifestRaw)
		}
	})
}

// TestAbortCheckpointOperationRetiresIntent drives the abort happy path end
// to end on a live source: durable aborting before the resume, exactly one
// resume and one guest error release, the exact recorded birth alive before
// and after, lineage invalidated, and the durable aborted fact gating every
// retirement until the abort acknowledgment.
func TestAbortCheckpointOperationRetiresIntent(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("abort resumed the source %d times, want exactly 1", resumes)
	}
	assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	if snapshots := api.countSnapshotCreates(); snapshots != 0 {
		t.Fatalf("abort took %d snapshots", snapshots)
	}
	// The exact recorded birth survived the handback.
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after abort = %q", disk.CheckpointOperation.Phase)
	}
	if !disk.BaseMemoryLineageLost {
		t.Fatal("abort did not invalidate the incremental lineage before success")
	}
	// The aborted fact keeps the evidence gate: new checkpoints and deletes
	// stay blocked, and the SUCCESS acknowledgment refuses it too.
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint-retry"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("checkpoint after abort = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after abort = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, binding); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("success ack of an aborted operation = %v, want ErrFailedPrecondition", err)
	}
	// Repeated aborts of the durable fact are idempotent and never resume
	// again; a further abort after the abort acknowledgment is refused.
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("idempotent abort replay = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("abort replay resumed the source again: %d", resumes)
	}
	if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("ack aborted = %v", err)
	}
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("abort after abort acknowledgment = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete after abort acknowledgment = %v", err)
	}
}

// TestAbortCheckpointOperationInterruptedPhases proves every interruption of
// the abort sequence retains its evidence, never claims an unproven
// resumption, and retries to completion.
func TestAbortCheckpointOperationInterruptedPhases(t *testing.T) {
	binding := testCheckpointOperationBinding("gen-live")

	t.Run("aborting write failure", func(t *testing.T) {
		handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		before := instance.snapshot()
		makeStateDirUnwritable(t, instance)

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if err == nil || !containsAll(err.Error(), "persist aborting checkpoint operation witness") {
			t.Fatalf("abort must fail on the durable decision boundary: %v", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 0 {
			t.Fatalf("abort resumed the source %d times before the decision was durable", resumes)
		}
		if observations := agent.abortObservations(); len(observations) != 0 {
			t.Fatalf("abort released the guest before the decision was durable: %+v", observations)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
			t.Fatalf("durable phase after failed aborting write = %+v %v", disk.CheckpointOperation, readErr)
		}
		// Repaired storage: the retry completes with exactly one resume.
		makeStateDirWritable(instance)
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("abort after repair = %v", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 1 {
			t.Fatalf("abort retry resumed the source %d times, want 1", resumes)
		}
		disk, readErr = readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
			t.Fatalf("durable phase after abort retry = %+v %v", disk.CheckpointOperation, readErr)
		}
	})

	t.Run("ambiguous aborted write", func(t *testing.T) {
		handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		before := instance.snapshot()
		// Deterministic injection at the guest abort release: the aborting
		// decision is already durable, the aborted write has not run.
		agent.mu.Lock()
		agent.onAbort = blockStateWriteFromHook(before)
		agent.mu.Unlock()
		t.Cleanup(func() {
			// Restore only when the hook actually blocked; otherwise the
			// blocked file was never created.
			if _, statErr := os.Stat(filepath.Join(
				before.BundlePath, firecrackerArtifactsDir,
				firecrackerStateFilename+".blocked")); statErr == nil {
				unblockStateWriteFromHook(t, before)
			}
		})

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if hookErr := agent.abortHookError(); hookErr != nil {
			t.Fatalf("abort injection failed: %v", hookErr)
		}
		if err == nil || !containsAll(err.Error(), "persist aborted checkpoint operation witness") {
			t.Fatalf("abort must fail on the aborted write: %v", err)
		}
		if !containsAll(err.Error(), "the source was resumed and released") {
			t.Fatalf("failure must not deny the resumption that happened: %v", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 1 {
			t.Fatalf("ambiguous aborted write resumed %d times, want 1", resumes)
		}
		assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
		blocked, blockedErr := os.ReadFile(filepath.Join(
			before.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename+".blocked"))
		if blockedErr != nil {
			t.Fatal(blockedErr)
		}
		var blockedState firecrackerPersistedState
		if err := json.Unmarshal(blocked, &blockedState); err != nil ||
			blockedState.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
			t.Fatalf("durable phase after ambiguous aborted write = %+v %v", blockedState.CheckpointOperation, err)
		}
		if !instance.snapshot().CheckpointOperation.retainsEvidence() {
			t.Fatal("ambiguous aborted write released the in-memory evidence gate")
		}
		// The retry re-persists the abort fact from the aborted replay branch
		// — no second resume, no second guest release.
		unblockStateWriteFromHook(t, before)
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("abort retry after repair = %v", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 1 {
			t.Fatalf("abort retry resumed the source again: %d", resumes)
		}
		assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
			t.Fatalf("durable phase after abort retry = %+v %v", disk.CheckpointOperation, readErr)
		}
	})

	t.Run("dead source", func(t *testing.T) {
		handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		before := instance.snapshot()
		killCheckpointChild(t, before.PID)

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if err == nil || !containsAll(err.Error(), "cannot prove it resumes the recorded source") {
			t.Fatalf("abort of a dead source = %v, want the unproven-resumption refusal", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 0 {
			t.Fatalf("abort of a dead source resumed %d times", resumes)
		}
		if observations := agent.abortObservations(); len(observations) != 0 {
			t.Fatalf("abort of a dead source released the guest: %+v", observations)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
			t.Fatalf("refused abort mutated retained evidence: %+v %v", disk.CheckpointOperation, readErr)
		}
	})

	t.Run("reused source birth", func(t *testing.T) {
		handler, instance, api, _, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		before := instance.snapshot()
		// Rewrite the durable intent with a wrong start time: the recorded
		// source identity no longer describes the live PID.
		record := instance.snapshot().CheckpointOperation
		record.VMMStartTime++
		instance.setCheckpointOperation(record)
		if err := handler.persistInstance(instance); err != nil {
			t.Fatal(err)
		}

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
		if err == nil || !containsAll(err.Error(), "refusing to signal a reused pid") {
			t.Fatalf("abort with a recycled birth = %v, want the reused-pid refusal", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 0 {
			t.Fatalf("abort with a recycled birth resumed %d times", resumes)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
			t.Fatalf("durable phase after reused-birth refusal = %+v %v", disk.CheckpointOperation, readErr)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		before := instance.snapshot()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := handler.AbortCheckpointOperation(ctx, sandboxID, binding)
		// The cancelled context dies on the instance-state read that now
		// precedes every resume decision: nothing was resumed, the aborting
		// decision is durable, and the evidence is retained.
		if err == nil || !containsAll(err.Error(), "read the Firecracker instance state") {
			t.Fatalf("abort with a cancelled context = %v, want the state-read refusal", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 0 {
			t.Fatalf("cancelled abort resumed %d times", resumes)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
			t.Fatalf("durable phase after cancelled abort = %+v %v", disk.CheckpointOperation, readErr)
		}
		// The same decision retries to completion once the context works.
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("abort retry after cancellation = %v", err)
		}
		if resumes := api.countVMState("Resumed"); resumes != 1 {
			t.Fatalf("abort retry resumed %d times, want 1", resumes)
		}
		assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	})
}

// TestAbortCheckpointOperationRefusesSealedOrTerminalPhases pins the abort
// phase policy: a valid same-operation seal means Recover, an unattributable
// or legacy seal fails closed, and sealed or success-side phases are never
// aborted — with no source effect in any refusal.
func TestAbortCheckpointOperationRefusesSealedOrTerminalPhases(t *testing.T) {
	binding := testCheckpointOperationBinding("gen-live")

	subtests := []struct {
		name      string
		build     func(t *testing.T) (*Handler, *firecrackerInstance, string, *fakeFirecrackerAPI)
		fragments []string
	}{
		{
			name: "own complete seal means recover",
			build: func(t *testing.T) (*Handler, *firecrackerInstance, string, *fakeFirecrackerAPI) {
				sealedDir, _, sealedBinding := sealIdentifiedCheckpointArtifactBinding(t, "gen-live")
				handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
				info, err := os.Lstat(sealedDir)
				if err != nil {
					t.Fatal(err)
				}
				stat := info.Sys().(*syscall.Stat_t)
				state := instance.snapshot()
				birth, err := captureFirecrackerVMMBirthIdentity(state)
				if err != nil {
					t.Fatal(err)
				}
				instance.setCheckpointOperation(buildFirecrackerCheckpointOperationIntent(
					sealedBinding, state, birth, sealedDir,
					uint64(stat.Dev), stat.Ino,
				))
				if err := handler.persistInstance(instance); err != nil {
					t.Fatal(err)
				}
				return handler, instance, sandboxID, api
			},
			fragments: []string{"recover the operation instead of aborting"},
		},
		{
			name: "foreign seal fails closed",
			build: func(t *testing.T) (*Handler, *firecrackerInstance, string, *fakeFirecrackerAPI) {
				foreignDir, _, _ := sealIdentifiedCheckpointArtifactBinding(t, "gen-seal")
				handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
				info, err := os.Lstat(foreignDir)
				if err != nil {
					t.Fatal(err)
				}
				stat := info.Sys().(*syscall.Stat_t)
				state := instance.snapshot()
				birth, err := captureFirecrackerVMMBirthIdentity(state)
				if err != nil {
					t.Fatal(err)
				}
				// A version-2 record keeps this subtest on the seal-attribution
				// boundary: the foreign seal's directory claim binds a
				// different operation, so a version-3 record would be refused
				// on the claim first (covered by the claim tests).
				record := buildFirecrackerCheckpointOperationIntent(
					binding, state, birth, foreignDir, uint64(stat.Dev), stat.Ino,
				)
				record.Version = firecrackerCheckpointOperationRecordVersion2
				record.SandboxID = ""
				instance.setCheckpointOperation(record)
				if err := handler.persistInstance(instance); err != nil {
					t.Fatal(err)
				}
				return handler, instance, sandboxID, api
			},
			fragments: []string{"not this operation's verifiable seal"},
		},
		{
			name: "legacy seal fails closed",
			build: func(t *testing.T) (*Handler, *firecrackerInstance, string, *fakeFirecrackerAPI) {
				legacyDir := sealLegacyCheckpointArtifact(t)
				handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
				info, err := os.Lstat(legacyDir)
				if err != nil {
					t.Fatal(err)
				}
				stat := info.Sys().(*syscall.Stat_t)
				state := instance.snapshot()
				birth, err := captureFirecrackerVMMBirthIdentity(state)
				if err != nil {
					t.Fatal(err)
				}
				// Version 2 for the same reason as the foreign-seal case: a
				// legacy seal carries no claim at all, and the version-3
				// refusal for a missing claim is covered by the claim tests.
				record := buildFirecrackerCheckpointOperationIntent(
					binding, state, birth, legacyDir, uint64(stat.Dev), stat.Ino,
				)
				record.Version = firecrackerCheckpointOperationRecordVersion2
				record.SandboxID = ""
				instance.setCheckpointOperation(record)
				if err := handler.persistInstance(instance); err != nil {
					t.Fatal(err)
				}
				return handler, instance, sandboxID, api
			},
			fragments: []string{"carrying no operation binding"},
		},
	}
	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			handler, instance, sandboxID, api := tc.build(t)
			before := instance.snapshot()
			fd := checkpointTestPidfd(t, before.PID)

			err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("abort = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the boundary: %v", err)
			}
			if resumes := api.countVMState("Resumed"); resumes != 0 {
				t.Fatalf("refused abort resumed the source %d times", resumes)
			}
			disk, readErr := readFirecrackerState(before.BundlePath)
			if readErr != nil || disk.CheckpointOperation != before.CheckpointOperation {
				t.Fatalf("refused abort mutated retained evidence: %+v %v", disk.CheckpointOperation, readErr)
			}
			assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
		})
	}

	// Sealed and success-side phases are refused for both schema versions,
	// before any identity or source work.
	for _, tc := range []struct {
		name      string
		record    func() firecrackerCheckpointOperationRecord
		fragments []string
	}{
		{
			name: "v1 prepared",
			record: func() firecrackerCheckpointOperationRecord {
				return schemaTestV1Witness(firecrackerCheckpointOperationPhasePrepared)
			},
			fragments: []string{"cannot be aborted"},
		},
		{
			name: "v1 completed",
			record: func() firecrackerCheckpointOperationRecord {
				return schemaTestV1Witness(firecrackerCheckpointOperationPhaseCompleted)
			},
			fragments: []string{"cannot be aborted"},
		},
		{
			name: "v1 acked",
			record: func() firecrackerCheckpointOperationRecord {
				return schemaTestV1Witness(firecrackerCheckpointOperationPhaseAcked)
			},
			fragments: []string{"cannot be aborted"},
		},
		{
			name: "v2 prepared",
			record: func() firecrackerCheckpointOperationRecord {
				return schemaTestV2Witness(firecrackerCheckpointOperationPhasePrepared)
			},
			fragments: []string{"cannot be aborted"},
		},
		{
			name: "v2 abort-acked",
			record: func() firecrackerCheckpointOperationRecord {
				return schemaTestV2Witness(firecrackerCheckpointOperationPhaseAbortAcked)
			},
			fragments: []string{"already abort-acknowledged"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := tc.record()
			handler, instance, binding := schemaTestOperationInstance(t, record)
			before := schemaTestStateBytes(t, instance)

			err := handler.AbortCheckpointOperation(
				context.Background(), instance.snapshot().ID, binding,
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("abort of %s = %v, want ErrFailedPrecondition", tc.name, err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the phase policy: %v", err)
			}
			if after := schemaTestStateBytes(t, instance); string(before) != string(after) {
				t.Fatal("refused abort rewrote durable state")
			}
		})
	}
}

// TestAbortCheckpointOperationColdIntent drives the abort from a cold daemon:
// the identity, seal, and phase decisions are all made against the durable
// record before any recovery side effect, and the handback then completes
// against the live recorded source.
func TestAbortCheckpointOperationColdIntent(t *testing.T) {
	handler, sandboxID, _, command, state := coldCheckpointIntentFixture(t, "", nil)
	// The abort's resume and guest release need the incarnation's sockets:
	// the fake API reports the sandbox's instance id and the Paused state a
	// crashed-after-pause source is in.
	api := startFakeFirecrackerAPI(t, state.APIPath)
	api.setInstanceID(sandboxID)
	if err := api.pause(); err != nil {
		t.Fatal(err)
	}
	startFakeCheckpointAgent(t, state.VsockPath)
	fd := checkpointTestPidfd(t, command.Process.Pid)

	if err := handler.AbortCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	); err != nil {
		t.Fatalf("cold abort = %v", err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("cold abort resumed the source %d times, want 1", resumes)
	}
	handler.mu.RLock()
	aborted := handler.instances[sandboxID]
	handler.mu.RUnlock()
	assertLiveOwnedChild(t, aborted, fd, handler.binary, state.APIPath, sandboxID)
	disk, err := readFirecrackerState(state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after cold abort = %q", disk.CheckpointOperation.Phase)
	}
	aborted.markDeleting()

	// A sealed same-operation intent is refused cold — recover instead — with
	// no recovery side effect at all.
	t.Run("sealed same-operation intent", func(t *testing.T) {
		sealedDir, _, sealedBinding := sealIdentifiedCheckpointArtifactBinding(t, "gen-live")
		handler, sandboxID, readState, command, _ := coldCheckpointIntentFixture(t, sealedDir, nil)
		before := readState()

		err := handler.AbortCheckpointOperation(context.Background(), sandboxID, sealedBinding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("cold abort of a sealed intent = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "recover the operation instead of aborting") {
			t.Fatalf("refusal must demand recovery: %v", err)
		}
		assertColdRefusal(t, handler, sandboxID, before, readState, command.Process.Pid)
	})
}

// TestAbortCheckpointOperationLostReplyRetrySendsIdenticalRequest proves the
// host half of the retryable abort contract: after the guest release reply is
// lost, the retry re-sends the IDENTICAL full binding — never a legacy
// fallback — and both releases observe the durable aborting decision that was
// persisted before the resume could reach the guest. The guest-side receipt
// dedup itself is covered separately by the guest agent tests.
func TestAbortCheckpointOperationLostReplyRetrySendsIdenticalRequest(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	agent.mu.Lock()
	agent.refuseLegacyMessage = true
	agent.onAbort = func(firecrackerproto.CheckpointAbortRequest) (bool, error) {
		return true, nil // deliver the request, drop the reply
	}
	agent.mu.Unlock()

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if err == nil || !containsAll(err.Error(), "release Firecracker sandbox") {
		t.Fatalf("lost abort reply must fail the release: %v", err)
	}
	if !containsAll(err.Error(), "the guest error handoff is unconfirmed") {
		t.Fatalf("failure must report the unconfirmed release honestly: %v", err)
	}
	// The first release observed the durable aborting decision.
	assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
		t.Fatalf("durable phase after lost reply = %+v %v", disk.CheckpointOperation, readErr)
	}
	if !instance.snapshot().CheckpointOperation.retainsEvidence() {
		t.Fatal("lost reply released the in-memory evidence gate")
	}

	// The retry re-sends the identical request and completes.
	agent.mu.Lock()
	agent.onAbort = nil
	agent.mu.Unlock()
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort retry after lost reply = %v", err)
	}
	assertAbortObservations(t, agent, 2, binding,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborting)
	// No legacy message was ever sent: the legacy refusals stayed unanswered
	// because nothing fell back.
	if outcomes := agent.checkpointOutcomes(); len(outcomes) != 0 {
		t.Fatalf("abort fell back to the legacy message: %v", outcomes)
	}
	// The first attempt resumed the paused source exactly once; the retry
	// observes a Running instance through GET / and must NOT resume again —
	// resuming a running MicroVM is an error. The retry's idempotency is the
	// state-driven skip plus the guest receipt dedup above.
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("abort attempts resumed %d times, want exactly 1 across both attempts", resumes)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after retry = %+v %v", disk.CheckpointOperation, readErr)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
}

// TestAbortCheckpointOperationNoLegacyFallbackWhenAgentRefuses proves the
// runtime never degrades to the non-idempotent legacy error message when the
// guest agent rejects the retryable abort message: the abort stays failed
// with its aborting evidence retained, and a later attempt against an agent
// that understands the message completes through it.
func TestAbortCheckpointOperationNoLegacyFallbackWhenAgentRefuses(t *testing.T) {
	handler, instance, api, agent, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
	binding := testCheckpointOperationBinding("gen-live")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	agent.mu.Lock()
	agent.refuseAbortMessage = true
	agent.refuseLegacyMessage = true
	agent.mu.Unlock()

	err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding)
	if err == nil || !containsAll(err.Error(), "release Firecracker sandbox") {
		t.Fatalf("refused abort message must fail the release: %v", err)
	}
	// Nothing fell back: no legacy checkpoint message was sent, and the
	// guest-side refusal left the release unconfirmed with the aborting
	// evidence retained.
	if outcomes := agent.checkpointOutcomes(); len(outcomes) != 0 {
		t.Fatalf("runtime fell back to the legacy checkpoint message: %v", outcomes)
	}
	assertAbortObservations(t, agent, 1, binding, firecrackerCheckpointOperationPhaseAborting)
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborting {
		t.Fatalf("durable phase after refused message = %+v %v", disk.CheckpointOperation, readErr)
	}
	if !disk.CheckpointOperation.retainsEvidence() {
		t.Fatal("refused abort message released the evidence gate")
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("refused-message attempt resumed %d times, want 1", resumes)
	}

	// An agent that understands the message completes the same decision.
	agent.mu.Lock()
	agent.refuseAbortMessage = false
	agent.mu.Unlock()
	if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("abort retry with a capable agent = %v", err)
	}
	assertAbortObservations(t, agent, 2, binding)
	if outcomes := agent.checkpointOutcomes(); len(outcomes) != 0 {
		t.Fatalf("capable-agent retry still fell back: %v", outcomes)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAborted {
		t.Fatalf("durable phase after capable retry = %+v %v", disk.CheckpointOperation, readErr)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
}

// TestAckAbortedCheckpointOperationContract pins the abort acknowledgment:
// durable-first release for exactly the aborted (or already abort-acked)
// phases, no artifact requirement, no source effect, an in-memory gate that
// survives a failed write, and cold operation from the durable record.
func TestAckAbortedCheckpointOperationContract(t *testing.T) {
	// Phase refusals with a complete binding.
	for _, phase := range []string{
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked,
	} {
		t.Run("refuses/"+phase, func(t *testing.T) {
			record := schemaTestV2Witness(phase)
			handler, instance, binding := schemaTestOperationInstance(t, record)
			before := schemaTestStateBytes(t, instance)

			err := handler.AckAbortedCheckpointOperation(
				context.Background(), instance.snapshot().ID, binding,
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("abort ack of %s = %v, want ErrFailedPrecondition", phase, err)
			}
			if !containsAll(err.Error(), "not aborted") {
				t.Fatalf("refusal must name the abort-only policy: %v", err)
			}
			if after := schemaTestStateBytes(t, instance); string(before) != string(after) {
				t.Fatal("refused abort ack rewrote durable state")
			}
		})
	}
	// The legacy success-side phases of version 1 are refused identically.
	t.Run("refuses/v1-completed", func(t *testing.T) {
		record := schemaTestV1Witness(firecrackerCheckpointOperationPhaseCompleted)
		handler, instance, binding := schemaTestOperationInstance(t, record)
		if err := handler.AckAbortedCheckpointOperation(
			context.Background(), instance.snapshot().ID, binding,
		); !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("abort ack of a v1 completed record = %v, want ErrFailedPrecondition", err)
		}
	})

	// Live contract on a genuinely aborted operation: release, idempotent
	// retry, no source or artifact dependence, durable-first.
	t.Run("releases", func(t *testing.T) {
		handler, instance, api, _, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		binding := testCheckpointOperationBinding("gen-live")
		before := instance.snapshot()
		fd := checkpointTestPidfd(t, before.PID)
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatal(err)
		}
		resumesAfterAbort := api.countVMState("Resumed")

		if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("ack aborted = %v", err)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAbortAcked {
			t.Fatalf("durable phase after abort ack = %+v %v", disk.CheckpointOperation, readErr)
		}
		if disk.CheckpointOperation.retainsEvidence() {
			t.Fatal("abort-acked witness must not retain evidence")
		}
		// No source effect: nothing resumed, nothing stopped.
		if api.countVMState("Resumed") != resumesAfterAbort {
			t.Fatal("abort ack resumed the source")
		}
		assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
		// Idempotent retry.
		if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("idempotent abort ack = %v", err)
		}
		if err := handler.Delete(context.Background(), sandboxID); err != nil {
			t.Fatalf("delete after abort ack = %v", err)
		}
	})

	t.Run("persistence failure keeps gate", func(t *testing.T) {
		handler, instance, _, _, sandboxID, _ := checkpointIntentFixture(t, "gen-live")
		binding := testCheckpointOperationBinding("gen-live")
		before := instance.snapshot()
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatal(err)
		}
		repair := blockStateWrite(t, before)

		err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding)
		if err == nil || !containsAll(err.Error(), "persist abort acknowledgment") {
			t.Fatalf("abort ack did not reach the injected persistence failure: %v", err)
		}
		if !instance.snapshot().CheckpointOperation.retainsEvidence() {
			t.Fatal("abort ack persistence failed but the in-memory gate was released")
		}
		if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("delete after failed abort ack = %v, want the evidence-gate refusal", err)
		}
		repair(t)
		if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("abort ack after repair = %v", err)
		}
		disk, readErr := readFirecrackerState(before.BundlePath)
		if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAbortAcked {
			t.Fatalf("durable phase after repaired abort ack = %+v %v", disk.CheckpointOperation, readErr)
		}
	})

	t.Run("no artifact requirement and cold", func(t *testing.T) {
		handler, sandboxID, readState, _, state := coldCheckpointIntentFixture(t, "", nil)
		api := startFakeFirecrackerAPI(t, state.APIPath)
		api.setInstanceID(sandboxID)
		if err := api.pause(); err != nil {
			t.Fatal(err)
		}
		startFakeCheckpointAgent(t, state.VsockPath)
		binding := testCheckpointOperationBinding("gen-live")
		if err := handler.AbortCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatal(err)
		}
		// The caller-owned output directory is gone and the sandbox is cold:
		// the release works from the durable abort fact alone.
		if err := os.RemoveAll(state.CheckpointOperation.Directory); err != nil {
			t.Fatal(err)
		}
		handler.mu.Lock()
		delete(handler.instances, sandboxID)
		handler.mu.Unlock()
		before := readState()

		if err := handler.AckAbortedCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
			t.Fatalf("cold abort ack without the artifact = %v", err)
		}
		if after := readState(); string(before) == string(after) {
			t.Fatal("cold abort ack did not persist the release")
		}
		if resumes := api.countVMState("Resumed"); resumes != 1 {
			t.Fatalf("abort ack changed the source interaction count: %d", resumes)
		}
	})
}
