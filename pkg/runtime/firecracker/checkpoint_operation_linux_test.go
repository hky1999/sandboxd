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
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

var _ runtimecore.CheckpointOperationWitness = (*Handler)(nil)

// fakeVMMAPICall records one request the checkpoint flow made against the
// fake Firecracker API.
type fakeVMMAPICall struct {
	Method string
	Path   string
	State  string // the patched /vm state, empty for other calls
}

// fakeFirecrackerAPI stands up a unix HTTP server speaking the subset of the
// Firecracker API the checkpoint flow uses: GET / (InstanceInfo), PATCH /vm
// (pause/resume) with the real MicroVM state machine, and PUT
// /snapshot/create (which, like the real VMM, writes the component files the
// flow then seals). Every call is recorded so tests can prove flow ordering —
// in particular that a source was paused once and resumed only from Paused,
// never re-resumed while Running.
type fakeFirecrackerAPI struct {
	t *testing.T

	mu    sync.Mutex
	calls []fakeVMMAPICall
	// vmState is the MicroVM state GET / reports and PATCH /vm mutates. It
	// starts Running — the state every fixture's live source is in — and only
	// legal transitions move it: Paused from Running, Resumed from Paused.
	// Every other transition answers 400 exactly like the real VMM, so a
	// runtime bug that resumes a running source fails its test loudly.
	vmState string
	// instanceID is the id GET / reports; the fixture binds it to the sandbox
	// ID the way vmmCommand's --id argument does.
	instanceID string
	// failInstanceInfo makes GET / answer 500, the unreadable-source shape.
	failInstanceInfo bool
	// onSnapshotCreate runs exactly once inside the FIRST snapshot create
	// request, before its reply: the deterministic injection point between
	// the durable intent and the prepared promotion write. The hook must not
	// touch testing.T — it runs on the server goroutine — so it reports its
	// error through hookErr for the test goroutine to inspect.
	onSnapshotCreate func() error
	hookErr          error
	hookFired        bool
}

func startFakeFirecrackerAPI(t *testing.T, socket string) *fakeFirecrackerAPI {
	t.Helper()
	fake := &fakeFirecrackerAPI{t: t, vmState: firecrackerInstanceInfoStateRunning}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(fake.serve)}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		<-serverDone
		_ = os.Remove(socket)
	})
	return fake
}

// setInstanceID binds the id GET / reports. Fixtures set it to the sandbox ID
// so the production instance-id check has the real shape to verify.
func (fake *fakeFirecrackerAPI) setInstanceID(id string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.instanceID = id
}

// pause moves the fake MicroVM to Paused — the state a source is in after the
// checkpoint flow's pause request — so an abort fixture can model the
// post-pause crash window exactly. It reports the state actually left behind;
// pausing an already-paused source reports the refusal the real VMM gives.
func (fake *fakeFirecrackerAPI) pause() error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.vmState != firecrackerInstanceInfoStateRunning {
		return fmt.Errorf("fake VMM is %s, cannot pause", fake.vmState)
	}
	fake.vmState = firecrackerInstanceInfoStatePaused
	return nil
}

// setInstanceInfoFailure toggles GET / between serving InstanceInfo and
// answering 500, the shape of an unreadable source state.
func (fake *fakeFirecrackerAPI) setInstanceInfoFailure(fail bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.failInstanceInfo = fail
}

// forceVMState moves the fake MicroVM to an arbitrary raw state, including
// states outside the legal transition machine — the shape an unknown or
// transitional VMM state presents to the reconciliation paths.
func (fake *fakeFirecrackerAPI) forceVMState(state string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.vmState = state
}

// currentVMState reports the MicroVM state right now.
func (fake *fakeFirecrackerAPI) currentVMState() string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.vmState
}

// snapshotHookError returns the injection hook's result for the test
// goroutine to assert on.
func (fake *fakeFirecrackerAPI) snapshotHookError() error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.hookErr
}

// makeStateDirUnwritableFromHook is the background-safe form of
// makeStateDirUnwritable for injection hooks that run off the test
// goroutine: no testing.T, the error is the hook's return value.
func makeStateDirUnwritableFromHook(instance *firecrackerInstance) func() error {
	return func() error {
		dir := checkpointOperationStateDir(instance)
		if err := os.Chmod(dir, 0500); err != nil {
			return err
		}
		return nil
	}
}

func (fake *fakeFirecrackerAPI) serve(
	writer http.ResponseWriter,
	request *http.Request,
) {
	defer request.Body.Close()
	if request.Method == http.MethodGet && request.URL.Path == "/" {
		fake.mu.Lock()
		id, state, fail := fake.instanceID, fake.vmState, fake.failInstanceInfo
		fake.calls = append(fake.calls, fakeVMMAPICall{Method: request.Method, Path: request.URL.Path})
		fake.mu.Unlock()
		if fail {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"app_name":    "Firecracker",
			"id":          id,
			"state":       state,
			"vmm_version": "1.9.0-fake",
		})
		return
	}
	var payload map[string]any
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	call := fakeVMMAPICall{Method: request.Method, Path: request.URL.Path}
	if request.Method == http.MethodPatch && request.URL.Path == "/vm" {
		call.State, _ = payload["state"].(string)
		fake.mu.Lock()
		current := fake.vmState
		var next string
		switch call.State {
		case "Paused":
			// The real VMM pauses only a running instance.
			if current == firecrackerInstanceInfoStateRunning {
				next = firecrackerInstanceInfoStatePaused
			}
		case "Resumed":
			// The real VMM resumes only a paused instance; resuming a
			// running one is an error, not a no-op.
			if current == firecrackerInstanceInfoStatePaused {
				next = firecrackerInstanceInfoStateRunning
			}
		}
		if next == "" {
			fake.mu.Unlock()
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(fmt.Sprintf(
				`{"error":"invalid transition %s from %s"}`, call.State, current,
			)))
			return
		}
		fake.vmState = next
		fake.mu.Unlock()
	}
	if request.Method == http.MethodPut && request.URL.Path == "/snapshot/create" {
		for _, field := range []string{"snapshot_path", "mem_file_path"} {
			path, _ := payload[field].(string)
			if path == "" {
				fake.t.Errorf("snapshot create without %s", field)
				continue
			}
			if err := os.WriteFile(path, []byte(field+"\n"), 0600); err != nil {
				fake.t.Errorf("write fake snapshot component %s: %v", path, err)
			}
		}
		fake.mu.Lock()
		hook, fired := fake.onSnapshotCreate, fake.hookFired
		fake.hookFired = true
		fake.mu.Unlock()
		if hook != nil && !fired {
			// The hook's error never fails the reply: the injection targets
			// a later durable write, and the request still completes so the
			// flow reaches that write deterministically.
			if err := hook(); err != nil {
				fake.mu.Lock()
				fake.hookErr = err
				fake.mu.Unlock()
			}
		}
	}
	fake.mu.Lock()
	fake.calls = append(fake.calls, call)
	fake.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

func (fake *fakeFirecrackerAPI) recorded() []fakeVMMAPICall {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]fakeVMMAPICall(nil), fake.calls...)
}

func (fake *fakeFirecrackerAPI) countVMState(state string) int {
	count := 0
	for _, call := range fake.recorded() {
		if call.Path == "/vm" && call.State == state {
			count++
		}
	}
	return count
}

func (fake *fakeFirecrackerAPI) countSnapshotCreates() int {
	count := 0
	for _, call := range fake.recorded() {
		if call.Path == "/snapshot/create" {
			count++
		}
	}
	return count
}

// checkpointOperationFixture builds everything an identified stop-and-copy
// checkpoint needs to run the REAL flow against a live owned VMM-identity
// child: a mapped configured instance, a persisted generation-bound state
// file, handler-owned runtime and storage roots whose derived paths the
// delete flow validates, a digestible kernel, a writable layer to clone,
// chunks-mode seal settings so the sealed root binds through the shared root
// algorithm, a working VMM API socket, and a memory-writeback scheduler.
func checkpointOperationFixture(
	t *testing.T,
	generation string,
) (*Handler, *firecrackerInstance, *fakeFirecrackerAPI, string) {
	t.Helper()
	handler, instance := checkpointPersistenceFixture(t)
	instance.state.Generation = generation
	handler.instances = map[string]*firecrackerInstance{instance.state.ID: instance}
	kernel := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.kernelPath = kernel
	handler.storageRoot = t.TempDir()
	// The sandbox-derived socket directory hashes the sandbox ID; keep the
	// root short so the derived api.sock path stays under the kernel's unix
	// socket name limit even for long test names.
	shortRuntimeRoot, err := os.MkdirTemp(os.TempDir(), "fcop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortRuntimeRoot) })
	handler.runtimeRoot = shortRuntimeRoot
	runtimeDir := handler.runtimeDirectory(instance.state.ID)
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	storageDir := filepath.Join(handler.storageRoot, instance.state.ID)
	if err := os.Mkdir(storageDir, 0700); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(storageDir, "overlay.ext4")
	if err := os.WriteFile(overlayPath, []byte("overlay-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	instance.state.OverlayPath = overlayPath
	instance.state.APIPath = filepath.Join(runtimeDir, firecrackerAPISocket)
	instance.state.VsockPath = filepath.Join(runtimeDir, "absent-vsock.sock")
	handler.digestMemory = true
	handler.digestMemoryMode = checkpointchunks.FileDigestChunks
	handler.checkpointWriteback = newCheckpointWritebackScheduler()
	t.Cleanup(func() { close(handler.checkpointWriteback.queue) })
	spawnCheckpointOperationChild(t, handler, instance)
	api := startFakeFirecrackerAPI(t, instance.state.APIPath)
	api.setInstanceID(instance.state.ID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	return handler, instance, api, instance.state.ID
}

// spawnCheckpointOperationChild starts the owned VMM-identity child bound to
// the instance's already-configured socket paths, so fixtures control where
// the API socket lives while keeping the native argv/exe identity the
// runtime's process checks key on.
func spawnCheckpointOperationChild(
	t *testing.T,
	handler *Handler,
	instance *firecrackerInstance,
) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		t.Fatal(err)
	}
	handler.binary = binary
	command := handler.vmmCommand(instance.state.APIPath, instance.state.ID)
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
	instance.state.PID = command.Process.Pid
	if !firecrackerProcessMatches(instance.state.PID, binary, instance.state.APIPath, instance.state.ID) {
		t.Fatal("child identity mismatch")
	}
}

// checkpointOperationStateDir is the directory holding the persisted state
// file whose permissions gate the witness writes in fault tests.
func checkpointOperationStateDir(
	instance *firecrackerInstance,
) string {
	return filepath.Join(instance.state.BundlePath, firecrackerArtifactsDir)
}

// makeStateDirUnwritable blocks further state writes the way a failed or
// full disk would: the atomic write cannot create its temporary file. The
// directory stays readable so durable evidence remains observable.
func makeStateDirUnwritable(t *testing.T, instance *firecrackerInstance) {
	t.Helper()
	dir := checkpointOperationStateDir(instance)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
}

func makeStateDirWritable(instance *firecrackerInstance) {
	_ = os.Chmod(checkpointOperationStateDir(instance), 0700)
}

func testCheckpointOperationBinding(generation string) runtimecore.CheckpointOperationBinding {
	return runtimecore.CheckpointOperationBinding{
		OperationID:      "op-source-1",
		RequestDigest:    strings.Repeat("ab", 32),
		SourceGeneration: generation,
	}
}

// runIdentifiedCheckpoint executes the real identified stop-and-copy flow of
// the fixture and fails the test on an unexpected success.
func runIdentifiedCheckpoint(
	t *testing.T,
	handler *Handler,
	sandboxID, generation, directory string,
) error {
	t.Helper()
	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: directory,
		Operation: testCheckpointOperationBinding(generation),
	})
	if err == nil {
		t.Fatal("identified checkpoint unexpectedly succeeded")
	}
	return err
}

// sealIdentifiedCheckpointArtifact drives the real identified checkpoint flow
// on a disposable fixture and returns the sealed artifact directory with its
// bound root, giving recovery fixtures genuine evidence to reference.
func sealIdentifiedCheckpointArtifact(
	t *testing.T,
) (string, *checkpointroot.Binding) {
	t.Helper()
	handler, _, api, sandboxID := checkpointOperationFixture(t, "gen-seal")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: directory,
		Operation: testCheckpointOperationBinding("gen-seal"),
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
	return directory, root
}

// TestCheckpointOperationMustBeStopAndCopy pins the identified-operation
// admission shape at the runtime boundary: a binding with LeaveRunning is
// refused before any side effect, and so is an incomplete binding.
func TestCheckpointOperationMustBeStopAndCopy(t *testing.T) {
	handler, _, _, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instanceState(t, handler, sandboxID)
	fd := checkpointTestPidfd(t, before.PID)

	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:           sandboxID,
		Directory:    directory,
		LeaveRunning: true,
		Operation:    testCheckpointOperationBinding("gen-live"),
	})
	if !errors.Is(err, errord.ErrInvalidArgument) {
		t.Fatalf("leave-running identified checkpoint = %v, want ErrInvalidArgument", err)
	}
	if !containsAll(err.Error(), "must be stop-and-copy") {
		t.Fatalf("refusal must name the contract: %v", err)
	}
	// The refusal predates the lookup: no output directory, no pause, no
	// state mutation, and the source is untouched.
	assertNoCheckpointSideEffects(t, directory, handler, before, fd)
}

// TestCheckpointOperationIncompleteOrMismatchedBindingRejected proves the
// operation binding is validated against the runtime's own persisted identity
// before any checkpoint side effect, exactly like the generation expectation.
func TestCheckpointOperationIncompleteOrMismatchedBindingRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		binding   runtimecore.CheckpointOperationBinding
		wantErr   error
		fragments []string
	}{
		{
			name:    "missing operation id",
			binding: runtimecore.CheckpointOperationBinding{RequestDigest: strings.Repeat("ab", 32), SourceGeneration: "gen-live"},
			wantErr: errord.ErrInvalidArgument,
		},
		{
			name:    "missing request digest",
			binding: runtimecore.CheckpointOperationBinding{OperationID: "op-source-1", SourceGeneration: "gen-live"},
			wantErr: errord.ErrInvalidArgument,
		},
		{
			name:    "missing source generation",
			binding: runtimecore.CheckpointOperationBinding{OperationID: "op-source-1", RequestDigest: strings.Repeat("ab", 32)},
			wantErr: errord.ErrInvalidArgument,
		},
		{
			name: "mismatched source generation",
			binding: runtimecore.CheckpointOperationBinding{
				OperationID:      "op-source-1",
				RequestDigest:    strings.Repeat("ab", 32),
				SourceGeneration: "gen-other",
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{`"gen-live"`, `"gen-other"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _, sandboxID := checkpointOperationFixture(t, "gen-live")
			directory := filepath.Join(t.TempDir(), "checkpoint")
			before := instanceState(t, handler, sandboxID)
			fd := checkpointTestPidfd(t, before.PID)

			err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
				ID:        sandboxID,
				Directory: directory,
				Operation: tc.binding,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("identified checkpoint = %v, want %v", err, tc.wantErr)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must report the exact identity: %v", err)
			}
			assertNoCheckpointSideEffects(t, directory, handler, before, fd)
		})
	}
}

func instanceState(t *testing.T, handler *Handler, sandboxID string) firecrackerPersistedState {
	t.Helper()
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		t.Fatalf("sandbox %s is not mapped", sandboxID)
	}
	return instance.snapshot()
}

func assertNoCheckpointSideEffects(
	t *testing.T,
	directory string,
	handler *Handler,
	before firecrackerPersistedState,
	fd int,
) {
	t.Helper()
	if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("rejected checkpoint touched the output directory: %v", statErr)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("rejected checkpoint stopped the source")
	}
	after := instanceState(t, handler, before.ID)
	if after != before {
		t.Fatalf("rejected checkpoint mutated runtime state: %+v", after)
	}
	disk, err := readFirecrackerState(before.BundlePath)
	if err != nil || disk != before {
		t.Fatalf("rejected checkpoint mutated persisted state: %+v %v", disk, err)
	}
}

// TestCheckpointOperationRealFlowReachesCompletedWitness drives the complete
// identified flow — pause, clone, snapshot, seal, root bind, identity capture,
// prepared witness, stop, completion — against the fake VMM API and a live
// owned child, then proves the durable evidence and the ack-gated retirement.
func TestCheckpointOperationRealFlowReachesCompletedWitness(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: directory,
		Operation: testCheckpointOperationBinding("gen-live"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Flow ordering: exactly one pause, one snapshot, and never a resume.
	if pauses := api.countVMState("Paused"); pauses != 1 {
		t.Fatalf("pause calls = %d, want 1", pauses)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("snapshot create calls = %d, want 1", snapshots)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("stop-and-copy checkpoint resumed the source %d times", resumes)
	}
	// The source stopped before completion was declared.
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("completed operation returned before the kernel exit notification")
	}
	// Durable evidence: a sealed artifact root and a completed witness bound
	// to the exact operation and incarnation. The witness is the version-2
	// record promoted from the durable intent: it keeps the directory birth
	// identity and source birth captured before any side effect.
	root, err := checkpointroot.Bind(directory)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := readFirecrackerState(before.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	witness := disk.CheckpointOperation
	if witness.Phase != firecrackerCheckpointOperationPhaseCompleted {
		t.Fatalf("durable witness phase = %q, want completed", witness.Phase)
	}
	if witness.Version != firecrackerCheckpointOperationRecordVersion3 {
		t.Fatalf("durable witness version = %d, want %d", witness.Version, firecrackerCheckpointOperationRecordVersion3)
	}
	if witness.SandboxID != sandboxID {
		t.Fatalf("witness sandbox identity = %q, want %q", witness.SandboxID, sandboxID)
	}
	// The claim is durable ownership metadata of the output directory, never
	// artifact content: it binds this exact operation and survives the sealed
	// artifact beside it.
	claim, claimErr := readFirecrackerCheckpointClaim(directory)
	if claimErr != nil {
		t.Fatalf("sealed output carries no usable claim: %v", claimErr)
	}
	if claim.SandboxID != sandboxID || claim.OperationID != witness.OperationID ||
		claim.RequestDigest != witness.RequestDigest ||
		claim.SourceGeneration != witness.SourceGeneration ||
		claim.Directory != witness.Directory ||
		claim.DirectoryDev != witness.DirectoryDev ||
		claim.DirectoryInode != witness.DirectoryInode {
		t.Fatalf("claim drifted from the witness binding: claim %+v witness %+v", claim, witness)
	}
	if stat, statErr := os.Stat(directory); statErr != nil {
		t.Fatal(statErr)
	} else if unixStat, ok := stat.Sys().(*syscall.Stat_t); !ok ||
		witness.DirectoryDev != uint64(unixStat.Dev) ||
		witness.DirectoryInode != unixStat.Ino {
		t.Fatalf("witness directory identity drifted from the reserved output: %+v", witness)
	}
	if witness.OperationID != "op-source-1" ||
		witness.RequestDigest != strings.Repeat("ab", 32) ||
		witness.SourceGeneration != "gen-live" {
		t.Fatalf("witness binding drifted: %+v", witness)
	}
	if witness.RootDigest != root.RootDigest || witness.RootScheme != root.Scheme {
		t.Fatalf("witness root %s (%s) does not bind the sealed directory %s (%s)",
			witness.RootDigest, witness.RootScheme, root.RootDigest, root.Scheme)
	}
	if witness.VMMPID != before.PID || witness.VMMAPIPath != before.APIPath {
		t.Fatalf("witness did not capture the source identity: %+v", witness)
	}
	if !disk.Exited || disk.ExitCode != 0 {
		t.Fatalf("completed operation did not record the source exit: %+v", disk)
	}
	// The evidence-retention gate holds until the service acknowledges.
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete before ack = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); err != nil {
		t.Fatalf("ack = %v, err", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete after ack = %v", err)
	}
	if _, err := os.Stat(checkpointOperationStateDir(instance)); !os.IsNotExist(err) {
		t.Fatalf("state directory survived retirement: %v", err)
	}
}

// TestCheckpointOperationPreparedWitnessWriteFailureKeepsPauseAndArtifacts
// injects the ambiguity the prepared write must survive: the durable intent
// lands first, then the state write fails after the artifact is sealed, and
// its durability is unknown. The source must never be resumed, the sealed
// artifact must be retained, the in-memory constraint must bind this daemon,
// and both a new checkpoint and the evidence-clearing delete must stay
// blocked.
func TestCheckpointOperationPreparedWitnessWriteFailureKeepsPauseAndArtifacts(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	// The injection lands inside the FIRST snapshot request, before its
	// reply: the intent is already durable at that point and the prepared
	// promotion write has not run — exactly the 1405 window — without any
	// phase polling.
	api.onSnapshotCreate = makeStateDirUnwritableFromHook(instance)
	t.Cleanup(func() { makeStateDirWritable(instance) })

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if hookErr := api.snapshotHookError(); hookErr != nil {
		t.Fatalf("snapshot injection failed: %v", hookErr)
	}
	if !containsAll(err.Error(), "persist prepared checkpoint operation witness") {
		t.Fatalf("failure must name the ambiguous prepared write: %v", err)
	}
	// The write may have committed, so the failure path never resumed: one
	// pause, one snapshot, zero resumes, and the source is still alive.
	if pauses := api.countVMState("Paused"); pauses != 1 {
		t.Fatalf("pause calls = %d, want 1", pauses)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("ambiguous prepared write resumed the source %d times", resumes)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("source was stopped after an ambiguous prepared write")
	}
	// The sealed artifact is retained as the operation's evidence.
	if _, statErr := os.Stat(filepath.Join(directory, firecrackerCheckpointManifestName)); statErr != nil {
		t.Fatalf("sealed artifact was discarded: %v", statErr)
	}
	// The prepared-promotion write never landed, but the durable early
	// intent from before the side effects did: the disk keeps the intent
	// while the in-memory witness binds this daemon fail-closed at prepared.
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
		t.Fatalf("durable witness state = %+v %v, want the durable intent", disk.CheckpointOperation, readErr)
	}
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("in-memory witness phase = %q, want prepared", phase)
	}
	// A legacy checkpoint and both deletes stay blocked by the constraint.
	makeStateDirWritable(instance)
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint-retry"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("legacy checkpoint after prepared evidence = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after prepared evidence = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-live"); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("strict delete after prepared evidence = %v, want ErrFailedPrecondition", err)
	}
	if snapshotRetries := api.countSnapshotCreates(); snapshotRetries != 1 {
		t.Fatalf("blocked retries took %d snapshots, want 1", snapshotRetries)
	}
	assertLiveOwnedChild(t, instance, fd, handler.binary, before.APIPath, sandboxID)
}

// TestCheckpointOperationStopPhaseFailureRetainsPreparedEvidence fails the
// stop-source phase after the witness is durable: a tracked uffd handler
// whose exit cannot be confirmed keeps the operation at prepared with the
// sealed artifact retained, the VMM stop already confirmed, and the same
// operation retryable through recovery — never resumed, never re-snapshotted.
func TestCheckpointOperationStopPhaseFailureRetainsPreparedEvidence(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	// An intent-only uffd record: no captured process identity, so its exit
	// can never be confirmed — the honest post-stop failure shape.
	instance.state.Uffd = firecrackerUffdRecord{
		Version: firecrackerUffdRecordVersion,
		Phase:   firecrackerUffdPhasePending,
		Socket:  filepath.Join(instance.state.BundlePath, "uffd.sock"),
	}
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if !containsAll(err.Error(), "confirm uffd handler exit") {
		t.Fatalf("failure must name the unconfirmed stop phase: %v", err)
	}
	// Ordering: the VMM stop ran and was confirmed before the failure.
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("stop-phase failure preceded the VMM stop")
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("stop-phase failure resumed the source %d times", resumes)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("stop-phase failure re-took snapshots: %d", snapshots)
	}
	// The durable witness stays prepared; no completion was declared.
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("durable witness phase = %q, want prepared", disk.CheckpointOperation.Phase)
	}
	if disk.Exited {
		t.Fatalf("unconfirmed stop was recorded as an exit: %+v", disk)
	}
	if _, statErr := os.Stat(filepath.Join(directory, firecrackerCheckpointManifestName)); statErr != nil {
		t.Fatalf("sealed artifact was discarded: %v", statErr)
	}
	// The same operation retries through recovery and fails on the same
	// boundary without taking another snapshot or touching the artifact.
	_, recoverErr := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if recoverErr == nil || !containsAll(recoverErr.Error(), "confirm uffd handler exit") {
		t.Fatalf("recovery retried the wrong boundary: %v", recoverErr)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("recovery re-took snapshots: %d", snapshots)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("recovery mutated retained evidence: %+v %v", disk, readErr)
	}
}

// TestCheckpointOperationIgnoreTermChild is the child entry used by the
// completed-witness failure test: it ignores SIGTERM so the stop phase takes
// its full graceful window, giving the test a deterministic observation point
// between the durable prepared write and the completed write.
func TestCheckpointOperationIgnoreTermChild(t *testing.T) {
	if os.Getenv("AKERNEL_CHECKPOINT_OP_CHILD") == "1" {
		signal.Ignore(syscall.SIGTERM)
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{binary: binary}
	apiPath := filepath.Join(t.TempDir(), "api.sock")
	command := handler.vmmCommand(apiPath, "ignore-term-child")
	command.Args = append([]string{binary, "-test.run=^TestCheckpointOperationIgnoreTermChild$", "--"}, command.Args[1:]...)
	command.Env = append(os.Environ(), "AKERNEL_CHECKPOINT_OP_CHILD=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child readiness %q: %v", line, err)
	}
	if !firecrackerProcessMatches(command.Process.Pid, binary, apiPath, "ignore-term-child") {
		t.Fatal("ignore-term child lost its native identity")
	}
}

// startCheckpointOperationIgnoreTermChild spawns the SIGTERM-ignoring
// VMM-identity child bound to the fixture instance's API path.
func startCheckpointOperationIgnoreTermChild(
	t *testing.T,
	handler *Handler,
	instance *firecrackerInstance,
) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		t.Fatal(err)
	}
	handler.binary = binary
	command := handler.vmmCommand(instance.state.APIPath, instance.state.ID)
	command.Args = append([]string{binary, "-test.run=^TestCheckpointOperationIgnoreTermChild$", "--"}, command.Args[1:]...)
	command.Env = append(os.Environ(), "AKERNEL_CHECKPOINT_OP_CHILD=1")
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
	instance.state.PID = command.Process.Pid
}

// TestCheckpointOperationCompletedWitnessWriteFailureRetainsEvidence fails
// the completed write after the stop is confirmed: the durable record stays
// prepared, the error keeps the operation unrecoverable-as-success until a
// retry, and a later recovery of the same binding resolves from the
// completion this daemon already holds — with zero new snapshots.
func TestCheckpointOperationCompletedWitnessWriteFailureRetainsEvidence(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	// Replace the ordinary child with one that ignores SIGTERM, widening the
	// stop phase so the failure injection lands deterministically between
	// the durable prepared write and the completed write.
	instance.state.PID = 0
	startCheckpointOperationIgnoreTermChild(t, handler, instance)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	witnessDurable := make(chan struct{})
	go func() {
		defer close(witnessDurable)
		for {
			state, err := readFirecrackerState(before.BundlePath)
			if err == nil && state.CheckpointOperation.Phase ==
				firecrackerCheckpointOperationPhasePrepared {
				makeStateDirUnwritable(t, instance)
				return
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	<-witnessDurable
	if !containsAll(err.Error(), "persist completed checkpoint operation witness") {
		t.Fatalf("failure must name the unconfirmed completed write: %v", err)
	}
	// The stop itself was confirmed before the failed write.
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("completed-write failure preceded the confirmed stop")
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("completed-write failure resumed the source %d times", resumes)
	}
	// Durable evidence is retained at prepared; completion was never declared
	// on disk, and the sealed artifact survives.
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("durable witness phase = %q, want prepared", disk.CheckpointOperation.Phase)
	}
	if _, statErr := os.Stat(filepath.Join(directory, firecrackerCheckpointManifestName)); statErr != nil {
		t.Fatalf("sealed artifact was discarded: %v", statErr)
	}
	// The unpublished completion is equally absent from daemon memory: the
	// record stays prepared and the instance unfinished, so success cannot
	// be replayed while the durable fact is missing.
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("failed completion published phase %q in memory", phase)
	}
	if instance.snapshot().Exited {
		t.Fatal("failed completion published the terminal exit in memory")
	}
	// Repaired storage: recovery of the same binding persists the completion
	// for real — stop already confirmed — and returns the recorded root with
	// zero new snapshots.
	makeStateDirWritable(instance)
	completion, recoverErr := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if recoverErr != nil {
		t.Fatalf("recovery after repaired storage = %v", recoverErr)
	}
	if completion.RootDigest != disk.CheckpointOperation.RootDigest ||
		completion.RootScheme != disk.CheckpointOperation.RootScheme {
		t.Fatalf("recovery returned %s (%s), want the recorded root", completion.RootDigest, completion.RootScheme)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted || !disk.Exited {
		t.Fatalf("durable completion after repaired retry = %+v %v", disk.CheckpointOperation, readErr)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("recovery re-took snapshots: %d", snapshots)
	}
}

// coldCheckpointOperationFixture persists a recoverable incarnation with an
// operation witness under a handler whose in-memory map is EMPTY. Any cold
// path that reaches recoverState betrays itself by rewriting the state file
// and mapping the instance.
func coldCheckpointOperationFixture(
	t *testing.T,
	mutateWitness func(record *firecrackerCheckpointOperationRecord),
) (*Handler, string, func() []byte, *exec.Cmd, firecrackerPersistedState) {
	t.Helper()
	directory, root := sealIdentifiedCheckpointArtifact(t)
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
	const sandboxID = "cold-operation-source"
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
	state := firecrackerPersistedState{
		ID:          sandboxID,
		PID:         command.Process.Pid,
		BundlePath:  filepath.Join(handler.sandboxRoot, sandboxID),
		APIPath:     apiPath,
		VsockPath:   filepath.Join(runtimeDir, firecrackerVsock),
		OverlayPath: filepath.Join(overlayDir, "overlay.ext4"),
		Generation:  "gen-live",
		MemoryMiB:   512,
		Vcpus:       2,
		Configured:  true,
		CheckpointOperation: firecrackerCheckpointOperationRecord{
			Version:          firecrackerCheckpointOperationRecordVersion,
			Phase:            firecrackerCheckpointOperationPhasePrepared,
			OperationID:      "op-source-1",
			RequestDigest:    strings.Repeat("ab", 32),
			SourceGeneration: "gen-live",
			RootDigest:       root.RootDigest,
			RootScheme:       root.Scheme,
			Directory:        directory,
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
		state: state,
		done:  make(chan struct{}),
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

// assertColdRefusal proves a cold-path refusal observed the durable record
// without triggering any recovery side effect.
func assertColdRefusal(
	t *testing.T,
	handler *Handler,
	sandboxID string,
	before []byte,
	readState func() []byte,
	pid int,
) {
	t.Helper()
	if after := readState(); string(before) != string(after) {
		t.Fatalf("refused recovery rewrote durable state:\nbefore: %s\nafter:  %s", before, after)
	}
	handler.mu.RLock()
	_, mapped := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("refused recovery mapped the instance")
	}
	if checkpointTestExitReady(t, checkpointTestPidfd(t, pid)) {
		t.Fatal("refused recovery stopped the recorded source")
	}
}

// TestRecoverCheckpointOperationColdPreparedCompletesOriginalStop drives the
// daemon-crash reconciliation of a durable prepared witness with a live
// source: the binding, artifact root, and boot are verified cold before any
// recovery side effect, then the ORIGINAL stop is completed — no snapshot, no
// artifact allocation, no resume — and the completion becomes durable.
func TestRecoverCheckpointOperationColdPreparedCompletesOriginalStop(t *testing.T) {
	handler, sandboxID, _, command, state := coldCheckpointOperationFixture(t, nil)
	sealedDir := state.CheckpointOperation.Directory
	beforeEntries := directoryEntries(t, sealedDir)

	completion, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if completion.RootDigest != state.CheckpointOperation.RootDigest ||
		completion.RootScheme != state.CheckpointOperation.RootScheme {
		t.Fatalf("completion = %s (%s), want the recorded root", completion.RootDigest, completion.RootScheme)
	}
	// The original stop completed against the exact recorded process.
	fd := checkpointTestPidfd(t, command.Process.Pid)
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("recovery returned before the recorded source's kernel exit notification")
	}
	// The durable completion is bound to the original operation.
	disk, err := readFirecrackerState(state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted {
		t.Fatalf("durable witness phase = %q, want completed", disk.CheckpointOperation.Phase)
	}
	if disk.CheckpointOperation.OperationID != "op-source-1" ||
		disk.CheckpointOperation.RootDigest != state.CheckpointOperation.RootDigest {
		t.Fatalf("completion drifted from the original binding: %+v", disk.CheckpointOperation)
	}
	if !disk.Exited {
		t.Fatal("recovered completion did not record the source exit")
	}
	// Zero snapshot: the sealed evidence directory is untouched and no VMM
	// API was ever needed — this fixture has no API socket at all.
	if after := directoryEntries(t, sealedDir); after != beforeEntries {
		t.Fatalf("recovery touched the sealed artifact directory:\nbefore: %s\nafter:  %s", beforeEntries, after)
	}
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		t.Fatal("recovery did not map the instance")
	}
	instance.markDeleting()
}

// TestRecoverCheckpointOperationCompletedRecordIsPureQuery proves the
// completed branch returns the original binding's recorded result with zero
// further work: with the source already gone, nothing is stopped, signalled,
// or rewritten — not even the state file.
func TestRecoverCheckpointOperationCompletedRecordIsPureQuery(t *testing.T) {
	handler, sandboxID, readState, command, state := coldCheckpointOperationFixture(
		t, func(record *firecrackerCheckpointOperationRecord) {
			record.Phase = firecrackerCheckpointOperationPhaseCompleted
		},
	)
	stopCheckpointPersistenceChild(t, command)
	before := readState()

	completion, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if completion.RootDigest != state.CheckpointOperation.RootDigest ||
		completion.RootScheme != state.CheckpointOperation.RootScheme {
		t.Fatalf("completion = %s (%s), want the recorded root", completion.RootDigest, completion.RootScheme)
	}
	if after := readState(); string(before) != string(after) {
		t.Fatal("completed recovery rewrote durable state")
	}
}

// TestRecoverCheckpointOperationRefusesNonMatchingWitness pins the fail-closed
// boundary of the reconciliation: a missing record, a mismatched binding or
// generation, a corrupted witness, a drifted or vanished artifact root, and a
// changed host boot are all refused before any recovery side effect.
func TestRecoverCheckpointOperationRefusesNonMatchingWitness(t *testing.T) {
	otherRoot := strings.Repeat("cd", 32)
	for _, tc := range []struct {
		name      string
		mutate    func(*firecrackerCheckpointOperationRecord)
		binding   func(generation string) runtimecore.CheckpointOperationBinding
		wantErr   error
		fragments []string
	}{
		{
			name: "wrong operation id",
			binding: func(generation string) runtimecore.CheckpointOperationBinding {
				binding := testCheckpointOperationBinding(generation)
				binding.OperationID = "op-other"
				return binding
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"op-source-1", "op-other"},
		},
		{
			name: "wrong request digest",
			binding: func(generation string) runtimecore.CheckpointOperationBinding {
				binding := testCheckpointOperationBinding(generation)
				binding.RequestDigest = strings.Repeat("cd", 32)
				return binding
			},
			wantErr: errord.ErrFailedPrecondition,
		},
		{
			name: "wrong source generation",
			binding: func(string) runtimecore.CheckpointOperationBinding {
				return testCheckpointOperationBinding("gen-other")
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{`"gen-live"`, `"gen-other"`},
		},
		{
			name: "corrupted record version",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				// Versions 2 and 3 are real schemas now; a genuinely unknown
				// version must stay the unsupported-version refusal.
				record.Version = firecrackerCheckpointOperationRecordVersion3 + 1
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"unsupported checkpoint operation record version"},
		},
		{
			name: "drifted artifact root",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.RootDigest = otherRoot
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"now binds"},
		},
		{
			name: "vanished artifact directory",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.Directory = filepath.Join(record.Directory, "gone")
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"no longer verifiable"},
		},
		{
			name: "mismatched api path",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.VMMAPIPath = filepath.Join(record.VMMAPIPath, "rewritten")
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"incarnation state carries"},
		},
		{
			name: "rewritten uffd identity",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.Uffd = firecrackerUffdRecord{
					Version: firecrackerUffdRecordVersion,
					Phase:   firecrackerUffdPhasePending,
					Socket:  filepath.Join(record.Directory, "uffd.sock"),
				}
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"uffd handler identity"},
		},
		{
			name: "changed host boot",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.VMMBootID = uuid.New().String()
			},
			wantErr:   errord.ErrFailedPrecondition,
			fragments: []string{"refuses to reconcile across a host reboot"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, sandboxID, readState, command, _ := coldCheckpointOperationFixture(t, tc.mutate)
			before := readState()
			binding := tc.binding
			if binding == nil {
				binding = testCheckpointOperationBinding
			}

			_, err := handler.RecoverCheckpointOperation(
				context.Background(), sandboxID, binding("gen-live"),
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("recovery = %v, want %v", err, tc.wantErr)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("refusal must name the boundary: %v", err)
			}
			assertColdRefusal(t, handler, sandboxID, before, readState, command.Process.Pid)
		})
	}

	t.Run("missing witness record", func(t *testing.T) {
		handler, sandboxID, readState, command, state := coldCheckpointOperationFixture(t, nil)
		before := readState()
		// Drop the witness from the durable state: a plain legacy sandbox.
		disk := state
		disk.CheckpointOperation = firecrackerCheckpointOperationRecord{}
		if err := handler.persistInstance(&firecrackerInstance{state: disk, done: make(chan struct{})}); err != nil {
			t.Fatal(err)
		}
		before = readState()

		_, err := handler.RecoverCheckpointOperation(
			context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
		)
		if !errors.Is(err, errord.ErrNotFound) {
			t.Fatalf("recovery without witness = %v, want ErrNotFound", err)
		}
		assertColdRefusal(t, handler, sandboxID, before, readState, command.Process.Pid)
	})

	t.Run("missing sandbox state", func(t *testing.T) {
		handler := &Handler{
			sandboxRoot: t.TempDir(),
			instances:   make(map[string]*firecrackerInstance),
		}
		_, err := handler.RecoverCheckpointOperation(
			context.Background(), "never-existed", testCheckpointOperationBinding("gen-live"),
		)
		if !errors.Is(err, errord.ErrNotFound) {
			t.Fatalf("recovery of unknown sandbox = %v, want ErrNotFound", err)
		}
	})
}

// TestRecoverCheckpointOperationRefusesReusedPID proves the birth-identity
// contract of the reconciliation: a recorded start time that no longer
// describes the live PID is never signalled, the recorded process's outcome
// stays unknown, and the retained evidence is left in place.
func TestRecoverCheckpointOperationRefusesReusedPID(t *testing.T) {
	handler, sandboxID, _, _, state := coldCheckpointOperationFixture(
		t, func(record *firecrackerCheckpointOperationRecord) {
			record.VMMStartTime++
		},
	)
	fd := checkpointTestPidfd(t, state.PID)

	_, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err == nil || !containsAll(err.Error(), "refusing to signal a reused pid") {
		t.Fatalf("recovery with a recycled birth = %v, want refusal", err)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("recovery signalled a process the witness did not record")
	}
	disk, readErr := readFirecrackerState(state.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("refused recovery mutated retained evidence: %+v %v", disk, readErr)
	}
}

// TestCheckpointOperationEvidenceBlocksUntilAcknowledged runs the retention
// gate end to end on a durable prepared witness with a live source: legacy
// and strict deletes and new checkpoints are refused, a wrong acknowledgment
// is refused, the matching acknowledgment is idempotent, and only after it
// does the original generation's delete retire the sandbox.
func TestCheckpointOperationEvidenceBlocksUntilAcknowledged(t *testing.T) {
	handler, sandboxID, readState, _, state := coldCheckpointOperationFixture(t, nil)
	// Map the instance without running recovery's monitors: the retention
	// gate must hold on the durable record either way.
	handler.instances[sandboxID] = handler.recoverState(state)
	fd := checkpointTestPidfd(t, state.PID)
	before := readState()

	retryDirectory := filepath.Join(t.TempDir(), "checkpoint-retry")
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: retryDirectory,
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("legacy checkpoint against retained evidence = %v, want ErrFailedPrecondition", err)
	}
	if _, statErr := os.Stat(retryDirectory); !os.IsNotExist(statErr) {
		t.Fatalf("blocked checkpoint touched its output directory: %v", statErr)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("legacy delete against retained evidence = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-live"); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("strict delete against retained evidence = %v, want ErrFailedPrecondition", err)
	}
	if after := readState(); string(before) != string(after) {
		t.Fatal("blocked operations rewrote the durable evidence")
	}
	assertLiveOwnedChild(t, handler.instances[sandboxID], fd, handler.binary, state.APIPath, sandboxID)

	wrong := testCheckpointOperationBinding("gen-live")
	wrong.OperationID = "op-other"
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, wrong); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("wrong-binding ack = %v, want ErrFailedPrecondition", err)
	}

	// A prepared witness is not acknowledgeable: the stop it owes has not
	// been completed, and no internal caller may release that constraint.
	if ackErr := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); !errors.Is(ackErr, errord.ErrFailedPrecondition) || !containsAll(ackErr.Error(), "not completed") {
		t.Fatalf("ack of a prepared witness = %v, want the not-completed refusal", ackErr)
	}

	// Recover the operation first: the same binding completes the original
	// stop — the recorded source leaves — and only then may the service's
	// acknowledgment release the gate.
	completion, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err != nil {
		t.Fatalf("recover before ack = %v", err)
	}
	if completion.RootDigest != state.CheckpointOperation.RootDigest {
		t.Fatalf("recovered root %s, want the recorded %s", completion.RootDigest, state.CheckpointOperation.RootDigest)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("recovery returned before the recorded source's kernel exit notification")
	}
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); err != nil {
		t.Fatalf("matching ack after recovery = %v", err)
	}
	disk, err := readFirecrackerState(state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAcked {
		t.Fatalf("durable witness phase = %q, want acked", disk.CheckpointOperation.Phase)
	}
	// Idempotent: a lost reply may be retried and observes success.
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); err != nil {
		t.Fatalf("idempotent ack = %v", err)
	}

	// Acknowledged: the original generation's delete now retires the sandbox
	// and its evidence.
	if err := handler.DeleteStrict(context.Background(), sandboxID, "gen-live"); err != nil {
		t.Fatalf("delete after ack = %v", err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("delete after ack returned before the kernel exit notification")
	}
	if _, err := os.Stat(filepath.Join(state.BundlePath, firecrackerArtifactsDir)); !os.IsNotExist(err) {
		t.Fatalf("evidence survived retirement: %v", err)
	}
	// After retirement the durable record is gone: a further ack observes
	// absence rather than fabricating a release (the service's durable
	// receipt is the authority by then).
	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("ack after retirement = %v, want ErrNotFound", err)
	}
}

// TestAckCheckpointOperationAllowsRemovedArtifactDirectory pins the
// acknowledgment's scope: it releases evidence retention for a service that
// already durably recorded SUCCEEDED, so a caller-owned artifact directory
// legitimately removed after that success must not wedge the sandbox's
// retirement behind the evidence gate.
func TestAckCheckpointOperationAllowsRemovedArtifactDirectory(t *testing.T) {
	handler, sandboxID, _, _, state := coldCheckpointOperationFixture(
		t, func(record *firecrackerCheckpointOperationRecord) {
			record.Phase = firecrackerCheckpointOperationPhaseCompleted
		},
	)
	if err := os.RemoveAll(state.CheckpointOperation.Directory); err != nil {
		t.Fatal(err)
	}
	handler.instances[sandboxID] = handler.recoverState(state)

	if err := handler.AckCheckpointOperation(context.Background(), sandboxID, testCheckpointOperationBinding("gen-live")); err != nil {
		t.Fatalf("ack with the artifact directory removed = %v, want nil", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("delete after ack = %v", err)
	}
	// The recovery, in contrast, still refuses: completing an operation whose
	// sealed evidence vanished is not this path's to guess. (A fresh ack
	// matches only the retired sandbox's absence.)
	_, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if !errors.Is(err, errord.ErrNotFound) {
		t.Fatalf("recovery after retirement = %v, want ErrNotFound", err)
	}
}

// blockStateWrite replaces the persisted state file with a directory so the
// atomic rename inside every state write fails — even as root — while the
// state stays readable through the blocked path. The returned repair function
// restores the exact previous bytes and fails if they drifted, proving no
// writer persisted anything while writes were blocked.
func blockStateWrite(
	t *testing.T,
	state firecrackerPersistedState,
) func(t *testing.T) {
	t.Helper()
	path := filepath.Join(
		state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename,
	)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".blocked"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
		_ = os.Rename(path+".blocked", path)
	})
	return func(t *testing.T) {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".blocked", path); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Fatalf("durable state drifted while writes were blocked:\nbefore: %s\nafter:  %s", before, after)
		}
	}
}

// chooseVacantPID returns a recorded-PID shape no live process holds, for
// synthetic witness fixtures that must never touch a real process.
func chooseVacantPID(t *testing.T) int {
	t.Helper()
	for pid := 4194000; pid < 4195000; pid++ {
		if syscall.Kill(pid, 0) != nil {
			return pid
		}
	}
	t.Fatal("no vacant synthetic pid found")
	return 0
}

// TestAckPersistenceFailureKeepsEvidenceGate is the 1190 review regression:
// when the acknowledgment's durable write fails, the in-memory evidence gate
// must stay in force exactly as the error claims — never released from
// daemon memory alone. Repairing the storage and retrying then releases it
// durably.
func TestAckPersistenceFailureKeepsEvidenceGate(t *testing.T) {
	handler, instance := checkpointPersistenceFixture(t)
	binding := testCheckpointOperationBinding("review-generation")
	bootID, err := readFirecrackerBootID()
	if err != nil {
		t.Fatal(err)
	}
	state := instance.snapshot()
	state.Generation = binding.SourceGeneration
	state.PID = chooseVacantPID(t)
	state.APIPath = filepath.Join(t.TempDir(), "api.sock")
	state.CheckpointOperation = firecrackerCheckpointOperationRecord{
		Version:          firecrackerCheckpointOperationRecordVersion,
		Phase:            firecrackerCheckpointOperationPhaseCompleted,
		OperationID:      binding.OperationID,
		RequestDigest:    binding.RequestDigest,
		SourceGeneration: binding.SourceGeneration,
		RootDigest:       strings.Repeat("b", 64),
		RootScheme:       checkpointroot.Scheme,
		Directory:        t.TempDir(),
		VMMPID:           state.PID,
		VMMStartTime:     1,
		VMMBootID:        bootID,
		VMMAPIPath:       state.APIPath,
	}
	instance.mu.Lock()
	instance.state = state
	instance.mu.Unlock()
	handler.instances = map[string]*firecrackerInstance{state.ID: instance}
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	repair := blockStateWrite(t, state)

	err = handler.AckCheckpointOperation(context.Background(), state.ID, binding)
	if err == nil || !containsAll(err.Error(), "persist acknowledgment") {
		t.Fatalf("acknowledgment did not reach the injected persistence failure: %v", err)
	}
	// The gate the error promises is real: the retained evidence still blocks
	// the evidence-clearing delete from daemon memory alone.
	if !instance.snapshot().CheckpointOperation.retainsEvidence() {
		t.Fatal("ack persistence failed but the in-memory evidence gate was released")
	}
	if err := handler.Delete(context.Background(), state.ID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after failed acknowledgment = %v, want the evidence-gate refusal", err)
	}
	// The blocked write left the durable record at completed: read the exact
	// bytes set aside by the block (the live path is the placeholder).
	var durable firecrackerPersistedState
	blocked, readErr := os.ReadFile(filepath.Join(
		state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename+".blocked",
	))
	if readErr != nil || json.Unmarshal(blocked, &durable) != nil ||
		durable.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted {
		t.Fatalf("failed acknowledgment changed the durable phase: %+v %v", durable.CheckpointOperation, readErr)
	}

	// Repaired storage: the retry releases the gate through a durable write.
	repair(t)
	if err := handler.AckCheckpointOperation(context.Background(), state.ID, binding); err != nil {
		t.Fatalf("ack after repair = %v", err)
	}
	disk, durableErr := readFirecrackerState(state.BundlePath)
	if durableErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseAcked {
		t.Fatalf("durable phase after repaired acknowledgment = %+v %v", disk.CheckpointOperation, durableErr)
	}
	// The gate is released: the delete now runs past the evidence refusal
	// (its later steps may still fail on this synthetic fixture's paths).
	if err := handler.Delete(context.Background(), state.ID); errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after durable acknowledgment still hit the evidence gate: %v", err)
	}
}

// TestCompletedPersistenceFailureCannotReplaySuccess is the 1190 review
// regression: a completion whose durable write failed must not be replayed as
// success from daemon memory — the recovery has to keep failing until the
// completed fact is actually durable, and a repaired storage retry then
// completes it.
func TestCompletedPersistenceFailureCannotReplaySuccess(t *testing.T) {
	handler, sandboxID, _, _, state := coldCheckpointOperationFixture(t, nil)
	instance := &firecrackerInstance{state: state, done: make(chan struct{})}
	handler.instances[sandboxID] = instance
	binding := runtimecore.CheckpointOperationBinding{
		OperationID:      state.CheckpointOperation.OperationID,
		RequestDigest:    state.CheckpointOperation.RequestDigest,
		SourceGeneration: state.Generation,
	}
	repair := blockStateWrite(t, state)

	// The fixture already has a durable prepared record. Exercise the completion
	// publisher directly so the fault stays at completed persistence; subsequent
	// Recover calls below still check that memory cannot replay false success.
	instance.operationMu.Lock()
	err := handler.completeIdentifiedCheckpointOperation(instance, state.CheckpointOperation)
	instance.operationMu.Unlock()
	if err == nil || !containsAll(err.Error(), "persist completed checkpoint operation witness") {
		t.Fatalf("recovery did not reach the injected completion persistence failure: %v", err)
	}
	// Neither the record nor the terminal exit was published: the recovery
	// cannot answer success from memory while the durable record is blocked.
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("failed completion published phase %q in memory", phase)
	}
	if instance.snapshot().Exited {
		t.Fatal("failed completion published the terminal exit in memory")
	}
	if _, err = handler.RecoverCheckpointOperation(context.Background(), sandboxID, binding); err == nil {
		t.Fatal("recovery reported success from memory while the durable completion is still blocked")
	}

	// Repaired storage: the same operation's retry persists the completion
	// and only then reports it.
	repair(t)
	completion, err := handler.RecoverCheckpointOperation(context.Background(), sandboxID, binding)
	if err != nil {
		t.Fatalf("recovery after repair = %v", err)
	}
	if completion.RootDigest != state.CheckpointOperation.RootDigest {
		t.Fatalf("recovered completion root %s, want the recorded %s", completion.RootDigest, state.CheckpointOperation.RootDigest)
	}
	disk, readErr := readFirecrackerState(state.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted || !disk.Exited {
		t.Fatalf("durable completion after repair = %+v %v", disk.CheckpointOperation, readErr)
	}
}

// TestCompletedPublishOrderingHoldsAgainstConcurrentStateWriters proves the
// publish ordering under load: while the completion's durable write fails, a
// concurrent state writer (the asynchronous exit persistence, a recovery
// monitor) has no unpersisted completion to observe, so nothing it writes can
// carry one; after the storage is repaired the retry makes the completion
// durable.
func TestCompletedPublishOrderingHoldsAgainstConcurrentStateWriters(t *testing.T) {
	handler, sandboxID, _, _, state := coldCheckpointOperationFixture(t, nil)
	instance := &firecrackerInstance{state: state, done: make(chan struct{})}
	handler.instances[sandboxID] = instance
	binding := runtimecore.CheckpointOperationBinding{
		OperationID:      state.CheckpointOperation.OperationID,
		RequestDigest:    state.CheckpointOperation.RequestDigest,
		SourceGeneration: state.Generation,
	}
	repair := blockStateWrite(t, state)
	stopWriters := make(chan struct{})
	writersDone := make(chan struct{})
	var stopOnce sync.Once
	stopAndJoin := func() {
		stopOnce.Do(func() { close(stopWriters) })
		select {
		case <-writersDone:
		case <-time.After(5 * time.Second):
			t.Error("concurrent state writer did not stop")
		}
	}
	t.Cleanup(stopAndJoin)
	go func() {
		defer close(writersDone)
		for {
			select {
			case <-stopWriters:
				return
			default:
				// The asynchronous lifecycle writers persist whatever the
				// instance currently claims; any error is the blocked write.
				_ = handler.persistInstance(instance)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// The fixture already has a durable prepared record. Exercise the completion
	// publisher directly so the fault stays at completed persistence; subsequent
	// Recover calls below still check that memory cannot replay false success.
	instance.operationMu.Lock()
	err := handler.completeIdentifiedCheckpointOperation(instance, state.CheckpointOperation)
	instance.operationMu.Unlock()
	if err == nil || !containsAll(err.Error(), "persist completed checkpoint operation witness") {
		t.Fatalf("recovery did not reach the injected completion persistence failure: %v", err)
	}
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("concurrent writers observed an unpersisted phase %q", phase)
	}
	stopAndJoin()

	// Nothing any concurrent writer flushed while writes were blocked changed
	// the durable record: it still holds the prepared witness.
	repair(t)
	disk, readErr := readFirecrackerState(state.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("concurrent writer carried an uncommitted completion to disk: %+v %v", disk.CheckpointOperation, readErr)
	}
	if _, err := handler.RecoverCheckpointOperation(context.Background(), sandboxID, binding); err != nil {
		t.Fatalf("recovery after repair = %v", err)
	}
	disk, readErr = readFirecrackerState(state.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted {
		t.Fatalf("durable completion after repaired retry = %+v %v", disk.CheckpointOperation, readErr)
	}
}

// TestRecoveryKeepsCheckpointOperationConstraint proves a daemon restart
// cannot silently lift the constraint: recoverState retains the witness in
// the recovered instance and in the state it rewrites, so checkpoints and
// evidence-clearing deletes stay blocked until recovery or acknowledgment.
func TestRecoveryKeepsCheckpointOperationConstraint(t *testing.T) {
	handler, sandboxID, _, command, state := coldCheckpointOperationFixture(t, nil)
	fd := checkpointTestPidfd(t, state.PID)

	recovered := handler.recoverState(state)
	if recovered.snapshot().CheckpointOperation != state.CheckpointOperation {
		t.Fatalf("recovery dropped the witness: %+v", recovered.snapshot().CheckpointOperation)
	}
	disk, err := readFirecrackerState(state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation != state.CheckpointOperation {
		t.Fatalf("recovery rewrite dropped the witness: %+v", disk.CheckpointOperation)
	}
	handler.instances[sandboxID] = recovered
	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:        sandboxID,
		Directory: filepath.Join(t.TempDir(), "checkpoint"),
	}); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("checkpoint after restart = %v, want ErrFailedPrecondition", err)
	}
	if err := handler.Delete(context.Background(), sandboxID); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("delete after restart = %v, want ErrFailedPrecondition", err)
	}
	assertLiveOwnedChild(t, recovered, fd, handler.binary, state.APIPath, sandboxID)

	// Quiet the recovery monitor before the temporary roots disappear.
	recovered.markDeleting()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recovered.done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery monitor did not observe the child exit")
	}
}

// TestCheckpointLegacyFlowUnchangedByOperationSupport proves the legacy
// leave-running checkpoint keeps its exact behavior with the new code in
// place: the sealed artifact is followed by a resume, no witness is written,
// and the sandbox stays running.
func TestCheckpointLegacyFlowUnchangedByOperationSupport(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)

	if err := handler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{
		ID:           sandboxID,
		Directory:    directory,
		LeaveRunning: true,
	}); err != nil {
		t.Fatal(err)
	}
	if resumes := api.countVMState("Resumed"); resumes != 1 {
		t.Fatalf("legacy leave-running checkpoint resumed %d times, want 1", resumes)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("legacy leave-running checkpoint stopped the source")
	}
	disk, err := readFirecrackerState(before.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation != (firecrackerCheckpointOperationRecord{}) {
		t.Fatalf("legacy checkpoint wrote an operation witness: %+v", disk.CheckpointOperation)
	}
	if disk.Exited {
		t.Fatal("legacy leave-running checkpoint recorded an exit")
	}
	// Legacy delete still retires the sandbox directly: no witness, no gate.
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatalf("legacy delete = %v", err)
	}
}

func directoryEntries(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, fmt.Sprintf("%s:%v", entry.Name(), entry.IsDir()))
	}
	return strings.Join(names, ",")
}

// Verify artifact retirement does not make acknowledgment depend on cache residency.
func TestAckCheckpointOperationAfterArtifactGCIndependentOfMapping(t *testing.T) {
	for _, cold := range []bool{false, true} {
		name := "hot"
		if cold {
			name = "cold"
		}
		t.Run(name, func(t *testing.T) {
			h, sid, _, _, state := coldCheckpointOperationFixture(t, nil)
			binding := testCheckpointOperationBinding(state.Generation)
			if _, err := h.RecoverCheckpointOperation(context.Background(), sid, binding); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(state.CheckpointOperation.Directory); err != nil {
				t.Fatal(err)
			}
			if cold {
				h.mu.Lock()
				delete(h.instances, sid)
				h.mu.Unlock()
			}
			if err := h.AckCheckpointOperation(context.Background(), sid, binding); err != nil {
				t.Fatalf("ack after completed source/artifact GC (cold=%v): %v", cold, err)
			}
		})
	}
}

// Persistent preparation failure must never allow a hot retry to stop its source.
func TestRecoverCheckpointOperationPreparedRetryPersistsBeforeStopping(t *testing.T) {
	handler, instance, api, sandboxID := checkpointOperationFixture(t, "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	before := instance.snapshot()
	fd := checkpointTestPidfd(t, before.PID)
	// Same deterministic injection point: durable intent, no prepared write.
	api.onSnapshotCreate = makeStateDirUnwritableFromHook(instance)
	t.Cleanup(func() { makeStateDirWritable(instance) })

	// The original checkpoint seals the artifact and then fails the prepared
	// witness write: the source stays paused, the durable intent stays on
	// disk, and the in-memory prepared record binds this daemon.
	err := runIdentifiedCheckpoint(t, handler, sandboxID, "gen-live", directory)
	if hookErr := api.snapshotHookError(); hookErr != nil {
		t.Fatalf("snapshot injection failed: %v", hookErr)
	}
	if !containsAll(err.Error(), "persist prepared checkpoint operation witness") {
		t.Fatalf("failure must name the ambiguous prepared write: %v", err)
	}
	disk, readErr := readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
		t.Fatalf("durable witness state = %+v %v, want the durable intent", disk.CheckpointOperation, readErr)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("source already stopped before the retry")
	}

	// Hot retry with the storage still unwritable: the recovery must refuse
	// on the prepared re-persist boundary, before any stop processing.
	_, err = handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err == nil || !containsAll(err.Error(), "persist prepared checkpoint operation witness before recovering") {
		t.Fatalf("retry with unwritable storage = %v, want the prepared re-persist refusal", err)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("retry stopped the source although no durable prepared witness exists")
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("retry resumed the source %d times", resumes)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("retry re-took snapshots: %d", snapshots)
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseIntent {
		t.Fatalf("failed retry changed the durable intent: %+v %v", disk.CheckpointOperation, readErr)
	}
	if phase := instance.snapshot().CheckpointOperation.Phase; phase != firecrackerCheckpointOperationPhasePrepared {
		t.Fatalf("failed retry dropped the in-memory witness: %q", phase)
	}

	// Repaired storage: the same operation's recovery proves the prepared
	// boundary durably, completes the original stop, and returns the
	// originally sealed root — with no new snapshot or resume.
	makeStateDirWritable(instance)
	root, bindErr := checkpointroot.Bind(directory)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	completion, err := handler.RecoverCheckpointOperation(
		context.Background(), sandboxID, testCheckpointOperationBinding("gen-live"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if completion.RootDigest != root.RootDigest || completion.RootScheme != root.Scheme {
		t.Fatalf("recovered root %s (%s), want the sealed root %s (%s)",
			completion.RootDigest, completion.RootScheme, root.RootDigest, root.Scheme)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("repaired retry returned before the source's kernel exit notification")
	}
	disk, readErr = readFirecrackerState(before.BundlePath)
	if readErr != nil || disk.CheckpointOperation.Phase != firecrackerCheckpointOperationPhaseCompleted || !disk.Exited {
		t.Fatalf("durable completion after repaired retry = %+v %v", disk.CheckpointOperation, readErr)
	}
	if disk.CheckpointOperation.RootDigest != root.RootDigest {
		t.Fatalf("completion root drifted from the sealed artifact: %+v", disk.CheckpointOperation)
	}
	if snapshots := api.countSnapshotCreates(); snapshots != 1 {
		t.Fatalf("repaired retry re-took snapshots: %d", snapshots)
	}
	if resumes := api.countVMState("Resumed"); resumes != 0 {
		t.Fatalf("repaired retry resumed the source %d times", resumes)
	}
}
