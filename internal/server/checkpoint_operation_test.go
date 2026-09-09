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

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// checkpointOperationRuntimeHandler models a runtime whose stop-and-copy
// checkpoints write a sealed, root-bindable directory: the
// CheckpointOperationWriter capability the operation RPC requires. It is a
// fake runtime model for the server-side operation semantics — it is NOT a
// real Firecracker acceptance (no VMM, no memory wrapper, no cgroup path).
// It is registered under the runsc name so the plain checkpoint path runs on
// every host; the capability, not the runtime name, gates operation
// admission, exactly as CheckpointRootVerifier gates identified restores.
type checkpointOperationRuntimeHandler struct {
	*svc.FakeRuntimeHandler

	mu           sync.Mutex
	checkpointFn func(context.Context, svc.CheckpointConfig) error
	checkpoints  []svc.CheckpointConfig
}

var _ svc.CheckpointHandler = (*checkpointOperationRuntimeHandler)(nil)

func (h *checkpointOperationRuntimeHandler) Restore(context.Context, svc.StartConfig) error {
	return errors.New("restore is not exercised by checkpoint operation tests")
}

func awaitCheckpointOperationSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint runtime was not entered")
	}
}

func newCheckpointOperationRuntimeHandler() *checkpointOperationRuntimeHandler {
	return &checkpointOperationRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
}

func (h *checkpointOperationRuntimeHandler) Checkpoint(
	ctx context.Context,
	config svc.CheckpointConfig,
) error {
	h.mu.Lock()
	h.checkpoints = append(h.checkpoints, config)
	fn := h.checkpointFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, config)
	}
	return writeSealedCheckpointDirectory(config.Directory)
}

// SupportsCheckpointOperations declares the capability the server requires
// before admitting an identified checkpoint operation.
func (h *checkpointOperationRuntimeHandler) SupportsCheckpointOperations() bool {
	return true
}

func (h *checkpointOperationRuntimeHandler) checkpointCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.checkpoints)
}

// writeSealedCheckpointDirectory writes a real-shaped chunks-mode sealed
// layout (manifest, covered artifacts, valid chunk sidecars) into an existing
// output directory so the shared pkg/checkpointroot binder accepts it. It
// mirrors the seal shapes seedFirecrackerLayout builds for restore fixtures.
func writeSealedCheckpointDirectory(directory string) error {
	memory := "cold-memory-bytes"
	overlay := "overlay-bytes"
	files := map[string]string{
		"vmstate":          "state",
		"memory":           memory,
		restoreOverlayName: overlay,
	}
	manifest := fmt.Sprintf(
		`{"version":2,"snapshot_type":"Full","memory_size":%d,"memory_digest_mode":"chunks","digests":{"vmstate":"aa","memory":"bb"}}`,
		len(memory),
	)
	if err := os.WriteFile(filepath.Join(directory, restoreManifestName), []byte(manifest), 0600); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			return err
		}
	}
	if err := writeChunkSidecarForArtifact(directory, "memory", checkpointchunks.ManifestName, 16); err != nil {
		return err
	}
	return writeChunkSidecarForArtifact(directory, restoreOverlayName, restoreOverlaySidecarName, 16)
}

// writeChunkSidecarForArtifact is the error-returning form of
// writeValidChunkSidecar, usable from the fake runtime handler.
func writeChunkSidecarForArtifact(directory, artifact, sidecarName string, chunkBytes int64) error {
	content, err := os.ReadFile(filepath.Join(directory, artifact))
	if err != nil {
		return err
	}
	size := int64(len(content))
	entries := make([]checkpointchunks.Chunk, 0, (size+chunkBytes-1)/chunkBytes)
	for offset := int64(0); offset < size; offset += chunkBytes {
		end := offset + chunkBytes
		if end > size {
			end = size
		}
		sum := sha256.Sum256(content[offset:end])
		entries = append(entries, checkpointchunks.Chunk{Offset: offset, Digest: hex.EncodeToString(sum[:])})
	}
	manifest := &checkpointchunks.Manifest{
		Version:        1,
		File:           artifact,
		FileSize:       size,
		FileDigestMode: checkpointchunks.FileDigestChunks,
		FileDigest:     checkpointchunks.RootDigest(entries),
		ChunkBytes:     int(chunkBytes),
		ChunkCount:     len(entries),
		Entries:        entries,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, sidecarName), append(encoded, '\n'), 0600)
}

// newCheckpointOperationService builds a service whose checkpoint-operation
// journal is real on-disk state under root, so a test can simulate a daemon
// restart by building a second service over the same root.
func newCheckpointOperationService(t *testing.T, handler svc.Handler, root string) *sandboxService {
	t.Helper()

	handlerMap := cmap.New[svc.Handler]()
	handlerMap.Set(config.RuntimeNameRunsc, handler)
	runtimeBinary := map[string]string{config.RuntimeNameRunsc: "/fake/runsc"}

	operations, err := loadCheckpointOperations(root)
	require.NoError(t, err)
	intents, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)

	healthChan := make(chan bool, 10)
	manager, err := sandbox.NewManager(root, handlerMap, healthChan, nil, 1000)
	require.NoError(t, err)

	s := &sandboxService{
		config: config.Config{
			RootDir: root,
			PluginConfig: config.PluginConfig{
				RuntimeConfig: config.RuntimeConfig{
					RuntimeBinary: runtimeBinary,
				},
			},
		},
		serviceHandler:                    handlerMap,
		sandboxManager:                    manager,
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		store:                             store.NewMockStore(),
		fsMgr:                             newFSManager(nil),
		networkMgr:                        newNetworkManager(nil, "", false),
		startIntents:                      intents,
		checkpointOperations:              operations,
	}
	s.ready.Store(true)
	s.recoveryReady.Store(true)
	return s
}

// storeCheckpointOperationSandbox persists the running source sandbox with
// the physical generation label the daemon maintains.
func storeCheckpointOperationSandbox(t *testing.T, s *sandboxService, id, generation string) {
	t.Helper()
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: config.RuntimeNameRunsc,
		Labels:         map[string]string{resourceGenerationLabel: generation},
	}))
}

func checkpointOperationRequest(
	operationID, sandboxID, directory, generation string,
	timeout uint32,
) *runtime.CheckpointWithOperationRequest {
	return &runtime.CheckpointWithOperationRequest{
		OperationID: operationID,
		Checkpoint: &runtime.CheckpointRequest{
			ID:             sandboxID,
			CheckpointDir:  directory,
			TimeoutSeconds: timeout,
		},
		ExpectedGeneration: generation,
	}
}

// --- admission, identity, and replay ---

// TestCheckpointOperationSuccessRecordsSealedRoot pins the success contract:
// the runtime is entered once, the sealed content root of the output is read
// through the shared binder, and SUCCEEDED — with the root digest and scheme
// — is durable before the RPC reports success.
func TestCheckpointOperationSuccessRecordsSealedRoot(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-success", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-success-1", "sbox-cop-success", directory, "gen-1", 5))
	require.NoError(t, err)
	require.NotNil(t, opStatus)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, opStatus.GetState())
	assert.Equal(t, "sbox-cop-success", opStatus.GetSandboxID())
	assert.Equal(t, "gen-1", opStatus.GetSourceGeneration())
	assert.Equal(t, directory, opStatus.GetCheckpointDir())
	assert.Len(t, opStatus.GetRequestDigest(), checkpointroot.DigestHexLen)
	assert.Equal(t, checkpointroot.Scheme, opStatus.GetArtifactRootScheme())

	expected, err := checkpointroot.Bind(directory)
	require.NoError(t, err)
	assert.Equal(t, expected.RootDigest, opStatus.GetArtifactRootDigest())
	assert.Equal(t, 1, handler.checkpointCount())

	record, rerr := readCheckpointOperationRecord(
		filepath.Join(root, checkpointOperationsDirName), "op-success-1")
	require.NoError(t, rerr)
	assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
	require.NotNil(t, record.Artifact)
	assert.Equal(t, expected.RootDigest, record.Artifact.RootDigest)
	assert.Equal(t, expected.Scheme, record.Artifact.Scheme)
}

// TestCheckpointOperationSameIDDifferentIntentRefused pins identity: the
// digest covers every request field — directory, timeout, compression,
// snapshot type — and the expected generation, so no field can be swapped
// under a recorded ID, and the refusal has no side effects.
func TestCheckpointOperationSameIDDifferentIntentRefused(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-conflict", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	base := checkpointOperationRequest("op-conflict-1", "sbox-cop-conflict", directory, "gen-1", 5)
	opStatus, err := s.CheckpointWithOperation(context.Background(), base)
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, opStatus.GetState())

	conflicts := map[string]*runtime.CheckpointWithOperationRequest{
		"different directory": checkpointOperationRequest(
			"op-conflict-1", "sbox-cop-conflict", filepath.Join(t.TempDir(), "other"), "gen-1", 5),
		"different timeout": checkpointOperationRequest(
			"op-conflict-1", "sbox-cop-conflict", directory, "gen-1", 6),
		"different generation": checkpointOperationRequest(
			"op-conflict-1", "sbox-cop-conflict", directory, "gen-2", 5),
		"different sandbox": checkpointOperationRequest(
			"op-conflict-1", "sbox-cop-other", directory, "gen-1", 5),
		"compression added": {
			OperationID: "op-conflict-1",
			Checkpoint: &runtime.CheckpointRequest{
				ID:             "sbox-cop-conflict",
				CheckpointDir:  directory,
				TimeoutSeconds: 5,
				Compress:       true,
			},
			ExpectedGeneration: "gen-1",
		},
		"snapshot type added": {
			OperationID: "op-conflict-1",
			Checkpoint: &runtime.CheckpointRequest{
				ID:             "sbox-cop-conflict",
				CheckpointDir:  directory,
				TimeoutSeconds: 5,
				SnapshotType:   "Full",
			},
			ExpectedGeneration: "gen-1",
		},
	}
	for name, request := range conflicts {
		t.Run(name, func(t *testing.T) {
			_, err := s.CheckpointWithOperation(context.Background(), request)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.ErrorContains(t, err, "op-conflict-1")
		})
	}
	assert.Equal(t, 1, handler.checkpointCount(), "a conflicting replay must not execute the runtime")

	// The recorded success is untouched by the refused replays.
	final, err := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-conflict-1"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, final.GetState())
}

// TestCheckpointOperationConcurrentSameRequestExecutesOnce: concurrent
// same-ID callers join the single admitted execution; the runtime runs once
// and every caller observes the recorded terminal outcome.
func TestCheckpointOperationConcurrentSameRequestExecutesOnce(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		if err := writeSealedCheckpointDirectory(config.Directory); err != nil {
			return err
		}
		close(entered)
		<-release
		return nil
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-concurrent", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-concurrent-1", "sbox-cop-concurrent", directory, "gen-1", 30)

	const callers = 4
	results := make(chan *runtime.CheckpointOperationStatus, callers)
	for i := 0; i < callers; i++ {
		go func() {
			opStatus, err := s.CheckpointWithOperation(context.Background(), request)
			assert.NoError(t, err)
			results <- opStatus
		}()
	}
	awaitCheckpointOperationSignal(t, entered)
	// While the single execution runs, a query observes RUNNING.
	running, err := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-concurrent-1"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING, running.GetState())
	releaseOnce.Do(func() { close(release) })

	for i := 0; i < callers; i++ {
		select {
		case opStatus := <-results:
			require.NotNil(t, opStatus)
			assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, opStatus.GetState())
			assert.NotEmpty(t, opStatus.GetArtifactRootDigest())
		case <-time.After(10 * time.Second):
			t.Fatal("a joined caller did not observe the outcome")
		}
	}
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestCheckpointOperationReplyLostQueryAndReplayAfterRestart covers the reply
// loss: after a restart (fresh store over the same root), GetCheckpointOperation
// answers from the durable record, and replaying the same operation returns
// the recorded success without executing the runtime again and without
// requiring the source sandbox to still exist.
func TestCheckpointOperationReplyLostQueryAndReplayAfterRestart(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	first := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, first, "sbox-cop-lost", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-lost-1", "sbox-cop-lost", directory, "gen-1", 5)

	opStatus, err := first.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, err)
	expectedRoot := opStatus.GetArtifactRootDigest()
	require.NotEmpty(t, expectedRoot)

	// The caller deletes the source and the artifacts after the reply was
	// lost; neither is needed to resolve the operation.
	require.NoError(t, os.RemoveAll(directory))

	secondHandler := newCheckpointOperationRuntimeHandler()
	second := newCheckpointOperationService(t, secondHandler, root)

	queried, err := second.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-lost-1"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
	assert.Equal(t, expectedRoot, queried.GetArtifactRootDigest())
	assert.Equal(t, "sbox-cop-lost", queried.GetSandboxID())

	// The replay of the finished operation answers from history: the source
	// sandbox was never stored in the second service, and the runtime is not
	// invoked.
	replayed, err := second.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
	assert.Equal(t, expectedRoot, replayed.GetArtifactRootDigest())
	assert.Zero(t, secondHandler.checkpointCount())
}

// TestCheckpointOperationRestartAdmittedResolvesUnknownWithoutReexecution:
// an admitted record whose executor is gone resolves to unknown on restart —
// never guessed as success, never re-executed.
func TestCheckpointOperationRestartAdmittedResolvesUnknownWithoutReexecution(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	first := newCheckpointOperationService(t, handler, root)
	directory := filepath.Join(t.TempDir(), "checkpoint")
	digest, err := checkpointOperationRequestDigest(
		checkpointOperationRequest("op-crash-1", "sbox-cop-crash", directory, "gen-1", 5))
	require.NoError(t, err)

	// Simulate a crash between the durable admission and the execution: the
	// record exists on disk in the admitted phase with no executor.
	crashDraft := &checkpointOperationRecord{
		Version:       1,
		OperationID:   "op-crash-1",
		SandboxID:     "sbox-cop-crash",
		Generation:    "gen-1",
		Runtime:       config.RuntimeNameRunsc,
		CheckpointDir: directory,
		RequestDigest: digest,
		Phase:         checkpointOperationPhaseAdmitted,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	require.NoError(t, validateCheckpointOperationRecord(crashDraft))
	first.checkpointOperations.writeMu.Lock()
	require.NoError(t, first.checkpointOperations.durablyWrite(crashDraft))
	first.checkpointOperations.writeMu.Unlock()

	// Daemon restart: the journal load durably resolves admitted to unknown.
	secondHandler := newCheckpointOperationRuntimeHandler()
	second := newCheckpointOperationService(t, secondHandler, root)
	resolved, err := second.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-crash-1"})
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, resolved.GetState())
	assert.Contains(t, resolved.GetMessage(), "re-execution forbidden")

	record, rerr := readCheckpointOperationRecord(
		filepath.Join(root, checkpointOperationsDirName), "op-crash-1")
	require.NoError(t, rerr)
	assert.Equal(t, checkpointOperationPhaseUnknown, record.Phase)

	// The replay never re-executes, and the record's terminal phase is
	// answered even though the source exists and still matches: no guess is
	// made from the manifest or the source state.
	storeCheckpointOperationSandbox(t, second, "sbox-cop-crash", "gen-1")
	replayed, err := second.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-crash-1", "sbox-cop-crash", directory, "gen-1", 5))
	require.NoError(t, err)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, replayed.GetState())
	assert.Zero(t, secondHandler.checkpointCount())
	assert.NoDirExists(t, directory, "an unknown replay must not allocate the output directory")
}

// TestCheckpointOperationRuntimeFailureAfterEntryUnknownAndRetained: once the
// runtime checkpoint was entered, its error proves nothing — the outcome is
// unknown, the output directory is retained, and the source state is not
// guaranteed (the c2cd786 semantics under the operation record).
func TestCheckpointOperationRuntimeFailureAfterEntryUnknownAndRetained(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		if err := os.WriteFile(filepath.Join(config.Directory, "partial"), []byte("partial"), 0600); err != nil {
			return err
		}
		return errors.New("runtime checkpoint failed")
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-postentry", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-postentry-1", "sbox-cop-postentry", directory, "gen-1", 5))
	require.Error(t, err)
	assert.ErrorContains(t, err, "checkpoint outcome is unknown")
	assert.ErrorContains(t, err, fmt.Sprintf("artifacts are retained in %s", directory))
	require.NotNil(t, opStatus)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, opStatus.GetState())

	assert.FileExists(t, filepath.Join(directory, "partial"))
	record, rerr := readCheckpointOperationRecord(
		filepath.Join(s.config.RootDir, checkpointOperationsDirName), "op-postentry-1")
	require.NoError(t, rerr)
	assert.Equal(t, checkpointOperationPhaseUnknown, record.Phase)
	assert.Nil(t, record.Artifact, "an unknown outcome records no artifact root")
}

// TestCheckpointOperationTimeoutAfterEntryResolvesUnknown: a request timeout
// that fires after the runtime was entered is an unknown outcome, not a
// failure verdict, and keeps the directory.
func TestCheckpointOperationTimeoutAfterEntryResolvesUnknown(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	handler.checkpointFn = func(ctx context.Context, config svc.CheckpointConfig) error {
		if err := os.WriteFile(filepath.Join(config.Directory, "partial"), []byte("partial"), 0600); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-timeout", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	_, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-timeout-1", "sbox-cop-timeout", directory, "gen-1", 1))
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.ErrorContains(t, err, "checkpoint outcome is unknown")

	resolved, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-timeout-1"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, resolved.GetState())
	assert.FileExists(t, filepath.Join(directory, "partial"))
}

// TestCheckpointOperationPreEntryFailureRecordedFailed: a refusal before the
// runtime was entered is a proven failure — no artifact can exist, the
// attempt's output is cleaned, and the spent ID replays as FAILED.
func TestCheckpointOperationPreEntryFailureRecordedFailed(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, t.TempDir())
	// The sandbox carries a different physical generation than the request
	// expects; the authoritative check runs under the physical lock inside
	// the checkpoint path.
	storeCheckpointOperationSandbox(t, s, "sbox-cop-preentry", "gen-live")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-preentry-1", "sbox-cop-preentry", directory, "gen-1", 5))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "resource generation changed")
	require.NotNil(t, opStatus)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, opStatus.GetState())
	assert.Zero(t, handler.checkpointCount())
	assert.NoDirExists(t, directory)

	// The spent ID replays the failure from history without re-running.
	replayed, rerr := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-preentry-1", "sbox-cop-preentry", directory, "gen-1", 5))
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, replayed.GetState())
	assert.Zero(t, handler.checkpointCount())
}

// TestCheckpointOperationAdmissionWriteFailureSpendsIDWithoutExecution: when
// the durable admission write fails, the checkpoint never runs, the ID is
// spent as unknown, and no retry of the same ID can reach the runtime.
func TestCheckpointOperationAdmissionWriteFailureSpendsIDWithoutExecution(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-writefail", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	// A directory at the record path makes every write to it fail.
	require.NoError(t, os.Mkdir(
		filepath.Join(root, checkpointOperationsDirName, "op-writefail-1.json"), 0700))

	request := checkpointOperationRequest("op-writefail-1", "sbox-cop-writefail", directory, "gen-1", 5)
	_, err := s.CheckpointWithOperation(context.Background(), request)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.ErrorContains(t, err, "the operation ID must not be retried")
	assert.Zero(t, handler.checkpointCount())
	assert.NoDirExists(t, directory)

	// The failed admission resolves as unknown, and replaying the same ID
	// never executes.
	resolved, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-writefail-1"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, resolved.GetState())

	replayed, rerr := s.CheckpointWithOperation(context.Background(), request)
	require.NoError(t, rerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, replayed.GetState())
	assert.Zero(t, handler.checkpointCount())
}

// TestCheckpointOperationSuccessWriteFailureNotReportedAsSuccess: a
// checkpoint that completed but whose SUCCEEDED record cannot be persisted is
// reported as unknown — the success fact must never be claimed before it is
// durable, and the artifacts stay retained.
func TestCheckpointOperationSuccessWriteFailureNotReportedAsSuccess(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	root := t.TempDir()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, "sbox-cop-succfail", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
		if record.Phase == checkpointOperationPhaseSucceeded {
			return errors.New("journal fsync failed")
		}
		return s.checkpointOperations.durablyWrite(record)
	}

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-succfail-1", "sbox-cop-succfail", directory, "gen-1", 5))
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not be confirmed")
	assert.ErrorContains(t, err, "artifacts are retained in "+directory)
	require.NotNil(t, opStatus)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, opStatus.GetState())
	assert.Empty(t, opStatus.GetArtifactRootDigest())

	// The artifacts the runtime sealed are still there; only the success
	// fact is unproven.
	binding, bindErr := checkpointroot.Bind(directory)
	require.NoError(t, bindErr)
	assert.NotEmpty(t, binding.RootDigest)
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestCheckpointOperationUnbindableOutputNotSuccess: a runtime that returns
// nil without writing a sealed, root-bindable directory cannot produce a
// success fact — the outcome stays unknown and the output is retained.
func TestCheckpointOperationUnbindableOutputNotSuccess(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		return os.WriteFile(filepath.Join(config.Directory, "checkpoint.img"), []byte("image"), 0600)
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-unbound", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-unbound-1", "sbox-cop-unbound", directory, "gen-1", 5))
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not be confirmed")
	require.NotNil(t, opStatus)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, opStatus.GetState())
	assert.Empty(t, opStatus.GetArtifactRootDigest())
	assert.FileExists(t, filepath.Join(directory, "checkpoint.img"))
}

// --- request gates ---

func TestCheckpointOperationValidatesRequest(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-validate", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	valid := func() *runtime.CheckpointWithOperationRequest {
		return checkpointOperationRequest("op-validate-1", "sbox-cop-validate", directory, "gen-1", 5)
	}

	cases := map[string]func(*runtime.CheckpointWithOperationRequest){
		"leave running": func(r *runtime.CheckpointWithOperationRequest) {
			r.Checkpoint.LeaveRunning = true
		},
		"missing timeout": func(r *runtime.CheckpointWithOperationRequest) {
			r.Checkpoint.TimeoutSeconds = 0
		},
		"missing expected generation": func(r *runtime.CheckpointWithOperationRequest) {
			r.ExpectedGeneration = ""
		},
		"relative directory": func(r *runtime.CheckpointWithOperationRequest) {
			r.Checkpoint.CheckpointDir = "relative/checkpoint"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := valid()
			request.OperationID = "op-validate-" + name[:1] // distinct IDs are irrelevant: none may be spent
			mutate(request)
			_, err := s.CheckpointWithOperation(context.Background(), request)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	_, err := s.CheckpointWithOperation(context.Background(),
		&runtime.CheckpointWithOperationRequest{OperationID: "op-validate-nil"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// None of the refusals spent an ID or touched the runtime.
	_, err = s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-validate-1"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Zero(t, handler.checkpointCount())
}

// TestCheckpointOperationRefusesRuntimeWithoutCapability: a runtime that does
// not implement the sealed-checkpoint capability is explicitly refused at
// admission — never fallen back to the legacy checkpoint RPCs — and no record
// is spent.
func TestCheckpointOperationRefusesRuntimeWithoutCapability(t *testing.T) {
	s := newCheckpointOperationService(t, newCheckpointTestHandler(), t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-nocap", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")

	_, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-nocap-1", "sbox-cop-nocap", directory, "gen-1", 5))
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.ErrorContains(t, err, "identified checkpoint operations")

	_, err = s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-nocap-1"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestCheckpointOperationCallerCancelEndsOnlyTheWait: cancelling a joined
// replay's caller context ends that wait only; the admitted execution is
// detached from the caller and still records its outcome.
func TestCheckpointOperationCallerCancelEndsOnlyTheWait(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		if err := writeSealedCheckpointDirectory(config.Directory); err != nil {
			return err
		}
		close(entered)
		<-release
		return nil
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-cancelwait", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-cancelwait-1", "sbox-cop-cancelwait", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	joinCtx, cancel := context.WithCancel(context.Background())
	joinedDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(joinCtx, request)
		joinedDone <- err
	}()
	// The joined replay waits on the running execution; cancelling its caller
	// context returns that caller promptly with a cancellation error while
	// the executor keeps running.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-joinedDone:
		require.Error(t, err)
		assert.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("joined replay did not return after caller cancellation")
	}
	select {
	case err := <-executorDone:
		t.Fatalf("executor ended early: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-executorDone:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("executor did not finish after release")
	}
	resolved, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-cancelwait-1"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, resolved.GetState())
	assert.Equal(t, 1, handler.checkpointCount())
}

// TestCheckpointOperationShutdownWaitsForRealExit: shutdown closes admission,
// cancels the executor's context to request convergence, and blocks until the
// executor has actually returned — even when the runtime ignores the
// cancellation — before the caller may release runtime resources. An
// execution cancelled after the runtime was entered resolves to unknown.
func TestCheckpointOperationShutdownWaitsForRealExit(t *testing.T) {
	handler := newCheckpointOperationRuntimeHandler()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	handler.checkpointFn = func(_ context.Context, config svc.CheckpointConfig) error {
		if err := writeSealedCheckpointDirectory(config.Directory); err != nil {
			return err
		}
		close(entered)
		// Ignore the shutdown cancellation on purpose: shutdown must wait
		// for the real exit, not declare convergence from the deadline.
		<-release
		return errors.New("runtime checkpoint failed after shutdown cancel")
	}
	s := newCheckpointOperationService(t, handler, t.TempDir())
	storeCheckpointOperationSandbox(t, s, "sbox-cop-shutdown", "gen-1")
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-shutdown-1", "sbox-cop-shutdown", directory, "gen-1", 30)

	executorDone := make(chan error, 1)
	go func() {
		_, err := s.CheckpointWithOperation(context.Background(), request)
		executorDone <- err
	}()
	awaitCheckpointOperationSignal(t, entered)

	shutdownDone := make(chan struct{})
	go func() {
		s.checkpointOperations.shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while the executor was still running")
	case <-time.After(200 * time.Millisecond):
	}

	// Admission is closed: a fresh operation is refused and spent as unknown.
	refused, rerr := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest("op-shutdown-2", "sbox-cop-shutdown", filepath.Join(t.TempDir(), "other"), "gen-1", 5))
	require.Error(t, rerr)
	assert.Equal(t, codes.Unavailable, status.Code(rerr))
	assert.Nil(t, refused) // An error RPC does not carry a usable response.
	refused, queryErr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-shutdown-2"})
	require.NoError(t, queryErr)
	require.NotNil(t, refused)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, refused.GetState())

	releaseOnce.Do(func() { close(release) })
	select {
	case <-shutdownDone:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not return after the executor exited")
	}
	select {
	case err := <-executorDone:
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("executor did not finish")
	}
	resolved, qerr := s.GetCheckpointOperation(context.Background(),
		&runtime.GetCheckpointOperationRequest{OperationID: "op-shutdown-1"})
	require.NoError(t, qerr)
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, resolved.GetState())
}

// --- journal validation ---

func TestCheckpointOperationJournalValidation(t *testing.T) {
	writeRecord := func(t *testing.T, root, name string, content string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Join(root, checkpointOperationsDirName), 0700))
		require.NoError(t, os.WriteFile(
			filepath.Join(root, checkpointOperationsDirName, name), []byte(content), 0600))
	}
	validRecord := func(mutate func(*checkpointOperationRecord)) string {
		record := &checkpointOperationRecord{
			Version:       1,
			OperationID:   "op-journal-1",
			SandboxID:     "sbox-cop-journal",
			Generation:    "gen-1",
			Runtime:       config.RuntimeNameRunsc,
			CheckpointDir: "/checkpoints/one",
			RequestDigest: repeatHex(64),
			Phase:         checkpointOperationPhaseSucceeded,
			Artifact:      &checkpointOperationArtifact{RootDigest: repeatHex(64), Scheme: checkpointroot.Scheme},
			CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		}
		if mutate != nil {
			mutate(record)
		}
		data, err := json.Marshal(record)
		if err != nil {
			panic(err)
		}
		return string(data)
	}

	t.Run("valid record loads", func(t *testing.T) {
		root := t.TempDir()
		writeRecord(t, root, "op-journal-1.json", validRecord(nil))
		_, err := loadCheckpointOperations(root)
		assert.NoError(t, err)
	})

	t.Run("unknown field fails startup", func(t *testing.T) {
		root := t.TempDir()
		writeRecord(t, root, "op-journal-1.json", `{"version":1,"operation_id":"op-journal-1","sandbox_id":"sbox-cop-journal","generation":"gen-1","runtime":"runsc","checkpoint_dir":"/checkpoints/one","request_digest":"`+repeatHex(64)+`","phase":"succeeded","artifact":{"root_digest":"`+repeatHex(64)+`","scheme":"`+checkpointroot.Scheme+`"},"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","extra":1}`)
		_, err := loadCheckpointOperations(root)
		assert.Error(t, err)
	})

	t.Run("bad version and phase fail", func(t *testing.T) {
		for name, mutate := range map[string]func(*checkpointOperationRecord){
			"version":       func(r *checkpointOperationRecord) { r.Version = 2 },
			"phase":         func(r *checkpointOperationRecord) { r.Phase = "maybe" },
			"digest length": func(r *checkpointOperationRecord) { r.RequestDigest = "abc" },
			"artifact without success": func(r *checkpointOperationRecord) {
				r.Phase = checkpointOperationPhaseFailed
			},
			"success without artifact": func(r *checkpointOperationRecord) { r.Artifact = nil },
			"non-canonical dir": func(r *checkpointOperationRecord) {
				r.CheckpointDir = "/checkpoints/../one"
			},
		} {
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				writeRecord(t, root, "op-journal-1.json", validRecord(mutate))
				_, err := loadCheckpointOperations(root)
				assert.Error(t, err)
			})
		}
	})

	t.Run("mismatched operation ID fails", func(t *testing.T) {
		root := t.TempDir()
		record := validRecord(func(r *checkpointOperationRecord) { r.OperationID = "op-other" })
		writeRecord(t, root, "op-journal-1.json", record)
		_, err := loadCheckpointOperations(root)
		assert.Error(t, err)
	})

	t.Run("symlink record fails startup", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, checkpointOperationsDirName), 0700))
		target := filepath.Join(root, "real.json")
		require.NoError(t, os.WriteFile(target, []byte(validRecord(nil)), 0600))
		require.NoError(t, os.Symlink(target,
			filepath.Join(root, checkpointOperationsDirName, "op-journal-1.json")))
		_, err := loadCheckpointOperations(root)
		assert.Error(t, err)
	})
}

func repeatHex(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a' + byte(i%6)
	}
	return string(out)
}
