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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The subprocess crash regression for CheckpointWithOperation. The existing
// restart test fabricates an admitted record by hand and never runs the
// runtime; here the child runs the real service path — admission, the fake
// runtime's sealed output, the shared checkpointroot binding — and dies as a
// real process exactly when the SUCCEEDED record is about to become durable,
// which is the latest crash point that still loses the success fact. This
// models a daemon crash only: the fake runtime stands in for the VM, so no
// guest, VMM, or uffd behavior is under test.
const (
	checkpointOperationCrashChildEnv  = "SANDBOXD_CHECKPOINT_OPERATION_CRASH_CHILD"
	checkpointOperationCrashModeEnv   = "SANDBOXD_CHECKPOINT_OPERATION_CRASH_MODE"
	checkpointOperationCrashRootEnv   = "SANDBOXD_CHECKPOINT_OPERATION_CRASH_ROOT"
	checkpointOperationCrashOutputEnv = "SANDBOXD_CHECKPOINT_OPERATION_CRASH_OUTPUT"
	checkpointOperationCrashProofEnv  = "SANDBOXD_CHECKPOINT_OPERATION_CRASH_PROOF"

	checkpointOperationCrashSandbox    = "sbox-cop-subcrash"
	checkpointOperationCrashGeneration = "gen-1"

	// checkpointOperationCrashExit is the deliberate status the child exits
	// with from inside the persist seam. It is chosen away from go test's own
	// failure status (1), the panic status (2), and -1, which exec reports for
	// a child killed by a signal — so an exact match proves the child died at
	// the seam on its own terms, not from a harness malfunction or a timeout.
	checkpointOperationCrashExit = 86
	// checkpointOperationCrashHarnessExit marks a child-side malfunction
	// before the modeled crash point (a failure to record the evidence); it
	// must never satisfy the parent's status assertion.
	checkpointOperationCrashHarnessExit = 87
)

// checkpointOperationCrashProof is the evidence the dying child leaves at the
// seam. The root digest is only producible after checkpointroot.Bind read the
// sealed directory, so a proof carrying one proves the crash happened after
// the runtime callback returned and the binding succeeded.
type checkpointOperationCrashProof struct {
	OperationID            string `json:"operation_id"`
	Phase                  string `json:"phase"`
	RootDigest             string `json:"root_digest"`
	Scheme                 string `json:"scheme"`
	RuntimeCheckpointCalls int    `json:"runtime_checkpoint_calls"`
}

// TestCheckpointOperationCrashChild is the child half of the regression. It
// returns immediately unless the parent set the child env, so a plain
// `go test` run of the package executes nothing here. All shared paths come
// from the environment because the child never runs its own cleanup.
func TestCheckpointOperationCrashChild(t *testing.T) {
	if os.Getenv(checkpointOperationCrashChildEnv) != "1" {
		return
	}
	root := os.Getenv(checkpointOperationCrashRootEnv)
	directory := os.Getenv(checkpointOperationCrashOutputEnv)
	require.NotEmpty(t, root)
	require.NotEmpty(t, directory)

	handler := newCheckpointOperationRuntimeHandler()
	s := newCheckpointOperationService(t, handler, root)
	storeCheckpointOperationSandbox(t, s, checkpointOperationCrashSandbox, checkpointOperationCrashGeneration)

	if os.Getenv(checkpointOperationCrashModeEnv) == "crash" {
		// markSucceeded reaches this seam only after the runtime callback
		// returned nil and the sealed content root was read, and admission
		// writes call durablyWrite directly — so a SUCCEEDED-phase invocation
		// is exactly "the success fact is about to be durably written".
		// Exiting the process here skips every deferred cleanup, which is the
		// point: no in-process fallback may run after a real crash.
		s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
			if record.Phase != checkpointOperationPhaseSucceeded {
				return s.checkpointOperations.durablyWrite(record)
			}
			if record.Artifact == nil {
				fmt.Fprintf(os.Stderr, "crash child: SUCCEEDED record carries no artifact\n")
				os.Exit(checkpointOperationCrashHarnessExit)
			}
			proof, err := json.Marshal(checkpointOperationCrashProof{
				OperationID:            record.OperationID,
				Phase:                  record.Phase,
				RootDigest:             record.Artifact.RootDigest,
				Scheme:                 record.Artifact.Scheme,
				RuntimeCheckpointCalls: handler.checkpointCount(),
			})
			if err == nil {
				err = writeCheckpointOperationCrashProof(os.Getenv(checkpointOperationCrashProofEnv), proof)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "crash child: record evidence: %v\n", err)
				os.Exit(checkpointOperationCrashHarnessExit)
			}
			os.Exit(checkpointOperationCrashExit)
			return nil // unreachable: the process died above
		}
	}

	opStatus, err := s.CheckpointWithOperation(context.Background(),
		checkpointOperationRequest(
			"op-subcrash-1", checkpointOperationCrashSandbox, directory,
			checkpointOperationCrashGeneration, 30,
		))
	require.NoError(t, err)
	require.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, opStatus.GetState())
	require.NotEmpty(t, opStatus.GetArtifactRootDigest())
	require.Equal(t, 1, handler.checkpointCount())
}

// writeCheckpointOperationCrashProof makes the crash evidence visible to the
// parent before the child exits.
func writeCheckpointOperationCrashProof(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// runCheckpointOperationCrashChild re-enters this test binary as the child in
// the requested mode and returns its exit status and combined output. The
// bounded context is the backstop only; the expected termination is always the
// child's own exit.
func runCheckpointOperationCrashChild(t *testing.T, mode, root, directory, proof string) (int, string) {
	t.Helper()
	binary, err := os.Executable()
	require.NoError(t, err)
	binary, err = filepath.EvalSymlinks(binary)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary,
		"-test.run=^TestCheckpointOperationCrashChild$", "-test.timeout=30s", "-test.v")
	cmd.Env = append(os.Environ(),
		checkpointOperationCrashChildEnv+"=1",
		checkpointOperationCrashModeEnv+"="+mode,
		checkpointOperationCrashRootEnv+"="+root,
		checkpointOperationCrashOutputEnv+"="+directory,
		checkpointOperationCrashProofEnv+"="+proof,
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	runErr := cmd.Run()
	if runErr == nil {
		return 0, output.String()
	}
	var exitErr *exec.ExitError
	require.ErrorAsf(t, runErr, &exitErr, "child did not exit by itself: %v\nchild output:\n%s", runErr, output.String())
	return exitErr.ExitCode(), output.String()
}

// TestCheckpointOperationCrashBeforeSuccessPersistDurable pins the crash
// window between a completed checkpoint and its durable success fact: the
// dying daemon leaves an admitted record on disk and retained, valid artifacts
// behind, and the restarted daemon resolves the operation to unknown — never
// guessing success from the artifacts, never re-executing against the live
// source. The committed control run proves the child harness reaches and
// passes the same boundary when it does not die there, so the unknown outcome
// is attributable to the crash alone, not to an early exit.
func TestCheckpointOperationCrashBeforeSuccessPersistDurable(t *testing.T) {
	t.Run("crash while SUCCEEDED is about to become durable", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		proofPath := filepath.Join(t.TempDir(), "crash-proof.json")

		code, output := runCheckpointOperationCrashChild(t, "crash", root, directory, proofPath)
		require.Equal(t, checkpointOperationCrashExit, code,
			"child did not die at the seam\nchild output:\n%s", output)

		// The crash point is proven, not assumed: the seam fired for the
		// SUCCEEDED transition carrying a bindable root digest, after exactly
		// one runtime checkpoint call.
		data, err := os.ReadFile(proofPath)
		require.NoError(t, err, "the crash seam did not fire")
		var evidence checkpointOperationCrashProof
		require.NoError(t, json.Unmarshal(data, &evidence))
		assert.Equal(t, "op-subcrash-1", evidence.OperationID)
		assert.Equal(t, checkpointOperationPhaseSucceeded, evidence.Phase)
		assert.Equal(t, checkpointroot.Scheme, evidence.Scheme)
		assert.Equal(t, 1, evidence.RuntimeCheckpointCalls)

		// The durable journal still holds only the admission: no success fact,
		// and no half-written record beside it.
		record, rerr := readCheckpointOperationRecord(
			filepath.Join(root, checkpointOperationsDirName), "op-subcrash-1")
		require.NoError(t, rerr)
		assert.Equal(t, checkpointOperationPhaseAdmitted, record.Phase)
		assert.Nil(t, record.Artifact)
		entries, derr := os.ReadDir(filepath.Join(root, checkpointOperationsDirName))
		require.NoError(t, derr)
		assert.Len(t, entries, 1, "the journal must carry exactly the admitted record")

		// The retained output is a valid sealed checkpoint whose content root
		// matches the digest the dying daemon was about to record.
		retained, bindErr := checkpointroot.Bind(directory)
		require.NoError(t, bindErr)
		assert.Equal(t, evidence.RootDigest, retained.RootDigest)

		// Daemon restart over the same root: the admitted record resolves to
		// unknown, and the query never touches the runtime.
		restartedHandler := newCheckpointOperationRuntimeHandler()
		restarted := newCheckpointOperationService(t, restartedHandler, root)
		queried, qerr := restarted.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-subcrash-1"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
		assert.Contains(t, queried.GetMessage(), "re-execution forbidden")
		assert.Zero(t, restartedHandler.checkpointCount())

		// The same-request replay is answered from the record even with the
		// source looking live and matching: zero new runtime calls, and no
		// second execution of a checkpoint whose outcome is unproven.
		storeCheckpointOperationSandbox(t, restarted, checkpointOperationCrashSandbox, checkpointOperationCrashGeneration)
		replayed, plerr := restarted.CheckpointWithOperation(context.Background(),
			checkpointOperationRequest(
				"op-subcrash-1", checkpointOperationCrashSandbox, directory,
				checkpointOperationCrashGeneration, 30,
			))
		require.NoError(t, plerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, replayed.GetState())
		assert.Zero(t, restartedHandler.checkpointCount())
		// Reconciliation must preserve the unresolved artifacts, not merely
		// avoid invoking the runtime again. Check after both query and replay.
		afterReplay, err := checkpointroot.Bind(directory)
		require.NoError(t, err)
		assert.Equal(t, retained, afterReplay)
		resolvedRecord, err := readCheckpointOperationRecord(
			filepath.Join(root, checkpointOperationsDirName), "op-subcrash-1")
		require.NoError(t, err)
		assert.Equal(t, checkpointOperationPhaseUnknown, resolvedRecord.Phase)
		assert.Nil(t, resolvedRecord.Artifact)
	})

	t.Run("committed control reaches SUCCEEDED through the same path", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")

		code, output := runCheckpointOperationCrashChild(t, "commit", root, directory,
			filepath.Join(t.TempDir(), "control-proof.json"))
		require.Equal(t, 0, code, "control child failed\nchild output:\n%s", output)

		record, rerr := readCheckpointOperationRecord(
			filepath.Join(root, checkpointOperationsDirName), "op-subcrash-1")
		require.NoError(t, rerr)
		assert.Equal(t, checkpointOperationPhaseSucceeded, record.Phase)
		require.NotNil(t, record.Artifact)
		retained, bindErr := checkpointroot.Bind(directory)
		require.NoError(t, bindErr)
		assert.Equal(t, retained.RootDigest, record.Artifact.RootDigest)

		// After a clean commit, restart replays the recorded success with zero
		// new runtime calls — the contrast that attributes the crash case's
		// unknown outcome to the lost terminal write alone.
		restartedHandler := newCheckpointOperationRuntimeHandler()
		restarted := newCheckpointOperationService(t, restartedHandler, root)
		queried, qerr := restarted.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-subcrash-1"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, queried.GetState())
		replayed, plerr := restarted.CheckpointWithOperation(context.Background(),
			checkpointOperationRequest(
				"op-subcrash-1", checkpointOperationCrashSandbox, directory,
				checkpointOperationCrashGeneration, 30,
			))
		require.NoError(t, plerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, replayed.GetState())
		assert.Zero(t, restartedHandler.checkpointCount())
	})
}
