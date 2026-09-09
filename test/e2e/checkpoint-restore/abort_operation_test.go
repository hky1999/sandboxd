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

package main

// Regressions for the explicit abort-checkpoint-operation action: the wire
// contract (the COMPLETE original CheckpointWithOperation payload beside an
// independent abort timeout that never enters the request digest), the
// receipt contract (WITNESS_ABORTABLE protocol, FAILED state, and BOTH
// abort_confirmed and evidence_released true from THIS response for a zero
// exit), the no-fallback line — no recovery, no checkpoint RPC — and the
// pre-dial gates.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// abortOperationOptions is the flag value of a fully specified abort whose
// original checkpoint matches the pinned digest fixture field for field;
// only the independent abort timeout differs from the issue-time invocation,
// which is exactly what must not move the digest.
func abortOperationOptions() options {
	value := checkpointOperationOptions()
	value.action = "abort-checkpoint-operation"
	value.abortTimeoutSeconds = 77
	return value
}

// matchingAbortedReceipt builds the receipt a fully confirmed abort must
// answer with: the requested identity, the digest of the original payload,
// the FAILED (aborted) state with no sealed root, the WITNESS_ABORTABLE
// record protocol, the durable abort fact, and the per-call evidence release
// of THIS response. AbortConfirmed is durable history; EvidenceReleased alone
// reports that this invocation completed the acknowledgment.
func matchingAbortedReceipt(t *testing.T, value options) *runtime.CheckpointOperationStatus {
	t.Helper()
	digest, err := checkpointOperationRequestDigest(&runtime.CheckpointWithOperationRequest{
		OperationID:        value.operationID,
		Checkpoint:         checkpointRequestFromOptions(value),
		ExpectedGeneration: value.expectedGeneration,
	})
	if err != nil {
		t.Fatalf("receipt digest: %v", err)
	}
	return &runtime.CheckpointOperationStatus{
		OperationID:      value.operationID,
		SandboxID:        value.sandboxID,
		SourceGeneration: value.expectedGeneration,
		CheckpointDir:    filepath.Clean(value.checkpointDir),
		RequestDigest:    digest,
		State:            runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED,
		RecoveryProtocol: runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE,
		AbortConfirmed:   true,
		EvidenceReleased: true,
		Message:          "operation aborted",
	}
}

// TestAbortCheckpointOperationSendsExactOriginalPayload pins the abort wire
// contract: exactly one AbortCheckpointOperation call whose Operation is the
// COMPLETE original CheckpointWithOperationRequest — identical to what the
// checkpoint action sends for the same flags — beside an independent abort
// timeout. The receipt must carry the digest of that original payload alone
// (the pinned service vector), proving the abort timeout never participates
// in it.
func TestAbortCheckpointOperationSendsExactOriginalPayload(t *testing.T) {
	ctx := testContext(t)
	value := abortOperationOptions()
	client := &fakeClient{abortCheckpointStatus: matchingAbortedReceipt(t, value)}
	output, err := captureStdout(t, func() error {
		return abortCheckpointOperation(ctx, client, value, os.Stdout)
	})
	if err != nil {
		t.Fatalf("abort: %v", err)
	}
	if len(client.abortCheckpointCalls) != 1 || client.totalCalls() != 1 {
		t.Fatalf("AbortCheckpointOperation calls = %d (total %d), want exactly one abort RPC",
			len(client.abortCheckpointCalls), client.totalCalls())
	}
	if len(client.recoverCheckpointCalls) != 0 || len(client.checkpointCalls) != 0 ||
		len(client.checkpointIfCalls) != 0 || len(client.checkpointWithOperationCalls) != 0 {
		t.Fatalf("the abort reached a recovery or checkpoint RPC instead of the abort alone")
	}
	sent := client.abortCheckpointCalls[0]
	if sent.GetAbortTimeoutSeconds() != 77 {
		t.Errorf("abort_timeout_seconds = %d, want the independent 77", sent.GetAbortTimeoutSeconds())
	}
	// The wrapped operation must equal the issue-time request byte for byte:
	// the golden fixture IS what checkpointWithOperation sends for these
	// flags, so equality here proves the reconstruction is exact.
	original := sent.GetOperation()
	if original.GetOperationID() != "op-ck-1" || original.GetExpectedGeneration() != "gen-42" {
		t.Errorf("wrapped identity = %+v", original)
	}
	inner := original.GetCheckpoint()
	if inner.GetID() != "sbx-1" || inner.GetCheckpointDir() != "/tmp/cp" ||
		inner.GetTimeoutSeconds() != 30 || !inner.GetCompress() ||
		inner.GetLeaveRunning() || inner.GetSnapshotType() != "Full" {
		t.Errorf("wrapped original checkpoint request = %+v, want the issue-time fields unchanged", inner)
	}
	digest, err := checkpointOperationRequestDigest(original)
	if err != nil {
		t.Fatalf("digest the sent original: %v", err)
	}
	const goldenDigest = "5d1e7ac9962ff844b62ba32edf7f6928e4951ba20975c2d33d79009041ceb6bb"
	if digest != goldenDigest {
		t.Fatalf("digest of the aborted original = %s, want the pinned service vector %s — the payload reconstruction drifted", digest, goldenDigest)
	}
	if client.abortCheckpointStatus.GetRequestDigest() != digest {
		t.Fatalf("receipt digest %q does not answer for the sent original payload", client.abortCheckpointStatus.GetRequestDigest())
	}
	printed := parseCheckpointOperationStatus(t, output)
	if printed.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED ||
		printed.GetRecoveryProtocol() !=
			runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE ||
		!printed.GetAbortConfirmed() || !printed.GetEvidenceReleased() {
		t.Errorf("printed receipt = %+v, want FAILED/WITNESS_ABORTABLE with abort_confirmed and evidence_released", printed)
	}

	// A different abort timeout over the same original flags sends the same
	// digest-bound payload: the bound intent never moves with the attempt's
	// own bound.
	other := abortOperationOptions()
	other.abortTimeoutSeconds = 600
	client = &fakeClient{abortCheckpointStatus: matchingAbortedReceipt(t, other)}
	if _, err := captureStdout(t, func() error {
		return abortCheckpointOperation(ctx, client, other, os.Stdout)
	}); err != nil {
		t.Fatalf("abort with the maximum timeout: %v", err)
	}
	again, err := checkpointOperationRequestDigest(client.abortCheckpointCalls[0].GetOperation())
	if err != nil || again != goldenDigest {
		t.Fatalf("digest under abort timeout 600 = %s (%v), want the unchanged %s", again, err, goldenDigest)
	}
}

// TestAbortCheckpointOperationReceiptContract pins the receipt validation: a
// zero exit requires FAILED for exactly the reconstructed original request,
// under the WITNESS_ABORTABLE recovery protocol, with abort_confirmed=true
// AND evidence_released=true from THIS response. Anything else is printed
// (when the record is worth reconciling) and fails, or fails without output
// — never a silent success, and never a non-failure outcome.
func TestAbortCheckpointOperationReceiptContract(t *testing.T) {
	ctx := testContext(t)
	cases := []struct {
		name        string
		status      *runtime.CheckpointOperationStatus
		wantSuccess bool
		wantOutput  bool
		wantErrText string
	}{
		{
			name:        "confirmed released abort failure",
			status:      nil, // filled per-case from the options below
			wantSuccess: true,
			wantOutput:  true,
		},
		{
			name: "ordinary failed without abort confirmation",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.AbortConfirmed = false
				return s
			}(),
			wantOutput:  true,
			wantErrText: "abort_confirmed=false",
		},
		{
			name: "confirmed abort without evidence release",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.EvidenceReleased = false
				return s
			}(),
			wantOutput:  true,
			wantErrText: "evidence_released=false",
		},
		{
			name: "witness-only protocol record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.RecoveryProtocol =
					runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS
				return s
			}(),
			wantOutput:  false,
			wantErrText: "WITNESS_ABORTABLE records only",
		},
		{
			name: "legacy protocol record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.RecoveryProtocol =
					runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED
				return s
			}(),
			wantOutput:  false,
			wantErrText: "WITNESS_ABORTABLE records only",
		},
		{
			name: "unrecognized protocol enum",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol(7)
				return s
			}(),
			wantOutput:  false,
			wantErrText: "unrecognized recovery protocol",
		},
		{
			name: "wrong operation id",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.OperationID = "op-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "op-ck-1"`,
		},
		{
			name: "wrong sandbox id",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.SandboxID = "sbx-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "sbx-1"`,
		},
		{
			name: "wrong source generation",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.SourceGeneration = "gen-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "gen-42"`,
		},
		{
			name: "wrong checkpoint dir",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.CheckpointDir = "/tmp/other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: "canonical form",
		},
		{
			name: "wrong request digest",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.RequestDigest = strings.Repeat("ff", 32)
				return s
			}(),
			wantOutput:  false,
			wantErrText: "request_digest",
		},
		{
			name: "succeeded record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingCheckpointOperationReceipt(t, abortOperationOptions())
				s.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
				s.AbortConfirmed = false
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not FAILED",
		},
		{
			name: "unknown record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not FAILED",
		},
		{
			name: "running record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not FAILED",
		},
		{
			name: "unspecified state",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED
				return s
			}(),
			wantOutput:  false,
			wantErrText: "invalid record state",
		},
		{
			name: "failed record with sealed root",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingAbortedReceipt(t, abortOperationOptions())
				s.ArtifactRootDigest = strings.Repeat("ab", 32)
				s.ArtifactRootScheme = "v2:manifest+sidecar-roots"
				return s
			}(),
			wantOutput:  false,
			wantErrText: "sealed root",
		},
		{
			name:       "empty status",
			status:     nil,
			wantOutput: false,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := abortOperationOptions()
			receipt := testCase.status
			if receipt == nil && testCase.name == "confirmed released abort failure" {
				receipt = matchingAbortedReceipt(t, value)
			}
			client := &fakeClient{abortCheckpointStatus: receipt}
			output, err := captureStdout(t, func() error {
				return abortCheckpointOperation(ctx, client, value, os.Stdout)
			})
			if testCase.wantSuccess {
				if err != nil {
					t.Fatalf("a fully confirmed abort must exit zero: %v", err)
				}
			} else if err == nil {
				t.Fatal("an unproven abort receipt must fail the action")
			}
			if testCase.wantErrText != "" && !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Errorf("error %q lacks %q", err, testCase.wantErrText)
			}
			if testCase.wantOutput {
				status := parseCheckpointOperationStatus(t, output)
				if status.GetOperationID() != value.operationID {
					t.Errorf("reconciliation record = %+v, want the received receipt", status)
				}
			} else if output != "" {
				t.Errorf("stdout = %q, want none for %q", output, testCase.name)
			}
			if client.totalCalls() != 1 {
				t.Errorf("the receipt validation reached %d RPCs", client.totalCalls())
			}
		})
	}
}

// TestAbortCheckpointOperationNeverFallsBack pins that every failure of the
// abort RPC — Unimplemented from a server that predates or has not wired the
// abort surface, Unavailable, cancellation, a deadline, or a plain transport
// error — is terminal: no recovery RPC and no checkpoint RPC of any kind is
// attempted and nothing is printed as success. There is deliberately no
// structured not-found exit for this action either.
func TestAbortCheckpointOperationNeverFallsBack(t *testing.T) {
	ctx := testContext(t)
	failures := []error{
		status.Error(codes.Unimplemented, "sandboxd predates the abort RPC"),
		status.Error(codes.Unavailable, "daemon restarting"),
		status.Error(codes.Canceled, "caller cancelled"),
		status.Error(codes.DeadlineExceeded, "abort timed out"),
		status.Error(codes.FailedPrecondition, "witness-only record cannot be aborted"),
		status.Error(codes.NotFound, "checkpoint operation op-ck-1 is unknown"),
		errors.New("connection reset"),
	}
	for _, failure := range failures {
		client := &fakeClient{abortCheckpointErr: failure}
		output, err := captureStdout(t, func() error {
			return abortCheckpointOperation(ctx, client, abortOperationOptions(), os.Stdout)
		})
		if err == nil || !errors.Is(err, failure) {
			t.Fatalf("abort error = %v, want %v", err, failure)
		}
		if len(client.abortCheckpointCalls) != 1 {
			t.Fatalf("AbortCheckpointOperation calls = %d, want 1", len(client.abortCheckpointCalls))
		}
		if client.totalCalls() != 1 {
			t.Fatalf("the failed abort reached another RPC (%d total)", client.totalCalls())
		}
		if output != "" {
			t.Fatalf("failed abort printed %q, want no stdout", output)
		}
		if code := runExitCode(err); code != 1 {
			t.Fatalf("runExitCode(%v) = %d, want the generic 1 — the abort has no structured absence", failure, code)
		}
	}

	// The mirror image: a recovery failure never reaches the abort RPC, so
	// the two explicit reconciliations stay strictly separate actions.
	recovery := &fakeClient{recoverCheckpointErr: status.Error(codes.Unimplemented, "no recovery")}
	if _, err := captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, recovery, recoverOperationOptions(), os.Stdout)
	}); err == nil {
		t.Fatal("recovery must fail without the abort RPC")
	}
	if len(recovery.abortCheckpointCalls) != 0 {
		t.Fatalf("the failed recovery reached the abort RPC %d times", len(recovery.abortCheckpointCalls))
	}
}

// TestAbortCheckpointOperationInvalidInputReachesNoRPC pins the pre-dial
// gates: the abort demands the complete original payload under the same
// bounds the identified checkpoint enforces, plus its own abort-timeout
// bound, and direct callers of the helper are as safe as the CLI.
func TestAbortCheckpointOperationInvalidInputReachesNoRPC(t *testing.T) {
	ctx := testContext(t)
	client := new(fakeClient)
	invalid := map[string]func(*options){
		"path-unsafe operation id": func(v *options) { v.operationID = "op/../bad" },
		"missing generation":       func(v *options) { v.expectedGeneration = "" },
		"blank generation":         func(v *options) { v.expectedGeneration = "  " },
		"leave running":            func(v *options) { v.leaveRunning = true },
		"relative dir":             func(v *options) { v.checkpointDir = "cp" },
		"zero original timeout":    func(v *options) { v.checkpointTimeoutSeconds = 0 },
		"oversized original timeout": func(v *options) {
			v.checkpointTimeoutSeconds = checkpointOperationMaxTimeoutSeconds + 1
		},
		"zero abort timeout": func(v *options) { v.abortTimeoutSeconds = 0 },
		"oversized abort timeout": func(v *options) {
			v.abortTimeoutSeconds = checkpointOperationMaxTimeoutSeconds + 1
		},
		"missing sandbox":        func(v *options) { v.sandboxID = "" },
		"missing checkpoint dir": func(v *options) { v.checkpointDir = "" },
	}
	for name, mutate := range invalid {
		value := abortOperationOptions()
		mutate(&value)
		out := new(bytes.Buffer)
		if err := abortCheckpointOperation(ctx, client, value, out); err == nil {
			t.Errorf("abort accepted %s", name)
		} else if out.Len() != 0 {
			t.Errorf("abort %s printed %q before failing", name, out.String())
		}
		if client.totalCalls() != 0 {
			t.Fatalf("invalid input (%s) still reached %d RPCs", name, client.totalCalls())
		}
	}

	// The action's own flag surface: a well-formed invocation passes the
	// pre-dial gate, the expected generation belongs to it, and the misuse
	// of operation-mode pins stays rejected.
	if err := validateOptions(abortOperationOptions()); err != nil {
		t.Errorf("well-formed abort options rejected: %v", err)
	}
	for name, value := range map[string]options{
		"missing operation id": {action: "abort-checkpoint-operation", socket: "/run/sandboxd.sock",
			sandboxID: "sbx-1", checkpointDir: "/tmp/cp", expectedGeneration: "gen-42"},
		"root digest pin": {action: "abort-checkpoint-operation", socket: "/run/sandboxd.sock",
			operationID: "op-ck-1", sandboxID: "sbx-1", checkpointDir: "/tmp/cp",
			expectedGeneration: "gen-42", expectedRootDigest: strings.Repeat("a1", 32)},
	} {
		if err := validateOptions(value); err == nil {
			t.Errorf("conflicted abort options accepted (%s): %+v", name, value)
		}
	}
}

// TestAbortCheckpointOperationParseFlags runs the real argv parser for the
// abort mode: the flags bind (including the independent default abort
// timeout), a valid invocation passes validation, and both timeout bounds
// are enforced at the validation layer before any dial.
func TestAbortCheckpointOperationParseFlags(t *testing.T) {
	argv := []string{
		"--action=abort-checkpoint-operation",
		"--socket=/run/sandboxd.sock",
		"--sandbox-id=sbx-1",
		"--checkpoint-dir=/tmp/cp",
		"--checkpoint-timeout-seconds=30",
		"--abort-timeout-seconds=77",
		"--snapshot-type=Full",
		"--expected-generation=gen-42",
		"--operation-id=op-ck-1",
		"--leave-running=false",
	}
	value, err := parseFlags(argv, io.Discard)
	if err != nil {
		t.Fatalf("parse argv: %v", err)
	}
	if value.action != "abort-checkpoint-operation" || value.operationID != "op-ck-1" ||
		value.abortTimeoutSeconds != 77 || value.checkpointTimeoutSeconds != 30 || value.leaveRunning {
		t.Fatalf("argv bound the wrong mode: %+v", value)
	}
	if err := validateOptions(value); err != nil {
		t.Fatalf("valid abort argv rejected: %v", err)
	}

	// The abort timeout defaults to 180 and stays independent of the
	// original checkpoint timeout's default.
	defaulted, err := parseFlags([]string{
		"--action=abort-checkpoint-operation",
		"--socket=/run/sandboxd.sock",
		"--sandbox-id=sbx-1",
		"--checkpoint-dir=/tmp/cp",
		"--expected-generation=gen-42",
		"--operation-id=op-ck-1",
		"--leave-running=false",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parse defaulted argv: %v", err)
	}
	if defaulted.abortTimeoutSeconds != 180 || defaulted.checkpointTimeoutSeconds != 180 ||
		defaulted.recoveryTimeoutSeconds != 180 {
		t.Fatalf("timeout defaults = abort %d, checkpoint %d, recovery %d; want 180 each",
			defaulted.abortTimeoutSeconds, defaulted.checkpointTimeoutSeconds, defaulted.recoveryTimeoutSeconds)
	}

	// The abort's own bound is enforced before the dial.
	oversized := append([]string{}, argv...)
	oversized[5] = "--abort-timeout-seconds=601"
	value, err = parseFlags(oversized, io.Discard)
	if err != nil {
		t.Fatalf("parse oversized argv: %v", err)
	}
	runErr := run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--abort-timeout-seconds must be between 1 and 600") {
		t.Fatalf("oversized abort timeout error = %v", runErr)
	}

	// The original timeout keeps its checkpoint-mode bound here too.
	staleOriginal := append([]string{}, argv...)
	staleOriginal[4] = "--checkpoint-timeout-seconds=601"
	value, err = parseFlags(staleOriginal, io.Discard)
	if err != nil {
		t.Fatalf("parse stale original timeout argv: %v", err)
	}
	runErr = run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--checkpoint-timeout-seconds must be between 1 and 600") {
		t.Fatalf("stale original timeout error = %v", runErr)
	}

	// Omitting --operation-id entirely never selects a legacy mode.
	noOperation := append([]string{}, argv...)
	noOperation[len(noOperation)-1] = "--operation-id="
	value, err = parseFlags(noOperation, io.Discard)
	if err != nil {
		t.Fatalf("parse explicit empty argv: %v", err)
	}
	runErr = run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--operation-id must not be empty") {
		t.Fatalf("explicit empty --operation-id error = %v", runErr)
	}
}

// TestAbortConfirmedContradictoryShapeRejected pins the one structural rule
// of abort_confirmed across every receipt consumer: the durable abort fact
// belongs only to a FAILED record under WITNESS_ABORTABLE without a sealed
// root. A SUCCEEDED record carrying it is contradictory even with a fully
// valid root, and no other state or protocol may claim it — while a legal
// historical true is printed as the fact it is, inferring nothing.
func TestAbortConfirmedContradictoryShapeRejected(t *testing.T) {
	ctx := testContext(t)

	// An identified-checkpoint success claiming a confirmed abort is
	// malformed, root validity notwithstanding.
	value := checkpointOperationOptions()
	receipt := matchingCheckpointOperationReceipt(t, value)
	receipt.AbortConfirmed = true
	client := &fakeClient{checkpointWithOperationStatus: receipt}
	output, err := captureStdout(t, func() error {
		return checkpoint(ctx, client, value)
	})
	if err == nil || !strings.Contains(err.Error(), "abort_confirmed=true") {
		t.Fatalf("SUCCEEDED receipt with abort_confirmed = %v, want a shape error", err)
	}
	if output != "" {
		t.Errorf("malformed receipt printed %q, want no stdout", output)
	}

	// A fully released explicit recovery claiming a confirmed abort is
	// equally contradictory.
	recovery := recoverOperationOptions()
	recovered := matchingRecoveredReceipt(t, recovery)
	recovered.AbortConfirmed = true
	recoveryClient := &fakeClient{recoverCheckpointStatus: recovered}
	output, err = captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, recoveryClient, recovery, os.Stdout)
	})
	if err == nil || !strings.Contains(err.Error(), "abort_confirmed=true") {
		t.Fatalf("recovery receipt with abort_confirmed = %v, want a shape error", err)
	}
	if output != "" {
		t.Errorf("malformed recovery printed %q, want no stdout", output)
	}

	// The query validator refuses the same contradiction and accepts the
	// legal historical shape.
	bad := queryCheckpointOperationRecord()
	bad.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	bad.AbortConfirmed = true
	if err := validateCheckpointOperationRecordReply(bad, "op-ck-1"); err == nil ||
		!strings.Contains(err.Error(), "abort_confirmed=true") {
		t.Fatalf("SUCCEEDED query record with abort_confirmed = %v, want a shape error", err)
	}
	good := queryCheckpointOperationRecord()
	good.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
	good.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	good.ArtifactRootDigest = ""
	good.ArtifactRootScheme = ""
	good.AbortConfirmed = true
	if err := validateCheckpointOperationRecordReply(good, "op-ck-1"); err != nil {
		t.Fatalf("a FAILED WITNESS_ABORTABLE record with a historical abort fact was refused: %v", err)
	}
	withRoot := queryCheckpointOperationRecord()
	withRoot.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
	withRoot.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	withRoot.AbortConfirmed = true
	if err := validateCheckpointOperationRecordReply(withRoot, "op-ck-1"); err == nil ||
		!strings.Contains(err.Error(), "abort_confirmed=true") {
		t.Fatalf("FAILED record with a root and abort_confirmed = %v, want a shape error", err)
	}

	// A protocol-2 recovery without this response's release proof fails
	// exactly like a WITNESS one: both protocols owe the explicit release.
	unreleased := recoverOperationOptions()
	unreleasedReceipt := matchingRecoveredReceipt(t, unreleased)
	unreleasedReceipt.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	unreleasedReceipt.EvidenceReleased = false
	unreleasedClient := &fakeClient{recoverCheckpointStatus: unreleasedReceipt}
	output, err = captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, unreleasedClient, unreleased, os.Stdout)
	})
	if err == nil || !strings.Contains(err.Error(), "evidence_released=false") {
		t.Fatalf("protocol-2 recovery without release = %v, want the unproven-release failure", err)
	}
	if parseCheckpointOperationStatus(t, output).GetOperationID() != unreleased.operationID {
		t.Errorf("the unreleased protocol-2 receipt was not printed for reconciliation: %q", output)
	}
}

// TestAbortProtocolFieldAcrossActions pins how the WITNESS_ABORTABLE
// protocol value is treated by the other operation actions: it is legal
// record history everywhere — an identified checkpoint under protocol 2
// succeeds and serializes the fact verbatim, and an explicit recovery of a
// protocol-2 record is accepted with its release proof — while the abort
// remains the only action that may confirm one.
func TestAbortProtocolFieldAcrossActions(t *testing.T) {
	ctx := testContext(t)

	// An identified checkpoint admitted under protocol 2 keeps its success
	// contract: reported verbatim, no release gating on this action.
	value := checkpointOperationOptions()
	receipt := matchingCheckpointOperationReceipt(t, value)
	receipt.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	receipt.EvidenceReleased = true
	client := &fakeClient{checkpointWithOperationStatus: receipt}
	output, err := captureStdout(t, func() error {
		return checkpoint(ctx, client, value)
	})
	if err != nil {
		t.Fatalf("protocol-2 checkpoint success: %v", err)
	}
	printed := parseCheckpointOperationStatus(t, output)
	if printed.GetRecoveryProtocol() !=
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE ||
		printed.GetAbortConfirmed() {
		t.Errorf("protocol-2 receipt fields were not serialized verbatim: %+v", printed)
	}

	// An explicit recovery of a protocol-2 record is a legal success: the
	// same receipt contract as WITNESS, release proof included.
	recovery := recoverOperationOptions()
	recovered := matchingRecoveredReceipt(t, recovery)
	recovered.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	recoveryClient := &fakeClient{recoverCheckpointStatus: recovered}
	if _, err := captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, recoveryClient, recovery, os.Stdout)
	}); err != nil {
		t.Fatalf("protocol-2 recovery success: %v", err)
	}
	if len(recoveryClient.abortCheckpointCalls) != 0 {
		t.Fatalf("the protocol-2 recovery reached the abort RPC")
	}

	// The query prints the field without inferring anything from it: a
	// historical abort confirmation on a queried record is just a fact in
	// the output, never a release or a success.
	query := queryCheckpointOperationRecord()
	query.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
	query.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE
	query.ArtifactRootDigest = ""
	query.ArtifactRootScheme = ""
	queryClient := &fakeClient{getCheckpointOperationStatus: query}
	queryOutput, err := captureStdout(t, func() error {
		return getCheckpointOperation(ctx, queryClient, options{operationID: "op-ck-1"}, os.Stdout)
	})
	if err != nil {
		t.Fatalf("query of a FAILED protocol-2 record: %v", err)
	}
	printedQuery := parseCheckpointOperationStatus(t, queryOutput)
	if printedQuery.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED {
		t.Errorf("queried record = %+v, want the FAILED fact printed verbatim", printedQuery)
	}
}
