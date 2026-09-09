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

// Regressions for the explicit recover-checkpoint-operation action: the wire
// contract (the COMPLETE original CheckpointWithOperation payload beside an
// independent recovery timeout that never enters the request digest), the
// receipt contract (WITNESS protocol plus evidence_released=true from THIS
// response for a zero exit), the no-fallback line, and the pre-dial gates.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recoverOperationOptions is the flag value of a fully specified recovery
// whose original checkpoint matches the pinned digest fixture field for
// field; only the independent recovery timeout differs from the issue-time
// invocation, which is exactly what must not move the digest.
func recoverOperationOptions() options {
	value := checkpointOperationOptions()
	value.action = "recover-checkpoint-operation"
	value.recoveryTimeoutSeconds = 77
	return value
}

// matchingRecoveredReceipt builds the receipt a successful recovery must
// answer with: the requested identity, the digest of the original payload,
// the sealed root, the WITNESS record protocol, and the release proof of
// THIS response.
func matchingRecoveredReceipt(t *testing.T, value options) *runtime.CheckpointOperationStatus {
	t.Helper()
	receipt := matchingCheckpointOperationReceipt(t, value)
	receipt.RecoveryProtocol =
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS
	receipt.EvidenceReleased = true
	return receipt
}

// TestRecoverCheckpointOperationSendsExactOriginalPayload pins the recovery
// wire contract: exactly one RecoverCheckpointOperation call whose Operation
// is the COMPLETE original CheckpointWithOperationRequest — identical to what
// the checkpoint action sends for the same flags — beside an independent
// recovery timeout. The receipt must carry the digest of that original
// payload alone (the pinned service vector), proving the recovery timeout
// never participates in it.
func TestRecoverCheckpointOperationSendsExactOriginalPayload(t *testing.T) {
	ctx := testContext(t)
	value := recoverOperationOptions()
	client := &fakeClient{recoverCheckpointStatus: matchingRecoveredReceipt(t, value)}
	output, err := captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, client, value, os.Stdout)
	})
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if len(client.recoverCheckpointCalls) != 1 || client.totalCalls() != 1 {
		t.Fatalf("RecoverCheckpointOperation calls = %d (total %d), want exactly one recovery RPC",
			len(client.recoverCheckpointCalls), client.totalCalls())
	}
	if len(client.checkpointCalls) != 0 || len(client.checkpointIfCalls) != 0 ||
		len(client.checkpointWithOperationCalls) != 0 {
		t.Fatalf("the recovery reached a checkpoint RPC instead of reconciling the recorded one")
	}
	sent := client.recoverCheckpointCalls[0]
	if sent.GetRecoveryTimeoutSeconds() != 77 {
		t.Errorf("recovery_timeout_seconds = %d, want the independent 77", sent.GetRecoveryTimeoutSeconds())
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
	// The digest the CLI validated is computed from the reconstructed
	// original payload alone and must equal the pinned service vector — the
	// same digest the original checkpoint bound — no matter the recovery
	// timeout sent beside it.
	digest, err := checkpointOperationRequestDigest(original)
	if err != nil {
		t.Fatalf("digest the sent original: %v", err)
	}
	const goldenDigest = "5d1e7ac9962ff844b62ba32edf7f6928e4951ba20975c2d33d79009041ceb6bb"
	if digest != goldenDigest {
		t.Fatalf("digest of the recovered original = %s, want the pinned service vector %s — the payload reconstruction drifted", digest, goldenDigest)
	}
	if client.recoverCheckpointStatus.GetRequestDigest() != digest {
		t.Fatalf("receipt digest %q does not answer for the sent original payload", client.recoverCheckpointStatus.GetRequestDigest())
	}
	printed := parseCheckpointOperationStatus(t, output)
	if printed.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED ||
		printed.GetRecoveryProtocol() !=
			runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS ||
		!printed.GetEvidenceReleased() {
		t.Errorf("printed receipt = %+v, want SUCCEEDED/WITNESS with evidence_released=true", printed)
	}

	// A different recovery timeout over the same original flags sends the
	// same digest-bound payload: the bound intent never moves with the
	// attempt's own bound.
	other := recoverOperationOptions()
	other.recoveryTimeoutSeconds = 600
	client = &fakeClient{recoverCheckpointStatus: matchingRecoveredReceipt(t, other)}
	if _, err := captureStdout(t, func() error {
		return recoverCheckpointOperation(ctx, client, other, os.Stdout)
	}); err != nil {
		t.Fatalf("recovery with the maximum timeout: %v", err)
	}
	again, err := checkpointOperationRequestDigest(client.recoverCheckpointCalls[0].GetOperation())
	if err != nil || again != goldenDigest {
		t.Fatalf("digest under recovery timeout 600 = %s (%v), want the unchanged %s", again, err, goldenDigest)
	}
}

// TestRecoverCheckpointOperationReceiptContract pins the receipt validation:
// a zero exit requires SUCCEEDED for exactly the reconstructed original
// request, under the WITNESS recovery protocol, with evidence_released=true
// from THIS response. Anything else is printed (when the record is worth
// reconciling) and fails, or fails without output — never a silent success.
func TestRecoverCheckpointOperationReceiptContract(t *testing.T) {
	ctx := testContext(t)
	cases := []struct {
		name        string
		status      *runtime.CheckpointOperationStatus
		wantSuccess bool
		wantOutput  bool
		wantErrText string
	}{
		{
			name:        "released witness success",
			status:      nil, // filled per-case from the options below
			wantSuccess: true,
			wantOutput:  true,
		},
		{
			name: "unreleased witness success",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.EvidenceReleased = false
				return s
			}(),
			wantOutput:  true,
			wantErrText: "evidence_released=false",
		},
		{
			name: "legacy protocol record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.RecoveryProtocol =
					runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED
				return s
			}(),
			wantOutput:  false,
			wantErrText: "witness-capable records only",
		},
		{
			name: "unrecognized protocol enum",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol(7)
				return s
			}(),
			wantOutput:  false,
			wantErrText: "unrecognized recovery protocol",
		},
		{
			name: "wrong operation id",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.OperationID = "op-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "op-ck-1"`,
		},
		{
			name: "wrong sandbox id",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.SandboxID = "sbx-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "sbx-1"`,
		},
		{
			name: "wrong source generation",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.SourceGeneration = "gen-other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: `does not match requested "gen-42"`,
		},
		{
			name: "wrong checkpoint dir",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.CheckpointDir = "/tmp/other"
				return s
			}(),
			wantOutput:  false,
			wantErrText: "canonical form",
		},
		{
			name: "wrong request digest",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.RequestDigest = strings.Repeat("ff", 32)
				return s
			}(),
			wantOutput:  false,
			wantErrText: "request_digest",
		},
		{
			name: "running record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
				s.ArtifactRootDigest = ""
				s.ArtifactRootScheme = ""
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not SUCCEEDED",
		},
		{
			name: "unknown record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN
				s.ArtifactRootDigest = ""
				s.ArtifactRootScheme = ""
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not SUCCEEDED",
		},
		{
			name: "failed record",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
				s.ArtifactRootDigest = ""
				s.ArtifactRootScheme = ""
				return s
			}(),
			wantOutput:  true,
			wantErrText: "is not SUCCEEDED",
		},
		{
			name: "unspecified state",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED
				s.ArtifactRootDigest = ""
				s.ArtifactRootScheme = ""
				return s
			}(),
			wantOutput:  false,
			wantErrText: "invalid record state",
		},
		{
			name: "succeeded without root",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.ArtifactRootDigest = ""
				s.ArtifactRootScheme = ""
				return s
			}(),
			wantOutput:  false,
			wantErrText: "artifact_root_digest",
		},
		{
			name: "succeeded with foreign scheme",
			status: func() *runtime.CheckpointOperationStatus {
				s := matchingRecoveredReceipt(t, recoverOperationOptions())
				s.ArtifactRootScheme = "v1:foreign"
				return s
			}(),
			wantOutput:  false,
			wantErrText: "root scheme",
		},
		{
			name:       "empty status",
			status:     nil,
			wantOutput: false,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := recoverOperationOptions()
			receipt := testCase.status
			if receipt == nil && testCase.name == "released witness success" {
				receipt = matchingRecoveredReceipt(t, value)
			}
			client := &fakeClient{recoverCheckpointStatus: receipt}
			output, err := captureStdout(t, func() error {
				return recoverCheckpointOperation(ctx, client, value, os.Stdout)
			})
			if testCase.wantSuccess {
				if err != nil {
					t.Fatalf("a released witness success must exit zero: %v", err)
				}
			} else if err == nil {
				t.Fatal("an unproven recovery receipt must fail the action")
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

// TestRecoverCheckpointOperationNeverFallsBack pins that every failure of
// the recovery RPC — Unimplemented from an older server, Unavailable,
// cancellation, a deadline, or a plain transport error — is terminal: no
// checkpoint RPC of any kind is attempted and nothing is printed as success.
// There is also deliberately no structured not-found exit for this action:
// a recovery targets an already-recorded operation, so callers reconciling
// absence use the query action.
func TestRecoverCheckpointOperationNeverFallsBack(t *testing.T) {
	ctx := testContext(t)
	failures := []error{
		status.Error(codes.Unimplemented, "sandboxd predates the recovery RPC"),
		status.Error(codes.Unavailable, "daemon restarting"),
		status.Error(codes.Canceled, "caller cancelled"),
		status.Error(codes.DeadlineExceeded, "recovery timed out"),
		status.Error(codes.FailedPrecondition, "legacy record without a witness"),
		status.Error(codes.NotFound, "checkpoint operation op-ck-1 is unknown"),
		errors.New("connection reset"),
	}
	for _, failure := range failures {
		client := &fakeClient{recoverCheckpointErr: failure}
		output, err := captureStdout(t, func() error {
			return recoverCheckpointOperation(ctx, client, recoverOperationOptions(), os.Stdout)
		})
		if err == nil || !errors.Is(err, failure) {
			t.Fatalf("recovery error = %v, want %v", err, failure)
		}
		if len(client.recoverCheckpointCalls) != 1 {
			t.Fatalf("RecoverCheckpointOperation calls = %d, want 1", len(client.recoverCheckpointCalls))
		}
		if client.totalCalls() != 1 {
			t.Fatalf("the failed recovery reached another RPC (%d total)", client.totalCalls())
		}
		if output != "" {
			t.Fatalf("failed recovery printed %q, want no stdout", output)
		}
		if code := runExitCode(err); code != 1 {
			t.Fatalf("runExitCode(%v) = %d, want the generic 1 — recovery has no structured absence", failure, code)
		}
	}
}

// TestRecoverCheckpointOperationInvalidInputReachesNoRPC pins the pre-dial
// gates: the recovery demands the complete original payload under the same
// bounds the identified checkpoint enforces, plus its own recovery-timeout
// bound, and direct callers of the helper are as safe as the CLI.
func TestRecoverCheckpointOperationInvalidInputReachesNoRPC(t *testing.T) {
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
		"zero recovery timeout": func(v *options) { v.recoveryTimeoutSeconds = 0 },
		"oversized recovery timeout": func(v *options) {
			v.recoveryTimeoutSeconds = checkpointOperationMaxTimeoutSeconds + 1
		},
		"missing sandbox":        func(v *options) { v.sandboxID = "" },
		"missing checkpoint dir": func(v *options) { v.checkpointDir = "" },
	}
	for name, mutate := range invalid {
		value := recoverOperationOptions()
		mutate(&value)
		out := new(bytes.Buffer)
		if err := recoverCheckpointOperation(ctx, client, value, out); err == nil {
			t.Errorf("recovery accepted %s", name)
		} else if out.Len() != 0 {
			t.Errorf("recovery %s printed %q before failing", name, out.String())
		}
		if client.totalCalls() != 0 {
			t.Fatalf("invalid input (%s) still reached %d RPCs", name, client.totalCalls())
		}
	}

	// The action's own flag surface: a well-formed invocation passes the
	// pre-dial gate, the expected generation belongs to it, and the misuse
	// of operation-mode pins stays rejected.
	if err := validateOptions(recoverOperationOptions()); err != nil {
		t.Errorf("well-formed recovery options rejected: %v", err)
	}
	for name, value := range map[string]options{
		"missing operation id": {action: "recover-checkpoint-operation", socket: "/run/sandboxd.sock",
			sandboxID: "sbx-1", checkpointDir: "/tmp/cp", expectedGeneration: "gen-42"},
		"root digest pin": {action: "recover-checkpoint-operation", socket: "/run/sandboxd.sock",
			operationID: "op-ck-1", sandboxID: "sbx-1", checkpointDir: "/tmp/cp",
			expectedGeneration: "gen-42", expectedRootDigest: strings.Repeat("a1", 32)},
	} {
		if err := validateOptions(value); err == nil {
			t.Errorf("conflicted recovery options accepted (%s): %+v", name, value)
		}
	}
}

// TestRecoverCheckpointOperationParseFlags runs the real argv parser for the
// recovery mode: the flags bind, a valid invocation passes validation, and
// the two timeout bounds are enforced at the validation layer before any
// dial.
func TestRecoverCheckpointOperationParseFlags(t *testing.T) {
	argv := []string{
		"--action=recover-checkpoint-operation",
		"--socket=/run/sandboxd.sock",
		"--sandbox-id=sbx-1",
		"--checkpoint-dir=/tmp/cp",
		"--checkpoint-timeout-seconds=30",
		"--recovery-timeout-seconds=77",
		"--snapshot-type=Full",
		"--expected-generation=gen-42",
		"--operation-id=op-ck-1",
		"--leave-running=false",
	}
	value, err := parseFlags(argv, io.Discard)
	if err != nil {
		t.Fatalf("parse argv: %v", err)
	}
	if value.action != "recover-checkpoint-operation" || value.operationID != "op-ck-1" ||
		value.recoveryTimeoutSeconds != 77 || value.checkpointTimeoutSeconds != 30 || value.leaveRunning {
		t.Fatalf("argv bound the wrong mode: %+v", value)
	}
	if err := validateOptions(value); err != nil {
		t.Fatalf("valid recovery argv rejected: %v", err)
	}

	// The recovery's own bound is enforced before the dial.
	oversized := append([]string{}, argv...)
	oversized[5] = "--recovery-timeout-seconds=601"
	value, err = parseFlags(oversized, io.Discard)
	if err != nil {
		t.Fatalf("parse oversized argv: %v", err)
	}
	runErr := run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--recovery-timeout-seconds must be between 1 and 600") {
		t.Fatalf("oversized recovery timeout error = %v", runErr)
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
	noOperation = append(noOperation[:len(noOperation)-2], "--operation-id=")
	value, err = parseFlags(noOperation, io.Discard)
	if err != nil {
		t.Fatalf("parse explicit empty argv: %v", err)
	}
	runErr = run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--operation-id must not be empty") {
		t.Fatalf("explicit empty --operation-id error = %v", runErr)
	}
}

// TestCheckpointOperationProtocolFieldValidation pins how the two existing
// actions treat the new record fields: both defined protocols are legal
// history wherever facts are compared — a legacy success keeps its existing
// acceptance, a witness success is accepted with its release fact serialized
// — while an out-of-range protocol is a protocol error everywhere, never a
// value to reinterpret as legacy.
func TestCheckpointOperationProtocolFieldValidation(t *testing.T) {
	ctx := testContext(t)
	for name, protocol := range map[string]runtime.CheckpointOperationRecoveryProtocol{
		"legacy":  runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED,
		"witness": runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
	} {
		value := checkpointOperationOptions()
		receipt := matchingCheckpointOperationReceipt(t, value)
		receipt.RecoveryProtocol = protocol
		// A witness first-issue success that acknowledged in the same call
		// reports true; a legacy success has no release fact at all. Either
		// way the checkpoint action reports the fact without gating on it.
		receipt.EvidenceReleased = protocol ==
			runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS
		client := &fakeClient{checkpointWithOperationStatus: receipt}
		output, err := captureStdout(t, func() error {
			return checkpoint(ctx, client, value)
		})
		if err != nil {
			t.Fatalf("%s checkpoint success: %v", name, err)
		}
		printed := parseCheckpointOperationStatus(t, output)
		if printed.GetRecoveryProtocol() != protocol || printed.GetEvidenceReleased() != receipt.GetEvidenceReleased() {
			t.Errorf("%s receipt fields were not serialized verbatim: %+v", name, printed)
		}
	}

	// An out-of-range protocol is rejected by every reader.
	for name, mutate := range map[string]func(*runtime.CheckpointOperationStatus){
		"checkpoint receipt": func(s *runtime.CheckpointOperationStatus) {
			s.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol(9)
		},
	} {
		value := checkpointOperationOptions()
		receipt := matchingCheckpointOperationReceipt(t, value)
		mutate(receipt)
		client := &fakeClient{checkpointWithOperationStatus: receipt}
		output, err := captureStdout(t, func() error {
			return checkpoint(ctx, client, value)
		})
		if err == nil || !strings.Contains(err.Error(), "unrecognized recovery protocol") {
			t.Fatalf("%s with an unknown protocol = %v, want a protocol error", name, err)
		}
		if output != "" {
			t.Errorf("%s printed %q, want no stdout", name, output)
		}
	}
	query := queryCheckpointOperationRecord()
	query.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol(-2)
	if err := validateCheckpointOperationRecordReply(query, "op-ck-1"); err == nil ||
		!strings.Contains(err.Error(), "unrecognized recovery protocol") {
		t.Fatalf("query record with an unknown protocol = %v, want a protocol error", err)
	}

	// The scheme constant this file relies on stays the shared one.
	if checkpointroot.Scheme == "" {
		t.Fatal("the shared root scheme constant is empty")
	}
}
