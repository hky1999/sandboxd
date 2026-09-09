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

import (
	"reflect"
	"testing"
)

func TestParseMountFlags(t *testing.T) {
	mounts, err := parseMountFlags([]string{
		"/host/data:/mnt/data:bind:ro,nodev",
		"tmpfs:/run/cache:tmpfs:rw,size=1m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mount count = %d", len(mounts))
	}
	if mounts[0].GetHostPath() != "/host/data" ||
		mounts[0].GetTarget() != "/mnt/data" ||
		mounts[0].GetType() != "bind" ||
		!reflect.DeepEqual(mounts[0].GetOptions(), []string{"ro", "nodev"}) {
		t.Fatalf("first mount = %+v", mounts[0])
	}
	if mounts[1].GetHostPath() != "tmpfs" ||
		mounts[1].GetType() != "tmpfs" ||
		!reflect.DeepEqual(mounts[1].GetOptions(), []string{"rw", "size=1m"}) {
		t.Fatalf("second mount = %+v", mounts[1])
	}
}

func TestParseMountFlagsRejectsMalformedValue(t *testing.T) {
	for _, value := range []string{"", "source", ":/target", "source:"} {
		if _, err := parseMountFlags([]string{value}); err == nil {
			t.Fatalf("accepted malformed mount %q", value)
		}
	}
}

// --- identified source checkpoint operations ---

// testContext bounds every CLI-under-test call: a misbehaving stub fails the
// test at the deadline instead of blocking the suite indefinitely.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// goldenWrappedCheckpointOperation is the fixture whose service-algorithm
// digest was computed independently (clone the wrapped request, drop the
// operation ID, marshal deterministically, SHA-256): the pinned hex below is
// that vector, so any drift in the CLI's fingerprint fails the test instead of
// silently unbinding the CLI from the server's request identity.
func goldenWrappedCheckpointOperation() *runtime.CheckpointWithOperationRequest {
	return &runtime.CheckpointWithOperationRequest{
		OperationID: "op-ck-1",
		Checkpoint: &runtime.CheckpointRequest{
			ID:             "sbx-1",
			CheckpointDir:  "/tmp/cp",
			TimeoutSeconds: 30,
			Compress:       true,
			LeaveRunning:   false,
			SnapshotType:   "Full",
		},
		ExpectedGeneration: "gen-42",
	}
}

// TestCheckpointOperationRequestDigestMatchesServiceAlgorithm pins the digest
// contract: a fixed golden value, invariance under a new operation ID (the ID
// is the key being bound, not the intent), and sensitivity to every semantic
// field of the wrapped request.
func TestCheckpointOperationRequestDigestMatchesServiceAlgorithm(t *testing.T) {
	golden := goldenWrappedCheckpointOperation()
	digest, err := checkpointOperationRequestDigest(golden)
	if err != nil {
		t.Fatalf("digest golden: %v", err)
	}
	const want = "5d1e7ac9962ff844b62ba32edf7f6928e4951ba20975c2d33d79009041ceb6bb"
	if digest != want {
		t.Fatalf("digest = %s, want the pinned service vector %s", digest, want)
	}

	renamed := goldenWrappedCheckpointOperation()
	renamed.OperationID = "op-entirely-different"
	renamedDigest, err := checkpointOperationRequestDigest(renamed)
	if err != nil {
		t.Fatalf("digest renamed: %v", err)
	}
	if renamedDigest != digest {
		t.Fatalf("digest changed with the operation ID alone: %s vs %s", renamedDigest, digest)
	}

	stable, err := checkpointOperationRequestDigest(goldenWrappedCheckpointOperation())
	if err != nil || stable != digest {
		t.Fatalf("digest is not deterministic across calls: %s vs %s (%v)", stable, digest, err)
	}

	mutations := map[string]func(*runtime.CheckpointWithOperationRequest){
		"sandbox id":     func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.ID = "sbx-2" },
		"checkpoint dir": func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.CheckpointDir = "/tmp/other" },
		"timeout":        func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.TimeoutSeconds = 31 },
		"compress":       func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.Compress = false },
		"leave running":  func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.LeaveRunning = true },
		"snapshot type":  func(r *runtime.CheckpointWithOperationRequest) { r.Checkpoint.SnapshotType = "Incremental" },
		"generation":     func(r *runtime.CheckpointWithOperationRequest) { r.ExpectedGeneration = "gen-43" },
	}
	for name, mutate := range mutations {
		mutated := goldenWrappedCheckpointOperation()
		mutate(mutated)
		mutatedDigest, err := checkpointOperationRequestDigest(mutated)
		if err != nil {
			t.Fatalf("digest %s: %v", name, err)
		}
		if mutatedDigest == digest {
			t.Errorf("digest ignored a semantic field change (%s)", name)
		}
	}
}

// checkpointOperationOptions is the flag value of a fully specified
// identified checkpoint, matching the digest fixture field for field.
func checkpointOperationOptions() options {
	return options{
		action:                   "checkpoint",
		socket:                   "/run/sandboxd.sock",
		sandboxID:                "sbx-1",
		checkpointDir:            "/tmp/cp",
		checkpointTimeoutSeconds: 30,
		compress:                 true,
		leaveRunning:             false,
		snapshotType:             "Full",
		expectedGeneration:       "gen-42",
		operationID:              "op-ck-1",
		operationIDSet:           true,
	}
}

// matchingCheckpointOperationReceipt builds the SUCCEEDED receipt the options
// above must produce: the requested identity, the canonical directory, the
// digest of the very wrapped request the CLI sends, and a sealed root under
// the shared scheme.
func matchingCheckpointOperationReceipt(t *testing.T, value options) *runtime.CheckpointOperationStatus {
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
		OperationID:        value.operationID,
		SandboxID:          value.sandboxID,
		SourceGeneration:   value.expectedGeneration,
		CheckpointDir:      filepath.Clean(value.checkpointDir),
		RequestDigest:      digest,
		State:              runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED,
		ArtifactRootDigest: strings.Repeat("ab", 32),
		ArtifactRootScheme: checkpointroot.Scheme,
		Message:            "checkpoint completed",
	}
}

// checkpointRequestFromOptions rebuilds the legacy CheckpointRequest the
// checkpoint action assembles, so tests can assert the identified mode sends
// exactly those fields unchanged.
func checkpointRequestFromOptions(value options) *runtime.CheckpointRequest {
	return &runtime.CheckpointRequest{
		ID:             value.sandboxID,
		CheckpointDir:  value.checkpointDir,
		TimeoutSeconds: uint32(value.checkpointTimeoutSeconds),
		Compress:       value.compress,
		LeaveRunning:   value.leaveRunning,
		SnapshotType:   value.snapshotType,
	}
}

// parseCheckpointOperationStatus asserts the CLI printed exactly one
// protojson CheckpointOperationStatus — all twelve snake_case keys,
// nothing else — so callers can reject mixed or partial output instead of
// guessing. The recovery-protocol, evidence-release, and abort-confirmation
// transport fields are part of the record surface every reply serializes.
func parseCheckpointOperationStatus(t *testing.T, output string) *runtime.CheckpointOperationStatus {
	t.Helper()
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal([]byte(output), &fields); err != nil {
		t.Fatalf("stdout %q is not one JSON object: %v", output, err)
	}
	for _, key := range []string{
		"operation_id", "sandbox_id", "state", "source_generation",
		"checkpoint_dir", "request_digest", "artifact_root_digest",
		"artifact_root_scheme", "message", "recovery_protocol",
		"evidence_released", "abort_confirmed",
	} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("stdout %q lacks the %q field", output, key)
		}
	}
	if len(fields) != 12 {
		t.Fatalf("stdout %q must carry exactly the twelve record fields, got %d keys", output, len(fields))
	}
	status := new(runtime.CheckpointOperationStatus)
	if err := (protojson.UnmarshalOptions{}).Unmarshal([]byte(output), status); err != nil {
		t.Fatalf("stdout %q is not one protojson CheckpointOperationStatus: %v", output, err)
	}
	return status
}

// TestCheckpointWithOperationSendsCompleteRequest pins the identified
// checkpoint wire contract: one CheckpointWithOperation call carrying the
// complete legacy CheckpointRequest unchanged plus the operation identity and
// expected generation, no legacy checkpoint RPC, and — only after the receipt
// proves the requested intent — one strict protojson object on stdout.
func TestCheckpointWithOperationSendsCompleteRequest(t *testing.T) {
	ctx := testContext(t)
	value := checkpointOperationOptions()
	client := &fakeClient{checkpointWithOperationStatus: matchingCheckpointOperationReceipt(t, value)}
	output, err := captureStdout(t, func() error {
		return checkpoint(ctx, client, value)
	})
	if err != nil {
		t.Fatalf("identified checkpoint: %v", err)
	}
	if len(client.checkpointWithOperationCalls) != 1 {
		t.Fatalf("CheckpointWithOperation calls = %d, want 1", len(client.checkpointWithOperationCalls))
	}
	if client.totalCalls() != 1 {
		t.Fatalf("identified checkpoint reached %d RPCs in total", client.totalCalls())
	}
	if len(client.checkpointCalls) != 0 || len(client.checkpointIfCalls) != 0 {
		t.Fatalf("identified checkpoint reached a legacy checkpoint RPC")
	}
	sent := client.checkpointWithOperationCalls[0]
	if sent.GetOperationID() != "op-ck-1" || sent.GetExpectedGeneration() != "gen-42" {
		t.Errorf("wrapped identity = %+v", sent)
	}
	inner := sent.GetCheckpoint()
	if inner.GetID() != "sbx-1" || inner.GetCheckpointDir() != "/tmp/cp" ||
		inner.GetTimeoutSeconds() != 30 || !inner.GetCompress() ||
		inner.GetLeaveRunning() || inner.GetSnapshotType() != "Full" {
		t.Errorf("wrapped checkpoint request = %+v, want the legacy fields unchanged", inner)
	}
	printed := parseCheckpointOperationStatus(t, output)
	if printed.GetOperationID() != "op-ck-1" || printed.GetSandboxID() != "sbx-1" ||
		printed.GetSourceGeneration() != "gen-42" ||
		printed.GetCheckpointDir() != "/tmp/cp" {
		t.Errorf("printed identity = %+v", printed)
	}
	if printed.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
		t.Errorf("printed state = %s", printed.GetState())
	}
	if printed.GetArtifactRootDigest() != strings.Repeat("ab", 32) ||
		printed.GetArtifactRootScheme() != checkpointroot.Scheme {
		t.Errorf("printed sealed root = %s (%s)", printed.GetArtifactRootDigest(), printed.GetArtifactRootScheme())
	}

	// The directory spelling is sent verbatim — the digest preserves it —
	// while the receipt names the canonical cleaned form the service binds.
	unclean := checkpointOperationOptions()
	unclean.checkpointDir = "/tmp/cp/../cp"
	client = &fakeClient{checkpointWithOperationStatus: matchingCheckpointOperationReceipt(t, unclean)}
	output, err = captureStdout(t, func() error {
		return checkpoint(ctx, client, unclean)
	})
	if err != nil {
		t.Fatalf("identified checkpoint with unclean spelling: %v", err)
	}
	if got := client.checkpointWithOperationCalls[0].GetCheckpoint().GetCheckpointDir(); got != "/tmp/cp/../cp" {
		t.Errorf("sent directory = %q, want the original spelling", got)
	}
	if status := parseCheckpointOperationStatus(t, output); status.GetCheckpointDir() != "/tmp/cp" {
		t.Errorf("printed directory = %q, want the canonical form", status.GetCheckpointDir())
	}
}

// TestCheckpointWithOperationNeverFallsBack pins that every failure of the
// identified RPC — Unimplemented and Unavailable from an older or sick server,
// cancellation, or a plain transport error — is terminal: no legacy
// checkpoint RPC is attempted and nothing is printed as success.
func TestCheckpointWithOperationNeverFallsBack(t *testing.T) {
	ctx := testContext(t)
	failures := []error{
		status.Error(codes.Unimplemented, "sandboxd predates the identified checkpoint RPCs"),
		status.Error(codes.Unavailable, "daemon restarting"),
		status.Error(codes.Canceled, "caller cancelled"),
		status.Error(codes.DeadlineExceeded, "checkpoint timed out"),
		errors.New("connection reset"),
	}
	for _, failure := range failures {
		client := &fakeClient{checkpointWithOperationErr: failure}
		output, err := captureStdout(t, func() error {
			return checkpoint(ctx, client, checkpointOperationOptions())
		})
		if err == nil || !errors.Is(err, failure) {
			t.Fatalf("identified checkpoint error = %v, want %v", err, failure)
		}
		if len(client.checkpointWithOperationCalls) != 1 {
			t.Fatalf("CheckpointWithOperation calls = %d, want 1", len(client.checkpointWithOperationCalls))
		}
		if len(client.checkpointCalls) != 0 || len(client.checkpointIfCalls) != 0 {
			t.Fatalf("failed identified checkpoint fell back to a legacy checkpoint RPC")
		}
		if output != "" {
			t.Fatalf("failed identified checkpoint printed %q, want no stdout", output)
		}
	}
}

// TestCheckpointOperationReceiptMustMatchIntent pins the receipt validation:
// a zero exit requires SUCCEEDED for exactly the requested operation ID,
// sandbox, source generation, canonical directory, the digest of the request
// just sent, and a strict lowercase hex64 sealed root under the shared
// scheme. Records that merely name another intent, or claim SUCCEEDED without
// provable root evidence, never reach stdout at all.
func TestCheckpointOperationReceiptMustMatchIntent(t *testing.T) {
	mutate := map[string]func(*runtime.CheckpointOperationStatus){
		"wrong operation id": func(s *runtime.CheckpointOperationStatus) { s.OperationID = "op-other" },
		"wrong sandbox id": func(s *runtime.CheckpointOperationStatus) {
			s.SandboxID = "sbx-other"
		},
		"wrong source generation": func(s *runtime.CheckpointOperationStatus) {
			s.SourceGeneration = "gen-other"
		},
		"wrong checkpoint dir": func(s *runtime.CheckpointOperationStatus) {
			s.CheckpointDir = "/tmp/other"
		},
		"wrong request digest": func(s *runtime.CheckpointOperationStatus) {
			s.RequestDigest = strings.Repeat("ff", 32)
		},
		"succeeded without root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
		"succeeded with uppercase root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = strings.Repeat("AB", 32)
		},
		"succeeded with short root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = strings.Repeat("a", 63)
		},
		"succeeded with non-hex root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = strings.Repeat("g", 64)
		},
		"succeeded with foreign scheme": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootScheme = "v1:foreign"
		},
		"running with a root": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
		},
		"unspecified state": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
		"unrecognized positive state": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState(99)
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
	}
	for name, mutateOne := range mutate {
		t.Run(name, func(t *testing.T) {
			value := checkpointOperationOptions()
			status := matchingCheckpointOperationReceipt(t, value)
			mutateOne(status)
			client := &fakeClient{checkpointWithOperationStatus: status}
			output, err := captureStdout(t, func() error {
				return checkpoint(testContext(t), client, value)
			})
			if err == nil {
				t.Fatal("a mismatched receipt must fail the identified checkpoint")
			}
			if output != "" {
				t.Errorf("mismatched receipt (%s) printed %q, want no stdout", name, output)
			}
			if len(client.checkpointCalls) != 0 || len(client.checkpointIfCalls) != 0 {
				t.Errorf("mismatched receipt (%s) fell back to a legacy checkpoint RPC", name)
			}
		})
	}

	// Valid but unproven states print their reconciliation record — the state
	// field itself says not-succeeded — and still exit as errors.
	for name, state := range map[string]runtime.CheckpointOperationState{
		"running": runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING,
		"failed":  runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED,
		"unknown": runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN,
	} {
		t.Run(name, func(t *testing.T) {
			value := checkpointOperationOptions()
			status := matchingCheckpointOperationReceipt(t, value)
			status.State = state
			status.ArtifactRootDigest = ""
			status.ArtifactRootScheme = ""
			client := &fakeClient{checkpointWithOperationStatus: status}
			output, err := captureStdout(t, func() error {
				return checkpoint(testContext(t), client, value)
			})
			if err == nil {
				t.Fatalf("%s must not be reported as checkpoint success", name)
			}
			printed := parseCheckpointOperationStatus(t, output)
			if printed.GetState() != state || printed.GetArtifactRootDigest() != "" {
				t.Errorf("%s reconciliation record = %+v", name, printed)
			}
		})
	}

	// No status at all is a protocol error, not silence.
	client := &fakeClient{}
	if err := checkpointWithOperation(
		testContext(t), client, checkpointOperationOptions(),
		checkpointRequestFromOptions(checkpointOperationOptions()), &bytes.Buffer{},
	); err == nil {
		t.Fatal("empty operation status must fail")
	}
}

// queryCheckpointOperationRecord builds a well-formed queryable record
// fixture independent of any caller intent.
func queryCheckpointOperationRecord() *runtime.CheckpointOperationStatus {
	return &runtime.CheckpointOperationStatus{
		OperationID:        "op-ck-1",
		SandboxID:          "sbox-1",
		SourceGeneration:   "gen-42",
		CheckpointDir:      "/tmp/cp",
		RequestDigest:      strings.Repeat("cd", 32),
		State:              runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED,
		ArtifactRootDigest: strings.Repeat("ab", 32),
		ArtifactRootScheme: checkpointroot.Scheme,
	}
}

// TestGetCheckpointOperationQueryContract pins the query discipline: the
// action reads exactly one record, prints every retrievable state verbatim
// with a zero exit, and treats malformed or misrouted replies as protocol
// errors without stdout output.
func TestGetCheckpointOperationQueryContract(t *testing.T) {
	ctx := testContext(t)

	client := &fakeClient{getCheckpointOperationStatus: queryCheckpointOperationRecord()}
	output, err := captureStdout(t, func() error {
		return getCheckpointOperation(ctx, client, options{operationID: "op-ck-1"}, os.Stdout)
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(client.getCheckpointOperationCalls) != 1 ||
		client.getCheckpointOperationCalls[0].GetOperationID() != "op-ck-1" {
		t.Fatalf("GetCheckpointOperation calls = %+v", client.getCheckpointOperationCalls)
	}
	if client.totalCalls() != 1 {
		t.Fatalf("query reached %d RPCs in total", client.totalCalls())
	}
	printed := parseCheckpointOperationStatus(t, output)
	if printed.GetOperationID() != "op-ck-1" || printed.GetState() !=
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED ||
		printed.GetArtifactRootDigest() != strings.Repeat("ab", 32) {
		t.Errorf("printed record = %+v", printed)
	}

	// Every retrievable state is a legal answer: RUNNING, FAILED, and UNKNOWN
	// reconcile through the same zero-exit query, without a sealed root.
	for name, state := range map[string]runtime.CheckpointOperationState{
		"running": runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING,
		"failed":  runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED,
		"unknown": runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN,
	} {
		record := queryCheckpointOperationRecord()
		record.State = state
		record.ArtifactRootDigest = ""
		record.ArtifactRootScheme = ""
		record.Message = "reconcile me"
		client := &fakeClient{getCheckpointOperationStatus: record}
		output, err := captureStdout(t, func() error {
			return getCheckpointOperation(testContext(t), client, options{operationID: "op-ck-1"}, os.Stdout)
		})
		if err != nil {
			t.Fatalf("query of %s must exit zero: %v", name, err)
		}
		if status := parseCheckpointOperationStatus(t, output); status.GetState() != state ||
			status.GetMessage() != "reconcile me" {
			t.Errorf("%s printed record = %+v", name, status)
		}
	}

	// A record naming another operation is not the answer to this query; a
	// record violating the binding syntax is nothing to reconcile against.
	for name, mutate := range map[string]func(*runtime.CheckpointOperationStatus){
		"echo mismatch":          func(s *runtime.CheckpointOperationStatus) { s.OperationID = "op-other" },
		"empty sandbox identity": func(s *runtime.CheckpointOperationStatus) { s.SandboxID = "" },
		"blank generation":       func(s *runtime.CheckpointOperationStatus) { s.SourceGeneration = "  " },
		"relative dir":           func(s *runtime.CheckpointOperationStatus) { s.CheckpointDir = "cp" },
		"non-canonical dir": func(s *runtime.CheckpointOperationStatus) {
			s.CheckpointDir = "/tmp/cp/../cp"
		},
		"oversized dir": func(s *runtime.CheckpointOperationStatus) {
			s.CheckpointDir = "/" + strings.Repeat("d", maxCheckpointDirLength)
		},
		"uppercase request digest": func(s *runtime.CheckpointOperationStatus) {
			s.RequestDigest = strings.Repeat("CD", 32)
		},
		"short request digest": func(s *runtime.CheckpointOperationStatus) {
			s.RequestDigest = strings.Repeat("c", 63)
		},
		"unspecified state": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
		"unrecognized negative state": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState(-1)
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
		"succeeded without root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = ""
			s.ArtifactRootScheme = ""
		},
		"succeeded with bad root": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootDigest = "not-a-digest"
		},
		"succeeded with foreign scheme": func(s *runtime.CheckpointOperationStatus) {
			s.ArtifactRootScheme = "v1:foreign"
		},
		"running with a root": func(s *runtime.CheckpointOperationStatus) {
			s.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := queryCheckpointOperationRecord()
			mutate(record)
			client := &fakeClient{getCheckpointOperationStatus: record}
			output, err := captureStdout(t, func() error {
				return getCheckpointOperation(testContext(t), client, options{operationID: "op-ck-1"}, os.Stdout)
			})
			if err == nil {
				t.Fatalf("malformed record (%s) must fail the query", name)
			}
			if output != "" {
				t.Errorf("malformed record (%s) printed %q, want no stdout", name, output)
			}
		})
	}

	// No status at all is a protocol error.
	if err := getCheckpointOperation(ctx, &fakeClient{}, options{operationID: "op-ck-1"}, os.Stdout); err == nil {
		t.Fatal("empty query reply must fail")
	}
}

// TestGetCheckpointOperationNotFoundIsStructured pins the structured absence
// signal of the checkpoint query: exactly a gRPC NotFound reply maps to the
// sentinel exit code 3, while every other failure — including a gRPC Unknown
// status and not-found-flavored text under another code — stays a plain
// exit-1 error so subprocess callers fail closed on ambiguity.
func TestGetCheckpointOperationNotFoundIsStructured(t *testing.T) {
	ctx := testContext(t)
	notFound := status.Error(codes.NotFound, "checkpoint operation op-ck-1 is unknown")
	client := &fakeClient{getCheckpointOperationErr: notFound}
	err := getCheckpointOperation(ctx, client, options{operationID: "op-ck-1"}, os.Stdout)
	if err == nil {
		t.Fatal("a NotFound reply must fail the query")
	}
	if !errors.Is(err, errCheckpointOperationNotFound) {
		t.Fatalf("NotFound reply = %v, want the checkpoint sentinel", err)
	}
	if code := runExitCode(err); code != exitOperationNotFound {
		t.Fatalf("runExitCode(NotFound) = %d, want %d", code, exitOperationNotFound)
	}
	// The two query actions share the exit code but keep distinct sentinels,
	// so an error message can never claim the other action.
	if errors.Is(err, errOperationNotFound) {
		t.Fatalf("checkpoint NotFound must not raise the start sentinel: %v", err)
	}

	for name, failure := range map[string]error{
		"unknown":       status.Error(codes.Unknown, "journal glitch"),
		"unimplemented": status.Error(codes.Unimplemented, "sandboxd predates the identified checkpoint RPCs"),
		"unavailable":   status.Error(codes.Unavailable, "connection reset"),
		"deadline":      status.Error(codes.DeadlineExceeded, "query timed out"),
		"internal":      status.Error(codes.Internal, "journal unreadable"),
		"plain":         errors.New("transport closed"),
	} {
		client := &fakeClient{getCheckpointOperationErr: failure}
		err := getCheckpointOperation(ctx, client, options{operationID: "op-ck-1"}, os.Stdout)
		if err == nil || errors.Is(err, errCheckpointOperationNotFound) {
			t.Fatalf("%s query error = %v, want a plain (non-sentinel) failure", name, err)
		}
		if code := runExitCode(err); code != 1 {
			t.Fatalf("runExitCode(%s) = %d, want the generic 1", name, code)
		}
	}

	// Classification keys on the status code, never on error text.
	liar := status.Error(codes.Unavailable, "checkpoint operation op-ck-1 is unknown (not found)")
	client = &fakeClient{getCheckpointOperationErr: liar}
	err = getCheckpointOperation(ctx, client, options{operationID: "op-ck-1"}, os.Stdout)
	if errors.Is(err, errCheckpointOperationNotFound) {
		t.Fatal("a non-NotFound status carrying not-found text must not classify as absent")
	}
	if code := runExitCode(err); code != 1 {
		t.Fatalf("runExitCode(not-found text on Unavailable) = %d, want 1", code)
	}
}

// TestCheckpointOperationInvalidInputReachesNoRPC pins the pre-dial gates of
// both new modes: direct callers of the helpers are as safe as the CLI, and
// the query action rejects payload flags instead of silently ignoring
// explicit intent.
func TestCheckpointOperationInvalidInputReachesNoRPC(t *testing.T) {
	ctx := testContext(t)
	client := new(fakeClient)

	invalid := map[string]func(*options){
		"path-unsafe operation id": func(v *options) { v.operationID = "op/../bad" },
		"missing generation":       func(v *options) { v.expectedGeneration = "" },
		"blank generation":         func(v *options) { v.expectedGeneration = "  " },
		"leave running":            func(v *options) { v.leaveRunning = true },
		"relative dir":             func(v *options) { v.checkpointDir = "cp" },
		"zero timeout":             func(v *options) { v.checkpointTimeoutSeconds = 0 },
		"oversized timeout": func(v *options) {
			v.checkpointTimeoutSeconds = checkpointOperationMaxTimeoutSeconds + 1
		},
	}
	for name, mutate := range invalid {
		value := checkpointOperationOptions()
		mutate(&value)
		out := new(bytes.Buffer)
		if err := checkpointWithOperation(ctx, client, value, checkpointRequestFromOptions(value), out); err == nil {
			t.Errorf("identified checkpoint accepted %s", name)
		} else if out.Len() != 0 {
			t.Errorf("identified checkpoint %s printed %q before failing", name, out.String())
		}
		if client.totalCalls() != 0 {
			t.Fatalf("invalid input (%s) still reached %d RPCs", name, client.totalCalls())
		}
	}

	if err := getCheckpointOperation(ctx, client, options{}, os.Stdout); err == nil {
		t.Error("query accepted an empty operation ID")
	}
	if err := getCheckpointOperation(
		ctx, client, options{operationID: "op/../bad"}, os.Stdout,
	); err == nil {
		t.Error("query accepted a path-unsafe operation ID")
	}
	if client.totalCalls() != 0 {
		t.Fatalf("invalid query input still reached %d RPCs", client.totalCalls())
	}

	// The query action's flag surface: payload flags are explicit intent to
	// reject, and the missing operation ID never reaches the dial.
	for name, value := range map[string]options{
		"query with sandbox id":      {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1", sandboxID: "sbx-1"},
		"query with checkpoint dir":  {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1", checkpointDir: "/tmp/cp"},
		"query with request file":    {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1", requestFile: "/tmp/start.json"},
		"query with snapshot type":   {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1", snapshotType: "Full"},
		"query with workload cmd":    {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1", workloadCmd: "id"},
		"query without operation id": {action: "get-checkpoint-operation", socket: "/run/sandboxd.sock"},
	} {
		if err := validateOptions(value); err == nil {
			t.Errorf("conflicted query options accepted (%s): %+v", name, value)
		}
	}

	// A well-formed query invocation passes the pre-dial gate.
	if err := validateOptions(options{
		action: "get-checkpoint-operation", socket: "/run/sandboxd.sock", operationID: "op-1",
	}); err != nil {
		t.Errorf("well-formed query options rejected: %v", err)
	}
}

// TestParseFlagsCheckpointOperationModes runs the real argv parser: a fully
// specified identified checkpoint binds every flag, an explicitly empty
// --operation-id on the checkpoint action fails before the dial, and the
// checkpoint-timeout bound is enforced at the validation layer.
func TestParseFlagsCheckpointOperationModes(t *testing.T) {
	argv := []string{
		"--action=checkpoint",
		"--socket=/run/sandboxd.sock",
		"--sandbox-id=sbx-1",
		"--checkpoint-dir=/tmp/cp",
		"--checkpoint-timeout-seconds=30",
		"--snapshot-type=Full",
		"--expected-generation=gen-42",
		"--operation-id=op-ck-1",
		"--leave-running=false",
	}
	value, err := parseFlags(argv, io.Discard)
	if err != nil {
		t.Fatalf("parse argv: %v", err)
	}
	if !value.operationIDSet || value.operationID != "op-ck-1" || value.leaveRunning {
		t.Fatalf("argv bound the wrong mode: %+v", value)
	}
	if err := validateOptions(value); err != nil {
		t.Fatalf("valid identified checkpoint argv rejected: %v", err)
	}

	// The argv default --leave-running=true is the explicit opt-out the mode
	// refuses, before any dial.
	defaultRunning := append([]string{}, argv[:len(argv)-1]...)
	value, err = parseFlags(defaultRunning, io.Discard)
	if err != nil {
		t.Fatalf("parse default argv: %v", err)
	}
	runErr := run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--leave-running=false") {
		t.Fatalf("default leave-running error = %v", runErr)
	}

	// An explicitly empty --operation-id is intent, not omission, and fails
	// the pre-dial gate instead of selecting the legacy checkpoint.
	explicitEmpty := append(append([]string{}, argv[:len(argv)-2]...), "--leave-running=false", "--operation-id=")
	value, err = parseFlags(explicitEmpty, io.Discard)
	if err != nil {
		t.Fatalf("parse explicit empty argv: %v", err)
	}
	if !value.operationIDSet || value.operationID != "" {
		t.Fatalf("explicit empty --operation-id not recorded: %+v", value)
	}
	runErr = run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "--operation-id must not be empty") {
		t.Fatalf("explicit empty --operation-id error = %v", runErr)
	}

	// The service-side timeout ceiling is enforced client-side too.
	oversized := append(append([]string{}, argv[:5]...),
		"--checkpoint-timeout-seconds=601", argv[6], argv[7], argv[8])
	value, err = parseFlags(oversized, io.Discard)
	if err != nil {
		t.Fatalf("parse oversized timeout argv: %v", err)
	}
	runErr = run(value)
	if runErr == nil || !strings.Contains(runErr.Error(), "between 1 and 600") {
		t.Fatalf("oversized timeout error = %v", runErr)
	}

	// Omitting --operation-id entirely keeps the legacy checkpoint argv valid.
	legacy := append([]string{}, argv[:7]...)
	value, err = parseFlags(legacy, io.Discard)
	if err != nil {
		t.Fatalf("parse legacy argv: %v", err)
	}
	if value.operationIDSet {
		t.Fatalf("omitted --operation-id recorded presence: %+v", value)
	}
	if err := validateOptions(value); err != nil {
		t.Fatalf("legacy checkpoint argv must stay valid: %v", err)
	}
}
