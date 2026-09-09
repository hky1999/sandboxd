// Copyright 2026 Ant Group Corporation.
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

// Regressions for the witness-recovery integration of the resumable source
// checkpoint: an admitted WITNESS record's success is accepted only with a
// proven evidence release — the initial success that acknowledged in its own
// call needs no extra command, everything else performs exactly one explicit
// recover-checkpoint-operation carrying the complete original payload — an
// UNKNOWN WITNESS record may be reconciled by that same single recovery, and
// every failure (command, unreleased receipt, contradicted receipt, RUNNING,
// FAILED) fails closed at checkpoint-issued with no new operation ID, no
// checkpoint fallback, and no target contact.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recoveryArgv collects the explicit recovery commands that ran.
func recoveryArgv(calls []nodeCall) []string {
	var argvs []string
	for _, c := range calls {
		if strings.Contains(c.argv, "--action recover-checkpoint-operation") {
			argvs = append(argvs, c.argv)
		}
	}
	return argvs
}

// queryArgv collects the checkpoint-operation queries that ran.
func queryArgv(calls []nodeCall) []string {
	var argvs []string
	for _, c := range calls {
		if strings.Contains(c.argv, "--action get-checkpoint-operation") {
			argvs = append(argvs, c.argv)
		}
	}
	return argvs
}

// assertRecoveryPayload pins the one recovery command this migration may
// issue: the COMPLETE original pinned payload — the same flags the checkpoint
// issue sends — plus the fixed independent recovery timeout. The controller
// contributes only journal-pinned values and its logical checkpoint path; the
// node CLI maps that path and the service re-digests the full original
// request.
func assertRecoveryPayload(t *testing.T, argv, migrationID string) {
	t.Helper()
	for _, want := range []string{
		"--sandbox-id sbox-x",
		"--checkpoint-dir /mnt/cn/ck/m-sbox-x-" + migrationID,
		"--checkpoint-timeout-seconds 180",
		"--compress=false",
		"--leave-running=false",
		"--operation-id checkpoint-" + migrationID,
		"--expected-generation g1",
		"--recovery-timeout-seconds 180",
	} {
		if !strings.Contains(argv, want) {
			t.Fatalf("the recovery command lacks %q:\n%s", want, argv)
		}
	}
}

// TestResumableWitnessInitialReleasedSuccessNoExtraCommand pins the
// zero-overhead happy path: a WITNESS source checkpoint whose own call
// completed the acknowledgment is accepted directly — its receipt proves the
// release from THIS response — with no query and no recovery command, and a
// finished migration still replays with zero node commands.
func TestResumableWitnessInitialReleasedSuccessNoExtraCommand(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	args := []string{"-journal", journal, "-migration-id", "happy1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the witness happy path must finish without extra commands: %s", out)
	}
	calls := readCalls(t, state)
	if recoveries := recoveryArgv(calls); len(recoveries) != 0 {
		t.Fatalf("a released initial success triggered recovery commands: %v", recoveries)
	}
	if queries := queryArgv(calls); len(queries) != 0 {
		t.Fatalf("a successful first issue was re-queried: %v", queries)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("the node never acknowledged the witness success: %v\n%s", err, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
	// done replay: zero further node commands.
	before := len(readCalls(t, state))
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("done replay failed: %s", out)
	}
	if after := len(readCalls(t, state)); after != before {
		t.Fatalf("done replay issued %d additional node commands", after-before)
	}
}

// TestResumableWitnessAckFailureRecoveredThroughExplicitRecovery pins the
// release gate for a durable success: the node recorded SUCCEEDED but the
// runtime acknowledgment failed, so the issuing command fails. The SAME
// process must query the record, refuse to accept the unproven release, and
// perform exactly ONE explicit recovery with the complete original payload —
// never a same-payload replay, which could not release anything — and only
// its released receipt, repeating the queried fact, seals the checkpoint.
func TestResumableWitnessAckFailureRecoveredThroughExplicitRecovery(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("fail-source-ack", "")
	args := []string{"-journal", journal, "-migration-id", "ackfail1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the ack failure must be reconciled by one explicit recovery: %s", out)
	}
	calls := readCalls(t, state)
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 (no re-execution, no replay)\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-replays"); got != 0 {
		t.Fatalf("receipt replays = %d, want 0 (a replay cannot release evidence)\n%s", got, out)
	}
	recoveries := recoveryArgv(calls)
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want exactly 1:\n%s", len(recoveries), debugCalls(calls))
	}
	assertRecoveryPayload(t, recoveries[0], "ackfail1")
	if queries := queryArgv(calls); len(queries) != 1 {
		t.Fatalf("queries = %d, want exactly 1 (the record is read before any recovery):\n%s", len(queries), debugCalls(calls))
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
	if root := journalField(t, journal, "source_root_digest"); root == "" {
		t.Fatal("the released receipt was never preserved")
	}
	if _, err := os.Stat(filepath.Join(state, "source-retired")); err != nil {
		t.Fatalf("source never retired: %v\n%s", err, out)
	}
}

// TestResumableWitnessUnknownRecoveredByOneExplicitRecovery pins the UNKNOWN
// reconciliation: a WITNESS record whose outcome could not be proven is —
// after the query's identity checks — reconciled by exactly ONE explicit
// recovery of the SAME operation carrying the full original payload. The
// recovery completes the stop-source flow, persists the success, and releases
// the evidence; only then is the receipt preserved and the checkpoint sealed.
// No new operation ID, no checkpoint fallback, one actual execution.
func TestResumableWitnessUnknownRecoveredByOneExplicitRecovery(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("checkpoint-operation-state", "unknown")
	args := []string{"-journal", journal, "-migration-id", "unknown1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("an UNKNOWN witness record must be recoverable: %s", out)
	}
	calls := readCalls(t, state)
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 (the recovery never snapshots)\n%s", got, out)
	}
	recoveries := recoveryArgv(calls)
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want exactly 1:\n%s", len(recoveries), debugCalls(calls))
	}
	assertRecoveryPayload(t, recoveries[0], "unknown1")
	if got := fakeReadCount(t, state, "source-recoveries"); got != 1 {
		t.Fatalf("node-side recoveries = %d, want 1\n%s", got, out)
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("the recovery never released the evidence: %v\n%s", err, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
	// The recovered completion finalized the source exactly once.
	if _, err := os.Stat(filepath.Join(state, "stopped")); err != nil {
		t.Fatalf("the recovered stop-source flow never finalized the source: %v\n%s", err, out)
	}
}

// TestResumableWitnessUnknownRecoveryFailureFailsClosed pins the bounded,
// fail-closed behavior of the recovery attempt: a failing recovery leaves the
// journal at checkpoint-issued with no preserved receipt, no re-issued
// checkpoint, no new operation ID, and no target contact — and every NEW
// process may again attempt exactly one recovery after re-querying.
func TestResumableWitnessUnknownRecoveryFailureFailsClosed(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("checkpoint-operation-state", "unknown")
	write("fail-recover-op", "")
	args := []string{"-journal", journal, "-migration-id", "failrec1"}
	bin := buildCnMigrate(t)
	nodes := catalogStandIn(t, state)
	code, _, out := runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a failed recovery must fail the migration: %s", out)
	}
	if !strings.Contains(out, "explicit recovery") {
		t.Fatalf("the report does not name the failed recovery:\n%s", out)
	}
	first := readCalls(t, state)
	issues := identifiedCheckpointArgv(first)
	if len(issues) != 1 {
		t.Fatalf("checkpoint issues = %d, want exactly 1 (the original admission):\n%s", len(issues), debugCalls(first))
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("an unrecovered record preserved a success receipt")
	}
	// A new process retries the SAME bounded shape: query first, then at most
	// one recovery — and fails closed again while the fault persists.
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a persistently failing recovery must keep failing: %s", out)
	}
	second := readCalls(t, state)
	fresh := second[len(first):]
	if queries := queryArgv(fresh); len(queries) != 1 {
		t.Fatalf("the retry must re-query exactly once, got %d:\n%s", len(queries), debugCalls(fresh))
	}
	if recoveries := recoveryArgv(fresh); len(recoveries) != 1 {
		t.Fatalf("the retry must attempt at most one recovery, got %d:\n%s", len(recoveries), debugCalls(fresh))
	}
	for _, c := range fresh {
		if strings.Contains(c.argv, "--action checkpoint ") || c.node == "T" {
			t.Fatalf("the recovery failure still issued %s", c.argv)
		}
	}
	// Once the fault clears, the same process shape finishes the migration
	// without ever re-executing the checkpoint.
	if err := os.Remove(filepath.Join(state, "fail-recover-op")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the cleared recovery did not finish the migration: %s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 across every process\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableWitnessUnreleasedRecoveryReceiptRefused pins the release
// check itself: a recovery reply that reports evidence_released=false proves
// nothing — even shaped like a success — so nothing is preserved, the journal
// stays at checkpoint-issued, and no target is contacted.
func TestResumableWitnessUnreleasedRecoveryReceiptRefused(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("checkpoint-operation-state", "unknown")
	write("recover-receipt-unreleased", "")
	args := []string{"-journal", journal, "-migration-id", "unrel1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("an unreleased recovery receipt was accepted: %s", out)
	}
	if !strings.Contains(out, "evidence_released=false") {
		t.Fatalf("the report does not name the unproven release:\n%s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("an unreleased receipt was preserved")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" || strings.Contains(c.argv, "cn-publish") {
			t.Fatalf("the migration continued past the unproven release: %s", c.argv)
		}
	}
}

// TestResumableWitnessContradictedRecoveryReceiptRefused pins the
// fact-comparison of the recovery: a released receipt that does not repeat
// the already-observed completion (the sealed root here) is a contradiction,
// not a newer truth — the journal stays at checkpoint-issued with no
// preserved receipt and no target contact.
func TestResumableWitnessContradictedRecoveryReceiptRefused(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("fail-source-ack", "")
	// The recovery reply alone lies about the sealed root; the durable record
	// (which the query already printed truthfully) keeps the real one.
	write("poison-recovery-receipt", "artifact_root_digest")
	args := []string{"-journal", journal, "-migration-id", "contradict1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a contradicted recovery receipt was accepted: %s", out)
	}
	if !strings.Contains(out, "does not repeat the recorded completion fact") {
		t.Fatalf("the report does not name the contradiction:\n%s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("a contradicted receipt was preserved")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" {
			t.Fatalf("the migration continued past the contradiction: %s", c.argv)
		}
	}
}

// TestResumableWitnessRunningAndFailedNeverRecovered pins the two records a
// recovery must refuse even under the witness protocol: a still-RUNNING
// execution is pending (recovery would act beside a live executor) and a
// FAILED record is spent forever. Neither triggers a recovery command, a
// re-issue, or a target contact; the journal stays at checkpoint-issued.
func TestResumableWitnessRunningAndFailedNeverRecovered(t *testing.T) {
	for _, operationState := range []string{"running", "failed"} {
		t.Run(operationState, func(t *testing.T) {
			state, journal, write := stageState(t)
			write("checkpoint-op-protocol", "witness")
			write("checkpoint-operation-state", operationState)
			args := []string{"-journal", journal, "-migration-id", "refuse1"}
			code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("a %s witness record must fail the migration: %s", operationState, out)
			}
			if !strings.Contains(out, "CHECKPOINT_OPERATION_STATE_"+strings.ToUpper(operationState)) {
				t.Fatalf("the report does not name the operation state:\n%s", out)
			}
			if recoveries := recoveryArgv(readCalls(t, state)); len(recoveries) != 0 {
				t.Fatalf("a %s record triggered a recovery: %v", operationState, recoveries)
			}
			if journalField(t, journal, "stage") != stageCheckpointIssued {
				t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
			}
			for _, c := range readCalls(t, state) {
				if c.node == "T" {
					t.Fatalf("target contacted despite a %s witness record: %s", operationState, c.argv)
				}
			}
		})
	}
}

// TestResumableWitnessMappedPathRecoveryBindsPhysicalPayload pins the path
// discipline of the recovery: under an executor that maps the controller's
// logical checkpoint directory to a different physical path, the recovery
// carries the logical flag through the node CLI, the digest binds the
// physical request the CLI sends, and the service-side re-digestion accepts
// it — the controller never computes a digest from its logical path.
func TestResumableWitnessMappedPathRecoveryBindsPhysicalPayload(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("checkpoint-operation-state", "unknown")
	write("map-source-path", "")
	args := []string{"-journal", journal, "-migration-id", "mapped1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the mapped recovery was refused: %s", out)
	}
	recoveries := recoveryArgv(readCalls(t, state))
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want 1:\n%s", len(recoveries), out)
	}
	if !strings.Contains(recoveries[0], "--checkpoint-dir /mnt/cn/ck/m-sbox-x-mapped1") {
		t.Fatalf("the recovery did not carry the logical directory through the CLI mapping:\n%s", recoveries[0])
	}
	if _, err := os.Stat(filepath.Join(state, "checkpoint-op-reuse-refused")); err == nil {
		t.Fatalf("the mapped physical payload was refused by the operation binding:\n%s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableWitnessLostRecoveryReplyRetriedByNewProcess pins the lost
// recovery reply: the node completed the recovery and its acknowledgment but
// the answer never reached the CLI, so the process fails closed at
// checkpoint-issued without a preserved receipt; a NEW process re-queries,
// re-recovers the now-durable success (the acknowledgment is idempotent), and
// finishes — still with exactly one actual source checkpoint.
func TestResumableWitnessLostRecoveryReplyRetriedByNewProcess(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("fail-source-ack", "")
	write("lose-recover-reply", "")
	args := []string{"-journal", journal, "-migration-id", "lostreply1"}
	bin := buildCnMigrate(t)
	nodes := catalogStandIn(t, state)
	code, _, out := runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a lost recovery reply must fail closed: %s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("a receipt was preserved without a trustworthy recovery answer")
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("scenario setup: the lost recovery never committed its acknowledgment: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(state, "lose-recover-reply")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the retried recovery did not finish the migration: %s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-recoveries"); got != 2 {
		t.Fatalf("node-side recoveries = %d, want 2 (the committed one plus the retry's confirmation)\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableWitnessUnreleasedFirstReceiptRecovers pins the defensive gate
// on the issue path: a WITNESS success reply that reaches the CLI without
// proving its own release is not sealed as-is — exactly one explicit recovery
// follows, and only its released receipt, repeating the observed completion,
// persists. The initial success still costs no query.
func TestResumableWitnessUnreleasedFirstReceiptRecovers(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "witness")
	write("checkpoint-receipt-unreleased", "")
	args := []string{"-journal", journal, "-migration-id", "unrelfirst1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the unreleased first receipt must be completed by one recovery: %s", out)
	}
	calls := readCalls(t, state)
	recoveries := recoveryArgv(calls)
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want exactly 1:\n%s", len(recoveries), debugCalls(calls))
	}
	assertRecoveryPayload(t, recoveries[0], "unrelfirst1")
	if queries := queryArgv(calls); len(queries) != 0 {
		t.Fatalf("a successful issue was re-queried before the recovery: %v", queries)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableLegacySuccessKeepsReplayBehavior pins the compatibility line:
// a protocol-0 historical success keeps its existing verification — one
// same-payload replay of the SAME operation, no recovery command, no release
// demands — and still finishes the migration.
func TestResumableLegacySuccessKeepsReplayBehavior(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	args := []string{"-journal", journal, "-migration-id", "legacy1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the legacy ack-loss reconciliation must keep working: %s", out)
	}
	calls := readCalls(t, state)
	if recoveries := recoveryArgv(calls); len(recoveries) != 0 {
		t.Fatalf("a legacy record was recovered: %v", recoveries)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-replays"); got != 1 {
		t.Fatalf("receipt replays = %d, want 1 (the historical same-payload verification)\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestParseCheckpointOperationStatusProtocol pins the receipt reader's
// protocol discipline: both defined protocols decode (each is legal history
// the controller may reconcile), while an out-of-range value is rejected as
// a protocol error — an unsupported protocol must never be read as the
// legacy one, because the field decides which records hold recoverable
// runtime evidence.
func TestParseCheckpointOperationStatusProtocol(t *testing.T) {
	base := `{
  "operation_id": "checkpoint-x",
  "sandbox_id": "sbox-x",
  "state": "CHECKPOINT_OPERATION_STATE_SUCCEEDED",
  "source_generation": "g1",
  "checkpoint_dir": "/mnt/cn/ck/m-sbox-x-x",
  "request_digest": "%s",
  "artifact_root_digest": "%s",
  "artifact_root_scheme": "v2:manifest+sidecar-roots",
  "message": "",
  "recovery_protocol": %s,
  "evidence_released": %s
}`
	digest := strings.Repeat("0a", 32)
	root := strings.Repeat("1b", 32)
	for name, protocol := range map[string]string{
		"legacy":    `"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED"`,
		"witness":   `"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS"`,
		"abortable": `"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE"`,
	} {
		status, err := parseCheckpointOperationStatus(fmt.Sprintf(base, digest, root, protocol, "false"))
		if err != nil {
			t.Fatalf("%s receipt did not decode: %v", name, err)
		}
		if status.GetEvidenceReleased() {
			t.Errorf("%s receipt wrongly reported a release", name)
		}
	}
	for name, protocol := range map[string]string{
		"out-of-range number": "7",
		"unknown enum name":   `"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_QUANTUM"`,
	} {
		_, err := parseCheckpointOperationStatus(fmt.Sprintf(base, digest, root, protocol, "true"))
		if err == nil {
			t.Fatalf("an unsupported protocol (%s) was accepted as a receipt", name)
		}
		// The out-of-range number decodes into the enum and must be caught by
		// the reader's own protocol check; an unknown enum name already fails
		// inside protojson, which is an equally strict rejection.
		if protocol == "7" && !strings.Contains(err.Error(), "recovery protocol") {
			t.Fatalf("the %s error does not name the protocol: %v", name, err)
		}
	}
}
