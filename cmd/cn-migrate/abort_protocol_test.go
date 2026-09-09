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

// Regressions for the WITNESS_ABORTABLE (protocol 2) integration of the
// resumable source checkpoint: a protocol-2 success owes exactly the same
// explicit release proof as WITNESS — an unreleased success or recovery
// receipt is refused — explicit recovery succeeds under protocol 2 as under
// 1, an UNKNOWN protocol-2 record gets the same single recovery (never an
// automatic abort), a FAILED record carrying the durable abort fact stays a
// migration failure with no publish, restore, or source retirement, and the
// abort command itself is never issued by this controller.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// abortArgv collects any abort commands that ran — the controller must
// never issue one; the explicit abort belongs to the node CLI alone.
func abortArgv(calls []nodeCall) []string {
	var argvs []string
	for _, c := range calls {
		if strings.Contains(c.argv, "--action abort-checkpoint-operation") {
			argvs = append(argvs, c.argv)
		}
	}
	return argvs
}

// TestResumableAbortableProtocol2InitialReleasedSuccessNoExtraCommand pins
// the protocol-2 happy path: a WITNESS_ABORTABLE source checkpoint whose own
// call completed the acknowledgment is accepted directly — the release proof
// requirement is identical to WITNESS — with no query, no recovery, and no
// abort command.
func TestResumableAbortableProtocol2InitialReleasedSuccessNoExtraCommand(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "abortable")
	args := []string{"-journal", journal, "-migration-id", "happy2"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the protocol-2 happy path must finish without extra commands: %s", out)
	}
	calls := readCalls(t, state)
	if recoveries := recoveryArgv(calls); len(recoveries) != 0 {
		t.Fatalf("a released protocol-2 success triggered recovery commands: %v", recoveries)
	}
	if aborts := abortArgv(calls); len(aborts) != 0 {
		t.Fatalf("the controller issued abort commands: %v", aborts)
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("the node never acknowledged the protocol-2 success: %v\n%s", err, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableAbortableProtocol2AckLossRecoveredThroughExplicitRecovery pins
// the protocol-2 release gate for a durable success: the node recorded
// SUCCEEDED but the acknowledgment failed, so the issuing command fails and
// the SAME process must query the record and perform exactly ONE explicit
// recovery — the recovery is legal under protocol 2 as under 1 — and only
// its released receipt, repeating the queried fact, seals the checkpoint.
func TestResumableAbortableProtocol2AckLossRecoveredThroughExplicitRecovery(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "abortable")
	write("fail-source-ack", "")
	args := []string{"-journal", journal, "-migration-id", "ackfail2"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the protocol-2 ack failure must be reconciled by one explicit recovery: %s", out)
	}
	calls := readCalls(t, state)
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 (no re-execution, no replay)\n%s", got, out)
	}
	recoveries := recoveryArgv(calls)
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want exactly 1:\n%s", len(recoveries), debugCalls(calls))
	}
	assertRecoveryPayload(t, recoveries[0], "ackfail2")
	if aborts := abortArgv(calls); len(aborts) != 0 {
		t.Fatalf("the controller issued abort commands: %v", aborts)
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("the recovery never released the protocol-2 evidence: %v\n%s", err, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableAbortableProtocol2UnreleasedRecoveryReceiptRefused pins that
// the protocol-2 release demand is not weaker than WITNESS: a recovery reply
// reporting evidence_released=false proves nothing — even shaped like a
// success — so nothing is preserved, the journal stays at checkpoint-issued,
// no target is contacted, and no abort is attempted as a way out.
func TestResumableAbortableProtocol2UnreleasedRecoveryReceiptRefused(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "abortable")
	write("checkpoint-operation-state", "unknown")
	write("recover-receipt-unreleased", "")
	args := []string{"-journal", journal, "-migration-id", "unrel2"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("an unreleased protocol-2 recovery receipt was accepted: %s", out)
	}
	if !strings.Contains(out, "evidence_released=false") {
		t.Fatalf("the report does not name the unproven release:\n%s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("an unreleased protocol-2 receipt was preserved")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" || strings.Contains(c.argv, "cn-publish") ||
			strings.Contains(c.argv, "--action abort-checkpoint-operation") {
			t.Fatalf("the migration continued past the unproven release: %s", c.argv)
		}
	}
}

// TestResumableAbortableProtocol2UnknownRecoveredByOneExplicitRecovery pins
// the UNKNOWN reconciliation under protocol 2: the record is reconciled by
// exactly ONE explicit recovery of the SAME operation — never an automatic
// abort — and only its released receipt persists.
func TestResumableAbortableProtocol2UnknownRecoveredByOneExplicitRecovery(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "abortable")
	write("checkpoint-operation-state", "unknown")
	args := []string{"-journal", journal, "-migration-id", "unknown2"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("an UNKNOWN protocol-2 record must be recoverable: %s", out)
	}
	calls := readCalls(t, state)
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 (the recovery never snapshots)\n%s", got, out)
	}
	recoveries := recoveryArgv(calls)
	if len(recoveries) != 1 {
		t.Fatalf("explicit recovery commands = %d, want exactly 1:\n%s", len(recoveries), debugCalls(calls))
	}
	if aborts := abortArgv(calls); len(aborts) != 0 {
		t.Fatalf("an UNKNOWN protocol-2 record was aborted automatically: %v", aborts)
	}
	if _, err := os.Stat(filepath.Join(state, "source-evidence-released")); err != nil {
		t.Fatalf("the recovery never released the evidence: %v\n%s", err, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableConfirmedAbortNeverSucceedsMigration pins the failure line: a
// FAILED protocol-2 record carrying the durable abort_confirmed fact — the
// strongest abort shape there is — still fails the migration. Nothing is
// published, no target is started or restored, the source generation is not
// retired, the journal stays at checkpoint-issued, and no abort command runs
// (the record is read exactly as the failure it is).
func TestResumableConfirmedAbortNeverSucceedsMigration(t *testing.T) {
	state, journal, write := stageState(t)
	write("checkpoint-op-protocol", "abortable")
	write("checkpoint-operation-state", "failed")
	write("checkpoint-op-aborted", "")
	args := []string{"-journal", journal, "-migration-id", "abortfail1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a confirmed abort must remain a migration failure: %s", out)
	}
	if !strings.Contains(out, "CHECKPOINT_OPERATION_STATE_FAILED") {
		t.Fatalf("the report does not name the FAILED outcome:\n%s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("a FAILED record preserved a success receipt")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" || strings.Contains(c.argv, "cn-publish") ||
			strings.Contains(c.argv, "--action delete") ||
			strings.Contains(c.argv, "--action abort-checkpoint-operation") {
			t.Fatalf("a confirmed abort still authorized %s", c.argv)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "source-retired")); err == nil {
		t.Fatal("a confirmed abort retired the source generation")
	}
}

// TestParseCheckpointOperationStatusAbortConfirmed pins the receipt reader's
// abort-fact discipline: abort_confirmed=true decodes only on a FAILED
// WITNESS_ABORTABLE record without a sealed root; a SUCCEEDED record, a
// witness-only record, or a root-carrying record claiming it is a malformed
// reply, not history to reconcile.
func TestParseCheckpointOperationStatusAbortConfirmed(t *testing.T) {
	document := func(state, root, scheme, protocol, abort string) string {
		return fmt.Sprintf(`{
  "operation_id": "checkpoint-x",
  "sandbox_id": "sbox-x",
  "state": "%s",
  "source_generation": "g1",
  "checkpoint_dir": "/mnt/cn/ck/m-sbox-x-x",
  "request_digest": "%s",
  "artifact_root_digest": %s,
  "artifact_root_scheme": %s,
  "message": "",
  "recovery_protocol": %s,
  "evidence_released": false,
  "abort_confirmed": %s
}`,
			state, strings.Repeat("0a", 32), root, scheme, protocol, abort)
	}
	const abortable = `"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE"`
	ok, err := parseCheckpointOperationStatus(document(
		"CHECKPOINT_OPERATION_STATE_FAILED", `""`, `""`, abortable, "true"))
	if err != nil {
		t.Fatalf("a FAILED protocol-2 record with a durable abort fact did not decode: %v", err)
	}
	if !ok.GetAbortConfirmed() {
		t.Fatal("the durable abort fact was not decoded")
	}
	root := `"` + strings.Repeat("1b", 32) + `"`
	scheme := `"v2:manifest+sidecar-roots"`
	for name, doc := range map[string]string{
		"succeeded with abort fact": document(
			"CHECKPOINT_OPERATION_STATE_SUCCEEDED", root, scheme, abortable, "true"),
		"witness protocol with abort fact": document(
			"CHECKPOINT_OPERATION_STATE_FAILED", root, scheme,
			`"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS"`, "true"),
		"legacy protocol with abort fact": document(
			"CHECKPOINT_OPERATION_STATE_FAILED", root, scheme,
			`"CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED"`, "true"),
		"protocol-2 failed with root and abort fact": document(
			"CHECKPOINT_OPERATION_STATE_FAILED", root, scheme, abortable, "true"),
	} {
		if _, err := parseCheckpointOperationStatus(doc); err == nil {
			t.Fatalf("a malformed abort_confirmed shape (%s) was accepted as a receipt", name)
		} else if !strings.Contains(err.Error(), "abort_confirmed") {
			t.Fatalf("the %s error does not name the abort fact: %v", name, err)
		}
	}
}
