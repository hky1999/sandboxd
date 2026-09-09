package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSHA(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func sourceRootDigest(dir string) string {
	if b, e := os.ReadFile(filepath.Join(dir, "source-root-digest")); e == nil {
		return strings.TrimSpace(string(b))
	}
	return testSHA([]byte("sealed fixture"))
}
func targetGenerationValue(dir string) string {
	if b, e := os.ReadFile(filepath.Join(dir, "target-birth-generation")); e == nil {
		return strings.TrimSpace(string(b))
	}
	return "t1"
}
func targetInspectJSON(dir string) string {
	g := targetGenerationValue(dir)
	if b, e := os.ReadFile(filepath.Join(dir, "target-generation")); e == nil {
		g = strings.TrimSpace(string(b))
	}
	b, _ := json.Marshal(map[string]any{"id": "sbox-x", "labels": map[string]string{sourceGenerationLabel: g}})
	return string(b)
}
func operationReceiptJSON(operation, sandbox, state, generation string) string {
	b, _ := json.Marshal(map[string]any{"operation_id": operation, "sandbox_id": sandbox, "state": "START_OPERATION_STATE_" + strings.ToUpper(state), "resource_generation": generation})
	return string(b)
}
func TestResumableLostReplyRetirementRetryAndDone(t *testing.T) {
	state := t.TempDir()
	put := func(n string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(state, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	put("req.json", []byte(`{"runtime":"firecracker"}`))
	put("lose-restore-reply", nil)
	put("fail-retire", nil)
	bin := buildCnMigrate(t)
	nodes := catalogStandIn(t, state)
	args := []string{"-journal", filepath.Join(state, "journal.json"), "-migration-id", "retry1"}
	code, _, out := runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 || !strings.Contains(out, "source-cleanup-pending") {
		t.Fatalf("first migration must preserve target success for retirement retry: code=%d %s", code, out)
	}
	if e := os.Remove(filepath.Join(state, "fail-retire")); e != nil {
		t.Fatal(e)
	}
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("retry: code=%d %s", code, out)
	}
	creations, err := os.ReadFile(filepath.Join(state, "target-creations"))
	if err != nil || len(creations) != 1 {
		t.Fatalf("expected one target creation, got %q (%v)", creations, err)
	}
	calls := readCalls(t, state)
	checkpoints, restores, deletes := 0, 0, 0
	for _, c := range calls {
		if strings.Contains(c.argv, "--action checkpoint ") {
			checkpoints++
		}
		if strings.Contains(c.argv, "--action restore ") {
			restores++
		}
		if strings.Contains(c.argv, "--action delete ") {
			deletes++
			if !strings.Contains(c.argv, "--expected-generation g1") {
				t.Fatal("retirement lost original generation")
			}
		}
	}
	if checkpoints != 1 || restores != 2 || deletes != 2 {
		t.Fatalf("checkpoint=%d restore=%d delete=%d", checkpoints, restores, deletes)
	}
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 0 {
		t.Fatal(out)
	}
	if len(readCalls(t, state)) != len(calls) {
		t.Fatal("done replay issued node commands")
	}
}

func TestResumableRefusesUnprovenProgress(t *testing.T) {
	bin := buildCnMigrate(t)
	for _, scenario := range []string{"checkpoint-unknown", "target-replaced", "intent-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			state := t.TempDir()
			write := func(name, text string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(state, name), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("req.json", `{"runtime":"firecracker"}`)
			if scenario == "checkpoint-unknown" {
				// The source operation is durably UNKNOWN: the runtime was
				// entered and the outcome could not be proven. This is NOT
				// an ack loss — nothing may adopt or re-execute it.
				write("checkpoint-operation-state", "unknown")
			} else {
				write("fail-retire", "")
			}
			args := []string{"-journal", filepath.Join(state, "journal.json"), "-migration-id", "refuse1"}
			nodes := catalogStandIn(t, state)
			code, _, out := runMigrate(t, bin, state, nodes, 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("initial failure expected: %s", out)
			}
			before := readCalls(t, state)
			switch scenario {
			case "checkpoint-unknown":
				// nothing changes: the operation stays UNKNOWN
			case "target-replaced":
				write("target-generation", "replacement-t2")
				os.Remove(filepath.Join(state, "fail-retire"))
			case "intent-conflict":
				args = append(args, "-store", "different-store")
			}
			code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("unproven resume accepted: %s", out)
			}
			after := readCalls(t, state)
			for _, c := range after[len(before):] {
				if strings.Contains(c.argv, "--action checkpoint ") || strings.Contains(c.argv, "--action restore ") || strings.Contains(c.argv, "--action delete ") {
					t.Fatalf("unsafe resume command: %s", c.argv)
				}
			}
			switch scenario {
			case "checkpoint-unknown":
				// The only legal command of the second process is the
				// operation query — no re-execution, no target, no rollback.
				if fresh := after[len(before):]; len(fresh) != 1 ||
					!strings.Contains(fresh[0].argv, "get-checkpoint-operation") ||
					!strings.Contains(fresh[0].argv, "checkpoint-refuse1") {
					t.Fatalf("second process must only query the source operation, got %v", fresh)
				}
				if _, err := os.Stat(filepath.Join(state, "stopped")); err == nil {
					t.Fatal("an UNKNOWN operation finalized the source")
				}
			case "intent-conflict":
				if len(after) != len(before) {
					t.Fatal("changed intent contacted node")
				}
			}
		})
	}
}
func TestJournalErrorReleasesLockAndPreservesProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	intent := migrationIntent{MigrationID: "lock1", Sandbox: "sbox-x", Source: "S", Store: "store", RequestFile: "/req", ExecTemplate: "runner {node}"}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openJournal(path, intent); err == nil {
		t.Fatal("corruption accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	record, store, err := openJournal(path, intent)
	if err != nil {
		t.Fatalf("failed open leaked lock: %v", err)
	}
	if _, _, err := openJournal(path, intent); err == nil {
		t.Fatal("concurrent journal open accepted")
	}
	record.SourceGeneration = "g1"
	record.Stage = stageCheckpointIssued
	if err := store.save(record); err != nil {
		t.Fatal(err)
	}
	store.lock.Close()
	record, store, err = openJournal(path, intent)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	if record.Stage != stageCheckpointIssued {
		t.Fatal("persisted progress reset")
	}
}

func TestJournalReadMetadataBound(t *testing.T) {
	p := filepath.Join(t.TempDir(), "journal")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxJournalBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := loadJournal(p); err == nil {
		t.Fatal("oversize journal accepted")
	}
	if _, err := loadJournal(t.TempDir()); err == nil {
		t.Fatal("directory journal accepted")
	}
}

func TestResumableExplicitEmptyFlagsNeverSelectLegacy(t *testing.T) {
	bin := buildCnMigrate(t)
	for _, args := range [][]string{{"-journal", ""}, {"-migration-id", ""}, {"-journal", "", "-migration-id", ""}} {
		state := t.TempDir()
		if err := os.WriteFile(filepath.Join(state, "calls"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		code, _, out := runMigrate(t, bin, state, "http://unused", time.Second, args...)
		if code != 1 || !strings.Contains(out, "must not be empty") {
			t.Fatalf("empty progress flags accepted: %s", out)
		}
		if len(readCalls(t, state)) != 0 {
			t.Fatal("explicit empty progress flag ran legacy node commands")
		}
	}
}

func TestResumableDoesNotAdoptConflictingOperationHistory(t *testing.T) {
	state := t.TempDir()
	for name, value := range map[string]string{"req.json": `{"runtime":"firecracker"}`, "reject-operation-conflict": "", "operation-state": "succeeded", "target-generation": "old-birth", "target-birth-generation": "old-birth"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, "-journal", filepath.Join(state, "journal.json"), "-migration-id", "collision1")
	if code == 0 {
		t.Fatalf("conflicting historical success was adopted: %s", out)
	}
	for _, c := range readCalls(t, state) {
		if strings.Contains(c.argv, "--action delete ") {
			t.Fatal("retired source after restore request conflict")
		}
	}
}

// journalField reads one field out of the durable journal record for stage
// and receipt assertions. An absent field reads as the empty string.
func journalField(t *testing.T, path, field string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal %s: %v", path, err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("parse journal %s: %v", path, err)
	}
	value, ok := record[field]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

// identifiedCheckpointArgv collects the checkpoint commands that ran under
// the durable source operation identity.
func identifiedCheckpointArgv(calls []nodeCall) []string {
	var argvs []string
	for _, c := range calls {
		if strings.Contains(c.argv, "--action checkpoint ") &&
			strings.Contains(c.argv, "--operation-id checkpoint-") {
			argvs = append(argvs, c.argv)
		}
	}
	return argvs
}

// stageState prepares the common fixtures of one resumable scenario and
// returns the journal path plus a write helper for control files.
func stageState(t *testing.T) (state, journal string, write func(name, text string)) {
	t.Helper()
	state = t.TempDir()
	write = func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(state, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("req.json", `{"runtime":"firecracker"}`)
	return state, filepath.Join(state, "journal.json"), write
}

// TestResumableSourceAckLossReconcilesInSameCall drives the source success
// ack loss: the node durably recorded the SUCCEEDED receipt but the reply
// never reached the CLI. The SAME process must reconcile it — query the
// operation, replay the identical pinned payload, validate the receipt —
// and finish the migration with exactly ONE actual source checkpoint.
func TestResumableSourceAckLossReconcilesInSameCall(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	args := []string{"-journal", journal, "-migration-id", "ackloss1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("ack-loss reconciliation did not finish the migration: %s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 (the runtime checkpoint runs once per operation)\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-replays"); got != 1 {
		t.Fatalf("receipt replays = %d, want 1 (the SUCCEEDED record is verified by one same-payload replay)\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
	if _, err := os.Stat(filepath.Join(state, "source-retired")); err != nil {
		t.Fatalf("source never retired: %v\n%s", err, out)
	}
}

// TestResumableSourceAckAndQueryLossRetryNewProcess drives the compounded
// loss: the checkpoint reply is lost AND the immediate reconciliation query
// fails ambiguously. The first process stops at checkpoint-issued without a
// preserved receipt; a NEW process reconciles through the query and the
// same-payload replay, still with exactly one actual source checkpoint.
func TestResumableSourceAckAndQueryLossRetryNewProcess(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	write("fail-checkpoint-query", "")
	args := []string{"-journal", journal, "-migration-id", "twoloss1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("ambiguous query must stop the first process: %s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("a receipt was preserved without a trustworthy query answer")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" {
			t.Fatalf("target contacted after an unresolved source checkpoint: %s", c.argv)
		}
	}
	// Only the query fault clears: the record is durable, so the new process
	// resolves the same operation — and the still-staged lost reply must not
	// matter, because the record answers the replay.
	if err := os.Remove(filepath.Join(state, "fail-checkpoint-query")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("new process did not finish the reconciled migration: %s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1 across both processes\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-replays"); got != 1 {
		t.Fatalf("receipt replays = %d, want 1\n%s", got, out)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableIssuedNotFoundResendsSameOperation drives the proven-absent
// record: the operation was refused before admission (the query answers the
// structured not-found exit code), which authorizes exactly one resend of
// the SAME operation with the SAME payload — never a new identity, a fresh
// inspect, or a legacy checkpoint.
func TestResumableIssuedNotFoundResendsSameOperation(t *testing.T) {
	state, journal, write := stageState(t)
	write("refuse-checkpoint-op", "")
	args := []string{"-journal", journal, "-migration-id", "resend1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("refused admission must fail the first process: %s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	firstIssues := identifiedCheckpointArgv(readCalls(t, state))
	if len(firstIssues) != 2 {
		t.Fatalf("first process must issue and resend once under the same identity, got %d checkpoint commands:\n%s", len(firstIssues), out)
	}
	if firstIssues[0] != firstIssues[1] {
		t.Fatalf("the not-found resend changed the payload:\n%s\n%s", firstIssues[0], firstIssues[1])
	}
	if err := os.Remove(filepath.Join(state, "refuse-checkpoint-op")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("same-identity resend did not complete the migration: %s", out)
	}
	secondIssues := identifiedCheckpointArgv(readCalls(t, state))
	if len(secondIssues) != 3 || secondIssues[2] != firstIssues[0] {
		t.Fatalf("the new process must resend the identical operation payload, got:\n%s", strings.Join(secondIssues, "\n"))
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
}

// TestResumableNonSucceededSourceOperationStops pins the fail-closed states:
// a durably RUNNING, UNKNOWN, or FAILED source operation authorizes nothing.
// No re-execution, no rollback, no legacy checkpoint, no target — the
// journal stays at checkpoint-issued and the operation ID stays spent.
func TestResumableNonSucceededSourceOperationStops(t *testing.T) {
	for _, operationState := range []string{"running", "unknown", "failed"} {
		t.Run(operationState, func(t *testing.T) {
			state, journal, write := stageState(t)
			write("checkpoint-operation-state", operationState)
			args := []string{"-journal", journal, "-migration-id", "stop1"}
			code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("a %s operation must fail the migration: %s", operationState, out)
			}
			if !strings.Contains(out, "CHECKPOINT_OPERATION_STATE_"+strings.ToUpper(operationState)) {
				t.Fatalf("the report does not name the operation state:\n%s", out)
			}
			if journalField(t, journal, "stage") != stageCheckpointIssued {
				t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
			}
			if _, err := os.Stat(filepath.Join(state, "stopped")); err == nil {
				t.Fatalf("a %s operation finalized the source", operationState)
			}
			for _, c := range readCalls(t, state) {
				if c.node == "T" {
					t.Fatalf("target contacted despite a %s source operation: %s", operationState, c.argv)
				}
			}
			before := readCalls(t, state)
			code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("a spent %s operation must keep failing: %s", operationState, out)
			}
			fresh := readCalls(t, state)[len(before):]
			if len(fresh) != 1 || !strings.Contains(fresh[0].argv, "get-checkpoint-operation") {
				t.Fatalf("the retry must only re-query the spent operation, got %v", fresh)
			}
			if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
				t.Fatalf("actual source checkpoints = %d, want 1 (a spent operation is never re-executed)", got)
			}
		})
	}
}

// TestResumableRejectsWrongSourceReceipt pins the receipt validation: a
// reply that does not answer for THIS operation, sandbox, generation, pinned
// payload digest, or root scheme is refused — no receipt is preserved, the
// journal stays at checkpoint-issued, and nothing else runs.
func TestResumableRejectsWrongSourceReceipt(t *testing.T) {
	for _, field := range []string{"operation_id", "sandbox_id", "source_generation", "request_digest", "artifact_root_scheme"} {
		t.Run(field, func(t *testing.T) {
			state, journal, write := stageState(t)
			write("poison-checkpoint-receipt", field)
			args := []string{"-journal", journal, "-migration-id", "poison1"}
			code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 1 {
				t.Fatalf("a receipt with a wrong %s was accepted: %s", field, out)
			}
			if journalField(t, journal, "stage") != stageCheckpointIssued {
				t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
			}
			if journalField(t, journal, "source_root_digest") != "" {
				t.Fatal("an untrusted receipt was preserved in the journal")
			}
			for _, c := range readCalls(t, state) {
				if c.node == "T" || strings.Contains(c.argv, "cn-publish") {
					t.Fatalf("the migration continued past a rejected receipt: %s", c.argv)
				}
			}
			if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
				t.Fatalf("actual source checkpoints = %d, want 1", got)
			}
		})
	}
}

// TestResumableRefusesChangedArtifactAfterCompletion pins the root binding:
// the receipt's sealed root is a completion-time fact, so a directory whose
// content root drifted after the historical success is refused at the
// bind-source-root gate — never re-pinned as if it were the sealed artifact.
func TestResumableRefusesChangedArtifactAfterCompletion(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	write("fail-checkpoint-query", "")
	args := []string{"-journal", journal, "-migration-id", "drift1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("scenario setup: the ambiguous query must stop the first process: %s", out)
	}
	// The durable receipt bound the ORIGINAL root; the directory now derives
	// a different one.
	write("source-root-digest", strings.Repeat("e", 64))
	if err := os.Remove(filepath.Join(state, "fail-checkpoint-query")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a changed artifact was adopted as the sealed checkpoint: %s", out)
	}
	if !strings.Contains(out, "changed after the checkpoint completed") {
		t.Fatalf("the report does not refuse the changed artifact:\n%s", out)
	}
	if stage := journalField(t, journal, "stage"); stage != stageCheckpointSealed {
		t.Fatalf("journal stage = %q, want checkpoint-sealed (the receipt is kept, the artifact is not re-pinned)", stage)
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" || strings.Contains(c.argv, "cn-publish") {
			t.Fatalf("the migration continued past the drifted artifact: %s", c.argv)
		}
	}
}

// TestResumableRefusesChangedPayloadAfterHistoricalSuccess pins the payload
// binding: after a historical SUCCEEDED, only the identical pinned payload
// may replay under the operation ID. A journal whose pinned payload was
// edited (the timeout here) is refused by the record itself, and the
// migration never reaches a target.
func TestResumableRefusesChangedPayloadAfterHistoricalSuccess(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	write("fail-checkpoint-query", "")
	args := []string{"-journal", journal, "-migration-id", "payload1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("scenario setup: the ambiguous query must stop the first process: %s", out)
	}
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"checkpoint_timeout_seconds": 180`) {
		t.Fatalf("journal does not pin the fixed timeout:\n%s", raw)
	}
	edited := strings.Replace(string(raw), `"checkpoint_timeout_seconds": 180`, `"checkpoint_timeout_seconds": 181`, 1)
	if edited == string(raw) || os.WriteFile(journal, []byte(edited), 0600) != nil {
		t.Fatal("could not stage the edited payload")
	}
	if err := os.Remove(filepath.Join(state, "fail-checkpoint-query")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 {
		t.Fatalf("a changed payload replayed under a historical operation ID: %s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "checkpoint-op-reuse-refused")); err != nil {
		t.Fatalf("the record did not refuse the changed payload:\n%s", out)
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if journalField(t, journal, "source_root_digest") != "" {
		t.Fatal("an unverified historical receipt was preserved")
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" {
			t.Fatalf("target contacted after the payload conflict: %s", c.argv)
		}
	}
}

// writeV1Journal stages a record exactly as the version 1 build wrote it,
// with an intent that matches this invocation so the only rejection reason
// can be the schema itself.
func writeV1Journal(t *testing.T, path, stage string) {
	t.Helper()
	executor, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record := map[string]any{
		"version":              1,
		"migration_id":         "old1",
		"sandbox":              "sbox-x",
		"source":               "S",
		"store":                "fake",
		"request_file":         filepath.Join(filepath.Dir(path), "req.json"),
		"exec_template":        executor + " -test.run=TestExecutorHelper -- " + filepath.Dir(path) + " {node}",
		"checkpoint_dir":       migrationCheckpointDirFor("sbox-x", "old1"),
		"operation_id":         migrationOperationIDFor("old1"),
		"source_generation":    "g1",
		"root_digest":          strings.Repeat("a", 64),
		"root_scheme":          "v2:manifest+sidecar-roots",
		"request_digest":       strings.Repeat("b", 64),
		"target":               "T",
		"target_generation":    "t1",
		"stage":                stage,
		"updated_at_unix_nano": 1,
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestResumableV1IssuedJournalRefusedNotRewritten pins the v1 hard line: an
// unfinished v1 record issued its checkpoint through the legacy RPC with no
// durable operation identity, so even a NotFound answer from the new query
// API proves nothing about that old request. The build refuses to resume it
// with ZERO node commands — not even a query — and leaves the file
// byte-identical.
func TestResumableV1IssuedJournalRefusedNotRewritten(t *testing.T) {
	state, journal, write := stageState(t)
	writeV1Journal(t, journal, stageCheckpointIssued)
	write("calls", "")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, "-journal", journal, "-migration-id", "old1")
	if code != 1 {
		t.Fatalf("an unfinished v1 journal was resumed: %s", out)
	}
	if !strings.Contains(out, "version 1") {
		t.Fatalf("the report does not name the v1 compatibility limit:\n%s", out)
	}
	if calls := readCalls(t, state); len(calls) != 0 {
		t.Fatalf("the refused v1 journal contacted nodes: %v", calls)
	}
	after, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("the v1 journal was rewritten:\n%s\n%s", before, after)
	}
}

// TestResumableV1DoneJournalReplaysWithZeroCalls pins the one v1 stage this
// build still loads: a terminal done record replays as a pure report with
// zero node commands, and is never rewritten to version 2.
func TestResumableV1DoneJournalReplaysWithZeroCalls(t *testing.T) {
	state, journal, write := stageState(t)
	writeV1Journal(t, journal, stageDone)
	write("calls", "")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, "-journal", journal, "-migration-id", "old1")
	if code != 0 {
		t.Fatalf("a terminal v1 done journal must replay as success: %s", out)
	}
	if calls := readCalls(t, state); len(calls) != 0 {
		t.Fatalf("the v1 done replay issued node commands: %v", calls)
	}
	after, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("the v1 done journal was rewritten:\n%s\n%s", before, after)
	}
}

// TestResumableUnsupportedSourceOperationNoFallback pins the no-fallback
// line: a node that refuses the identified checkpoint (an old server
// returning Unimplemented included) fails the migration every time. No
// legacy checkpoint RPC, no unconditional snapshot, no re-inspected
// generation — the journal stays at checkpoint-issued for the operator.
func TestResumableUnsupportedSourceOperationNoFallback(t *testing.T) {
	state, journal, write := stageState(t)
	write("refuse-checkpoint-op", "")
	args := []string{"-journal", journal, "-migration-id", "unimpl1"}
	for run := 1; run <= 2; run++ {
		code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
		if code != 1 {
			t.Fatalf("run %d: an unsupported source operation must fail: %s", run, out)
		}
	}
	calls := readCalls(t, state)
	queries, checkpoints := 0, identifiedCheckpointArgv(calls)
	for _, c := range calls {
		if strings.Contains(c.argv, "get-checkpoint-operation") {
			queries++
		}
	}
	if len(checkpoints) == 0 || queries == 0 {
		t.Fatalf("the reconciliation must use the new query and identified checkpoint only:\n%s", debugCalls(calls))
	}
	for _, argv := range checkpoints {
		if !strings.Contains(argv, "--operation-id checkpoint-unimpl1") ||
			!strings.Contains(argv, "--expected-generation g1") {
			t.Fatalf("a checkpoint ran outside the durable identity: %s", argv)
		}
	}
	if journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
	}
	if fakeReadCount(t, state, "source-checkpoint-executions") != 0 {
		t.Fatal("the refused node still executed a checkpoint")
	}
}

func debugCalls(calls []nodeCall) string {
	var lines []string
	for _, c := range calls {
		lines = append(lines, c.node+" "+c.argv)
	}
	return strings.Join(lines, "\n")
}

// TestResumableCombinedSourceAckLossTargetAckLossRetireFailure stacks the
// acceptance matrix's combined case: the source checkpoint ack is lost (and
// reconciled through query + replay in the same call), the target restore
// ack is lost (and reconciled through the target operation record), and the
// source retirement then fails. The retry finishes the migration with one
// actual source checkpoint and one target creation.
func TestResumableCombinedSourceAckLossTargetAckLossRetireFailure(t *testing.T) {
	state, journal, write := stageState(t)
	write("lose-checkpoint-reply", "")
	write("lose-restore-reply", "")
	write("fail-retire", "")
	args := []string{"-journal", journal, "-migration-id", "combined1"}
	code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 1 || !strings.Contains(out, "source-cleanup-pending") {
		t.Fatalf("the combined failure must surface as source-cleanup-pending: code=%d %s", code, out)
	}
	if err := os.Remove(filepath.Join(state, "fail-retire")); err != nil {
		t.Fatal(err)
	}
	code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
	if code != 0 {
		t.Fatalf("the retry did not finish the combined migration: %s", out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
		t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
	}
	if got := fakeReadCount(t, state, "source-checkpoint-replays"); got != 1 {
		t.Fatalf("receipt replays = %d, want 1\n%s", got, out)
	}
	if creations, err := os.ReadFile(filepath.Join(state, "target-creations")); err != nil || len(creations) != 1 {
		t.Fatalf("target creations = %q (%v), want exactly one", creations, err)
	}
	if journalField(t, journal, "stage") != stageDone {
		t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
	}
}

// TestResumableIssuedWithPreservedReceiptRecovers pins the crash window the
// two-step persist leaves: the receipt is durable while the stage is still
// checkpoint-issued. A new process reconciles that state through the query
// and replay, holds both answers to the preserved receipt, and finishes;
// a preserved receipt the record contradicts is refused instead.
func TestResumableIssuedWithPreservedReceiptRecovers(t *testing.T) {
	for _, scenario := range []string{"consistent", "contradicted"} {
		t.Run(scenario, func(t *testing.T) {
			state, journal, write := stageState(t)
			write("fail-publish", "")
			args := []string{"-journal", journal, "-migration-id", "window1"}
			code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 1 || !strings.Contains(out, "cn-publish failed") {
				t.Fatalf("scenario setup: expected a publish failure, code=%d %s", code, out)
			}
			// Roll the record back into the crash window: the receipt is
			// durable but the stage still says the checkpoint is issued.
			raw, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			rewound := strings.Replace(string(raw), `"stage": "`+stageRootBound+`"`, `"stage": "`+stageCheckpointIssued+`"`, 1)
			if rewound == string(raw) {
				t.Fatalf("could not rewind the journal stage:\n%s", raw)
			}
			if scenario == "contradicted" {
				// The preserved receipt no longer matches what the record
				// will answer for.
				rewound = strings.Replace(rewound, `"source_root_digest": "`+sourceRootDigest(state)+`"`, `"source_root_digest": "`+strings.Repeat("f", 64)+`"`, 1)
			}
			if err := os.WriteFile(journal, []byte(rewound), 0600); err != nil {
				t.Fatal(err)
			}
			// The publish fault was only the brake that stopped the first
			// run inside the post-seal stages; the recovery run must be
			// free to finish.
			if err := os.Remove(filepath.Join(state, "fail-publish")); err != nil {
				t.Fatal(err)
			}
			code, _, out = runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if scenario == "consistent" {
				if code != 0 {
					t.Fatalf("the preserved-receipt crash window did not recover: %s", out)
				}
				if got := fakeReadCount(t, state, "source-checkpoint-executions"); got != 1 {
					t.Fatalf("actual source checkpoints = %d, want 1\n%s", got, out)
				}
				if journalField(t, journal, "stage") != stageDone {
					t.Fatalf("journal stage = %q, want done", journalField(t, journal, "stage"))
				}
			} else {
				if code != 1 {
					t.Fatalf("a contradicted preserved receipt was accepted: %s", out)
				}
				if !strings.Contains(out, "disagree") {
					t.Fatalf("the report does not name the receipt contradiction:\n%s", out)
				}
				if journalField(t, journal, "stage") != stageCheckpointIssued {
					t.Fatalf("journal stage = %q, want checkpoint-issued", journalField(t, journal, "stage"))
				}
			}
		})
	}
}
