// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// The resumable migration mode, enabled by the paired -journal and
// -migration-id flags. It runs the same stop-and-copy migration as the
// legacy one-shot path, but every stage is pinned in the durable journal
// before the side effect that gives the stage its name, so a retry after a
// lost reply, a killed CLI, or a crash resumes the SAME migration:
//
//   - the checkpoint directory, the source checkpoint operation ID, and the
//     target operation ID are pure functions of the migration ID, so a
//     retry never forks a second checkpoint or a second target start;
//   - the source checkpoint runs as an identified stop-and-copy operation
//     (CheckpointWithOperation) whose complete payload — directory,
//     generation, timeout, compression, snapshot flavor — is pinned in the
//     journal and replayed from it, so the request bound to the operation
//     ID can never drift with future defaults. A lost or failed reply is
//     reconciled by querying the durable operation record FIRST. Only a
//     proven-absent record (the structured not-found exit code of the query
//     action, never stderr text) permits re-issuing the very same operation
//     with the very same payload; a SUCCEEDED record additionally requires
//     proof of the caller's payload before it authorizes anything, because
//     the query answer alone does not bind the caller's request. A record
//     admitted under the WITNESS recovery protocol must additionally prove
//     the release of its retained evidence — evidence_released=true in the
//     response being accepted — before its receipt is preserved and the
//     checkpoint is sealed: an initial success that acknowledged in its own
//     call is accepted with no extra command, while anything else performs
//     exactly one explicit recover-checkpoint-operation carrying the
//     COMPLETE original payload, which the service re-digests against the
//     record and which must repeat the same op/sandbox/generation/request
//     digest/root/scheme and complete the acknowledgment. A record admitted
//     under a witness-capable protocol — WITNESS or WITNESS_ABORTABLE —
//     owes that same release proof (explicit recovery succeeds under either
//     protocol); a SUCCEEDED protocol-0 record keeps the historical
//     same-payload replay; an UNKNOWN witness-capable record may be
//     reconciled by the same single explicit recovery; UNKNOWN protocol-0,
//     RUNNING, FAILED — including a durably confirmed abort, which is never
//     a migration success — and ambiguous answers fail closed: no source
//     rollback, no legacy checkpoint RPC, no new operation ID, no target
//     start, and no automatic abort — the explicit abort belongs to the
//     node CLI, never this controller;
//   - the checkpoint receipt's sealed root is preserved durably before the
//     checkpoint-sealed stage, and the later root binding must re-derive
//     exactly that root and scheme from the artifact — a directory whose
//     content changed after completion is refused, never re-pinned;
//   - the checkpoint content root is pinned from the source through the
//     read-only checkpoint-root action, and the restore names it as
//     --expected-root-digest, so the operation binds to the artifact it
//     restores and a replaced directory cannot ride the operation ID;
//   - a restore whose reply was lost is resolved by querying the durable
//     operation record FIRST; only a proven-absent record permits
//     re-issuing the very same operation, and RUNNING / UNKNOWN / FAILED /
//     ambiguous answers fail closed: no source rollback, no new operation
//     ID, no target delete;
//   - the target's birth generation is taken from the operation receipt,
//     never from a later inspect: before the source generation is retired,
//     the target must be RUNNING and still carry that receipt generation;
//   - the source is never rolled back automatically in this mode. The
//     source was finalized at checkpoint time (--leave-running=false); a
//     rollback would race whatever the target already did, so failures keep
//     the sealed checkpoint, the artifacts, and the exact pending stage for
//     a retry or an operator.
//
// This is a staged integration, not final fencing: the journal is
// node-local CLI progress, not a cross-node writer lease, and the source
// operation records are node-local idempotency state, not cross-node
// ownership. Version 1 journals from the pre-operation flow are refused
// unless already `done`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"google.golang.org/protobuf/encoding/protojson"
)

// exitCodeOperationNotFound mirrors the checkpoint-restore CLI's structured
// not-found exit code for the --action get-start-operation and
// --action get-checkpoint-operation queries. It is the ONLY absent-record
// signal this CLI accepts — an executor that swallows exit codes turns
// every query into an ambiguous failure, which fails closed.
const exitCodeOperationNotFound = 3

// resumableConfig carries the validated flags of one resumable invocation.
type resumableConfig struct {
	sandbox     string
	source      string
	execTpl     string
	storeSpec   string
	nodes       string
	to          string
	srcGen      string
	ckReq       string
	bin         string
	wait        time.Duration
	jsonOut     bool
	journalPath string
	migrationID string
}

// runResumableMigration executes the journaled migration flow. It either
// finishes the report with the process exit code or reports failure through
// the shared finish() path; the journal lock is held until the process ends.
func runResumableMigration(cfg resumableConfig) {
	report := migrateReport{
		Sandbox:     cfg.sandbox,
		Source:      cfg.source,
		MigrationID: cfg.migrationID,
		Journal:     cfg.journalPath,
	}
	fail := func(step, detail string) {
		report.Error = detail
		report.Steps = append(report.Steps, stepLog{Step: step, Detail: detail, Failed: true})
		finish(report, cfg.jsonOut, false)
	}
	// runCode executes one node command and returns its exit code (0 on
	// success, -1 when the executor could not be run at all). Success of a
	// step is the exit status, not the output.
	runCode := func(node, step string, args ...string) (string, int) {
		started := time.Now()
		tpl := strings.ReplaceAll(cfg.execTpl, "{node}", node)
		full := append(strings.Fields(tpl), args...)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.wait)
		defer cancel()
		cmd := exec.CommandContext(ctx, full[0], full[1:]...)
		out, err := cmd.CombinedOutput()
		trimmed := strings.TrimSpace(string(out))
		code := 0
		if err != nil {
			code = -1
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				code = exited.ExitCode()
			}
		}
		report.Steps = append(report.Steps, stepLog{
			Step: step, Detail: trimmed, TookMs: time.Since(started).Milliseconds(), Failed: err != nil,
		})
		return trimmed, code
	}
	run := func(node, step string, args ...string) (string, bool) {
		trimmed, code := runCode(node, step, args...)
		return trimmed, code == 0
	}
	lastDetail := func() string {
		if len(report.Steps) == 0 {
			return ""
		}
		return report.Steps[len(report.Steps)-1].Detail
	}
	// persist durably advances the journal; a stage that names a side effect
	// is persisted BEFORE the command runs, so its unknown-outcome window is
	// always observable by the next process.
	var journal *migrationJournal
	var store *journalStore
	persist := func(stage string, mutate func(*migrationJournal)) {
		mutate(journal)
		journal.Stage = stage
		if err := store.save(journal); err != nil {
			fail("journal", fmt.Sprintf("cannot durably record stage %s: %v — the run stops here with the journal at its last durable stage", stage, err))
		}
		report.Stage = stage
	}

	loaded, journalFile, err := openJournal(cfg.journalPath, migrationIntent{
		MigrationID:       cfg.migrationID,
		Sandbox:           cfg.sandbox,
		Source:            cfg.source,
		Store:             cfg.storeSpec,
		RequestFile:       cfg.ckReq,
		ExecTemplate:      cfg.execTpl,
		PreferredTo:       cfg.to,
		ExpectedSourceGen: cfg.srcGen,
	})
	if err != nil {
		fail("journal", err.Error())
	}
	journal, store = loaded, journalFile
	report.Checkpoint = journal.CheckpointDir
	report.SourceGeneration = journal.SourceGeneration
	report.Target = journal.Target
	report.Stage = journal.Stage

	// issueSourceCheckpoint runs the identified source checkpoint exactly as
	// pinned in the journal: the durable operation identity, the captured
	// generation, and the complete fixed CheckpointRequest payload (sandbox,
	// directory spelling, timeout, compression, leave-running, snapshot
	// flavor) all come from the record, so every invocation — first issue,
	// NotFound resend, and SUCCEEDED verification replay alike — sends
	// byte-stable intent. There is deliberately no legacy fallback: an
	// unsupported or unavailable CheckpointWithOperation is a hard failure,
	// because a fallback would checkpoint outside the durable identity this
	// flow is about to reconcile.
	issueSourceCheckpoint := func() (string, int) {
		return runCode(cfg.source, "checkpoint", cfg.bin+"/checkpoint-restore",
			"--action", "checkpoint", "--socket", "/run/sandboxd/sandboxd.sock",
			"--sandbox-id", cfg.sandbox,
			"--checkpoint-dir", journal.CheckpointDir,
			"--checkpoint-timeout-seconds", strconv.FormatUint(uint64(journal.CheckpointTimeoutSeconds), 10),
			"--compress="+strconv.FormatBool(journal.CheckpointCompress),
			"--leave-running="+strconv.FormatBool(journal.CheckpointLeaveRunning),
			"--snapshot-type", journal.CheckpointSnapshotType,
			"--operation-id", journal.SourceOperationID,
			"--expected-generation", journal.SourceGeneration)
	}
	// receiptConflict validates one checkpoint operation receipt against this
	// migration: the echoed identities, the terminal success state, the
	// request digest validated by the node CLI, and the sealed
	// root's digest shape and scheme. The receipt's checkpoint directory is
	// deliberately NOT compared with the journal's logical path — under an
	// executor template the node-local CLI already verified the server's
	// canonical directory against the directory actually sent, and the two
	// spellings legitimately differ across the mapping.
	receiptConflict := func(status *runtime.CheckpointOperationStatus) string {
		if status.GetOperationID() != journal.SourceOperationID {
			return fmt.Sprintf("receipt operation %q does not answer for the journaled source operation %q", status.GetOperationID(), journal.SourceOperationID)
		}
		if status.GetSandboxID() != cfg.sandbox {
			return fmt.Sprintf("receipt sandbox %q is not the migrated sandbox %q", status.GetSandboxID(), cfg.sandbox)
		}
		if status.GetSourceGeneration() != journal.SourceGeneration {
			return fmt.Sprintf("receipt source_generation %q is not the pinned generation %q", status.GetSourceGeneration(), journal.SourceGeneration)
		}
		if status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED {
			return fmt.Sprintf("operation state %s is not SUCCEEDED", status.GetState())
		}
		// The node CLI validates the exact request it sent, including the
		// executor-mapped directory spelling. The controller only knows the
		// logical path and cannot independently reconstruct those bytes.
		// Reconciliation additionally requires same-request replay and equal
		// query/replay/persisted receipts below.
		if len(status.GetRequestDigest()) != 64 || !isHex(status.GetRequestDigest()) || status.GetRequestDigest() != strings.ToLower(status.GetRequestDigest()) {
			return fmt.Sprintf("receipt request_digest %q is not a canonical SHA-256 digest", status.GetRequestDigest())
		}
		if len(status.GetArtifactRootDigest()) != 64 || !isHex(status.GetArtifactRootDigest()) || status.GetArtifactRootDigest() != strings.ToLower(status.GetArtifactRootDigest()) {
			return fmt.Sprintf("receipt artifact_root_digest %q is not a 64-hex digest", status.GetArtifactRootDigest())
		}
		if status.GetArtifactRootScheme() != checkpointroot.Scheme {
			return fmt.Sprintf("receipt artifact_root_scheme %q is not the shared root scheme %q", status.GetArtifactRootScheme(), checkpointroot.Scheme)
		}
		return ""
	}
	// parseReceipt strictly decodes the protojson CheckpointOperationStatus
	// the operation-mode CLI prints on stdout: one document, no unknown
	// fields, no trailing content. Output of a FAILED command is never
	// parsed as a receipt — callers only reach here on exit 0.
	parseReceipt := func(output string) (*runtime.CheckpointOperationStatus, error) {
		status, err := parseCheckpointOperationStatus(output)
		if err != nil {
			return nil, fmt.Errorf("the checkpoint operation reply is not a readable receipt: %w", err)
		}
		return status, nil
	}
	// persistReceiptConflict additionally holds a receipt that is already
	// durable in the journal to the newly observed one: once a success
	// receipt is preserved, every later observation of the same operation
	// must repeat it exactly, or the record is not trustworthy.
	persistReceiptConflict := func(status *runtime.CheckpointOperationStatus) string {
		if strings.TrimSpace(journal.SourceRootDigest) == "" {
			return ""
		}
		if status.GetRequestDigest() != journal.SourceOpRequestDigest ||
			status.GetArtifactRootDigest() != journal.SourceRootDigest ||
			status.GetArtifactRootScheme() != journal.SourceRootScheme ||
			status.GetSourceGeneration() != journal.SourceGeneration {
			return fmt.Sprintf(
				"operation %s now reports (digest %s, root %s, scheme %s, generation %s) but the journal already preserved (digest %s, root %s, scheme %s, generation %s) — the durable receipt and the record disagree",
				journal.SourceOperationID,
				status.GetRequestDigest(), status.GetArtifactRootDigest(), status.GetArtifactRootScheme(), status.GetSourceGeneration(),
				journal.SourceOpRequestDigest, journal.SourceRootDigest, journal.SourceRootScheme, journal.SourceGeneration,
			)
		}
		return ""
	}
	// recoverSourceOperation issues this process's ONE explicit recovery
	// attempt of the recorded source operation. The command repeats the
	// COMPLETE original payload exactly as pinned in the journal — the same
	// flags issueSourceCheckpoint sends, mapped to the node's physical
	// request by the same node CLI — plus an independent recovery timeout
	// that bounds the reconciliation attempt only and never rewrites the
	// recorded operation or its request digest. The controller never
	// recomputes a service digest from its logical checkpoint path: the node
	// CLI validates the digest of the physical request it actually sent, and
	// the service recomputes the digest from the full original request
	// before authorizing anything.
	recoverSourceOperation := func() (string, int) {
		return runCode(cfg.source, "recover-checkpoint-operation", cfg.bin+"/checkpoint-restore",
			"--action", "recover-checkpoint-operation", "--socket", "/run/sandboxd/sandboxd.sock",
			"--sandbox-id", cfg.sandbox,
			"--checkpoint-dir", journal.CheckpointDir,
			"--checkpoint-timeout-seconds", strconv.FormatUint(uint64(journal.CheckpointTimeoutSeconds), 10),
			"--compress="+strconv.FormatBool(journal.CheckpointCompress),
			"--leave-running="+strconv.FormatBool(journal.CheckpointLeaveRunning),
			"--snapshot-type", journal.CheckpointSnapshotType,
			"--operation-id", journal.SourceOperationID,
			"--expected-generation", journal.SourceGeneration,
			"--recovery-timeout-seconds", strconv.FormatUint(uint64(identifiedRecoveryTimeoutSeconds), 10))
	}
	// releaseProven reports whether a success receipt itself proves the
	// release of the retained evidence. A protocol-0 record keeps its
	// historical meaning — it predates the witness, holds no runtime
	// evidence, and has no release gate — while every witness-capable
	// success (WITNESS or WITNESS_ABORTABLE) must carry
	// evidence_released=true from THIS response: the field is per-call, a
	// query or replay answer reports false by construction, and a false
	// answer proves nothing about any past or lost acknowledgment.
	releaseProven := func(status *runtime.CheckpointOperationStatus) bool {
		switch status.GetRecoveryProtocol() {
		case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED:
			return true
		case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
			runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE:
			return status.GetEvidenceReleased()
		default:
			return false
		}
	}
	// recoveryConflict validates one explicit recovery receipt against the
	// success fact this process already observed: the recovery must repeat
	// the same operation, sandbox, generation, request digest, sealed root,
	// and scheme, and must itself prove the release. evidence_released and
	// the protocol field are transport facts of the response that carried
	// them, never content to preserve — the comparison below deliberately
	// excludes them and the release is demanded separately, from this reply.
	recoveryConflict := func(recovered, prior *runtime.CheckpointOperationStatus) string {
		if prior != nil &&
			(recovered.GetOperationID() != prior.GetOperationID() ||
				recovered.GetSandboxID() != prior.GetSandboxID() ||
				recovered.GetSourceGeneration() != prior.GetSourceGeneration() ||
				recovered.GetRequestDigest() != prior.GetRequestDigest() ||
				recovered.GetArtifactRootDigest() != prior.GetArtifactRootDigest() ||
				recovered.GetArtifactRootScheme() != prior.GetArtifactRootScheme()) {
			return fmt.Sprintf(
				"the recovery of operation %s reported (sandbox %s, generation %s, digest %s, root %s, scheme %s) but the record already answered (sandbox %s, generation %s, digest %s, root %s, scheme %s) — the recovery does not repeat the recorded completion fact",
				recovered.GetOperationID(),
				recovered.GetSandboxID(), recovered.GetSourceGeneration(), recovered.GetRequestDigest(),
				recovered.GetArtifactRootDigest(), recovered.GetArtifactRootScheme(),
				prior.GetSandboxID(), prior.GetSourceGeneration(), prior.GetRequestDigest(),
				prior.GetArtifactRootDigest(), prior.GetArtifactRootScheme(),
			)
		}
		if !witnessCapableRecoveryProtocol(recovered.GetRecoveryProtocol()) {
			return fmt.Sprintf(
				"the recovery receipt reports recovery protocol %s — an explicit recovery is defined for witness-capable records only, and a legacy or unknown protocol cannot be recovered",
				recovered.GetRecoveryProtocol(),
			)
		}
		if !recovered.GetEvidenceReleased() {
			return "the recovery receipt reports evidence_released=false — this response did not complete the runtime acknowledgment, so the release of the retained evidence is unproven"
		}
		return ""
	}
	// persistSourceReceipt is the single durable step that seals a
	// checkpoint: the exact source receipt — request digest, sealed root,
	// scheme — is preserved WHILE THE STAGE IS STILL checkpoint-issued, so a
	// crash before the stage advance leaves an observable, reloadable fact
	// rather than a lost one. Callers must already have proven the success
	// AND, for a WITNESS record, the release of the retained evidence.
	persistSourceReceipt := func(status *runtime.CheckpointOperationStatus) {
		if conflict := persistReceiptConflict(status); conflict != "" {
			fail("checkpoint", fmt.Sprintf("%s — failing closed with the journal at checkpoint-issued; reconcile operation %q on %s manually", conflict, journal.SourceOperationID, cfg.source))
		}
		persist(stageCheckpointIssued, func(j *migrationJournal) {
			j.SourceOpRequestDigest = status.GetRequestDigest()
			j.SourceRootDigest = status.GetArtifactRootDigest()
			j.SourceRootScheme = status.GetArtifactRootScheme()
		})
		persist(stageCheckpointSealed, func(*migrationJournal) {})
	}
	// recoverReleased performs this process's ONE explicit recovery/Ack
	// attempt and persists the source receipt only after the release is
	// verified. prior is the success fact the recovery must repeat exactly,
	// or nil when the record was UNKNOWN — the recovery then establishes the
	// fact itself through the full receipt validation. Every failure — the
	// command, an unparseable reply, a receipt that fails validation, does
	// not repeat the observed fact, or does not prove the release — fails
	// closed: the journal stays at checkpoint-issued, nothing is re-issued
	// under a new ID, no checkpoint fallback runs, nothing is rolled back,
	// and no target is started. There is no recursion into the reconcile
	// path and no second attempt inside one process.
	recoverReleased := func(prior *runtime.CheckpointOperationStatus) {
		reply, code := recoverSourceOperation()
		if code != 0 {
			fail("checkpoint", fmt.Sprintf(
				"the explicit recovery of source operation %q on %s failed (exit %d) — the journal stays at checkpoint-issued; the operation ID is unchanged, no receipt is preserved, no checkpoint fallback, no rollback, no target start; retry this migration to attempt the recovery again or reconcile the operation manually",
				journal.SourceOperationID, cfg.source, code))
		}
		recovered, err := parseReceipt(reply)
		if err != nil {
			fail("checkpoint", fmt.Sprintf(
				"the recovery reply of operation %q is not a readable receipt: %v — failing closed at checkpoint-issued; query the operation on %s before doing anything else",
				journal.SourceOperationID, err, cfg.source))
		}
		if conflict := receiptConflict(recovered); conflict != "" {
			fail("checkpoint", fmt.Sprintf(
				"the recovery receipt does not prove this operation succeeded for this migration: %s — the journal stays at checkpoint-issued; no receipt is preserved, no rollback, no target start; reconcile operation %q on %s manually",
				conflict, journal.SourceOperationID, cfg.source))
		}
		if conflict := recoveryConflict(recovered, prior); conflict != "" {
			fail("checkpoint", fmt.Sprintf(
				"%s — failing closed at checkpoint-issued with no receipt preserved; reconcile operation %q on %s manually",
				conflict, journal.SourceOperationID, cfg.source))
		}
		persistSourceReceipt(recovered)
	}
	// acceptSourceReceipt is the single way a checkpoint becomes sealed: the
	// reply parses, carries this migration's identity, reports SUCCEEDED
	// with the pinned payload's digest and a well-shaped sealed root, and —
	// for a WITNESS record — proves the release of the retained evidence
	// from THIS response. An initial success whose own call completed the
	// acknowledgment is accepted directly with no extra RPC; one that does
	// not prove the release (a first reply, a replay) triggers exactly one
	// explicit recovery that must repeat the same completion fact. A
	// protocol-0 success keeps its historical acceptance unchanged.
	acceptSourceReceipt := func(output string) {
		status, err := parseReceipt(output)
		if err != nil {
			fail("checkpoint", fmt.Sprintf("%v — the journal stays at checkpoint-issued; query operation %q on %s before doing anything else", err, journal.SourceOperationID, cfg.source))
		}
		if conflict := receiptConflict(status); conflict != "" {
			fail("checkpoint", fmt.Sprintf(
				"the checkpoint receipt does not prove this operation succeeded for this migration: %s — the journal stays at checkpoint-issued, no receipt is preserved, and no rollback or target start happens; reconcile operation %q on %s manually",
				conflict, journal.SourceOperationID, cfg.source))
		}
		if releaseProven(status) {
			persistSourceReceipt(status)
			return
		}
		recoverReleased(status)
	}
	// reconcileSourceCheckpoint resolves a checkpoint whose reply was lost
	// or whose issuing process died. The durable operation record is queried
	// FIRST, and the outcome is bounded — one query plus at most one
	// same-identity re-issue, replay, or explicit recovery per process, no
	// loops, no recursion:
	//   - the structured not-found exit code is the only proof the operation
	//     was never admitted, and it authorizes exactly one resend of the
	//     SAME operation with the SAME pinned payload — never a new ID, a
	//     re-inspected generation, or a legacy RPC. A not-found record that
	//     contradicts an already-preserved receipt is an inconsistency and
	//     fails closed instead of re-executing;
	//   - a SUCCEEDED WITNESS record owes the evidence release: the query
	//     answer reports evidence_released=false by construction, so one
	//     explicit recovery carrying the COMPLETE original payload both
	//     proves the payload binding (the service recomputes the request
	//     digest from that payload and refuses a changed one) and completes
	//     the acknowledgment; its receipt must repeat the queried fact
	//     exactly and prove the release before anything is accepted;
	//   - a SUCCEEDED protocol-0 record keeps the historical verification:
	//     the same-payload checkpoint is replayed once (the daemon replays
	//     the recorded outcome and refuses a changed request) and the
	//     replayed receipt must repeat the queried one exactly;
	//   - an UNKNOWN WITNESS record may be reconciled by exactly one
	//     explicit recovery of the same operation after the identity checks
	//     — no new operation ID, no checkpoint fallback;
	//   - RUNNING reports the still-pending execution and fails closed (an
	//     in-flight outcome authorizes nothing and cannot be waited out
	//     here); FAILED, an UNKNOWN protocol-0 record, an unparseable or
	//     mismatched record, and every ambiguous query error stop the run:
	//     the journal stays at checkpoint-issued, nothing is rolled back, no
	//     target is started, and the operation ID stays spent.
	reconcileSourceCheckpoint := func() {
		output, code := runCode(cfg.source, "query-checkpoint-operation", cfg.bin+"/checkpoint-restore",
			"--action", "get-checkpoint-operation", "--socket", "/run/sandboxd/sandboxd.sock",
			"--operation-id", journal.SourceOperationID)
		switch {
		case code == exitCodeOperationNotFound:
			if strings.TrimSpace(journal.SourceRootDigest) != "" {
				fail("checkpoint", fmt.Sprintf(
					"operation %s is absent on %s but this journal already preserved its success receipt — the record and the receipt contradict; failing closed at checkpoint-issued with no re-execution, no rollback, and no target",
					journal.SourceOperationID, cfg.source))
			}
			reply, resend := issueSourceCheckpoint()
			if resend != 0 {
				fail("checkpoint", fmt.Sprintf(
					"the checkpoint retry failed after the operation record was absent — its outcome is unknown; the journal stays at checkpoint-issued, operation %q may still have been admitted on %s, and no rollback, no new operation ID, and no target start happen; retry this migration to reconcile",
					journal.SourceOperationID, cfg.source))
			}
			acceptSourceReceipt(reply)
		case code != 0:
			fail("checkpoint", fmt.Sprintf(
				"the checkpoint operation query failed ambiguously (exit %d) — failing closed: the journal stays at checkpoint-issued; no rollback, no legacy checkpoint, no new operation ID, no target start; resolve operation %q on %s manually or retry this migration",
				code, journal.SourceOperationID, cfg.source))
		default:
			queried, err := parseReceipt(output)
			if err != nil {
				fail("checkpoint", fmt.Sprintf(
					"the checkpoint operation query returned an unreadable record: %v — failing closed at checkpoint-issued; resolve operation %q on %s manually",
					err, journal.SourceOperationID, cfg.source))
			}
			if queried.GetOperationID() != journal.SourceOperationID || queried.GetSandboxID() != cfg.sandbox ||
				queried.GetSourceGeneration() != journal.SourceGeneration {
				fail("checkpoint", fmt.Sprintf(
					"operation %q on %s does not answer for this migration (sandbox %q, generation %q) — failing closed at checkpoint-issued with no rollback and no target; reconcile the record, then continue with a new -migration-id",
					queried.GetOperationID(), cfg.source, queried.GetSandboxID(), queried.GetSourceGeneration()))
			}
			switch queried.GetState() {
			case runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN:
				// Only a witness-capable record (WITNESS or WITNESS_ABORTABLE)
				// may be recovered: its admission verified the runtime holds
				// the operation evidence, so one explicit recovery can
				// complete the stop-source flow and release it. A protocol-0
				// UNKNOWN stays unprovable — the same refusal as before these
				// protocols existed. An UNKNOWN record is never aborted
				// automatically; the explicit abort is node-CLI only.
				if witnessCapableRecoveryProtocol(queried.GetRecoveryProtocol()) {
					recoverReleased(nil)
					return
				}
				fail("checkpoint", fmt.Sprintf(
					"source checkpoint operation %q on %s is %s under the legacy recovery protocol — its outcome cannot be proven recoverable and the operation ID is spent: the journal stays at checkpoint-issued; no re-execution, no rollback, no legacy checkpoint, no new operation ID, no target start; reconcile the record and the source, then continue with a new -migration-id",
					journal.SourceOperationID, cfg.source, queried.GetState()))
			case runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING:
				fail("checkpoint", fmt.Sprintf(
					"source checkpoint operation %q on %s is still RUNNING — its outcome is pending and authorizes nothing yet: the journal stays at checkpoint-issued and the operation ID is spent; no re-execution, no recovery beside a live execution, no rollback, no legacy checkpoint, no new operation ID, no target start; retry this migration once the execution finishes, or reconcile the record and then continue with a new -migration-id",
					journal.SourceOperationID, cfg.source))
			case runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED:
				// A FAILED record stays a migration failure even when it
				// carries a durably confirmed abort: the confirmed abort
				// releases runtime evidence, never this migration — nothing
				// is published, restored, or retired on its account.
				fail("checkpoint", fmt.Sprintf(
					"source checkpoint operation %q on %s is %s (a confirmed abort included) — its outcome does not authorize this migration: the journal stays at checkpoint-issued and the operation ID is spent; no re-execution, no recovery, no rollback, no legacy checkpoint, no new operation ID, no target start; reconcile the record and the source, then continue with a new -migration-id",
					journal.SourceOperationID, cfg.source, queried.GetState()))
			default:
				// SUCCEEDED: the release gate decides how the historical
				// fact may be verified against this migration's payload.
				if conflict := persistReceiptConflict(queried); conflict != "" {
					fail("checkpoint", fmt.Sprintf("%s — failing closed at checkpoint-issued; reconcile operation %q on %s manually", conflict, journal.SourceOperationID, cfg.source))
				}
				if witnessCapableRecoveryProtocol(queried.GetRecoveryProtocol()) {
					// The query proves the success but never the release,
					// and a same-payload replay would prove the binding yet
					// still answer evidence_released=false. One explicit
					// recovery carries the COMPLETE original payload — the
					// service recomputes the request digest from it and
					// refuses a changed binding, which is the same-payload
					// verification the replay provides — and completes the
					// acknowledgment the release gate requires.
					recoverReleased(queried)
					return
				}
				// Protocol-0 history keeps its existing verification: replay
				// the exact pinned request once so the daemon (and the
				// receipt validation above) can refuse a changed intent, and
				// require the replay to repeat the queried fact.
				reply, replay := issueSourceCheckpoint()
				if replay != 0 {
					fail("checkpoint", fmt.Sprintf(
						"historical operation success could not be verified against this migration's pinned payload — the replay failed, so the journal stays at checkpoint-issued; no receipt is preserved, no rollback, no new operation ID, no target start; retry this migration to reconcile",
					))
				}
				replayed, err := parseReceipt(reply)
				if err != nil {
					fail("checkpoint", fmt.Sprintf("%v — the journal stays at checkpoint-issued; query operation %q on %s before doing anything else", err, journal.SourceOperationID, cfg.source))
				}
				if conflict := receiptConflict(replayed); conflict != "" {
					fail("checkpoint", fmt.Sprintf(
						"the replayed checkpoint receipt does not prove this operation succeeded for this migration: %s — the journal stays at checkpoint-issued; no rollback and no target start; reconcile operation %q on %s manually",
						conflict, journal.SourceOperationID, cfg.source))
				}
				if replayed.GetArtifactRootDigest() != queried.GetArtifactRootDigest() ||
					replayed.GetArtifactRootScheme() != queried.GetArtifactRootScheme() ||
					replayed.GetSourceGeneration() != queried.GetSourceGeneration() ||
					replayed.GetRequestDigest() != queried.GetRequestDigest() {
					fail("checkpoint", fmt.Sprintf(
						"the replay of operation %s did not repeat the queried receipt (digest %s, root %s, scheme %s, generation %s) — failing closed at checkpoint-issued; reconcile the record on %s manually",
						journal.SourceOperationID,
						replayed.GetRequestDigest(), replayed.GetArtifactRootDigest(), replayed.GetArtifactRootScheme(), replayed.GetSourceGeneration(),
						cfg.source))
				}
				acceptSourceReceipt(reply)
			}
		}
	}

	// A finished migration replays as a pure report: no node command at all,
	// because everything the stages name is already durably done. This also
	// holds for a terminal version 1 `done` record — the one v1 stage this
	// build still loads.
	if journal.Stage == stageDone {
		report.OK = true
		finish(report, cfg.jsonOut, true)
	}
	// A checkpoint that was issued but not yet proven sealed is reconciled
	// through the durable source operation record — never by guessing.
	if journal.Stage == stageCheckpointIssued {
		reconcileSourceCheckpoint()
	}

	// Pin the source incarnation once, before anything is issued. A resume
	// past this stage does NOT re-probe the source: it was finalized at
	// checkpoint time, and the identified checkpoint already refuses a
	// replaced incarnation by generation.
	if journal.Stage == stagePrepared {
		if _, ok := run(cfg.source, "list", cfg.bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); !ok {
			fail("list", "source listing failed")
		}
		if !listHasRunningSandbox(lastDetail(), cfg.sandbox) {
			fail("list", fmt.Sprintf("sandbox %s not RUNNING on source %s", cfg.sandbox, cfg.source))
		}
		if _, ok := run(cfg.source, "inspect", cfg.bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "inspect", cfg.sandbox); !ok {
			fail("inspect", "source inspect failed — cannot pin the source generation; refusing to checkpoint")
		}
		generation, genErr := sourceGeneration(lastDetail(), cfg.sandbox)
		if genErr != nil {
			fail("inspect", fmt.Sprintf("cannot pin the source generation: %v", genErr))
		}
		if journal.ExpectedSourceGen != "" && journal.ExpectedSourceGen != generation {
			fail("inspect", fmt.Sprintf(
				"source %s holds generation %q but -source-generation requires %q — the sandbox was replaced on the source; refusing to checkpoint the replacement",
				cfg.source, generation, journal.ExpectedSourceGen))
		}
		persist(stageSourcePinned, func(j *migrationJournal) { j.SourceGeneration = generation })
		report.SourceGeneration = journal.SourceGeneration
	}

	// Checkpoint the pinned incarnation as an identified stop-and-copy
	// operation. checkpoint-issued is durable BEFORE the command runs, so
	// its unknown-outcome window is always observable by the next process;
	// on any failure the reconciliation runs immediately in this same
	// process, and its own failure leaves the journal at checkpoint-issued
	// for the next process — the same bounded rules, never a re-execution
	// without a proven-absent record.
	if journal.Stage == stageSourcePinned {
		persist(stageCheckpointIssued, func(*migrationJournal) {})
		if reply, code := issueSourceCheckpoint(); code == 0 {
			acceptSourceReceipt(reply)
		} else {
			reconcileSourceCheckpoint()
		}
	}

	// Pin the artifact's content root AND the exact restore request bytes
	// from the source, in one read-only roundtrip: the request file is
	// node-local, so the source node's checkpoint-root action hashes it
	// (--request-file) beside the artifact identity. The freshly derived
	// root and scheme must repeat the source receipt's sealed root exactly:
	// the receipt is a completion-time fact and does not attest the files
	// are still unchanged, so a directory that drifted after completion is
	// refused here — never re-pinned as if it were the sealed checkpoint.
	// The restore request digest is pinned beside them and NEVER refreshed
	// afterwards; it stays strictly separate from the checkpoint request
	// digest the source receipt carried.
	if journal.Stage == stageCheckpointSealed {
		root, scheme, requestDigest, bindErr := bindSourceIdentity(cfg, run, journal)
		if bindErr != nil {
			fail("bind-source-root", bindErr.Error())
		}
		if root != journal.SourceRootDigest || scheme != journal.SourceRootScheme {
			fail("bind-source-root", fmt.Sprintf(
				"the sealed directory at %s now derives root %s (%s) but the source receipt bound root %s (%s) at completion — the artifact changed after the checkpoint completed; refusing to re-pin the changed artifact as this checkpoint (no rollback, no target start; reconcile the artifact on %s, then continue with a new -migration-id)",
				journal.CheckpointDir, root, scheme, journal.SourceRootDigest, journal.SourceRootScheme, cfg.source))
		}
		persist(stageRootBound, func(j *migrationJournal) {
			j.RootDigest = root
			j.RootScheme = scheme
			j.RequestDigest = requestDigest
		})
	}

	// Publish on the source. Publication is idempotent, so a failure keeps
	// the stage and the retry resumes it; the source is NOT rolled back —
	// this mode has no automatic compensation.
	if journal.Stage == stageRootBound {
		if _, ok := run(cfg.source, "publish", cfg.bin+"/cn-publish",
			"-checkpoint-dir", journal.CheckpointDir, "-store", cfg.storeSpec); !ok {
			fail("publish", fmt.Sprintf(
				"cn-publish failed on source — publication is idempotent, retry this migration; the source stays finalized with the sealed checkpoint preserved at %s (no automatic rollback in this mode)",
				journal.CheckpointDir))
		}
		persist(stagePublished, func(*migrationJournal) {})
	}

	// Place once: after the target is saved in the journal, a retry may not
	// change the node — the previous attempt may already have materialized
	// or restored there.
	if journal.Stage == stagePublished {
		nodeRecords, _ := checkpointlocator.FetchAll(context.Background(), strings.Split(cfg.nodes, ","))
		var compat *checkpointlocator.CheckpointCompat
		var compatErr error
		for _, addr := range strings.Split(cfg.nodes, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			var candidate *checkpointlocator.CheckpointCompat
			candidate, compatErr = checkpointlocator.FetchCheckpointCompat(context.Background(), addr, dirBase(journal.CheckpointDir))
			if compatErr == nil {
				compat = candidate
				break
			}
		}
		if compatErr != nil {
			fail("place", compatErr.Error())
		}
		exclude := []string{cfg.source}
		if journal.PreferredTo != "" {
			exclude = append(exclude, nodeIDsExcept(nodeRecords, cfg.source, journal.PreferredTo)...)
		}
		placement, placeErr := checkpointlocator.Decide(checkpointlocator.Input{
			CheckpointID:     dirBase(journal.CheckpointDir),
			Compat:           compat,
			OriginNodeID:     cfg.source,
			ExcludeNodes:     exclude,
			RequirePublished: true,
			PublishState:     checkpointpublish.StatePublished,
			Nodes:            nodeRecords,
		})
		if placeErr != nil {
			fail("place", placeErr.Error())
		}
		persist(stagePlaced, func(j *migrationJournal) { j.Target = placement.NodeID })
		report.Target = journal.Target
	}

	// Materialize on the target. A retry first derives the root of whatever
	// already sits at the destination: an artifact with the pinned root is
	// the previous attempt's completed fetch (skipped), a different root is
	// somebody else's checkpoint (refused — never overwritten), and only an
	// unverifiable/absent directory is fetched, then verified against the
	// pinned root before the restore may name it.
	if journal.Stage == stagePlaced {
		existing, code := runCode(journal.Target, "probe-target-root", cfg.bin+"/checkpoint-restore",
			"--action", "checkpoint-root", "--checkpoint-dir", journal.CheckpointDir)
		switch {
		case code == 0:
			root, _, parseErr := parseCheckpointRootOutput(existing)
			if parseErr != nil {
				fail("materialize", fmt.Sprintf("the target's existing artifact identity is unreadable: %v", parseErr))
			}
			if root != journal.RootDigest {
				fail("materialize", fmt.Sprintf(
					"target %s already holds a different checkpoint at %s (root %s, this migration pinned %s) — refusing to overwrite a different non-empty artifact; resolve the destination manually",
					journal.Target, journal.CheckpointDir, root, journal.RootDigest))
			}
		default:
			if _, ok := run(journal.Target, "materialize", cfg.bin+"/cn-fetch",
				"-into", journal.CheckpointDir, "-id", dirBase(journal.CheckpointDir), "-store", cfg.storeSpec); !ok {
				fail("materialize", "cn-fetch failed on target — materialization is idempotent, retry this migration")
			}
			landed, code := runCode(journal.Target, "verify-target-root", cfg.bin+"/checkpoint-restore",
				"--action", "checkpoint-root", "--checkpoint-dir", journal.CheckpointDir)
			root, _, parseErr := parseCheckpointRootOutput(landed)
			if code != 0 || parseErr != nil || root != journal.RootDigest {
				fail("materialize", fmt.Sprintf(
					"the materialized artifact on target %s does not match the pinned source root — refusing to restore from it", journal.Target))
			}
		}
		persist(stageMaterialized, func(*migrationJournal) {})
	}

	// Restore on the target as a durable start operation bound to the pinned
	// root. restore-issued is durable BEFORE the command runs; a lost reply
	// is then resolved only through the operation record (reconcile below).
	issueRestore := func() (string, bool) {
		return run(journal.Target, "restore", cfg.bin+"/checkpoint-restore",
			"--action", "restore", "--socket", "/run/sandboxd/sandboxd.sock",
			"--target-id", cfg.sandbox, "--request-file", cfg.ckReq,
			"--checkpoint-dir", journal.CheckpointDir,
			"--operation-id", journal.OperationID,
			"--expected-root-digest", journal.RootDigest,
			"--expected-request-digest", journal.RequestDigest)
	}
	// recordReceipt persists the restore's success from the RECEIPT — the
	// target's birth generation is whatever the operation created, never
	// what a later inspect happens to show.
	recordReceipt := func(output string) {
		status, parseErr := parseStartOperationStatus(output)
		if parseErr != nil {
			fail("restore", fmt.Sprintf("the restore reply is not a readable operation receipt: %v — the journal stays at restore-issued; query the operation on the target before doing anything else", parseErr))
		}
		if status.GetOperationID() != journal.OperationID || status.GetSandboxID() != cfg.sandbox ||
			status.GetState() != runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED ||
			strings.TrimSpace(status.GetResourceGeneration()) == "" {
			fail("restore", fmt.Sprintf(
				"the restore receipt does not prove this operation succeeded (operation %q, sandbox %q, state %s, generation %q) — the journal stays at restore-issued; reconcile operation %q on target %s before doing anything else",
				status.GetOperationID(), status.GetSandboxID(), status.GetState(), status.GetResourceGeneration(), journal.OperationID, journal.Target))
		}
		persist(stageRestoreSucceeded, func(j *migrationJournal) {
			j.TargetGeneration = status.GetResourceGeneration()
		})
	}
	// reconcileRestore resolves a restore whose reply was lost or whose
	// issuing process died: the durable operation record is queried FIRST.
	// Only the structured not-found exit code proves the operation was never
	// admitted and permits re-issuing the very same identity; RUNNING,
	// UNKNOWN, FAILED, an identity mismatch, or any ambiguous query failure
	// fails closed — no source rollback, no new operation ID, no target
	// delete. An in-flight restore cannot be proven cancelled by anything
	// this CLI can observe.
	reconcileRestore := func() {
		output, code := runCode(journal.Target, "query-operation", cfg.bin+"/checkpoint-restore",
			"--action", "get-start-operation", "--socket", "/run/sandboxd/sandboxd.sock",
			"--operation-id", journal.OperationID)
		switch {
		case code == exitCodeOperationNotFound:
			// The record is absent: the operation was never admitted, so the
			// SAME identity is re-issued once — the replay is idempotent on
			// the server and the request/root/target are the journaled ones.
			reply, ok := issueRestore()
			if !ok {
				fail("restore", fmt.Sprintf(
					"the restore retry failed after the operation record was absent — its outcome is unknown; the journal stays at restore-issued and operation %q may still have been admitted on target %s; no rollback, no new operation ID, no target delete",
					journal.OperationID, journal.Target))
			}
			recordReceipt(reply)
		case code != 0:
			fail("restore", fmt.Sprintf(
				"the operation query failed ambiguously (exit %d) — failing closed: the journal stays at restore-issued; no rollback, no new operation ID, no target delete; resolve operation %q on target %s manually",
				code, journal.OperationID, journal.Target))
		default:
			status, parseErr := parseStartOperationStatus(output)
			if parseErr != nil {
				fail("restore", fmt.Sprintf(
					"the operation query returned an unreadable record: %v — failing closed; resolve operation %q on target %s manually",
					parseErr, journal.OperationID, journal.Target))
			}
			if status.GetOperationID() != journal.OperationID || status.GetSandboxID() != cfg.sandbox ||
				status.GetState() != runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED ||
				strings.TrimSpace(status.GetResourceGeneration()) == "" {
				fail("restore", fmt.Sprintf(
					"operation %q on target %s is %s (sandbox %q, generation %q) — not a proven success for this migration; the journal stays at restore-issued and the operation ID is spent; no rollback, no new operation ID, no target delete: reconcile the record, then continue with a new -migration-id",
					journal.OperationID, journal.Target, status.GetState(), status.GetSandboxID(), status.GetResourceGeneration()))
			}
			// Query status alone has no request/root binding. Replaying the
			// same operation makes the daemon validate the journaled request
			// and root before its historical success can authorize retirement.
			reply, ok := issueRestore()
			if !ok {
				fail("restore", "historical operation success could not be verified against this migration request; preserving restore-issued without source retirement")
			}
			confirmed, err := parseStartOperationStatus(reply)
			if err != nil || confirmed.GetResourceGeneration() != status.GetResourceGeneration() {
				fail("restore", "operation replay did not confirm the queried birth generation; preserving restore-issued")
			}
			recordReceipt(reply)
		}
	}

	switch journal.Stage {
	case stageMaterialized:
		persist(stageRestoreIssued, func(*migrationJournal) {})
		if reply, ok := issueRestore(); ok {
			recordReceipt(reply)
		} else {
			reconcileRestore()
		}
	case stageRestoreIssued:
		reconcileRestore()
	}

	// Retire the source copy — only after the target is proven to hold the
	// sandbox this operation created. The receipt is a historical fact, not
	// a liveness claim, so the target must currently list the sandbox
	// RUNNING and its live incarnation must still carry the receipt's birth
	// generation; a target that was replaced since must not be paid for by
	// retiring the source.
	if journal.Stage == stageRestoreSucceeded {
		if _, ok := run(journal.Target, "verify", cfg.bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "list"); !ok ||
			!listHasRunningSandbox(lastDetail(), cfg.sandbox) {
			fail("verify", fmt.Sprintf(
				"target %s does not list the sandbox RUNNING — the SUCCEEDED receipt is historical, not a liveness claim; retry this migration to re-verify (no rollback, no target delete)",
				journal.Target))
		}
		if _, ok := run(journal.Target, "inspect", cfg.bin+"/sbox",
			"--address", "/run/sandboxd/sandboxd.sock", "inspect", cfg.sandbox); !ok {
			fail("verify", fmt.Sprintf(
				"target inspect failed — cannot confirm the receipt generation %s on target %s; refusing to retire the source",
				journal.TargetGeneration, journal.Target))
		}
		generation, genErr := sourceGeneration(lastDetail(), cfg.sandbox)
		if genErr != nil {
			fail("verify", fmt.Sprintf("cannot read the target incarnation: %v — refusing to retire the source", genErr))
		}
		if generation != journal.TargetGeneration {
			fail("retire-source", fmt.Sprintf(
				"target %s holds generation %q but the restore receipt created %q — the target sandbox was replaced; refusing to retire the source generation %q (and refusing to delete the replacement target: that decision is not this tool's)",
				journal.Target, generation, journal.TargetGeneration, journal.SourceGeneration))
		}
		// Same-conditions retirement every time: the retry re-issues exactly
		// this generation-scoped delete; a completed receipt replays as
		// success and there is deliberately no fallback.
		if _, ok := run(cfg.source, "delete-source", cfg.bin+"/checkpoint-restore",
			"--action", "delete", "--socket", "/run/sandboxd/sandboxd.sock",
			"--sandbox-id", cfg.sandbox,
			"--expected-generation", journal.SourceGeneration); !ok {
			fail("delete-source", fmt.Sprintf(
				"source-cleanup-pending: conditional retirement of generation %s failed — retry this migration (the same generation-scoped delete is reissued; a completed receipt replays); an unconditional delete must not be used",
				journal.SourceGeneration))
		}
		persist(stageDone, func(*migrationJournal) {})
	}

	report.OK = true
	finish(report, cfg.jsonOut, true)
}

// bindSourceIdentity pins both identities a restore needs before any target
// is contacted: the artifact content root of the sealed checkpoint and the
// sha-256 of the exact restore request bytes, both derived read-only on the
// source node in one checkpoint-root roundtrip.
func bindSourceIdentity(
	cfg resumableConfig,
	run func(node, step string, args ...string) (string, bool),
	journal *migrationJournal,
) (root, scheme, requestDigest string, err error) {
	output, ok := run(cfg.source, "bind-source-root", cfg.bin+"/checkpoint-restore",
		"--action", "checkpoint-root", "--checkpoint-dir", journal.CheckpointDir,
		"--request-file", cfg.ckReq)
	if !ok {
		return "", "", "", fmt.Errorf(
			"cannot derive the artifact root and request digest for %s (request %s) on %s: %s",
			journal.CheckpointDir, cfg.ckReq, cfg.source, output)
	}
	root, scheme, requestDigest, err = parseSourceIdentityOutput(output)
	if err != nil {
		return "", "", "", fmt.Errorf("the checkpoint-root reply from %s is not a strict identity: %v", cfg.source, err)
	}
	return root, scheme, requestDigest, nil
}

// parseSourceIdentityOutput strictly decodes the source bind reply: exactly
// the keys root, scheme, and request_sha256 — the request pin is mandatory
// here, because a migration that cannot name its request bytes must not
// reach a restore. Mixed or partial output fails instead of being guessed at.
func parseSourceIdentityOutput(output string) (root, scheme, requestDigest string, err error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", "", "", errors.New("empty output")
	}
	var value struct {
		Root          string `json:"root"`
		Scheme        string `json:"scheme"`
		RequestSHA256 string `json:"request_sha256"`
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return "", "", "", fmt.Errorf("parse {root,scheme,request_sha256} JSON: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return "", "", "", errors.New("output carries trailing content after the JSON object")
	}
	if len(value.Root) != 64 || !isHex(value.Root) {
		return "", "", "", fmt.Errorf("root %q is not a 64-hex digest", value.Root)
	}
	if strings.TrimSpace(value.Scheme) == "" {
		return "", "", "", errors.New("scheme is blank")
	}
	if len(value.RequestSHA256) != 64 || !isHex(value.RequestSHA256) {
		return "", "", "", fmt.Errorf("request_sha256 %q is not a 64-hex digest", value.RequestSHA256)
	}
	return value.Root, value.Scheme, value.RequestSHA256, nil
}

// parseCheckpointRootOutput strictly decodes the one JSON object the
// checkpoint-root action prints for a directory-only probe: exactly the keys
// root and scheme, a 64-hex root, a non-empty scheme. Mixed or partial
// output fails instead of being guessed at.
func parseCheckpointRootOutput(output string) (root, scheme string, err error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", "", errors.New("empty output")
	}
	var value struct {
		Root   string `json:"root"`
		Scheme string `json:"scheme"`
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return "", "", fmt.Errorf("parse {root,scheme} JSON: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return "", "", errors.New("output carries trailing content after the JSON object")
	}
	if len(value.Root) != 64 || !isHex(value.Root) {
		return "", "", fmt.Errorf("root %q is not a 64-hex digest", value.Root)
	}
	if strings.TrimSpace(value.Scheme) == "" {
		return "", "", errors.New("scheme is blank")
	}
	return value.Root, value.Scheme, nil
}

// parseStartOperationStatus strictly decodes the protojson
// StartOperationStatus the operation-mode CLI prints: one document, no
// unknown fields, no trailing content.
func parseStartOperationStatus(output string) (*runtime.StartOperationStatus, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, errors.New("empty output")
	}
	status := new(runtime.StartOperationStatus)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(trimmed), status); err != nil {
		return nil, fmt.Errorf("parse StartOperationStatus protojson: %w", err)
	}
	if status.GetOperationID() == "" || status.GetSandboxID() == "" {
		return nil, fmt.Errorf("receipt %v carries no operation or sandbox identity", status)
	}
	return status, nil
}

// witnessCapableRecoveryProtocol reports whether a record admitted under
// this protocol holds runtime evidence an explicit recovery can act on.
// WITNESS and WITNESS_ABORTABLE records are both recoverable and both owe
// the release proof; a legacy protocol-0 record holds no witness and is
// refused by the service before any reply.
func witnessCapableRecoveryProtocol(
	protocol runtime.CheckpointOperationRecoveryProtocol,
) bool {
	switch protocol {
	case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE:
		return true
	default:
		return false
	}
}

// parseCheckpointOperationStatus strictly decodes the protojson
// CheckpointOperationStatus the operation-mode CLI prints for the identified
// source checkpoint, its query, and its explicit recovery: one document, no
// unknown fields, no trailing content. UNSPECIFIED states are rejected — a
// healthy daemon never reports one, so it is a protocol error rather than a
// state to guess about. The recovery protocol is accepted in all three of
// its defined values (legacy, witness, and witness-abortable records are
// equally legal history) while an out-of-range value is rejected: an
// unsupported protocol must never be reinterpreted as the legacy protocol,
// because the field decides whether the record holds recoverable runtime
// evidence. evidence_released is decoded but never trusted as history — it
// is a fact about the response that carried it, nothing more.
// abort_confirmed is validated for shape only — a durable abort fact may be
// restated solely by a FAILED record under WITNESS_ABORTABLE without a
// sealed root — and never infers anything: a historical confirmation
// releases no gate and converts no failure into a migration success.
func parseCheckpointOperationStatus(output string) (*runtime.CheckpointOperationStatus, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, errors.New("empty output")
	}
	status := new(runtime.CheckpointOperationStatus)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(trimmed), status); err != nil {
		return nil, fmt.Errorf("parse CheckpointOperationStatus protojson: %w", err)
	}
	if status.GetOperationID() == "" || status.GetSandboxID() == "" {
		return nil, fmt.Errorf("receipt %v carries no operation or sandbox identity", status)
	}
	switch status.GetState() {
	case runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED,
		runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN:
	default:
		return nil, fmt.Errorf("receipt reports unrecognized operation state %s", status.GetState())
	}
	switch status.GetRecoveryProtocol() {
	case runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_UNSPECIFIED,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS,
		runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE:
	default:
		return nil, fmt.Errorf(
			"receipt reports unrecognized recovery protocol %s; refusing to treat an unknown protocol as legacy",
			status.GetRecoveryProtocol(),
		)
	}
	if status.GetAbortConfirmed() &&
		(status.GetState() != runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED ||
			status.GetRecoveryProtocol() !=
				runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE ||
			status.GetArtifactRootDigest() != "" ||
			status.GetArtifactRootScheme() != "") {
		return nil, fmt.Errorf(
			"receipt reports abort_confirmed=true outside a FAILED WITNESS_ABORTABLE record without a sealed root; malformed reply",
		)
	}
	return status, nil
}
