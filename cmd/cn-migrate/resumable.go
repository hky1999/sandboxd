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
//   - the checkpoint directory and the target operation ID are pure
//     functions of the migration ID, so a retry never forks a second
//     checkpoint or a second target start;
//   - the checkpoint content root is pinned from the source through the
//     read-only checkpoint-root action, and the restore names it as
//     --expected-root-digest, so the operation binds to the artifact it
//     restores and a replaced directory cannot ride the operation ID;
//   - a restore whose reply was lost is resolved by querying the durable
//     operation record FIRST; only a proven-absent record (the structured
//     not-found exit code of the query action, never stderr text) permits
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
// node-local CLI progress, not a cross-node writer lease, and an outstanding
// checkpoint with an unknown outcome stays pending — this mode neither
// re-issues it nor decides it, because nothing observable here can prove
// whether the source executed it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/checkpointlocator"
	"github.com/inclusionAI/sandboxd/pkg/checkpointpublish"
	"google.golang.org/protobuf/encoding/protojson"
)

// exitCodeOperationNotFound mirrors the checkpoint-restore CLI's structured
// not-found exit code for --action get-start-operation. It is the ONLY
// absent-record signal this CLI accepts — an executor that swallows exit
// codes turns every query into an ambiguous failure, which fails closed.
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

	// A finished migration replays as a pure report: no node command at all,
	// because everything the stages name is already durably done.
	if journal.Stage == stageDone {
		report.OK = true
		finish(report, cfg.jsonOut, true)
	}
	// An outstanding checkpoint with an unknown outcome stays pending: a
	// failed command does not prove the source never executed it, and
	// nothing this CLI can observe decides it. No re-issue (a second
	// checkpoint could seal a replacement incarnation or clobber the sealed
	// one), no rollback, no target start — the operator reconciles the
	// checkpoint, then resumes with a fresh migration ID.
	if journal.Stage == stageCheckpointIssued {
		fail("checkpoint", fmt.Sprintf(
			"the previous checkpoint command's outcome is unknown (journal at checkpoint-issued for %s on %s) — this mode re-issues nothing, rolls back nothing, and starts no target; reconcile the checkpoint manually and continue with a new -migration-id once decided",
			journal.CheckpointDir, journal.Source,
		))
	}

	// Pin the source incarnation once, before anything is issued. A resume
	// past this stage does NOT re-probe the source: it was finalized at
	// checkpoint time, and the conditional checkpoint already refuses a
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

	// Checkpoint, conditionally on the pinned generation. The issued stage
	// is durable BEFORE the command runs; on any failure the record stays
	// there and every later process refuses to continue (see above).
	if journal.Stage == stageSourcePinned {
		persist(stageCheckpointIssued, func(*migrationJournal) {})
		if _, ok := run(cfg.source, "checkpoint", cfg.bin+"/checkpoint-restore",
			"--action", "checkpoint", "--socket", "/run/sandboxd/sandboxd.sock",
			"--request-file", cfg.ckReq, "--sandbox-id", cfg.sandbox,
			"--checkpoint-dir", journal.CheckpointDir, "--compress=false",
			"--leave-running=false",
			"--expected-generation", journal.SourceGeneration); !ok {
			fail("checkpoint", fmt.Sprintf(
				"checkpoint command failed — its outcome is unknown (a failed command does not prove it was not executed); the journal stays at checkpoint-issued, the source is left exactly as it is, and no rollback or target start happens in this mode; reconcile the checkpoint at %s on %s, then continue with a new -migration-id",
				journal.CheckpointDir, cfg.source))
		}
		persist(stageCheckpointSealed, func(*migrationJournal) {})
	}

	// Pin the artifact's content root AND the exact restore request bytes
	// from the source, in one read-only roundtrip: the request file is
	// node-local, so the source node's checkpoint-root action hashes it
	// (--request-file) beside the artifact identity. Both digests are pinned
	// at root-bound and NEVER refreshed afterwards — a retry that finds
	// different bytes at the same request path fails at the restore instead
	// of quietly re-pinning content under the same operation identity. The
	// same root later gates the target's materialization and names the
	// restore's expected root, so the source root and the materialized root
	// must agree or nothing runs.
	if journal.Stage == stageCheckpointSealed {
		root, scheme, requestDigest, bindErr := bindSourceIdentity(cfg, run, journal)
		if bindErr != nil {
			fail("bind-source-root", bindErr.Error())
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
