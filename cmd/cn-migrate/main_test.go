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

// Orchestration regressions for the F2 ownership phases, driven the same
// way the review reproduced the defects: a real cn-migrate binary built
// from this package, a fake executor that records every node command into a
// state directory while simulating node outcomes, and in-process HTTP
// stand-ins for the node catalog and (when a pending-restore URL is staged)
// a node service that accepts a restore and suspends it independently of
// the CLI. Scenarios:
//
//   - target verified RUNNING, then every source cleanup attempt fails —
//     the migration must fail loudly WITHOUT issuing rollback-restore to
//     the source, because resurrecting the source next to a running target
//     recreates dual writers;
//   - publish fails while the target is still untouched — the source MUST
//     be rolled back from its local checkpoint (the safe compensation path
//     stays intact);
//   - the target restore is accepted and suspended by the node service,
//     the CLI's 1s -wait kills the client executor so the step fails with
//     the request outcome unknown, and only after the CLI has exited does
//     the test release the request so the restore commits late on the
//     target — the CLI must issue NO source rollback and NO target delete
//     around the unknown outcome, leaving the late-committed target as the
//     only writer (the source was finalized at checkpoint time);
//
//   - the source incarnation is pinned by a structured inspect: a missing
//     generation label, or an optional -source-generation that does not
//     match the captured label, stops the run before any checkpoint side
//     effect;
//
//   - the checkpoint and the source retirement are conditional on the
//     pinned generation — the fake node decides their side effects from the
//     --expected-generation it actually receives, so an incarnation
//     replaced between checkpoint and retirement is never snapshotted or
//     retired by the stale value, and a failed conditional retirement is
//     terminal (source-cleanup-pending): no bare sbox delete, no
//     empty-listing fallback, no rollback of the running target.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestExecutorHelper(t *testing.T) {
	// This test binary is re-executed as the node executor via -exec; when
	// invoked that way the args after "--" carry the state dir and node.
	if os.Getenv("CN_MIGRATE_EXECUTOR") == "" {
		t.Skip("direct run; serves as executor only under the orchestration tests")
	}
	args := os.Args
	for i := range args {
		if args[i] == "--" && i+2 < len(args) {
			executorMain(args[i+1], args[i+2], args[i+3:])
			os.Exit(0) // executor mode: no test-framework output
		}
	}
	os.Exit(2)
}

func executorMain(stateDir, node string, args []string) {
	record := func() {
		f, err := os.OpenFile(filepath.Join(stateDir, "calls"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			_ = json.NewEncoder(f).Encode([]string{node, strings.Join(args, " ")})
			f.Close()
		}
	}
	has := func(flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	value := func(flag string) string {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == flag {
				return args[i+1]
			}
		}
		return ""
	}
	// controlExists / controlValue read the test's staged node-state files.
	controlExists := func(name string) bool {
		_, err := os.Stat(filepath.Join(stateDir, name))
		return err == nil
	}
	controlValue := func(name, fallback string) string {
		if raw, err := os.ReadFile(filepath.Join(stateDir, name)); err == nil {
			return strings.TrimSpace(string(raw))
		}
		return fallback
	}
	// relayPendingRestore hands a target restore over to the test's node
	// stand-in, which accepts it and suspends it independently of this
	// process. It returns false only when no URL is staged; once relayed it
	// exits with the stand-in's verdict and never returns. The client
	// timeout sits far above the CLI's 1s -wait so the CLI's
	// CommandContext kill — not this timeout — is what ends the executor;
	// the suspended request keeps its server-side lifecycle.
	relayPendingRestore := func() bool {
		raw, err := os.ReadFile(filepath.Join(stateDir, "pending-restore-url"))
		if err != nil {
			return false
		}
		body, _ := json.Marshal(map[string]any{"node": node, "argv": args})
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Post(
			strings.TrimSpace(string(raw)), "application/json", bytes.NewReader(body))
		if err != nil {
			os.Exit(1)
		}
		defer resp.Body.Close()
		var res struct {
			ExitCode int `json:"exit_code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		os.Exit(res.ExitCode)
		return false // unreachable: the relay path always exits above
	}
	record()
	switch {
	case has("list"):
		if node == "S" {
			if _, err := os.Stat(filepath.Join(stateDir, "stopped")); err == nil {
				os.Exit(1) // source sandboxd "lost" after checkpoint finalization
			}
		}
		os.Stdout.WriteString("ID STATUS RUNTIME\nsbox-x SANDBOX_STATE_RUNNING firecracker\n")
	case has("inspect"):
		if node != "S" {
			// The target's inspect answers with the incarnation the restore
			// operation created — the receipt's birth generation — unless a
			// test replaced the target sandbox after the restore.
			os.Stdout.WriteString(targetInspectJSON(stateDir))
			os.Exit(0)
		}
		os.Stdout.WriteString(inspectJSON(stateDir))
		if raw, err := os.ReadFile(filepath.Join(stateDir, "replace-after-inspect")); err == nil {
			if err := os.WriteFile(filepath.Join(stateDir, "source-generation"), raw, 0o600); err != nil {
				os.Exit(2)
			}
		}
	case has("--action"):
		switch value("--action") {
		case "checkpoint":
			if operation := value("--operation-id"); operation != "" {
				identifiedCheckpointExecutor(stateDir, args, operation, value)
			}
			if controlExists("fail-checkpoint") {
				os.Exit(1) // the command fails; whether the server executed it is unknowable
			}
			expected := value("--expected-generation")
			if expected == "" {
				_ = os.WriteFile(filepath.Join(stateDir, "bare-checkpoint"), nil, 0o600)
				os.Exit(1) // an unconditional checkpoint would snapshot an unnamed incarnation
			}
			if expected != liveGeneration(stateDir) {
				_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-refused"), nil, 0o600)
				os.Exit(1) // FailedPrecondition: the pinned incarnation is gone
			}
			_ = os.WriteFile(filepath.Join(stateDir, "stopped"), nil, 0o600)
			_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-id"),
				[]byte(filepath.Base(value("--checkpoint-dir"))), 0o600)
			// Optional replacement staged by a test: after the checkpoint
			// seals, another actor retires that incarnation and starts a
			// fresh one under the same ID on the source.
			if raw, err := os.ReadFile(filepath.Join(stateDir, "replace-source")); err == nil {
				_ = os.WriteFile(filepath.Join(stateDir, "source-generation"),
					bytes.TrimSpace(raw), 0o600)
			}
		case "checkpoint-root":
			// The read-only identity action. The source answers only once a
			// checkpoint sealed; the target answers only once an artifact
			// landed (the fetch below records its root).
			dir := value("--checkpoint-dir")
			if dir == "" || !strings.HasPrefix(dir, "/") {
				os.Exit(2)
			}
			if controlExists("root-unreadable") {
				os.Exit(1)
			}
			digest := ""
			if node == "S" {
				if !controlExists("checkpoint-id") {
					os.Exit(1) // nothing sealed at that directory
				}
				digest = sourceRootDigest(stateDir)
			} else if raw, err := os.ReadFile(filepath.Join(stateDir, "target-root-digest")); err == nil {
				digest = strings.TrimSpace(string(raw))
			} else {
				os.Exit(1) // no materialized artifact at the destination
			}
			identity := map[string]string{"root": digest, "scheme": "v2:manifest+sidecar-roots"}
			if requestPath := value("--request-file"); requestPath != "" {
				data, err := os.ReadFile(requestPath)
				if err != nil {
					os.Exit(1)
				}
				identity["request_sha256"] = testSHA(data)
			}
			_ = json.NewEncoder(os.Stdout).Encode(identity)
			os.Exit(0)
		case "get-checkpoint-operation":
			// The source-operation query: answers only from the durable
			// record, never executes work, and uses the CLI's structured
			// not-found exit code when the record is absent.
			operation := value("--operation-id")
			if operation == "" || !strings.HasPrefix(operation, "checkpoint-") {
				os.Exit(2)
			}
			if controlExists("fail-checkpoint-query") {
				os.Exit(1) // an ambiguous query failure
			}
			raw, err := os.ReadFile(fakeCheckpointRecordPath(stateDir, operation))
			if err != nil {
				fmt.Fprintf(os.Stderr, "checkpoint operation %s is unknown\n", operation)
				os.Exit(exitCodeOperationNotFound) // the structured absence signal
			}
			var record fakeCheckpointRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				os.Exit(1) // a corrupt record is an ambiguous failure
			}
			status := &runtime.CheckpointOperationStatus{
				OperationID:        record.OperationID,
				SandboxID:          record.SandboxID,
				State:              fakeCheckpointOpState(record.State),
				SourceGeneration:   record.SourceGeneration,
				CheckpointDir:      record.CheckpointDir,
				RequestDigest:      record.RequestDigest,
				ArtifactRootDigest: record.ArtifactRootDigest,
				ArtifactRootScheme: record.ArtifactRootScheme,
			}
			fakeApplyReceiptPoison(stateDir, status)
			fakePrintCheckpointOpStatus(status)
			os.Exit(0)
		case "get-start-operation":
			operation := value("--operation-id")
			if operation == "" || !strings.HasPrefix(operation, "migrate-") {
				os.Exit(2)
			}
			switch state := controlValue("operation-state", "notfound"); state {
			case "notfound":
				fmt.Fprintf(os.Stderr, "start operation %s is unknown\n", operation)
				os.Exit(exitCodeOperationNotFound) // the structured absence signal
			case "succeeded", "running", "unknown", "failed":
				generation := ""
				if state == "succeeded" {
					generation = targetGenerationValue(stateDir)
				}
				fmt.Println(operationReceiptJSON(operation, "sbox-x", state, generation))
				os.Exit(0)
			default:
				fmt.Println("executor exploded")
				os.Exit(1) // an ambiguous query failure
			}
		case "restore":
			if operation := value("--operation-id"); operation != "" {
				if controlExists("reject-operation-conflict") {
					os.Exit(1)
				}
				// Operation-mode restore (the resumable CLI): the node
				// records the durable start operation exactly as the daemon
				// would — the birth generation is assigned at admission and
				// returned by the receipt — and binds it to the pinned root.
				if !strings.HasPrefix(operation, "migrate-") ||
					value("--expected-root-digest") != sourceRootDigest(stateDir) ||
					value("--checkpoint-dir") == "" || value("--request-file") == "" {
					_ = os.WriteFile(filepath.Join(stateDir, "bad-operation-restore"), nil, 0o600)
					os.Exit(1)
				}
				if controlValue("operation-state", "") == "succeeded" {
					fmt.Println(operationReceiptJSON(operation, "sbox-x", "succeeded", targetGenerationValue(stateDir)))
					os.Exit(0) // same accepted operation replays without creating a target
				}
				created, err := os.OpenFile(filepath.Join(stateDir, "target-creations"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					os.Exit(2)
				}
				_, _ = created.Write([]byte("x"))
				_ = created.Close()
				birth := controlValue("target-birth-generation", "t1")
				_ = os.WriteFile(filepath.Join(stateDir, "target-generation"), []byte(birth), 0o600)
				_ = os.WriteFile(filepath.Join(stateDir, "operation-state"), []byte("succeeded"), 0o600)
				_ = os.WriteFile(filepath.Join(stateDir, "target-running"), nil, 0o600)
				if controlExists("lose-restore-reply") {
					os.Exit(1) // the node committed; the reply never reached the CLI
				}
				fmt.Println(operationReceiptJSON(operation, "sbox-x", "succeeded", birth))
				os.Exit(0)
			}
			if node == "T" {
				if !relayPendingRestore() {
					_ = os.WriteFile(filepath.Join(stateDir, "target-running"), nil, 0o600)
				}
			} else {
				_ = os.WriteFile(filepath.Join(stateDir, "source-rollback-running"), nil, 0o600)
			}
		case "delete":
			expected := value("--expected-generation")
			if expected == "" {
				_ = os.WriteFile(filepath.Join(stateDir, "bare-delete"), nil, 0o600)
				os.Exit(1) // a bare-ID delete could retire a replacement incarnation
			}
			if _, err := os.Stat(filepath.Join(stateDir, "fail-retire")); err == nil {
				os.Exit(1) // conditional retirement keeps failing on the source
			}
			if expected != liveGeneration(stateDir) {
				_ = os.WriteFile(filepath.Join(stateDir, "retire-refused"),
					[]byte(liveGeneration(stateDir)), 0o600)
				os.Exit(1) // FailedPrecondition: the incarnation was replaced
			}
			_ = os.WriteFile(filepath.Join(stateDir, "source-retired"), nil, 0o600)
		}
	case filepath.Base(args[0]) == "cn-publish":
		if _, err := os.Stat(filepath.Join(stateDir, "fail-publish")); err == nil {
			os.Exit(1) // publish keeps failing on the source
		}
	case filepath.Base(args[0]) == "cn-fetch":
		if controlExists("fail-fetch") {
			os.Exit(1)
		}
		// The artifact lands on the target carrying the source's content
		// root, which a later checkpoint-root read observes.
		_ = os.WriteFile(filepath.Join(stateDir, "target-root-digest"),
			[]byte(sourceRootDigest(stateDir)), 0o600)
	case has("delete"):
		// Any bare `sbox ... delete` reaching the node is a cn-migrate
		// regression: retirement only ever goes through the conditional
		// checkpoint-restore path above. Fail and leave a marker.
		_ = os.WriteFile(filepath.Join(stateDir, "sbox-delete"), nil, 0o600)
		os.Exit(1)
	}
}

// liveGeneration returns the incarnation label the fake source node holds
// for the sandbox, seeding it with g1 on first use so a later replacement
// (the replace-source control) can flip it.
func liveGeneration(stateDir string) string {
	path := filepath.Join(stateDir, "source-generation")
	if raw, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(raw))
	}
	_ = os.WriteFile(path, []byte("g1"), 0o600)
	return "g1"
}

// fakeCheckpointRecord is the fake node's durable checkpoint-operation
// receipt — the server-side journal entry, persisted independently of any
// response the CLI does or does not receive.
type fakeCheckpointRecord struct {
	OperationID        string `json:"operation_id"`
	SandboxID          string `json:"sandbox_id"`
	SourceGeneration   string `json:"source_generation"`
	CheckpointDir      string `json:"checkpoint_dir"`
	RequestDigest      string `json:"request_digest"`
	State              string `json:"state"`
	ArtifactRootDigest string `json:"artifact_root_digest,omitempty"`
	ArtifactRootScheme string `json:"artifact_root_scheme,omitempty"`
}

// fakeCheckpointRecordPath names the durable record of one operation ID.
func fakeCheckpointRecordPath(stateDir, operation string) string {
	return filepath.Join(stateDir, "checkpoint-op-"+operation+".json")
}

// fakeCount appends one tally to a counter file, creating it on first use.
func fakeCount(stateDir, name string) {
	f, err := os.OpenFile(filepath.Join(stateDir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write([]byte("x"))
	_ = f.Close()
}

// fakeReadCount reads a counter file the fake node maintains.
func fakeReadCount(t *testing.T, stateDir, name string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, name))
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "x")
}

// fakeBoolFlag reads one boolean flag from an argv, accepting both the
// "--flag" and "--flag=value" spellings, and reports whether it was present.
// An absent flag returns the Go zero value (false) plus false.
func fakeBoolFlag(args []string, flag string) (value, present bool) {
	for _, arg := range args {
		if arg == flag {
			return true, true
		}
		if strings.HasPrefix(arg, flag+"=") {
			switch strings.TrimPrefix(arg, flag+"=") {
			case "true":
				return true, true
			case "false":
				return false, true
			}
		}
	}
	return false, false
}

// fakeCheckpointOpDigest recomputes the deterministic request digest of an
// identified checkpoint exactly the way the node CLI and the service do:
// the wrapped request with the operation ID dropped, deterministically
// marshaled, SHA-256. The fake uses it to bind the record to the payload it
// actually admitted, so a replay under the same ID with any changed field is
// refused instead of silently re-answered.
func fakeCheckpointOpDigest(args []string, value func(string) string) (string, error) {
	timeout, err := strconv.ParseUint(value("--checkpoint-timeout-seconds"), 10, 32)
	if err != nil {
		return "", err
	}
	compress, _ := fakeBoolFlag(args, "--compress")
	leaveRunning, _ := fakeBoolFlag(args, "--leave-running")
	wrapped := &runtime.CheckpointWithOperationRequest{
		OperationID: "",
		Checkpoint: &runtime.CheckpointRequest{
			ID:             value("--sandbox-id"),
			CheckpointDir:  value("--checkpoint-dir"),
			TimeoutSeconds: uint32(timeout),
			Compress:       compress,
			LeaveRunning:   leaveRunning,
			SnapshotType:   value("--snapshot-type"),
		},
		ExpectedGeneration: value("--expected-generation"),
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrapped)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// fakeCheckpointOpState maps a control-file state name onto the enum value
// the protojson receipt carries.
func fakeCheckpointOpState(state string) runtime.CheckpointOperationState {
	switch state {
	case "running":
		return runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
	case "succeeded":
		return runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED
	case "failed":
		return runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
	case "unknown":
		return runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN
	}
	return runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED
}

// fakePrintCheckpointOpStatus prints one CheckpointOperationStatus as the
// operation-mode CLI does: a single protojson object on stdout.
func fakePrintCheckpointOpStatus(status *runtime.CheckpointOperationStatus) {
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(status)
	if err != nil {
		os.Exit(2)
	}
	fmt.Println(string(data))
}

// fakeApplyReceiptPoison corrupts exactly one field of a receipt about to be
// printed, modeling a wrong answer from the record/CLI boundary. The durable
// record keeps the truth; only the printed reply lies.
func fakeApplyReceiptPoison(stateDir string, status *runtime.CheckpointOperationStatus) {
	switch controlFileValue(stateDir, "poison-checkpoint-receipt") {
	case "operation_id":
		status.OperationID = "checkpoint-someone-else"
	case "sandbox_id":
		status.SandboxID = "sbox-y"
	case "source_generation":
		status.SourceGeneration = "g9"
	case "request_digest":
		status.RequestDigest = "invalid-request-digest" // controller syntax check; valid but mismatched RPC digests are rejected by the real CLI tests
	case "artifact_root_digest":
		status.ArtifactRootDigest = strings.Repeat("cd", 32)
	case "artifact_root_scheme":
		status.ArtifactRootScheme = "v9:wrong-scheme"
	}
}

// controlFileValue reads a trimmed control file or "" when absent.
func controlFileValue(stateDir, name string) string {
	raw, err := os.ReadFile(filepath.Join(stateDir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// controlPresent reports whether a staged control file exists.
func controlPresent(stateDir, name string) bool {
	_, err := os.Stat(filepath.Join(stateDir, name))
	return err == nil
}

// status renders the durable record as the operation receipt.
func (r fakeCheckpointRecord) status() *runtime.CheckpointOperationStatus {
	return &runtime.CheckpointOperationStatus{
		OperationID:        r.OperationID,
		SandboxID:          r.SandboxID,
		State:              fakeCheckpointOpState(r.State),
		SourceGeneration:   r.SourceGeneration,
		CheckpointDir:      r.CheckpointDir,
		RequestDigest:      r.RequestDigest,
		ArtifactRootDigest: r.ArtifactRootDigest,
		ArtifactRootScheme: r.ArtifactRootScheme,
	}
}

// identifiedCheckpointExecutor emulates the node CLI and daemon contract for
// `--action checkpoint --operation-id ...`. It enforces the same local
// contract the node CLI does (complete fixed stop-and-copy payload), binds
// the durable record to the deterministic digest of the payload actually
// admitted, persists that record BEFORE any response so a lost reply still
// leaves the reconcilable fact, executes the runtime checkpoint exactly once
// per operation ID, answers replays from the record while refusing a changed
// payload, and counts actual executions separately from replays.
func identifiedCheckpointExecutor(stateDir string, args []string, operation string, value func(string) string) {
	sandbox := value("--sandbox-id")
	dir := value("--checkpoint-dir")
	if controlPresent(stateDir, "map-source-path") {
		dir = filepath.Join("/physical/source/checkpoints", filepath.Base(dir))
		originalValue := value
		value = func(flag string) string {
			if flag == "--checkpoint-dir" {
				return dir
			}
			return originalValue(flag)
		}
	}
	generation := value("--expected-generation")
	timeout, timeoutErr := strconv.ParseUint(value("--checkpoint-timeout-seconds"), 10, 32)
	leaveRunning, leaveSet := fakeBoolFlag(args, "--leave-running")
	if sandbox == "" || dir == "" || !strings.HasPrefix(dir, "/") || generation == "" ||
		timeoutErr != nil || timeout < 1 || timeout > 600 || !leaveSet || leaveRunning {
		_ = os.WriteFile(filepath.Join(stateDir, "bad-identified-checkpoint"), nil, 0o600)
		os.Exit(1) // the node CLI refuses a malformed or non-stop-and-copy identified checkpoint locally
	}
	digest, err := fakeCheckpointOpDigest(args, value)
	if err != nil {
		os.Exit(1)
	}
	recordPath := fakeCheckpointRecordPath(stateDir, operation)
	if raw, readErr := os.ReadFile(recordPath); readErr == nil {
		var record fakeCheckpointRecord
		if json.Unmarshal(raw, &record) != nil {
			os.Exit(1)
		}
		if record.RequestDigest != digest {
			_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-op-reuse-refused"), nil, 0o600)
			os.Exit(1) // the daemon refuses reuse of an operation ID with a different request
		}
		fakeCount(stateDir, "source-checkpoint-replays")
		status := record.status()
		fakeApplyReceiptPoison(stateDir, status)
		fakePrintCheckpointOpStatus(status)
		if record.State != "succeeded" {
			os.Exit(1) // the CLI reports the recorded non-success outcome, then fails
		}
		os.Exit(0)
	}
	// A staged refusal models a server that predates or refuses the new RPC
	// before admission: the command fails, no record exists, and the query
	// later answers structured not-found. There is never a legacy fallback.
	if controlPresent(stateDir, "refuse-checkpoint-op") {
		os.Exit(1)
	}
	if generation != liveGeneration(stateDir) {
		_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-refused"), nil, 0o600)
		os.Exit(1) // FailedPrecondition: the pinned incarnation is gone; nothing is recorded
	}
	state := controlFileValue(stateDir, "checkpoint-operation-state")
	if state == "" {
		state = "succeeded"
	}
	if fakeCheckpointOpState(state) == runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNSPECIFIED {
		os.Exit(2) // an unrecognized state is a protocol error, not a record
	}
	record := fakeCheckpointRecord{
		OperationID:      operation,
		SandboxID:        sandbox,
		SourceGeneration: generation,
		CheckpointDir:    dir,
		RequestDigest:    digest,
		State:            state,
	}
	if state == "succeeded" {
		record.ArtifactRootDigest = sourceRootDigest(stateDir)
		record.ArtifactRootScheme = "v2:manifest+sidecar-roots"
	}
	// The receipt is durable before any response and before the side-effect
	// markers: it survives a lost reply, and the actual-execution counter
	// stays separable from every later CLI replay.
	encoded, marshalErr := json.Marshal(record)
	if marshalErr != nil || os.WriteFile(recordPath, append(encoded, '\n'), 0o600) != nil {
		os.Exit(2)
	}
	fakeCount(stateDir, "source-checkpoint-executions")
	if state == "succeeded" {
		_ = os.WriteFile(filepath.Join(stateDir, "stopped"), nil, 0o600)
		_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-id"), []byte(filepath.Base(dir)), 0o600)
		// Optional replacement staged by a test: after the checkpoint seals,
		// another actor retires that incarnation and starts a fresh one
		// under the same ID on the source.
		if raw, replaceErr := os.ReadFile(filepath.Join(stateDir, "replace-source")); replaceErr == nil {
			_ = os.WriteFile(filepath.Join(stateDir, "source-generation"), bytes.TrimSpace(raw), 0o600)
		}
	}
	if controlPresent(stateDir, "lose-checkpoint-reply") {
		os.Exit(1) // the node committed; the reply never reached the CLI
	}
	status := record.status()
	fakeApplyReceiptPoison(stateDir, status)
	fakePrintCheckpointOpStatus(status)
	if state != "succeeded" {
		os.Exit(1) // a recorded non-success outcome is reported, then fails
	}
	os.Exit(0)
}

// inspectJSON renders the sandbox exactly the way `sbox inspect` does:
// encoding/json over the generated runtime.SandboxStatus, whose
// omitempty drops the proto3-zero RUNNING state field entirely. A staged
// no-label control models a pre-generation node that carries no incarnation
// identity at all.
func inspectJSON(stateDir string) string {
	labels := map[string]string{sourceGenerationLabel: liveGeneration(stateDir)}
	if _, err := os.Stat(filepath.Join(stateDir, "no-label")); err == nil {
		labels = nil
	}
	status := &runtime.SandboxStatus{
		ID:     "sbox-x",
		State:  runtime.SandboxState_SANDBOX_STATE_RUNNING,
		Labels: labels,
	}
	encoded, err := json.MarshalIndent(status, "", " ")
	if err != nil {
		return ""
	}
	return string(encoded) + "\n"
}

func TestMigrateTargetOwnedNeverRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "fail-retire"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The catalog stand-in mirrors the probe that reproduced the defect:
	// one node record for T and a checkpoint entry that follows whatever
	// checkpoint ID the executor observed.
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/node") {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "T", "runtimes": []map[string]string{{"name": "firecracker"}}})
			return
		}
		id, err := os.ReadFile(filepath.Join(state, "checkpoint-id"))
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"checkpoints": []map[string]any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checkpoints": []map[string]any{{"id": strings.TrimSpace(string(id)), "compat": nil}},
		})
	}))
	defer catalog.Close()

	bin := filepath.Join(t.TempDir(), "cn-migrate")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOCACHE="+os.Getenv("GOCACHE"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cn-migrate: %v\n%s", err, out)
	}
	executor := os.Args[0]
	tpl := executor + " -test.run=TestExecutorHelper -- " + state + " {node}"
	cmd := exec.Command(bin,
		"-sandbox", "sbox-x", "-source", "S",
		"-exec", tpl,
		"-store", "fake",
		"-nodes", catalog.URL,
		"-json")
	cmd.Env = append(os.Environ(), "CN_MIGRATE_EXECUTOR=1", "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0", "GOCACHE="+os.Getenv("GOCACHE"))
	out, _ := cmd.CombinedOutput()
	report := string(out)

	if _, err := os.Stat(filepath.Join(state, "target-running")); err != nil {
		t.Fatalf("scenario setup: target never ran\n%s", report)
	}
	if _, err := os.Stat(filepath.Join(state, "source-rollback-running")); err == nil {
		t.Fatalf("F2 regression: source rollback-restore issued after the target was verified RUNNING\n%s", report)
	}
	if !strings.Contains(report, "no rollback") {
		t.Fatalf("report does not state the ownership decision\n%s", report)
	}
	if !strings.Contains(report, "source-cleanup-pending") {
		t.Fatalf("report does not name the lingering cleanup state\n%s", report)
	}
	calls, _ := os.ReadFile(filepath.Join(state, "calls"))
	for _, line := range strings.Split(string(calls), "\n") {
		if strings.Contains(line, "rollback-restore") && strings.Contains(line, "\"S\"") {
			t.Fatalf("F2 regression: rollback-restore command sent to the source\n%s", report)
		}
	}
	// The retirement failed and stayed failed: the exact command sequence
	// ends with the one conditional delete — no bare sbox delete, no empty
	// listing offered as a retirement proof, no retry loop.
	assertCallSequence(t, state, []string{
		"S:list", "S:inspect", "S:checkpoint", "S:publish",
		"T:fetch", "T:restore", "T:list", "S:delete",
	}, report)
}

// cliReport is the subset of cn-migrate's -json report the orchestration
// tests assert on.
type cliReport struct {
	Sandbox          string `json:"sandbox"`
	Source           string `json:"source"`
	Target           string `json:"target"`
	Checkpoint       string `json:"checkpoint_dir"`
	SourceGeneration string `json:"source_generation"`
	Steps            []struct {
		Step   string `json:"step"`
		Detail string `json:"detail"`
		TookMs int64  `json:"took_ms"`
		Failed bool   `json:"failed"`
	} `json:"steps"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// buildCnMigrate compiles the package under test into a scratch binary: the
// regressions must drive the real CLI, not a test-linked main.
func buildCnMigrate(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cn-migrate")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOCACHE="+os.Getenv("GOCACHE"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cn-migrate: %v\n%s", err, out)
	}
	return bin
}

// catalogStandIn serves the two GETs the CLI's placement performs: one node
// record for T and a checkpoint entry that follows whatever checkpoint ID
// the executor observed.
func catalogStandIn(t *testing.T, state string) string {
	t.Helper()
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/node") {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "T", "runtimes": []map[string]string{{"name": "firecracker"}}})
			return
		}
		id, err := os.ReadFile(filepath.Join(state, "checkpoint-id"))
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"checkpoints": []map[string]any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"checkpoints": []map[string]any{{"id": strings.TrimSpace(string(id)), "compat": nil}},
		})
	}))
	t.Cleanup(catalog.Close)
	return catalog.URL
}

// runMigrate executes the real CLI through the executor-helper template,
// captures its -json report, and echoes the report plus every recorded node
// command into the test log. Extra flags (e.g. -source-generation) are
// appended after the fixed ones.
func runMigrate(t *testing.T, bin, state, nodes string, wait time.Duration, extra ...string) (int, cliReport, string) {
	t.Helper()
	executor := os.Args[0]
	tpl := executor + " -test.run=TestExecutorHelper -- " + state + " {node}"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{
		"-sandbox", "sbox-x", "-source", "S",
		"-exec", tpl,
		"-store", "fake",
		"-nodes", nodes,
		"-request-file", filepath.Join(state, "req.json"),
		"-bin", filepath.Join(state, "fakebin"),
		"-wait", wait.String(),
	}
	args = append(args, extra...)
	args = append(args, "-json")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "CN_MIGRATE_EXECUTOR=1", "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0", "GOCACHE="+os.Getenv("GOCACHE"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run cn-migrate: %v\nstderr:\n%s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	var report cliReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		t.Fatalf("parse cn-migrate report: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	t.Logf("cn-migrate exit=%d report:\n%s", code, stdout.String())
	if calls, err := os.ReadFile(filepath.Join(state, "calls")); err == nil {
		t.Logf("node commands issued by the CLI:\n%s", calls)
	} else {
		t.Fatalf("read recorded node calls: %v", err)
	}
	return code, report, stdout.String()
}

type nodeCall struct{ node, argv string }

// readCalls loads the executor's append-only record of every node command
// the CLI actually issued.
func readCalls(t *testing.T, state string) []nodeCall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(state, "calls"))
	if err != nil {
		t.Fatalf("read recorded node calls: %v", err)
	}
	var calls []nodeCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var pair []string
		if err := json.Unmarshal([]byte(line), &pair); err != nil || len(pair) != 2 {
			t.Fatalf("malformed recorded call %q: %v", line, err)
		}
		calls = append(calls, nodeCall{pair[0], pair[1]})
	}
	return calls
}

// callSeq renders the recorded commands as node:class pairs for exact
// sequence assertions. The class mirrors how the scenarios reason about a
// command: CLI basename plus its distinguishing verb token.
func callSeq(calls []nodeCall) []string {
	hasToken := func(argv, token string) bool {
		for _, f := range strings.Fields(argv) {
			if f == token {
				return true
			}
		}
		return false
	}
	seq := make([]string, 0, len(calls))
	for _, c := range calls {
		class := "unknown"
		switch filepath.Base(strings.Fields(c.argv)[0]) {
		case "sbox":
			if hasToken(c.argv, "delete") {
				class = "bare-delete" // a bare-ID delete; cn-migrate must never issue one
			} else if hasToken(c.argv, "inspect") {
				class = "inspect"
			} else if hasToken(c.argv, "list") {
				class = "list"
			}
		case "checkpoint-restore":
			if hasToken(c.argv, "restore") {
				class = "restore"
			} else if hasToken(c.argv, "checkpoint") {
				class = "checkpoint"
			} else if hasToken(c.argv, "delete") {
				class = "delete" // the conditional, receipt-gated retirement
			}
		case "cn-publish":
			class = "publish"
		case "cn-fetch":
			class = "fetch"
		}
		seq = append(seq, c.node+":"+class)
	}
	return seq
}

// assertCallSequence pins the exact node command sequence — the strongest
// form of "no rollback / no fence delete was ever issued".
func assertCallSequence(t *testing.T, state string, want []string, stdout string) {
	t.Helper()
	got := callSeq(readCalls(t, state))
	if !slices.Equal(got, want) {
		t.Fatalf("node command sequence = %v, want %v\n%s", got, want, stdout)
	}
}

// TestMigratePublishFailureRollsBackSource is the positive control for the
// safe compensation path: cn-publish fails while the target has not been
// asked to restore anything, so the source MUST be rolled back from its
// local checkpoint and the target MUST remain untouched.
func TestMigratePublishFailureRollsBackSource(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "fail-publish"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := catalogStandIn(t, state) // never queried: publish fails before placement

	code, report, stdout := runMigrate(t, buildCnMigrate(t), state, nodes, 10*time.Second)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	type step struct {
		name   string
		failed bool
	}
	var got []step
	for _, s := range report.Steps {
		got = append(got, step{s.Step, s.Failed})
	}
	want := []step{{"list", false}, {"inspect", false}, {"checkpoint", false}, {"publish", true}, {"rollback-restore", false}, {"publish", true}}
	if !slices.EqualFunc(got, want, func(a, b step) bool { return a == b }) {
		t.Fatalf("report steps = %v, want %v\n%s", got, want, stdout)
	}
	if !strings.Contains(report.Error, "rolled back") {
		t.Fatalf("report does not state the rollback\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "source-rollback-running")); err != nil {
		t.Fatalf("safe-compensation regression: source was not rolled back after a pre-restore publish failure\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "target-running")); err == nil {
		t.Fatalf("target was started in a pre-restore failure scenario\n%s", stdout)
	}
	// The target was never asked for anything: no fetch, no restore, no delete.
	assertCallSequence(t, state, []string{"S:list", "S:inspect", "S:checkpoint", "S:publish", "S:restore"}, stdout)
}

// TestMigrateRestoreUnknownOutcomeContainsLateCommit drives the 0020 P0
// counterexample shape through the real CLI: the target restore is accepted
// by the node stand-in and suspended, the CLI's 1s -wait kills the client
// executor so the restore step fails with the request outcome unknown, and
// only after the CLI process has exited does the test release the suspended
// request, letting the restore commit late on the target. The release is
// driven by CLI exit — never by waiting for a source rollback — so a fixed
// CLI cannot pass by stalling. Expected containment: no source rollback, no
// target delete, and the late-committed target as the only writer (the
// source was finalized at checkpoint time).
func TestMigrateRestoreUnknownOutcomeContainsLateCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()

	accepted := make(chan struct{}, 1)
	committed := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseNow := func() { releaseOnce.Do(func() { close(release) }) }
	var forcedBackstop atomic.Bool
	pending := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Node string   `json:"node"`
			Argv []string `json:"argv"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		t.Logf("node stand-in accepted restore request: node=%s argv=%s", req.Node, strings.Join(req.Argv, " "))
		select {
		case accepted <- struct{}{}:
		default:
		}
		// Hold the accepted restore. The test releases it only after the
		// CLI has exited — that is what makes the eventual commit "late".
		// The backstop exists only so a broken test cannot hang
		// server.Close; it never commits.
		select {
		case <-release:
		case <-time.After(15 * time.Second):
			forcedBackstop.Store(true)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The late restore commits: the target becomes a writer.
		_ = os.WriteFile(filepath.Join(state, "target-running"), nil, 0o600)
		select {
		case committed <- struct{}{}:
		default:
		}
		_, _ = w.Write([]byte("restored\n")) // usually a broken pipe: the client executor is already dead
	}))
	defer pending.Close()
	defer releaseNow() // LIFO: runs before pending.Close, so a still-held request is released rather than abandoned to the backstop

	if err := os.WriteFile(filepath.Join(state, "pending-restore-url"), []byte(pending.URL+"/node-command"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := catalogStandIn(t, state)

	// The helper disables only race-detector exit sleep, preserving this
	// original one-second RPC timeout under race instrumentation.
	code, report, stdout := runMigrate(t, buildCnMigrate(t), state, nodes, time.Second)

	// The suspended request must have been accepted before the CLI moved on.
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatalf("scenario setup: the suspended restore never arrived at the node stand-in\n%s", stdout)
	}

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (an unknown target outcome is a failure)\n%s", code, stdout)
	}
	type step struct {
		name   string
		failed bool
	}
	var got []step
	for _, s := range report.Steps {
		got = append(got, step{s.Step, s.Failed})
	}
	// list, inspect, checkpoint, publish, materialize, the killed restore,
	// and fail()'s 0ms summary line — nothing else may run.
	want := []step{{"list", false}, {"inspect", false}, {"checkpoint", false}, {"publish", false}, {"materialize", false}, {"restore", true}, {"restore", true}}
	if !slices.EqualFunc(got, want, func(a, b step) bool { return a == b }) {
		t.Fatalf("report steps = %v, want %v (no fence-target/confirm-fenced/rollback-restore may appear)\n%s", got, want, stdout)
	}
	for _, banned := range []string{"fence-target", "confirm-fenced", "rollback-restore", "verify", "delete-source", "confirm-source-gone"} {
		for _, s := range report.Steps {
			if s.Step == banned {
				t.Fatalf("compensation command %q issued around an unknown target outcome\n%s", banned, stdout)
			}
		}
	}
	// First restore line = the executor command killed by the 1s -wait; the
	// trailing line is fail()'s summary (0ms, detail == report.error).
	if took := report.Steps[5].TookMs; report.Steps[5].Failed && (took < 950 || took > 2000) {
		t.Fatalf("restore step took_ms = %d, want the 1s -wait kill (4900–6500ms)\n%s", took, stdout)
	}
	if last := report.Steps[len(report.Steps)-1]; last.TookMs != 0 || last.Detail != report.Error {
		t.Fatalf("trailing report line is not the fail() summary: %+v\n%s", last, stdout)
	}
	if !strings.Contains(report.Error, "TARGET OUTCOME UNKNOWN") {
		t.Fatalf("report does not state the unknown target outcome\n%s", stdout)
	}
	if report.Target != "T" || !strings.Contains(report.Error, report.Checkpoint) ||
		!strings.Contains(report.Error, "target "+report.Target) {
		t.Fatalf("report does not preserve the checkpoint id and target for manual recovery\n%s", stdout)
	}

	// The CLI is gone now — release the suspended restore and let it commit.
	releaseNow()
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatalf("the suspended restore did not commit after release\n%s", stdout)
	}
	if forcedBackstop.Load() {
		t.Fatalf("node stand-in hit its backstop instead of the test's release\n%s", stdout)
	}

	// Final ownership: exactly the target writer.
	if _, err := os.Stat(filepath.Join(state, "target-running")); err != nil {
		t.Fatalf("late-committed target never started\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "stopped")); err != nil {
		t.Fatalf("source was not finalized at checkpoint time\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "source-rollback-running")); err == nil {
		t.Fatalf("F2 regression: source rolled back next to an unknown target outcome; the late commit then creates dual writers\n%s", stdout)
	}
	// Command-level proof: the target saw only fetch + the hanging restore —
	// no fence delete; the source saw no restore (no rollback).
	assertCallSequence(t, state, []string{"S:list", "S:inspect", "S:checkpoint", "S:publish", "T:fetch", "T:restore"}, stdout)
}

// TestSourceGenerationParsing pins the inspect parser: every JSON shape
// `sbox inspect` emits for a RUNNING sandbox yields the generation, and
// every identity, label, or syntax deviation fails closed.
func TestSourceGenerationParsing(t *testing.T) {
	labelled := func(state, gen string) string {
		if state != "" {
			state = "," + state
		}
		return `{"id":"sbox-x"` + state + `,"labels":{"` + sourceGenerationLabel + `":"` + gen + `"}}`
	}
	ok := []struct{ name, in, want string }{
		{"maximum retirement generation", labelled(`"state":0`, strings.Repeat("g", 128)), strings.Repeat("g", 128)},
		{"numeric state", labelled(`"state":0`, "g1"), "g1"},
		{"omitted state is the proto3 zero RUNNING", labelled(``, "gen-2"), "gen-2"},
		{"state as its enum name string", labelled(`"state":"SANDBOX_STATE_RUNNING"`, "g3"), "g3"},
		{"other encoding/json fields present", `{"id":"sbox-x","command":["sh","-c","id"],"runtime":"firecracker","state":0,"started_at":1756000000,"labels":{"k":"v","` +
			sourceGenerationLabel + `":"g4"},"resources":null}`, "g4"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sourceGeneration(tc.in, "sbox-x")
			if err != nil {
				t.Fatalf("sourceGeneration(%s) = %v, want %q", tc.in, err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("sourceGeneration(%s) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	bad := []struct{ name, in, wantErr string }{
		{"wrong id", `{"id":"sbox-y","labels":{"` + sourceGenerationLabel + `":"g1"}}`, "does not match"},
		{"exited state", labelled(`"state":1`, "g1"), "not SANDBOX_STATE_RUNNING"},
		{"exited state by name", labelled(`"state":"SANDBOX_STATE_EXITED"`, "g1"), "not SANDBOX_STATE_RUNNING"},
		{"missing generation label", `{"id":"sbox-x","state":0}`, "resource-generation"},
		{"blank generation label", labelled(`"state":0`, "  "), "resource-generation"},
		{"oversized generation label", labelled(`"state":0`, strings.Repeat("g", 129)), "128"},
		{"free text around the json", "warn: degraded\n" + labelled(`"state":0`, "g1"), "parse SandboxStatus"},
		{"trailing content", labelled(`"state":0`, "g1") + " {}", "parse SandboxStatus"},
		{"unknown field", `{"id":"sbox-x","bogus":1,"labels":{"` + sourceGenerationLabel + `":"g1"}}`, "parse SandboxStatus"},
		{"empty output", "", "parse SandboxStatus"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sourceGeneration(tc.in, "sbox-x")
			if err == nil {
				t.Fatalf("sourceGeneration(%s) = %q, want an error mentioning %q", tc.in, got, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("sourceGeneration(%s) error = %v, want it to mention %q", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestMigrateStopsWhenGenerationCannotBePinned drives the pre-checkpoint
// gate through the real CLI: a source without the generation label (an old
// node) and an explicit -source-generation that does not match the captured
// incarnation both stop the run at the inspect step — before any checkpoint
// side effect, publish, or target command.
func TestMigrateStopsWhenGenerationCannotBePinned(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	scenarios := []struct {
		name      string
		stage     func(t *testing.T, state string)
		extraArgs []string
		wantErr   string
	}{
		{
			name:  "pre-generation source node carries no label",
			stage: func(t *testing.T, state string) { stageMarker(t, state, "no-label") },
			// The staged marker content is irrelevant; only presence matters.
			wantErr: "resource-generation",
		},
		{
			name: "stale -source-generation",
			stage: func(t *testing.T, state string) {
				if err := os.WriteFile(filepath.Join(state, "source-generation"), []byte("g-live"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			extraArgs: []string{"-source-generation", "g-stale"},
			wantErr:   "-source-generation",
		},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			tc.stage(t, state)
			nodes := catalogStandIn(t, state)

			code, report, stdout := runMigrate(t, buildCnMigrate(t), state, nodes, 10*time.Second, tc.extraArgs...)

			if code != 1 {
				t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
			}
			if report.OK || report.SourceGeneration != "" {
				t.Fatalf("run pinned or claimed success without a usable source generation\n%s", stdout)
			}
			if !strings.Contains(report.Error, tc.wantErr) {
				t.Fatalf("report error %q does not name the generation gate (%q)\n%s", report.Error, tc.wantErr, stdout)
			}
			// Stopped before the checkpoint: nothing was sealed, nothing
			// was published, and the target was never contacted.
			assertCallSequence(t, state, []string{"S:list", "S:inspect"}, stdout)
			if _, err := os.Stat(filepath.Join(state, "checkpoint-id")); err == nil {
				t.Fatalf("checkpoint side effect despite an unpinnable source generation\n%s", stdout)
			}
			if _, err := os.Stat(filepath.Join(state, "stopped")); err == nil {
				t.Fatalf("source finalized despite an unpinnable source generation\n%s", stdout)
			}
		})
	}
}

// TestMigrateSourceReplacedBeforeRetirementFailsClosed stages the source
// replacement between checkpoint and retirement: the pinned g1 incarnation
// is sealed and the target restores and verifies RUNNING, then another actor
// retires g1 and starts a fresh g2 incarnation under the same ID. The
// conditional retirement of g1 must be refused by the node (the fake node
// decides from the --expected-generation it actually receives) and the CLI
// must contain that failure: source-cleanup-pending, no rollback of the
// running target, no bare sbox delete, and no empty-listing fallback.
func TestMigrateSourceReplacedBeforeRetirementFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "replace-source"), []byte("g2"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := catalogStandIn(t, state)

	code, report, stdout := runMigrate(t, buildCnMigrate(t), state, nodes, 10*time.Second)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, stdout)
	}
	if report.OK {
		t.Fatalf("report claims success with an unresolved source cleanup\n%s", stdout)
	}
	if report.SourceGeneration != "g1" {
		t.Fatalf("run did not pin the captured generation: %q\n%s", report.SourceGeneration, stdout)
	}
	if !strings.Contains(report.Error, "source-cleanup-pending") {
		t.Fatalf("report does not name the source-cleanup-pending state\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "target-running")); err != nil {
		t.Fatalf("scenario setup: target never ran\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "source-rollback-running")); err == nil {
		t.Fatalf("F2 regression: source rolled back next to a verified RUNNING target\n%s", stdout)
	}
	// The node refused the stale retirement against the live g2 and no
	// retirement side effect landed — the replacement incarnation survives.
	if raw, err := os.ReadFile(filepath.Join(state, "retire-refused")); err != nil || strings.TrimSpace(string(raw)) != "g2" {
		t.Fatalf("conditional retirement did not compare against the live generation g2: %v %q\n%s", err, string(raw), stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "source-retired")); err == nil {
		t.Fatalf("a retirement side effect reached the source despite the generation mismatch\n%s", stdout)
	}
	// Exactly one conditional delete and nothing after it: the sequence
	// itself rules out a bare delete, a listing fallback, and a rollback.
	assertCallSequence(t, state, []string{
		"S:list", "S:inspect", "S:checkpoint", "S:publish",
		"T:fetch", "T:restore", "T:list", "S:delete",
	}, stdout)
}

// TestMigrateMatchedGenerationRetiresSource is the positive control for the
// generation discipline: with the pinned generation live on the source, the
// conditional checkpoint and the receipt-gated conditional retirement both
// succeed and the run reports success.
func TestMigrateMatchedGenerationRetiresSource(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()
	nodes := catalogStandIn(t, state)

	code, report, stdout := runMigrate(t, buildCnMigrate(t), state, nodes, 10*time.Second)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, stdout)
	}
	if !report.OK {
		t.Fatalf("report does not claim success\n%s", stdout)
	}
	if report.SourceGeneration != "g1" {
		t.Fatalf("report pinned generation %q, want g1\n%s", report.SourceGeneration, stdout)
	}
	if _, err := os.Stat(filepath.Join(state, "source-retired")); err != nil {
		t.Fatalf("conditional retirement did not retire the pinned generation\n%s", stdout)
	}
	for _, marker := range []string{"retire-refused", "checkpoint-refused", "bare-delete", "bare-checkpoint", "sbox-delete"} {
		if _, err := os.Stat(filepath.Join(state, marker)); err == nil {
			t.Fatalf("node recorded %s — cn-migrate issued an unconditional or mismatched command\n%s", marker, stdout)
		}
	}
	assertCallSequence(t, state, []string{
		"S:list", "S:inspect", "S:checkpoint", "S:publish",
		"T:fetch", "T:restore", "T:list", "S:delete",
	}, stdout)
}

// stageMarker drops an empty control file the fake node executor looks for.
func stageMarker(t *testing.T, state, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(state, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The source changes after inspection but before admission. The executor
// checks the live generation before recording any checkpoint side effect.
func TestMigrateSourceReplacedBeforeCheckpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and re-executes CLI")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "replace-after-inspect"), []byte("g2"), 0600); err != nil {
		t.Fatal(err)
	}
	code, report, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second)
	if code != 1 || report.OK || report.SourceGeneration != "g1" {
		t.Fatalf("unexpected result: %s", out)
	}
	assertCallSequence(t, state, []string{"S:list", "S:inspect", "S:checkpoint", "S:list"}, out)
	if liveGeneration(state) != "g2" {
		t.Fatal("replacement mutated")
	}
	if _, err := os.Stat(filepath.Join(state, "checkpoint-refused")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stopped", "checkpoint-id", "target-running", "source-rollback-running", "source-retired"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected side effect %s: %v", name, err)
		}
	}
}

func TestMigrateRejectsInvalidGenerationBeforeNodeCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and re-executes CLI")
	}
	bin := buildCnMigrate(t)
	for _, gen := range []string{"  ", strings.Repeat("g", 129)} {
		state := t.TempDir()
		// Empty call log lets the normal helper assert that no executor ran.
		stageMarker(t, state, "calls")
		code, report, out := runMigrate(t, bin, state, "http://127.0.0.1:1", time.Second, "-source-generation", gen)
		if code != 1 || report.OK || !strings.Contains(report.Error, "128 bytes") {
			t.Fatalf("unexpected result: %s", out)
		}
		assertCallSequence(t, state, nil, out)
	}
}
