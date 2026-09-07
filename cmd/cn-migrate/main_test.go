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
//     only writer (the source was finalized at checkpoint time).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	case has("--action"):
		switch value("--action") {
		case "checkpoint":
			_ = os.WriteFile(filepath.Join(stateDir, "stopped"), nil, 0o600)
			_ = os.WriteFile(filepath.Join(stateDir, "checkpoint-id"),
				[]byte(filepath.Base(value("--checkpoint-dir"))), 0o600)
		case "restore":
			if node == "T" {
				if !relayPendingRestore() {
					_ = os.WriteFile(filepath.Join(stateDir, "target-running"), nil, 0o600)
				}
			} else {
				_ = os.WriteFile(filepath.Join(stateDir, "source-rollback-running"), nil, 0o600)
			}
		}
	case filepath.Base(args[0]) == "cn-publish":
		if _, err := os.Stat(filepath.Join(stateDir, "fail-publish")); err == nil {
			os.Exit(1) // publish keeps failing on the source
		}
	case has("delete"):
		if node == "S" {
			os.Exit(1) // cleanup keeps failing on the source
		}
	}
}

func TestMigrateTargetOwnedNeverRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestration test builds and re-executes the CLI")
	}
	state := t.TempDir()
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
	cmd.Env = append(os.Environ(), "CN_MIGRATE_EXECUTOR=1", "GOCACHE="+os.Getenv("GOCACHE"))
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
	calls, _ := os.ReadFile(filepath.Join(state, "calls"))
	for _, line := range strings.Split(string(calls), "\n") {
		if strings.Contains(line, "rollback-restore") && strings.Contains(line, "\"S\"") {
			t.Fatalf("F2 regression: rollback-restore command sent to the source\n%s", report)
		}
	}
}

// cliReport is the subset of cn-migrate's -json report the orchestration
// tests assert on.
type cliReport struct {
	Sandbox    string `json:"sandbox"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	Checkpoint string `json:"checkpoint_dir"`
	Steps      []struct {
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
// command into the test log.
func runMigrate(t *testing.T, bin, state, nodes string, wait time.Duration) (int, cliReport, string) {
	t.Helper()
	executor := os.Args[0]
	tpl := executor + " -test.run=TestExecutorHelper -- " + state + " {node}"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-sandbox", "sbox-x", "-source", "S",
		"-exec", tpl,
		"-store", "fake",
		"-nodes", nodes,
		"-request-file", filepath.Join(state, "req.json"),
		"-bin", filepath.Join(state, "fakebin"),
		"-wait", wait.String(),
		"-json")
	cmd.Env = append(os.Environ(), "CN_MIGRATE_EXECUTOR=1", "GOCACHE="+os.Getenv("GOCACHE"))
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
				class = "delete"
			} else if hasToken(c.argv, "list") {
				class = "list"
			}
		case "checkpoint-restore":
			if hasToken(c.argv, "restore") {
				class = "restore"
			} else if hasToken(c.argv, "checkpoint") {
				class = "checkpoint"
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
	want := []step{{"list", false}, {"checkpoint", false}, {"publish", true}, {"rollback-restore", false}, {"publish", true}}
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
	assertCallSequence(t, state, []string{"S:list", "S:checkpoint", "S:publish", "S:restore"}, stdout)
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
	// list, checkpoint, publish, materialize, the killed restore, and
	// fail()'s 0ms summary line — nothing else may run.
	want := []step{{"list", false}, {"checkpoint", false}, {"publish", false}, {"materialize", false}, {"restore", true}, {"restore", true}}
	if !slices.EqualFunc(got, want, func(a, b step) bool { return a == b }) {
		t.Fatalf("report steps = %v, want %v (no fence-target/confirm-fenced/rollback-restore may appear)\n%s", got, want, stdout)
	}
	for _, banned := range []string{"fence-target", "confirm-fenced", "rollback-restore", "verify", "delete-source"} {
		for _, s := range report.Steps {
			if s.Step == banned {
				t.Fatalf("compensation command %q issued around an unknown target outcome\n%s", banned, stdout)
			}
		}
	}
	// First restore line = the executor command killed by -wait 1s; the
	// trailing line is fail()'s summary (0ms, detail == report.error).
	if took := report.Steps[4].TookMs; report.Steps[4].Failed && (took < 950 || took > 2000) {
		t.Fatalf("restore step took_ms = %d, want the 1s -wait kill (950–2000ms)\n%s", took, stdout)
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
	assertCallSequence(t, state, []string{"S:list", "S:checkpoint", "S:publish", "T:fetch", "T:restore"}, stdout)
}
