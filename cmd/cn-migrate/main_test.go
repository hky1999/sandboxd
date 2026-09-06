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

// Orchestration regression for the F2 ownership phases, driven the same way
// the review reproduced the defect: a real cn-migrate binary built from
// this package, a fake executor that records every node command into a
// state directory while simulating node outcomes, and an in-process HTTP
// stand-in for the node catalog. The scenario: checkpoint succeeds, the
// target restores and reports RUNNING, then every source cleanup attempt
// fails — the migration must fail loudly WITHOUT issuing rollback-restore
// to the source, because resurrecting the source next to a running target
// recreates dual writers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutorHelper(t *testing.T) {
	// This test binary is re-executed as the node executor via -exec; when
	// invoked that way the args after "--" carry the state dir and node.
	if os.Getenv("CN_MIGRATE_EXECUTOR") == "" {
		t.Skip("direct run; serves as executor only under TestMigrateTargetOwnedNeverRollsBack")
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
				_ = os.WriteFile(filepath.Join(stateDir, "target-running"), nil, 0o600)
			} else {
				_ = os.WriteFile(filepath.Join(stateDir, "source-rollback-running"), nil, 0o600)
			}
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
