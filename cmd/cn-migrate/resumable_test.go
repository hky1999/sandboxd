package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
				write("fail-checkpoint", "")
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
				os.Remove(filepath.Join(state, "fail-checkpoint"))
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
			if scenario != "target-replaced" && len(after) != len(before) {
				t.Fatal("unresolved/changed intent contacted node")
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
