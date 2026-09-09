package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewMappedSourcePath(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "normal"
		if lost {
			name = "lost-reply"
		}
		t.Run(name, func(t *testing.T) {
			state, journal, write := stageState(t)
			write("map-source-path", "")
			if lost {
				write("lose-checkpoint-reply", "")
			}
			args := []string{"-journal", journal, "-migration-id", "mapped1"}
			code, _, out := runMigrate(t, buildCnMigrate(t), state, catalogStandIn(t, state), 10*time.Second, args...)
			if code != 0 {
				t.Fatalf("mapped source request rejected: %s", out)
			}
			if journalField(t, journal, "stage") != stageDone {
				t.Fatal("migration did not finish")
			}
			if n := fakeReadCount(t, state, "source-checkpoint-executions"); n != 1 {
				t.Fatalf("executions=%d, want 1", n)
			}
			found := false
			for _, c := range readCalls(t, state) {
				if strings.Contains(c.argv, "--operation-id checkpoint-mapped1") {
					found = true
				}
			}
			if !found {
				t.Fatal("source operation identity absent")
			}
		})
	}
}

func TestReviewMappedSourcePathDriftRefusesReplay(t *testing.T) {
	state, journal, write := stageState(t)
	write("map-source-path", "")
	write("lose-checkpoint-reply", "")
	write("fail-checkpoint-query", "")
	args := []string{"-journal", journal, "-migration-id", "mapped-drift"}
	bin := buildCnMigrate(t)
	nodes := catalogStandIn(t, state)
	code, _, out := runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 || journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("setup did not remain issued: %s", out)
	}
	for _, name := range []string{"map-source-path", "fail-checkpoint-query"} {
		if err := os.Remove(filepath.Join(state, name)); err != nil {
			t.Fatal(err)
		}
	}
	code, _, out = runMigrate(t, bin, state, nodes, 10*time.Second, args...)
	if code != 1 || journalField(t, journal, "stage") != stageCheckpointIssued {
		t.Fatalf("changed mapping was accepted: %s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "checkpoint-op-reuse-refused")); err != nil {
		t.Fatal("changed physical payload was not refused by operation binding", err)
	}
	if n := fakeReadCount(t, state, "source-checkpoint-executions"); n != 1 {
		t.Fatalf("executions=%d, want 1", n)
	}
	for _, c := range readCalls(t, state) {
		if c.node == "T" {
			t.Fatalf("target called after mapping drift: %s", c.argv)
		}
	}
}
