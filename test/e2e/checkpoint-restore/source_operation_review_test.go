package main

import (
	"errors"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"strings"
	"testing"
)

type reviewFailWriter struct{ err error }

func (w reviewFailWriter) Write(p []byte) (int, error) { return 0, w.err }
func TestReviewSourceOperationOutputFailure(t *testing.T) {
	want := errors.New("injected stdout failure")
	err := printCheckpointOperationStatus(&runtime.CheckpointOperationStatus{}, reviewFailWriter{want})
	if !errors.Is(err, want) {
		t.Fatalf("stdout failure lost: got %v, want %v", err, want)
	}
}
func TestReviewSourceOperationQueryMalformedSandbox(t *testing.T) {
	s := &runtime.CheckpointOperationStatus{OperationID: "op-review", SandboxID: "sbox-review", SourceGeneration: "generation", CheckpointDir: "/tmp/checkpoint", RequestDigest: strings.Repeat("a", 64), State: runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN}
	if err := validateCheckpointOperationRecordReply(s, "op-review"); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	s.SandboxID = "../invalid"
	if err := validateCheckpointOperationRecordReply(s, "op-review"); err == nil {
		t.Fatal("malformed persisted sandbox identity accepted")
	}
}
