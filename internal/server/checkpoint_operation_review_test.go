package server

import (
	"context"
	"encoding/json"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
)

func reviewCheckpointRecord() *checkpointOperationRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &checkpointOperationRecord{Version: 1, OperationID: "review-op", SandboxID: "sbox-review-op", Generation: "generation", Runtime: config.RuntimeNameFirecracker, CheckpointDir: "/tmp/review-checkpoint", RequestDigest: strings.Repeat("a", 64), Phase: checkpointOperationPhaseSucceeded, Artifact: &checkpointOperationArtifact{RootDigest: strings.Repeat("b", 64), Scheme: "v2:manifest+sidecar-roots"}, CreatedAt: now, UpdatedAt: now}
}

func TestReviewCheckpointRecordRejectsInvalidIdentity(t *testing.T) {
	if err := validateCheckpointOperationRecord(reviewCheckpointRecord()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*checkpointOperationRecord)
	}{
		{"request digest nonhex", func(r *checkpointOperationRecord) { r.RequestDigest = strings.Repeat("z", 64) }},
		{"artifact digest nonhex", func(r *checkpointOperationRecord) { r.Artifact.RootDigest = strings.Repeat("z", 64) }},
		{"blank generation", func(r *checkpointOperationRecord) { r.Generation = " " }},
		{"malformed runtime", func(r *checkpointOperationRecord) { r.Runtime = "../runc" }},
		{"unsupported root scheme", func(r *checkpointOperationRecord) { r.Artifact.Scheme = "unknown-root" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewCheckpointRecord()
			tc.change(r)
			if err := validateCheckpointOperationRecord(r); err == nil {
				t.Fatal("invalid persisted identity accepted")
			}
		})
	}
}

func TestReviewCheckpointOperationRejectsExcessiveTimeoutBeforeLookup(t *testing.T) {
	h := &sandboxService{}
	h.recoveryReady.Store(true)
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("excessive timeout reached source lookup instead of validation: %v", p)
		}
	}()
	_, err := h.CheckpointWithOperation(context.Background(), &runtime.CheckpointWithOperationRequest{OperationID: "review-timeout", ExpectedGeneration: "generation", Checkpoint: &runtime.CheckpointRequest{ID: "sbox-review-timeout", CheckpointDir: "/tmp/review-timeout", TimeoutSeconds: 601}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestReviewCheckpointRecordFileKinds(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "directory", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			r := reviewCheckpointRecord()
			path := checkpointOperationPath(dir, r.OperationID)
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "regular":
				err = os.WriteFile(path, data, 0600)
			case "symlink":
				target := filepath.Join(dir, "target")
				if err = os.WriteFile(target, data, 0600); err == nil {
					err = os.Symlink(target, path)
				}
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "oversize":
				err = os.WriteFile(path, make([]byte, checkpointOperationMaxBytes+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = readCheckpointOperationRecord(dir, r.OperationID)
			if (err == nil) != (kind == "regular") {
				t.Fatalf("kind %s: %v", kind, err)
			}
		})
	}
}
