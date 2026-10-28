package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func checkpointSourceWithResourceRevision(t *testing.T, id string, revision uint64) checkpoint.SourceIdentity {
	t.Helper()
	source := checkpoint.SourceIdentity{CheckpointID: id, SourceID: "elastic", Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64), SourceGeneration: "generation-1", LeaveRunning: true}
	data, err := json.Marshal(map[string]uint64{"SourceResourceRevision": revision})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func TestCheckpointRejectsSourceRevisionChangedBeforePhysicalLock(t *testing.T) {
	h, _, resize := newResizeService(t)
	h.checkpointState = checkpointstate.NewCoordinator()
	source := checkpointSourceWithResourceRevision(t, "old-revision", 1)
	if _, err := h.ResizeResources(context.Background(), resize); err != nil {
		t.Fatal(err)
	}
	key := checkpointstate.CheckpointKey{SandboxID: "elastic", CheckpointID: source.CheckpointID}
	attempt, execute, err := h.checkpointState.BeginCheckpoint(key, "original-capture")
	if err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	handler := newCheckpointTestHandler()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	h.executeCheckpoint(context.Background(), directory, key, handler, handler, source, svc.CheckpointOptions{LeaveRunning: true}, attempt)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = attempt.Wait(ctx)
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Errorf("stale original revision was not rejected: %v", err)
	}
	handler.mu.Lock()
	calls := len(handler.checkpoints)
	handler.mu.Unlock()
	if calls != 0 {
		t.Errorf("stale original revision invoked physical checkpoint %d times", calls)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale source published artifact: %v", err)
	}
}

func TestCheckpointRejectsUnknownOriginalResourceRevision(t *testing.T) {
	h, _, _ := newResizeService(t)
	h.checkpointState = checkpointstate.NewCoordinator()
	_, journal := h.resourceStatePath("elastic", "generation-1")
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	source := checkpointSourceWithResourceRevision(t, "unknown-revision", 1)
	key := checkpointstate.CheckpointKey{SandboxID: "elastic", CheckpointID: source.CheckpointID}
	attempt, execute, err := h.checkpointState.BeginCheckpoint(key, "unknown-capture")
	if err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	handler := newCheckpointTestHandler()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	h.executeCheckpoint(context.Background(), directory, key, handler, handler, source, svc.CheckpointOptions{LeaveRunning: true}, attempt)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = attempt.Wait(ctx)
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Errorf("unknown original revision was not rejected: %v", err)
	}
	handler.mu.Lock()
	calls := len(handler.checkpoints)
	handler.mu.Unlock()
	if calls != 0 {
		t.Errorf("unknown original revision invoked physical checkpoint %d times", calls)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unknown source published artifact: %v", err)
	}
}

func TestResourceConditionReplayUsesOnlyItsOriginalCommittedArtifact(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{"runsc": newCheckpointTestHandler()})
	source := checkpoint.SourceIdentity{CheckpointID: "original-resource-condition", SourceID: "retired-source", SourceGeneration: "physical-generation", SourceResourceRevision: 7, Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64)}
	directory := filepath.Join(h.config.RootDir, "checkpoints", source.CheckpointID)
	if _, err := checkpoint.PublishAt(directory, source, func(image string) error { return os.WriteFile(image, []byte("original memory"), 0600) }); err != nil {
		t.Fatal(err)
	}
	command := &runtime.CheckpointRequest{ID: source.SourceID, CheckpointID: source.CheckpointID, CheckpointDir: directory}
	reply, err := h.CheckpointIfResources(context.Background(), &runtime.CheckpointIfResourcesRequest{Checkpoint: command, ExpectedGeneration: source.SourceGeneration, ExpectedRevision: 7})
	if err != nil || !reply.Success || reply.SourceResourceRevision != 7 || reply.SourceGeneration != source.SourceGeneration {
		t.Fatalf("original complete replay failed: reply=%v err=%v", reply, err)
	}
	for _, revision := range []uint64{0, 8} {
		if _, err = h.CheckpointIfResources(context.Background(), &runtime.CheckpointIfResourcesRequest{Checkpoint: command, ExpectedGeneration: source.SourceGeneration, ExpectedRevision: revision}); err == nil {
			t.Fatalf("adopted different or missing original revision %d", revision)
		}
	}
	if _, err = h.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{Checkpoint: command, ExpectedGeneration: source.SourceGeneration}); err == nil {
		t.Fatal("guarded original artifact downgraded to generation-only replay")
	}
}
