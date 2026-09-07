package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/checkpoint"
	"github.com/inclusionAI/sandboxd/internal/checkpointstate"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestCheckpointRevalidatesQueuedPhysicalGenerationBeforePublishing(t *testing.T) {
	h, _, _ := newResizeService(t)
	h.checkpointState = checkpointstate.NewCoordinator()
	key := checkpointstate.CheckpointKey{SandboxID: "elastic", CheckpointID: "queued-checkpoint"}
	attempt, execute, err := h.checkpointState.BeginCheckpoint(key, "fingerprint")
	if err != nil || !execute {
		t.Fatalf("begin: execute=%v err=%v", execute, err)
	}
	dir := filepath.Join(t.TempDir(), "checkpoint")
	source := checkpoint.SourceIdentity{CheckpointID: key.CheckpointID, SourceID: key.SandboxID, Runtime: "runsc", RootfsSHA256: strings.Repeat("a", 64), SourceGeneration: "generation-before-replacement"}
	// The command captured an old generation before acquiring the lock. A nil
	// runtime handler also ensures rejection happens before any physical call.
	h.executeCheckpoint(context.Background(), dir, key, nil, source, svc.CheckpointOptions{}, attempt)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := attempt.Wait(ctx); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("changed generation: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale command created artifact: %v", err)
	}
}
