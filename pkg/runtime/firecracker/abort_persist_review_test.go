package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewAbortingRetryPersistsBeforeResume(t *testing.T) {
	h, instance, api, id := checkpointOperationFixture(t, "gen-live")
	state := instance.snapshot()
	dir := t.TempDir()
	binding := testCheckpointOperationBinding("gen-live")
	dev, ino, err := claimFirecrackerCheckpointDirectory(dir, id, binding)
	if err != nil {
		t.Fatal(err)
	}
	birth, err := captureFirecrackerVMMBirthIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	record := buildFirecrackerCheckpointOperationIntent(binding, state, birth, dir, dev, ino)
	instance.setCheckpointOperation(record)
	if err = h.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	// First aborting write failed before committing: disk remains intent,
	// while the conservative hot witness already says aborting.
	record.Phase = firecrackerCheckpointOperationPhaseAborting
	instance.setCheckpointOperation(record)
	makeStateDirUnwritable(t, instance)
	defer makeStateDirWritable(instance)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = h.AbortCheckpointOperation(ctx, id, binding)
	if err == nil {
		t.Fatal("unwritable abort decision must fail")
	}
	if got := api.countVMState("Resumed"); got != 0 {
		t.Fatalf("retry resumed source %d times without making aborting durable", got)
	}
}

func TestReviewAbortRejectsHotIdentityDrift(t *testing.T) {
	for _, kind := range []string{"boot", "directory-inode", "claim-deleted"} {
		t.Run(kind, func(t *testing.T) {
			h, instance, api, id := checkpointOperationFixture(t, "gen-live")
			state := instance.snapshot()
			dir := t.TempDir()
			binding := testCheckpointOperationBinding("gen-live")
			dev, ino, err := claimFirecrackerCheckpointDirectory(dir, id, binding)
			if err != nil {
				t.Fatal(err)
			}
			birth, err := captureFirecrackerVMMBirthIdentity(state)
			if err != nil {
				t.Fatal(err)
			}
			record := buildFirecrackerCheckpointOperationIntent(binding, state, birth, dir, dev, ino)
			if kind == "boot" {
				record.VMMBootID = "11111111-2222-4333-8444-555555555555"
			} else if kind == "directory-inode" {
				record.DirectoryInode++
			} else {
				if err := os.Remove(filepath.Join(dir, firecrackerCheckpointClaimName())); err != nil {
					t.Fatal(err)
				}
			}
			instance.setCheckpointOperation(record)
			if err = h.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if err = h.AbortCheckpointOperation(ctx, id, binding); err == nil {
				t.Fatal("drift must be refused")
			}
			if kind == "claim-deleted" && !containsAll(err.Error(), "claim cannot be verified") {
				t.Fatalf("deleted claim refusal was masked by another mismatch: %v", err)
			}
			if got := api.countVMState("Resumed"); got != 0 {
				t.Fatalf("%s mismatch still resumed source %d times", kind, got)
			}
		})
	}
}
