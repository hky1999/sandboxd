// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// Startup must also discover histories whose original metadata directory was
// removed before completion publication. Enumerate through the original held
// journal, validate every public record, then release retirementMu before taking
// physical locks. Absence without a complete original history proves nothing.
func (h *sandboxService) failedCreationRetirementSnapshots(ctx context.Context) ([]*runtime.SandboxMetadata, error) {
	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	j, err := h.openRetirementProgressJournalLocked()
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(j.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), j.path)
	defer directory.Close()
	entries, err := directory.ReadDir(retirementReceiptLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > retirementReceiptLimit {
		return nil, fmt.Errorf("retirement recovery exceeds the entry limit")
	}
	var result []*runtime.SandboxMetadata
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if name == ".lock" || strings.HasPrefix(name, ".progress-") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("unexpected retirement progress entry")
		}
		record, err := h.readRetirementProgressFileLocked(j, name)
		if err != nil || record == nil {
			return nil, fmt.Errorf("original retirement recovery record is unavailable: %v", err)
		}
		var metadata runtime.SandboxMetadata
		if err := proto.Unmarshal(record.Original, &metadata); err != nil {
			return nil, err
		}
		if metadata.PhysicalPhase == runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
			result = append(result, &metadata)
		}
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	return result, nil
}

// A completed receipt may be replayed while the ID belongs to another intent.
// Only the immutable original history can identify an old reservation to drop;
// the current cache's generation alone is never permission to release its ID.
func (h *sandboxService) forgetCompletedFailedCreationIntent(id, generation string) error {
	for _, current := range h.sandboxManager.ListPhysicalIntents() {
		if current.ID != id || current.Labels[resourceGenerationLabel] != generation {
			continue
		}
		record, err := h.readRetirementProgress(id, generation)
		if err != nil {
			return err
		}
		if record == nil || !record.RootPending || len(record.Steps) != len(retirementProgressSteps) {
			return nil
		}
		var original runtime.SandboxMetadata
		if err := proto.Unmarshal(record.Original, &original); err != nil {
			return err
		}
		if original.PhysicalPhase == runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
			return h.sandboxManager.ForgetRetiredPhysicalIntent(&original)
		}
	}
	return nil
}

// The caller holds the physical lock and has confirmed all original resource
// steps. Keep the original in-memory reservation until completion is durable;
// a failed removal must not discard the only remaining ownership snapshot.
func (h *sandboxService) finishFailedCreationRetirement(ctx context.Context, metadata *runtime.SandboxMetadata, progress *retirementProgress) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.verifyOriginalPhysicalIntent(metadata); err != nil {
		return err
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return err
	}
	progress.RootPending = true
	if err := h.writeRetirementProgress(progress); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root := filepath.Join(h.config.RootDir, "containers", metadata.ID)
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove original physical intent root: %w", err)
	}
	if present, err := h.verifyRetirementProgressRoot(progress, true); err != nil {
		return err
	} else if present {
		return fmt.Errorf("original physical intent root removal is unconfirmed")
	}
	if err := syncRetirementDirectory(filepath.Dir(root)); err != nil {
		return err
	}
	if err := h.completeRetirementProgressStep(progress, "root"); err != nil {
		return err
	}
	if err := h.writeRetirement(metadata.ID, progress.Generation, true); err != nil {
		return err
	}
	return h.sandboxManager.ForgetRetiredPhysicalIntent(metadata)
}
