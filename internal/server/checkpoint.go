// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type checkpointDirectory struct {
	path    string
	created bool
}

func (h *sandboxService) Checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
) (*runtime.CheckpointResponse, error) {
	return h.checkpoint(ctx, request, "")
}

// CheckpointIfGeneration checkpoints the source sandbox only while it still
// carries the caller's expected server-assigned resource generation. The
// expectation is validated inside the shared checkpoint path while the
// per-ID physical lock is held — never by a separate Get followed by an
// unguarded checkpoint — so a stale or missing generation is rejected before
// the output directory is allocated or the runtime handler is invoked. This
// is an admission precondition, not a durable migration transaction: it
// neither fences later requests nor publishes a persistent receipt.
func (h *sandboxService) CheckpointIfGeneration(
	ctx context.Context,
	request *runtime.CheckpointIfGenerationRequest,
) (*runtime.CheckpointResponse, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "checkpoint request is nil")
	}
	if request.Checkpoint == nil {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"checkpoint request is required",
		)
	}
	if strings.TrimSpace(request.ExpectedGeneration) == "" {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"expected_generation is required",
		)
	}
	if len(request.ExpectedGeneration) > 256 {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"expected_generation exceeds 256 bytes",
		)
	}
	return h.checkpoint(ctx, request.Checkpoint, request.ExpectedGeneration)
}

// checkpoint is the shared implementation of the legacy and conditional RPCs.
// An empty expectedGeneration keeps the legacy unconditional semantics; when
// set, the sandbox's current resource generation must equal it exactly (the
// value is never trimmed), checked after the metadata is read under the
// physical lock and before any checkpoint side effect.
func (h *sandboxService) checkpoint(
	ctx context.Context,
	request *runtime.CheckpointRequest,
	expectedGeneration string,
) (*runtime.CheckpointResponse, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "checkpoint request is nil")
	}
	if strings.TrimSpace(request.ID) == "" {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox ID is required")
	}
	if request.TimeoutSeconds == 0 {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"checkpoint timeout_seconds must be greater than zero",
		)
	}

	// Fail fast on an in-flight checkpoint before waiting for the physical
	// lock, so a duplicate request is rejected instead of queueing behind the
	// operation it duplicates.
	if !h.beginCheckpoint(request.ID) {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint is already in progress for sandbox %s",
			request.ID,
		)
	}
	defer h.finishCheckpoint(request.ID)

	// The request timeout bounds the whole operation, including the queue
	// wait for the physical lock: a caller that cannot be cancelled (for
	// example a Background RPC) must not queue indefinitely behind a
	// long-running delete or start for the same ID.
	checkpointCtx, cancel := context.WithTimeout(
		ctx,
		time.Duration(request.TimeoutSeconds)*time.Second,
	)
	defer cancel()

	// Serialize the physical checkpoint against start and delete for this ID.
	// The source state checks and the runtime checkpoint itself run under the
	// lock, so a concurrent delete cannot retire the sandbox mid-checkpoint.
	// A queue timeout returns before any output directory is allocated or the
	// runtime is invoked.
	unlock, lockErr := h.resourceLocks.acquire(checkpointCtx, request.ID)
	if lockErr != nil {
		return nil, errord.ToGRPC(lockErr)
	}
	defer unlock()

	// A pending start intent means the ID's runtime state is undetermined;
	// checkpointing must not touch it. Refuse explicitly instead of failing
	// on the missing sandbox metadata below.
	if h.startIntents.Pending(request.ID) {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s is protected by a pending start intent; reconcile the retained start first",
			request.ID,
		)
	}

	sandbox, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if sandbox.Metadata == nil || sandbox.Metadata.RuntimeHandler == "" {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s has no runtime metadata",
			request.ID,
		)
	}

	// Conditional checkpoint admission: the incarnation identity is compared
	// while the physical lock is held, from the just-read metadata, and before
	// the output directory is allocated or any handler is invoked. A missing
	// or changed label is a hard rejection with zero side effects; the exact
	// string is used, without trimming the caller's expectation.
	if expectedGeneration != "" &&
		sandbox.Metadata.Labels[resourceGenerationLabel] != expectedGeneration {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s resource generation changed before checkpoint",
			request.ID,
		)
	}
	if sandbox.Status == nil ||
		sandbox.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s is not running",
			request.ID,
		)
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, errord.ToGRPC(errord.ErrNotImplemented)
	}
	checkpointHandler, ok := handler.(svc.CheckpointHandler)
	if !ok {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support checkpoint",
			sandbox.Metadata.RuntimeHandler,
		)
	}

	directory, err := prepareCheckpointOutputDirectory(request.CheckpointDir)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}

	cgroupPath := ""
	var resources *runtime.LinuxSandboxResources
	if sandbox.Metadata.RuntimeHandler == config.RuntimeNameFirecracker {
		resource, resourceErr := h.sandboxManager.CollectResourceByID(request.ID)
		if resourceErr != nil {
			_ = directory.cleanup()
			return nil, errord.ToGRPC(resourceErr)
		}
		cgroupPath = resource.Resources[config.ResourceNameCgroup]
		resources = checkpointGuestMemoryResources(sandbox.Spec)
		if resources == nil {
			resources = sandbox.Status.Get().Resources
		}
	}
	// runtimeCheckpointEntered flips immediately before the runtime checkpoint
	// call inside the memory-wrapper callback, and marks the boundary for the
	// output directory: past this point the runtime may have sealed artifacts
	// that a later step of its own can still fail (Firecracker seals and stops
	// the VMM before confirming the uffd handler exit). The callback always
	// runs synchronously on this goroutine, so the flag is written before
	// withTransientFirecrackerCheckpointMemory returns and read only after it.
	runtimeCheckpointEntered := false
	err = h.withTransientFirecrackerCheckpointMemory(
		checkpointCtx,
		sandbox.Metadata.RuntimeHandler,
		request.ID,
		cgroupPath,
		resources,
		handler,
		true,
		func() error {
			runtimeCheckpointEntered = true
			return checkpointHandler.Checkpoint(checkpointCtx, svc.CheckpointConfig{
				ID:           request.ID,
				Directory:    directory.path,
				CgroupPath:   cgroupPath,
				Compress:     request.Compress,
				LeaveRunning: request.LeaveRunning,
				SnapshotType: request.SnapshotType,
			})
		},
	)
	if err != nil {
		if checkpointCtx.Err() != nil {
			err = checkpointCtx.Err()
		}
		if runtimeCheckpointEntered {
			// The runtime checkpoint was entered, so this error proves
			// nothing about the artifacts: the runtime may already have
			// sealed a complete, restorable checkpoint and stopped the
			// source before its own finishing steps failed. Removing the
			// output here could destroy sealed artifacts, so the directory
			// is kept for inspection or manual restore and the error must
			// report the unknown outcome. The decision never consults the
			// manifest or the source state: neither is a success proof.
			return nil, errord.ToGRPC(fmt.Errorf(
				"checkpoint sandbox %s failed; checkpoint outcome is unknown and artifacts are retained in %s; "+
					"source sandbox state is not guaranteed: %w",
				request.ID,
				directory.path,
				err,
			))
		}
		// The runtime was never invoked, so no artifact can exist: only this
		// attempt's partial output is cleaned. cleanup removes a leaf created
		// for this attempt and empties a caller-provided leaf while
		// preserving the directory itself.
		operationErr := fmt.Errorf(
			"checkpoint sandbox %s failed before the runtime checkpoint was entered; "+
				"source sandbox state is not guaranteed: %w",
			request.ID,
			err,
		)
		if cleanupErr := directory.cleanup(); cleanupErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf(
				"clean checkpoint residuals in %s: %w",
				directory.path,
				cleanupErr,
			))
		}
		return nil, errord.ToGRPC(operationErr)
	}
	return &runtime.CheckpointResponse{}, nil
}

// checkpointGuestMemoryResources returns the guest-visible limit persisted in
// config.json. Unlike the live cgroup limit, this value cannot be confused
// with transient host checkpoint headroom left behind by a daemon restart.
func checkpointGuestMemoryResources(
	sandboxSpec *specs.Spec,
) *runtime.LinuxSandboxResources {
	if sandboxSpec == nil || sandboxSpec.Linux == nil ||
		sandboxSpec.Linux.Resources == nil ||
		sandboxSpec.Linux.Resources.Memory == nil ||
		sandboxSpec.Linux.Resources.Memory.Limit == nil ||
		*sandboxSpec.Linux.Resources.Memory.Limit <= 0 {
		return nil
	}
	resources := &runtime.LinuxSandboxResources{
		MemoryLimitInBytes: *sandboxSpec.Linux.Resources.Memory.Limit,
	}
	if swap := sandboxSpec.Linux.Resources.Memory.Swap; swap != nil {
		resources.MemorySwapLimitInBytes = *swap
	}
	return resources
}

func (h *sandboxService) beginCheckpoint(id string) bool {
	h.checkpointMu.Lock()
	defer h.checkpointMu.Unlock()
	if h.checkpointing == nil {
		h.checkpointing = make(map[string]struct{})
	}
	if _, ok := h.checkpointing[id]; ok {
		return false
	}
	h.checkpointing[id] = struct{}{}
	return true
}

func (h *sandboxService) finishCheckpoint(id string) {
	h.checkpointMu.Lock()
	delete(h.checkpointing, id)
	h.checkpointMu.Unlock()
}

func prepareCheckpointOutputDirectory(path string) (*checkpointDirectory, error) {
	clean, err := validateCheckpointPath(path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	switch {
	case err == nil:
		if !info.IsDir() {
			return nil, fmt.Errorf(
				"checkpoint directory %s is not a directory: %w",
				clean,
				errord.ErrInvalidArgument,
			)
		}
		entries, readErr := os.ReadDir(clean)
		if readErr != nil {
			return nil, fmt.Errorf("read checkpoint directory %s: %w", clean, readErr)
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf(
				"checkpoint directory %s is not empty: %w",
				clean,
				errord.ErrFailedPrecondition,
			)
		}
		return &checkpointDirectory{path: clean}, nil
	case errors.Is(err, os.ErrNotExist):
		parent := filepath.Dir(clean)
		if _, parentErr := validateCheckpointPath(parent, true); parentErr != nil {
			return nil, fmt.Errorf("invalid checkpoint parent directory: %w", parentErr)
		}
		if mkdirErr := os.Mkdir(clean, 0700); mkdirErr != nil {
			return nil, fmt.Errorf("create checkpoint directory %s: %w", clean, mkdirErr)
		}
		return &checkpointDirectory{path: clean, created: true}, nil
	default:
		return nil, fmt.Errorf("inspect checkpoint directory %s: %w", clean, err)
	}
}

func validateCheckpointInputDirectory(path string) (string, error) {
	clean, err := validateCheckpointPath(path, true)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return "", fmt.Errorf("read checkpoint directory %s: %w", clean, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf(
			"checkpoint directory %s is empty: %w",
			clean,
			errord.ErrFailedPrecondition,
		)
	}
	return clean, nil
}

func validateCheckpointPath(path string, mustExist bool) (string, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf(
			"checkpoint directory must be an absolute path: %w",
			errord.ErrInvalidArgument,
		)
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("checkpoint directory cannot be root: %w", errord.ErrInvalidArgument)
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && !mustExist && index == len(parts)-1 {
			return clean, nil
		}
		if err != nil {
			return "", fmt.Errorf("inspect checkpoint path %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("checkpoint path %s is a symbolic link: %w", current, errord.ErrInvalidArgument)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("checkpoint path %s is not a directory: %w", current, errord.ErrInvalidArgument)
		}
	}
	return clean, nil
}

func (directory *checkpointDirectory) cleanup() error {
	if directory.created {
		return os.RemoveAll(directory.path)
	}
	info, err := os.Lstat(directory.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("checkpoint path changed during cleanup")
	}
	entries, err := os.ReadDir(directory.path)
	if err != nil {
		return err
	}
	var cleanupErr error
	for _, entry := range entries {
		cleanupErr = errors.Join(cleanupErr, os.RemoveAll(filepath.Join(directory.path, entry.Name())))
	}
	return cleanupErr
}
