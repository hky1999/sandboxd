// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// pauseResume resolves the target sandbox and its runtime's TaskFreezer
// capability. The sandbox is required to be running: pausing a stopped
// sandbox or resuming an unpaused one is a caller bug, and runsc would
// surface it only as an opaque control error.
func (h *sandboxService) freezerFor(id string) (svc.TaskFreezer, error) {
	if id == "" {
		return nil, checkpointGRPCError(fmt.Errorf("id is required: %w", errord.ErrInvalidArgument))
	}
	sandbox, err := h.sandboxManager.Get(id)
	if err != nil {
		return nil, checkpointGRPCError(err)
	}
	if sandbox.Metadata == nil || sandbox.Status == nil {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox %s metadata is incomplete: %w", id, errord.ErrFailedPrecondition))
	}
	if sandbox.Metadata.RuntimeHandler != config.RuntimeNameRunsc {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support pause: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, checkpointGRPCError(errord.ErrNotImplemented)
	}
	freezer, ok := handler.(svc.TaskFreezer)
	if !ok {
		return nil, checkpointGRPCError(fmt.Errorf("runtime %q does not support pause: %w",
			sandbox.Metadata.RuntimeHandler, errord.ErrNotImplemented))
	}
	if state := sandbox.Status.Get().State(); state != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, checkpointGRPCError(fmt.Errorf("sandbox %s is %s: %w", id, state, errord.ErrFailedPrecondition))
	}
	return freezer, nil
}

// Pause freezes all tasks in a running sandbox. Identity, network, and
// broker-side records survive; only task execution stops.
func (h *sandboxService) Pause(
	ctx context.Context,
	request *runtime.PauseRequest,
) (*runtime.PauseResponse, error) {
	if request == nil {
		return nil, checkpointGRPCError(fmt.Errorf("request is required: %w", errord.ErrInvalidArgument))
	}
	freezer, err := h.freezerFor(request.ID)
	if err != nil {
		return nil, err
	}
	if err := freezer.Pause(ctx, request.ID); err != nil {
		return nil, checkpointGRPCError(err)
	}
	return &runtime.PauseResponse{}, nil
}

// Resume unfreezes a previously paused sandbox.
func (h *sandboxService) Resume(
	ctx context.Context,
	request *runtime.PauseRequest,
) (*runtime.PauseResponse, error) {
	if request == nil {
		return nil, checkpointGRPCError(fmt.Errorf("request is required: %w", errord.ErrInvalidArgument))
	}
	freezer, err := h.freezerFor(request.ID)
	if err != nil {
		return nil, err
	}
	if err := freezer.Resume(ctx, request.ID); err != nil {
		return nil, checkpointGRPCError(err)
	}
	return &runtime.PauseResponse{}, nil
}
