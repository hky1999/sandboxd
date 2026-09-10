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
	"fmt"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// restoreRuntimeQueryTimeout bounds the read-only liveness query issued by an
// authoritative restore answer. The query runs under the target sandbox's
// physical resource lock, so the bound also bounds how long any competing
// create/delete/resize on that sandbox can be delayed by a slow runtime.
const restoreRuntimeQueryTimeout = 5 * time.Second

// observeRuntimeRunning is the READ-ONLY runtime fact behind authoritative
// replay answers: List the owning runtime handler and report whether it
// currently holds this sandbox in the running state. A sandbox absent from
// the listing means the runtime does not exist (false, nil). A listing
// failure proves nothing (false, err): the caller must refuse rather than
// guess. The query never mutates and never triggers cleanup.
func (h *sandboxService) observeRuntimeRunning(ctx context.Context, sandboxID, runtimeHandler string) (bool, error) {
	if h == nil || sandboxID == "" || runtimeHandler == "" {
		return false, fmt.Errorf("runtime liveness fact requires a sandbox and handler identity: %w",
			errord.ErrFailedPrecondition)
	}
	handler, ok := h.serviceHandler.Get(runtimeHandler)
	if !ok || handler == nil {
		return false, fmt.Errorf("runtime handler %q is unavailable for the liveness fact of sandbox %s: %w",
			runtimeHandler, sandboxID, errord.ErrFailedPrecondition)
	}
	queryCtx, cancel := context.WithTimeout(ctx, restoreRuntimeQueryTimeout)
	defer cancel()
	states, err := handler.List(queryCtx)
	if err != nil {
		return false, fmt.Errorf("runtime %q liveness fact is unobservable for sandbox %s: %w",
			runtimeHandler, sandboxID, err)
	}
	for _, state := range states {
		if state == nil || state.ID != sandboxID {
			continue
		}
		return state.Status == svc.SandboxStatusRunning, nil
	}
	return false, nil
}
