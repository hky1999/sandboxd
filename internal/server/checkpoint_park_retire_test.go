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
	"errors"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
)

// parkRetireHandler simulates a runtime that does NOT terminate the sandbox
// after a completed dump (the deployed scheduler-line runsc build resumes
// tasks after save): the terminal state only appears when Delete runs. Each
// test wires onDeleted to decide what a Delete is allowed to accomplish.
type parkRetireHandler struct {
	*svc.FakeRuntimeHandler
	deleteCalls int
	deleteErr   error
	onDeleted   func()
}

func (h *parkRetireHandler) Delete(_ context.Context, sandboxID string) error {
	h.deleteCalls++
	if h.deleteErr != nil {
		return h.deleteErr
	}
	if h.onDeleted != nil {
		h.onDeleted()
	}
	return nil
}

func stageParkSource(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, sandboxMetadataFor(id)))
}

func sandboxMetadataFor(id string) *runtime.SandboxMetadata {
	return &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: config.RuntimeNameRunsc,
	}
}

// A source that exits on its own (upstream runsc semantics) must never see a
// forced delete.
func TestRetireParkedSourceAcceptsNaturalExit(t *testing.T) {
	handler := &parkRetireHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	const id = "sbox-park-retire-natural"
	stageParkSource(t, s, id)
	assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))

	assert.NoError(t, s.retireParkedSource(context.Background(), id, handler))
	assert.Equal(t, 0, handler.deleteCalls)
}

// A missing record is a real lookup failure, never a reason to destroy a
// runtime.
func TestRetireParkedSourcePropagatesLookupFailure(t *testing.T) {
	handler := &parkRetireHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})

	err := s.retireParkedSource(context.Background(), "sbox-park-retire-absent", handler)
	assert.ErrorIs(t, err, errord.ErrNotFound)
	assert.Equal(t, 0, handler.deleteCalls)
}

// The forced path destroys the runtime directly and succeeds once the manager
// observes the terminal state.
func TestForceRetireParkedSourceDeletesRuntimeAndObservesExit(t *testing.T) {
	handler := &parkRetireHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	const id = "sbox-park-retire-force"
	stageParkSource(t, s, id)
	handler.onDeleted = func() {
		assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	}

	assert.NoError(t, s.forceRetireParkedSource(context.Background(), id, handler))
	assert.Equal(t, 1, handler.deleteCalls)
}

// A failed forced delete must surface the compounded failure, not a success.
func TestForceRetireParkedSourceReportsDeleteFailure(t *testing.T) {
	handler := &parkRetireHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	const id = "sbox-park-retire-delete-fail"
	stageParkSource(t, s, id)
	handler.deleteErr = errors.New("runtime destroy refused")

	err := s.forceRetireParkedSource(context.Background(), id, handler)
	assert.ErrorContains(t, err, "forced retirement failed")
	assert.Equal(t, 1, handler.deleteCalls)
}

// A delete that returns nil but never produces a terminal state is still a
// failed retirement: the checkpoint attempt must not complete on it.
func TestForceRetireParkedSourceRequiresObservedExit(t *testing.T) {
	handler := &parkRetireHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: handler})
	const id = "sbox-park-retire-no-exit"
	stageParkSource(t, s, id)

	err := s.forceRetireParkedSource(context.Background(), id, handler)
	assert.ErrorContains(t, err, "did not observe exit after forced retirement")
	assert.Equal(t, 1, handler.deleteCalls)
}
