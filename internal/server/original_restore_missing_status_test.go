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
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// The missing-status fabrication: LoadStatus invents StartedAt=now when the
// status file does not exist, so a cold-loaded record whose runtime is long
// gone still reports SANDBOX_STATE_RUNNING. The restore replay lookup is an
// authoritative query and must not answer success on that cached RUNNING —
// it additionally requires a read-only runtime fact that the sandbox is
// actually running (F8 draft: "权威查询必须增加只读 runtime 事实核对").

// stageFabricatedRunning persists full metadata on disk (COMMITTED, restore
// identity, generation label) without any status file, then cold-loads it so
// the in-memory record carries the fabricated RUNNING status.
func stageFabricatedRunning(t *testing.T, s *sandboxService, id string) *runtime.RestoreIdentity {
	t.Helper()
	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-fabricated", RequestSha256: "sha-fabricated"}
	require.NoError(t, s.sandboxManager.PersistMetadata(id, &runtime.SandboxMetadata{
		ID:              id,
		RuntimeHandler:  "runsc",
		Labels:          map[string]string{resourceGenerationLabel: "generation-fabricated"},
		Ports:           []string{},
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
	}))
	// Cold load path: loadSandbox -> LoadStatus -> missing status file is
	// fabricated as RUNNING (pkg/sandbox/status.go LoadStatus).
	require.NoError(t, s.sandboxManager.ActivateMetadata(id))
	loaded, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, runtime.SandboxState_SANDBOX_STATE_RUNNING, loaded.Status.Get().State())
	return identity
}

func TestRestoreReplayRefusesFabricatedRunningWithoutRuntimeFact(t *testing.T) {
	// FakeRuntimeHandler.List reports no runtime at all: the fabricated
	// RUNNING must NOT become a successful idempotent replay.
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-fabricated-running"
	identity := stageFabricatedRunning(t, s, id)

	_, found, err := s.existingRestorePhysicalFact(context.Background(),
		&runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, identity)

	// RED today: found==true, err==nil — the replay grants a live response
	// for a sandbox whose runtime does not exist.
	require.Error(t, err, "fabricated RUNNING without a runtime fact must not answer replay success")
	require.Contains(t, err.Error(), "runtime")
	// The record exists; the answer is refused. found stays true per the
	// lookup's convention (record present, replay denied).
	require.True(t, found)
}

// runtimeFactHandler lets each test pin the exact read-only runtime fact the
// observation query will see.
type runtimeFactHandler struct {
	svc.Handler
	states []*svc.State
	err    error
}

func (h *runtimeFactHandler) List(ctx context.Context) ([]*svc.State, error) {
	return h.states, h.err
}

func TestRestoreReplayAcceptsFabricatedStatusWhenRuntimeFactConfirms(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": &runtimeFactHandler{
		Handler: svc.NewFakeRuntimeHandler(),
		states:  []*svc.State{{ID: "sbox-fabricated-confirmed", Status: svc.SandboxStatusRunning}},
	}})
	const id = "sbox-fabricated-confirmed"
	identity := stageFabricatedRunning(t, s, id)

	resp, found, err := s.existingRestorePhysicalFact(context.Background(),
		&runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, identity)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "generation-fabricated", resp.ResourceGeneration)
}

func TestRestoreReplayRefusesWhenRuntimeFactReportsStopped(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": &runtimeFactHandler{
		Handler: svc.NewFakeRuntimeHandler(),
		states:  []*svc.State{{ID: "sbox-fabricated-stopped", Status: svc.SandboxStatusExited}},
	}})
	const id = "sbox-fabricated-stopped"
	identity := stageFabricatedRunning(t, s, id)

	_, found, err := s.existingRestorePhysicalFact(context.Background(),
		&runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, identity)
	require.Error(t, err)
	require.Contains(t, err.Error(), "runtime")
	require.True(t, found)
}

func TestRestoreReplayRefusesWhenRuntimeFactUnobservable(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": &runtimeFactHandler{
		Handler: svc.NewFakeRuntimeHandler(),
		err:     errors.New("runtime list failed"),
	}})
	const id = "sbox-fabricated-unobservable"
	identity := stageFabricatedRunning(t, s, id)

	// An unreadable fact proves nothing: conservative refusal, never success.
	_, found, err := s.existingRestorePhysicalFact(context.Background(),
		&runtime.StartRequest{SandboxID: id, Runtime: "runsc"}, identity)
	require.Error(t, err)
	require.True(t, found)
}
