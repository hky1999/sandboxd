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

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// Deliberately does not implement StartFailureCleanupProver: a dispatch flag
// must not confuse admission rejection with an unproven runtime failure.
type restoreInvocationProbe struct {
	svc.FakeRuntimeHandler
	startCalls   int
	restoreCalls int
	startErr     error
	restoreErr   error
}

func (p *restoreInvocationProbe) Start(context.Context, svc.StartConfig) error {
	p.startCalls++
	return p.startErr
}

func (p *restoreInvocationProbe) Restore(context.Context, svc.StartConfig) error {
	p.restoreCalls++
	return p.restoreErr
}

func (*restoreInvocationProbe) Checkpoint(context.Context, svc.CheckpointConfig) error {
	return nil
}

func newRestoreInvocationService(t *testing.T, runtimeName string, handler svc.Handler) *sandboxService {
	t.Helper()
	service := newIntentTestService(t, handler)
	service.config.RuntimeConfig.RuntimeBinary[runtimeName] = "/fake/invocation-runtime"
	service.serviceHandler.Set(runtimeName, handler)
	return service
}

func TestFirecrackerRestorePreflightReportsNotInvoked(t *testing.T) {
	for _, name := range []string{"missing managed cgroup", "canceled memory slot"} {
		t.Run(name, func(t *testing.T) {
			probe := &restoreInvocationProbe{}
			service := newRestoreInvocationService(t, config.RuntimeNameFirecracker, probe)
			ctx := context.Background()
			if name == "canceled memory slot" {
				release, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
				require.NoError(t, err)
				defer release()
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			invoked, err := service.startSandboxRuntimeWithInvocation(ctx, config.RuntimeNameFirecracker, svc.StartConfig{
				ID:            "restore-preflight",
				CheckpointDir: "/unused/checkpoint",
			})
			require.Error(t, err)
			if name == "canceled memory slot" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorContains(t, err, "requires a managed cgroup")
			}
			require.False(t, invoked, "Restore was never entered")
			require.Zero(t, probe.startCalls)
			require.Zero(t, probe.restoreCalls)
		})
	}
}

func TestRuntimeInvocationTracksHandlerEntry(t *testing.T) {
	failure := errors.New("runtime failed after entry")
	tests := []struct {
		name          string
		runtimeName   string
		checkpointDir string
		runtimeErr    error
		wantStart     int
		wantRestore   int
	}{
		{name: "restore succeeds", runtimeName: config.RuntimeNameRunsc, checkpointDir: "/unused/checkpoint", wantRestore: 1},
		{name: "restore fails after entry", runtimeName: config.RuntimeNameRunsc, checkpointDir: "/unused/checkpoint", runtimeErr: failure, wantRestore: 1},
		{name: "restore cleanup pending stays raw", runtimeName: config.RuntimeNameRunsc, checkpointDir: "/unused/checkpoint", runtimeErr: svc.ErrStartCleanupPending, wantRestore: 1},
		{name: "start succeeds", runtimeName: config.RuntimeNameFirecracker, wantStart: 1},
		{name: "start fails after entry", runtimeName: config.RuntimeNameFirecracker, runtimeErr: failure, wantStart: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := &restoreInvocationProbe{startErr: test.runtimeErr, restoreErr: test.runtimeErr}
			service := newRestoreInvocationService(t, test.runtimeName, probe)
			invoked, err := service.startSandboxRuntimeWithInvocation(context.Background(), test.runtimeName, svc.StartConfig{
				ID:            "runtime-entry",
				CheckpointDir: test.checkpointDir,
			})
			require.True(t, invoked)
			if test.runtimeErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.runtimeErr)
			}
			require.Equal(t, test.wantStart, probe.startCalls)
			require.Equal(t, test.wantRestore, probe.restoreCalls)
		})
	}
}

func TestRestoreWithoutCapabilityReportsNotInvoked(t *testing.T) {
	service := newRestoreInvocationService(t, config.RuntimeNameRunsc, svc.NewFakeRuntimeHandler())
	invoked, err := service.startSandboxRuntimeWithInvocation(context.Background(), config.RuntimeNameRunsc, svc.StartConfig{
		ID:            "unsupported-restore",
		CheckpointDir: "/unused/checkpoint",
	})
	require.ErrorContains(t, err, "does not support checkpoint restore")
	require.False(t, invoked)
}
