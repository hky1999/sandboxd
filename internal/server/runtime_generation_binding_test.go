// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/runtime/runsc"
	"github.com/stretchr/testify/require"
)

func TestRuntimeStartGenerationComesFromOriginalMetadata(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	config := svc.StartConfig{ID: "sbox-original", ResourceGeneration: "injected-field", Annotations: map[string]string{resourceGenerationLabel: "injected-annotation"}}
	metadata := &runtime.SandboxMetadata{ID: config.ID, Labels: map[string]string{resourceGenerationLabel: "generation-original"}}
	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config, metadata))
	require.Len(t, handler.starts, 1)
	require.Equal(t, "generation-original", handler.starts[0].ResourceGeneration)
	require.Equal(t, "injected-field", config.ResourceGeneration)
	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config, nil))
	require.Empty(t, handler.starts[1].ResourceGeneration, "legacy input cannot adopt caller-provided ownership")
}

func TestFailedCreationCannotDeleteNativeRuntimeWithAnotherGeneration(t *testing.T) {
	s, metadata, request := failedCreationRetirementFixture(t, &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()})
	root := filepath.Join(t.TempDir(), "platform", "root")
	marker := filepath.Join(t.TempDir(), "unexpected-runtime-delete")
	bin := filepath.Join(t.TempDir(), "controlled-runsc")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	list, err := json.Marshal([]map[string]any{{"ociVersion": "1.0.2", "id": metadata.ID, "status": "running", "pid": 987654321, "bundle": "/original/bundle"}})
	require.NoError(t, err)
	script := "#!/bin/sh\ncase \"$*\" in\n*' list --format json') printf '%s\\n' " + quote(string(list)) + ";;\n*) : > " + quote(marker) + "; exit 99;;\nesac\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0700))
	cfg := s.config
	cfg.RootDir = root
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(root, "filestore")
	cfg.RuntimeConfig.LoopDeviceDir = filepath.Join(root, "loop-devices")
	handler, err := runsc.NewHandler(cfg, bin, nil)
	require.NoError(t, err)
	s.serviceHandler.Set("runsc", handler)
	state, err := json.Marshal(map[string]any{
		"id": metadata.ID, "status": "running", "bundleDir": "/original/bundle",
		"sandbox": map[string]any{"id": metadata.ID, "pid": 987654321, "controlSocketPath": "/replacement/control.sock"},
		"spec":    map[string]any{"annotations": map[string]string{resourceGenerationLabel: "generation-replacement"}},
	})
	require.NoError(t, err)
	statePath := filepath.Join(root, "runsc", metadata.ID+"_sandbox:"+metadata.ID+".state")
	require.NoError(t, os.WriteFile(statePath, state, 0600))
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.ErrorContains(t, err, "runtime generation")
	require.NoFileExists(t, marker)
	saved, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.Equal(t, state, saved)
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.Empty(t, progress.Steps)
	require.Error(t, s.xpuMgr.(generationDeviceLeaseManager).ConfirmReleasedForGeneration(metadata.ID, metadata.Labels[resourceGenerationLabel]))
}

func TestRuntimeRestoreGenerationComesFromFreshTargetMetadata(t *testing.T) {
	for _, throughStart := range []bool{false, true} {
		handler := newCheckpointTestHandler()
		service := newTestService(t, map[string]svc.Handler{"runsc": handler})
		config := svc.StartConfig{ID: "sbox-restored", ResourceGeneration: "checkpoint-source-generation", CheckpointDir: "/unused/checkpoint"}
		metadata := &runtime.SandboxMetadata{ID: config.ID, Labels: map[string]string{resourceGenerationLabel: "fresh-target-generation"}}
		var err error
		if throughStart {
			err = service.startSandboxRuntime(context.Background(), "runsc", config, metadata)
		} else {
			err = service.restoreSandboxRuntime(context.Background(), "runsc", config, "/unused/checkpoint.img", metadata)
		}
		require.NoError(t, err)
		require.Len(t, handler.restores, 1)
		require.Equal(t, "fresh-target-generation", handler.restores[0].ResourceGeneration)
	}
}

func TestRuntimeDispatchRejectsMetadataFromAnotherSandbox(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	config := svc.StartConfig{ID: "sbox-original"}
	metadata := &runtime.SandboxMetadata{ID: "replacement", Labels: map[string]string{resourceGenerationLabel: "generation-replacement"}}
	require.ErrorContains(t, service.startSandboxRuntime(context.Background(), "runsc", config, metadata), "another sandbox")
	require.ErrorContains(t, service.restoreSandboxRuntime(context.Background(), "runsc", config, "/unused/checkpoint.img", metadata), "another sandbox")
	require.Empty(t, handler.starts)
	require.Empty(t, handler.restores)
}
