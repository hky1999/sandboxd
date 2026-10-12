// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/runtime/runsc"
	"github.com/stretchr/testify/require"
)

func TestFailedCreationRuntimeSkippedStateCannotPublishRetirementOrRecycleResources(t *testing.T) {
	s, metadata, request := failedCreationRetirementFixture(t, &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()})
	root := filepath.Join(t.TempDir(), "platform", "root")
	marker := filepath.Join(t.TempDir(), "unexpected-runtime-mutation")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	bin := filepath.Join(t.TempDir(), "controlled-runsc")
	script := "#!/bin/sh\ncase \"$*\" in\n*' list --format json') printf '[]\\n';;\n*) : > " + quote(marker) + "; exit 99;;\nesac\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0700))
	cfg := s.config
	cfg.RootDir = root
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(root, "filestore")
	cfg.RuntimeConfig.LoopDeviceDir = filepath.Join(root, "loop-devices")
	handler, err := runsc.NewHandler(cfg, bin, nil)
	require.NoError(t, err)
	s.serviceHandler.Set("runsc", handler)
	state := filepath.Join(root, "runsc", metadata.ID+"_sandbox:"+metadata.ID+".state")
	require.NoError(t, os.WriteFile(state, []byte(`{"id":"`+metadata.ID+`","status":"running","sandbox":{"id":"`+metadata.ID+`","controlSocketPath":"/original/control.sock","pid":987654321}}`), 0600))
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: metadata.ID, ExpectedGeneration: metadata.Labels[resourceGenerationLabel]})
	require.ErrorContains(t, err, "omitted or invented")
	require.NoFileExists(t, marker, "incomplete inventory must stop before any runtime command that can mutate state")
	require.FileExists(t, state)
	require.DirExists(t, filepath.Join(s.config.RootDir, "containers", metadata.ID))
	require.Len(t, s.sandboxManager.ListPhysicalIntents(), 1)
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	progress, err := s.readRetirementProgress(metadata.ID, metadata.Labels[resourceGenerationLabel])
	require.NoError(t, err)
	require.Empty(t, progress.Steps)
	require.Error(t, s.xpuMgr.(generationDeviceLeaseManager).ConfirmReleasedForGeneration(metadata.ID, metadata.Labels[resourceGenerationLabel]))
}
