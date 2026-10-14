// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// This validator records the request after server admission, then stops before
// physical allocation. Both public entrypoints must apply the same restore
// policy before any runtime or allocator can see the request.
type checkpointAdmissionProbe struct {
	*checkpointTestHandler
	admitted *runtime.StartRequest
}

func (h *checkpointAdmissionProbe) ValidateStartRequest(req *runtime.StartRequest) error {
	h.admitted = proto.Clone(req).(*runtime.StartRequest)
	return errors.New("checkpoint admission probe stops before allocation")
}

func checkpointAdmissionService(t *testing.T) (*sandboxService, *checkpointAdmissionProbe) {
	t.Helper()
	handler := &checkpointAdmissionProbe{checkpointTestHandler: newCheckpointTestHandler()}
	service := newTestService(t, map[string]svc.Handler{"runsc": handler})
	service.config.DisableCgroup = false
	service.config.CPULimitMode = config.CPULimitModeQuota
	return service, handler
}

func checkpointAdmissionRequest(t *testing.T, dir string) *runtime.StartRequest {
	t.Helper()
	return &runtime.StartRequest{
		Runtime: "runsc",
		Rootfs: &runtime.RootfsConfig{Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{Path: t.TempDir()}},
		Resources:      map[string]float64{"CPU": 500, "Memory": 512},
		Labels:         map[string]string{elasticResourcesLabel: testPolicy},
		CheckpointInfo: &runtime.CheckpointInfo{CheckpointDir: dir},
	}
}

func TestCheckpointStartAdmissionUsesSavedElasticRestoreLimits(t *testing.T) {
	for _, api := range []string{"Start", "StartOperation"} {
		t.Run(api, func(t *testing.T) {
			service, handler := checkpointAdmissionService(t)
			dir := t.TempDir()
			writeElasticSidecar(t, dir, testPolicy, 389*1024*1024)
			request := checkpointAdmissionRequest(t, dir)
			original := proto.Clone(request)
			if api == "Start" {
				_, err := service.Start(context.Background(), request)
				require.ErrorContains(t, err, "checkpoint admission probe stops before allocation")
			} else {
				operation := startOperationRequest()
				operation.Start = request
				response, err := service.StartOperation(context.Background(), operation)
				require.NoError(t, err)
				require.Equal(t, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED, response.State)
				replay, err := service.GetStartOperation(context.Background(), startOperationQuery(operation))
				require.NoError(t, err)
				require.True(t, proto.Equal(response, replay))
			}
			require.NotNil(t, handler.admitted, "valid restore must reach runtime admission with its reserved ceiling")
			require.Equal(t, float64(512), handler.admitted.Resources["Memory"])
			require.Equal(t, float64(500), handler.admitted.Resources["CPU"])
			require.Equal(t, testPolicy, handler.admitted.Labels[elasticResourcesLabel])
			require.True(t, proto.Equal(original, request), "server must not mutate the caller request")
			require.Empty(t, service.sandboxManager.ListPhysicalIntents())
			require.Empty(t, handler.restores)
			require.Empty(t, handler.starts)
		})
	}
}

func TestCheckpointStartAdmissionKeepsSavedPolicyAndRejectsUnknownLimits(t *testing.T) {
	for _, kind := range []string{"source-ceiling", "source-policy-without-caller-label", "missing", "malformed", "unknown", "ordinary-start"} {
		t.Run(kind, func(t *testing.T) {
			service, handler := checkpointAdmissionService(t)
			dir := t.TempDir()
			writeElasticSidecar(t, dir, testPolicy, 389*1024*1024)
			request := checkpointAdmissionRequest(t, dir)
			switch kind {
			case "source-ceiling":
				request.Labels[elasticResourcesLabel] = `{"version":1,"CPU":{"initial":500,"ceiling":500},"Memory":{"initial":128,"ceiling":2048}}`
				request.Resources["Memory"] = 1024
			case "source-policy-without-caller-label":
				request.Labels = nil
			case "missing":
				require.NoError(t, os.Remove(filepath.Join(dir, resourceLimitsFile)))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "checkpoint.img"), []byte("fixture"), 0600))
				request.Resources["Memory"] = 128
			case "malformed":
				writeSidecar(t, dir, "invalid-json")
				request.Resources["Memory"] = 128
			case "unknown":
				writeSidecar(t, dir, `{"elastic_policy":"policy","memory_limit_bytes":407896064,"cpu_limits_known":true,"cpu_quota_usec":50000,"cpu_period_usec":100000}`)
				request.Resources["Memory"] = 128
			case "ordinary-start":
				request.CheckpointInfo = nil
			}
			_, err := service.Start(context.Background(), request)
			require.Error(t, err)
			if kind == "source-ceiling" || kind == "source-policy-without-caller-label" {
				require.ErrorContains(t, err, "checkpoint admission probe stops before allocation")
				require.NotNil(t, handler.admitted)
				require.Equal(t, testPolicy, handler.admitted.Labels[elasticResourcesLabel])
				expected := float64(512)
				if kind == "source-policy-without-caller-label" {
					expected = 389
				}
				require.Equal(t, expected, handler.admitted.Resources["Memory"])
			} else {
				require.Nil(t, handler.admitted, "invalid or unproven limits must reject before runtime admission")
			}
			require.Empty(t, service.sandboxManager.ListPhysicalIntents())
			require.Empty(t, handler.restores)
			require.Empty(t, handler.starts)
		})
	}
}
