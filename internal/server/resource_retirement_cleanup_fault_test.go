// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

func TestRetiredResourceStateUnlinkFailureCanRetry(t *testing.T) {
	h, c, path, raw := retiredResourceStateFixture(t)
	restoreRetiredResourceState(t, path, raw)
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	h.serviceHandler.Set("runsc", handler)
	request := &runtime.DeleteIfGenerationRequest{ID: "elastic", ExpectedGeneration: "generation-1"}
	freezeWrites, memoryWrites := c.freezeWrites, c.memoryWrites
	patch := gomonkey.ApplyFuncReturn(os.Remove, &os.PathError{Op: "remove", Path: path, Err: syscall.EIO})
	t.Cleanup(patch.Reset)
	_, err := h.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err, "a metadata unlink failure does not invalidate completed physical retirement")
	after, err := os.ReadFile(path)
	require.NoError(t, err, "the failed unlink must leave the original record")
	require.Equal(t, raw, after)
	patch.Reset()
	response, err := h.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "generation-1", response.RetiredGeneration)
	require.NoFileExists(t, path)
	require.Zero(t, handler.calls)
	require.Equal(t, freezeWrites, c.freezeWrites)
	require.Equal(t, memoryWrites, c.memoryWrites)
}

func TestRetiredResourceStateMissingRecordRetriesDirectorySync(t *testing.T) {
	h, _, path, _ := retiredResourceStateFixture(t)
	require.NoFileExists(t, path)
	unlock, err := h.resourceLocks.acquire(context.Background(), "elastic")
	require.NoError(t, err)
	defer unlock()
	receipt, err := h.readRetirement("elastic", "generation-1")
	require.NoError(t, err)
	require.True(t, receipt.Complete)
	patch := gomonkey.ApplyFuncReturn(syncRetirementDirectory, syscall.EIO)
	t.Cleanup(patch.Reset)
	require.ErrorIs(t, h.removeRetiredResourceOperationState("elastic", "generation-1"), syscall.EIO,
		"missing file must not hide the unconfirmed directory sync")
	patch.Reset()
	require.NoError(t, h.removeRetiredResourceOperationState("elastic", "generation-1"))
	require.NoFileExists(t, path)
}

func TestRetiredResourceStateFailedCreationCompletionReclaims(t *testing.T) {
	handler := &failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	h, metadata, _ := failedCreationRetirementFixture(t, handler)
	generation := metadata.Labels[resourceGenerationLabel]
	state := &resourceOperationState{
		SchemaVersion: resourceStateSchemaVersion,
		SandboxID:     metadata.ID, ResourceGeneration: generation,
		CgroupPath: "private-prepared-incarnation", CgroupInode: 17, CgroupDevice: 3,
		Revision: 1, CreatedAtUnixMs: time.Now().UnixMilli(),
	}
	require.NoError(t, h.saveResourceOperationState(state))
	_, path := h.resourceStatePath(metadata.ID, generation)
	require.NoError(t, h.reconcilePhysicalIntent(context.Background(), metadata))
	receipt, err := h.readRetirement(metadata.ID, generation)
	require.NoError(t, err)
	require.True(t, receipt.Complete)
	require.NoFileExists(t, path)
	require.Equal(t, 1, handler.prepared)
}
