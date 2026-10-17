// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// The private fake runtime retires a real private filesystem fixture. These
// tests exercise production receipt/recovery paths, not physical sandboxes.
func retiredResourceStateFixture(t *testing.T) (*sandboxService, *resizeCgroups, string, []byte) {
	t.Helper()
	h, c, _ := newShrinkService(t)
	stageFilesystemOwner(t, h, "elastic", "generation-1")
	stageEmptyDeviceOwner(t, h, "elastic", "generation-1")
	_, path := h.resourceStatePath("elastic", "generation-1")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, h.deleteSandboxRuntime(context.Background(), "elastic", "generation-1"))
	receipt, err := h.readRetirement("elastic", "generation-1")
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.True(t, receipt.Complete)
	return h, c, path, raw
}

func restoreRetiredResourceState(t *testing.T, path string, raw []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, raw, 0600))
}

func TestRetiredResourceStateReceiptReplayAfterReopen(t *testing.T) {
	h, _, path, raw := retiredResourceStateFixture(t)
	// Model the durable gap after receipt publication and before journal unlink.
	restoreRetiredResourceState(t, path, raw)
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	reopened := newTestService(t, map[string]svc.Handler{"runsc": handler})
	reopened.config.RootDir = h.config.RootDir
	response, err := reopened.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: "elastic", ExpectedGeneration: "generation-1",
	})
	require.NoError(t, err)
	require.Equal(t, "generation-1", response.RetiredGeneration)
	require.NoFileExists(t, path, "completed receipt replay must retry retired journal cleanup")
	require.Zero(t, handler.calls, "metadata cleanup must not repeat runtime deletion")
}

func TestRetiredResourceStateReceiptReplayPreservesReplacement(t *testing.T) {
	h, c, path, raw := retiredResourceStateFixture(t)
	restoreRetiredResourceState(t, path, raw)
	var replacement resourceOperationState
	require.NoError(t, json.Unmarshal(raw, &replacement))
	replacement.ResourceGeneration = "generation-2"
	replacement.Revision = 7
	require.NoError(t, h.saveResourceOperationState(&replacement))
	_, replacementPath := h.resourceStatePath("elastic", "generation-2")
	replacementRaw, err := os.ReadFile(replacementPath)
	require.NoError(t, err)
	storeSandboxForDelete(t, h, "elastic")
	require.NoError(t, h.sandboxManager.UpdateLabels("elastic", map[string]string{
		resourceGenerationLabel: "generation-2",
	}))
	freezeWrites, memoryWrites := c.freezeWrites, c.memoryWrites
	response, err := h.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: "elastic", ExpectedGeneration: "generation-1",
	})
	require.NoError(t, err)
	require.Equal(t, "generation-1", response.RetiredGeneration)
	require.NoFileExists(t, path)
	after, err := os.ReadFile(replacementPath)
	require.NoError(t, err)
	require.Equal(t, replacementRaw, after)
	current, err := h.sandboxManager.Get("elastic")
	require.NoError(t, err)
	require.Equal(t, "generation-2", current.Metadata.Labels[resourceGenerationLabel])
	require.Equal(t, freezeWrites, c.freezeWrites)
	require.Equal(t, memoryWrites, c.memoryWrites)
}

func TestRetiredResourceStateRecoveryReclaimsCompletedRecords(t *testing.T) {
	for _, open := range []bool{false, true} {
		name := "closed"
		if open {
			name = "owned-open"
		}
		t.Run(name, func(t *testing.T) {
			h, c, path, raw := retiredResourceStateFixture(t)
			if open {
				var state resourceOperationState
				require.NoError(t, json.Unmarshal(raw, &state))
				state.Stage = resourceStageFrozen
				state.FreezeOwned = true
				state.Revision++
				raw, _ = json.Marshal(state)
			}
			restoreRetiredResourceState(t, path, raw)
			freezeWrites, memoryWrites := c.freezeWrites, c.memoryWrites
			require.NoError(t, h.recoverResourceOperationStates(context.Background()))
			require.NoFileExists(t, path, "only the completed physical receipt permits reclamation")
			require.Equal(t, freezeWrites, c.freezeWrites, "never unfreeze a retired or replacement cgroup")
			require.Equal(t, memoryWrites, c.memoryWrites)
		})
	}
}

func TestRetiredResourceStateRecoveryRequiresExactCompletedReceipt(t *testing.T) {
	for _, proof := range []string{"missing", "pending", "different-generation", "corrupt"} {
		t.Run(proof, func(t *testing.T) {
			h, _, _ := newShrinkService(t)
			_, path := h.resourceStatePath("elastic", "generation-1")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			h.sandboxManager.Delete("elastic")
			switch proof {
			case "pending":
				require.NoError(t, h.writeRetirement("elastic", "generation-1", false))
			case "different-generation":
				require.NoError(t, h.writeRetirement("elastic", "generation-other", true))
			case "corrupt":
				dir, receiptPath := h.retirementPath("elastic", "generation-1")
				require.NoError(t, os.MkdirAll(dir, 0700))
				require.NoError(t, os.WriteFile(receiptPath, []byte("damaged"), 0600))
			}
			require.NoError(t, h.recoverResourceOperationStates(context.Background()))
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, after, "absence or an unverified receipt never authorizes deletion")
		})
	}
}

func TestRetiredResourceStateCleanupRetainsUnverifiableRecords(t *testing.T) {
	for _, variant := range []string{"damaged", "foreign-generation", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			h, _, path, raw := retiredResourceStateFixture(t)
			switch variant {
			case "damaged":
				raw = []byte("damaged")
				restoreRetiredResourceState(t, path, raw)
			case "foreign-generation":
				var state resourceOperationState
				require.NoError(t, json.Unmarshal(raw, &state))
				state.ResourceGeneration = "generation-other"
				raw, _ = json.Marshal(state)
				restoreRetiredResourceState(t, path, raw)
			case "symlink":
				target := filepath.Join(t.TempDir(), "outside-record")
				restoreRetiredResourceState(t, target, raw)
				require.NoError(t, os.Symlink(target, path))
			}
			_, err := h.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
				ID: "elastic", ExpectedGeneration: "generation-1",
			})
			require.NoError(t, err, "physical retirement remains valid even if metadata reclamation is unavailable")
			info, err := os.Lstat(path)
			require.NoError(t, err)
			if variant == "symlink" {
				require.NotZero(t, info.Mode()&os.ModeSymlink)
			}
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, after)
		})
	}
}

func TestRetiredResourceStateRecoveryRejectsNoncanonicalFilename(t *testing.T) {
	h, _, path, raw := retiredResourceStateFixture(t)
	wrong := filepath.Join(filepath.Dir(path), "foreign-name.json")
	restoreRetiredResourceState(t, wrong, raw)
	require.NoError(t, h.recoverResourceOperationStates(context.Background()))
	after, err := os.ReadFile(wrong)
	require.NoError(t, err)
	require.Equal(t, raw, after)
}
