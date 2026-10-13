// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeCreatingInventoryFixture(t *testing.T, client *Client, change func(map[string]any)) string {
	t.Helper()
	raw := cgroupRetirementJSON(t, "creating-original", "generation-original")
	raw["bundleDir"] = "/original/creating-bundle"
	if change != nil {
		change(raw)
	}
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	path := client.stateFilePath("creating-original")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func TestRunscCreatingInventoryRetainsUnpublishedOwnerWithoutEnteringLockedCLI(t *testing.T) {
	for _, emptyObject := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil-sandbox", true: "empty-sandbox"}[emptyObject], func(t *testing.T) {
			client := inventoryTestClient(t, "[]")
			marker := filepath.Join(t.TempDir(), "cli-called")
			require.NoError(t, os.WriteFile(client.Binary, []byte("#!/bin/sh\n: > "+inventoryShellQuote(marker)+"\nexit 99\n"), 0700))
			path := writeCreatingInventoryFixture(t, client, func(raw map[string]any) {
				if emptyObject {
					raw["sandbox"] = map[string]any{}
				}
			})
			nativeInventoryFixture(t, client, "running-peer")
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			data, err := client.ListJSON(context.Background())
			require.NoError(t, err)
			var states []*runtimeListedState
			require.NoError(t, json.Unmarshal(data, &states))
			require.Len(t, states, 2)
			var creating *runtimeListedState
			for _, state := range states {
				if state.ID == "creating-original" {
					creating = state
				}
			}
			require.NotNil(t, creating)
			require.Equal(t, "creating", creating.Status)
			require.Zero(t, creating.PID)
			require.Equal(t, "/original/creating-bundle", creating.Bundle)
			require.Equal(t, "generation-original", creating.Annotations[runtimeResourceGenerationAnnotation])
			require.NoFileExists(t, marker, "inventory must not wait on the intentionally held producer lock")
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Error(t, client.VerifyRuntimeGeneration(context.Background(), "creating-original", "generation-original"), "counting possible ownership must not manufacture process control authority")
		})
	}
}

func TestRunscCreatingInventoryCannotAdoptIncompleteOrContradictorySource(t *testing.T) {
	for _, change := range []string{"missing-group", "missing-generation", "scope", "foreign-generation", "invented-birth", "sentry-dispatched", "status", "bundle", "foreign-sandbox"} {
		t.Run(change, func(t *testing.T) {
			client := inventoryTestClient(t, "[]")
			writeCreatingInventoryFixture(t, client, func(raw map[string]any) {
				switch change {
				case "missing-group":
					delete(raw, "launchCgroup")
				case "missing-generation":
					delete(raw, "resourceGeneration")
				case "scope":
					delete(raw["launchCgroup"].(map[string]any), "boot_id")
				case "foreign-generation":
					raw["resourceGeneration"] = "replacement"
				case "invented-birth":
					raw["goferPid"] = 456
				case "sentry-dispatched":
					raw["sentryLaunchState"] = nativeDispatching
				case "status":
					raw["status"] = "running"
				case "bundle":
					raw["bundleDir"] = ""
				case "foreign-sandbox":
					raw["sandbox"] = map[string]any{"id": "replacement", "pid": 123}
				}
			})
			data, err := client.ListJSON(context.Background())
			require.Error(t, err)
			require.Empty(t, data)
		})
	}
}

func TestRunscCreatingInventoryCannotHideAnotherBrokenOwnerOrCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		client := inventoryTestClient(t, "[]")
		writeCreatingInventoryFixture(t, client, nil)
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		} else {
			require.NoError(t, os.WriteFile(client.stateFilePath("broken-peer"), []byte(`{"id":`), 0600))
		}
		data, err := client.ListJSON(ctx)
		cancel()
		require.Error(t, err)
		require.Empty(t, data)
	}
}

func TestRunscCreatingInventoryReplacementAndOmissionCannotResolveOwnership(t *testing.T) {
	client := inventoryTestClient(t, "[]")
	path := writeCreatingInventoryFixture(t, client, nil)
	nativeInventoryFixture(t, client, "running-peer")
	directory, err := os.Open(client.RootDir)
	require.NoError(t, err)
	defer directory.Close()
	before, err := readRuntimeInventory(context.Background(), directory)
	require.NoError(t, err)
	output, creating, err := creatingRuntimeInventory(before)
	require.NoError(t, err)
	require.True(t, creating)
	require.Error(t, verifyRuntimeInventory(before, before, []byte("[]")), "creating cannot hide itself or the live peer")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".replacement", data, 0600))
	require.NoError(t, os.Rename(path+".replacement", path))
	after, err := readRuntimeInventory(context.Background(), directory)
	require.NoError(t, err)
	require.Error(t, verifyRuntimeInventory(before, after, output), "byte-identical replacement must not borrow the original observation")
}
