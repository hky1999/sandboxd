// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedCreatePassesNativeGenerationFlagBeforeFullID(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	record := filepath.Join(t.TempDir(), "arguments")
	t.Setenv("GENERATION_TEST_ARGUMENT_RECORD", record)
	require.NoError(t, os.WriteFile(client.Binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$GENERATION_TEST_ARGUMENT_RECORD\"\n: > \"$GENERATION_TEST_COMMAND_MARKER\"\ncp \"$GENERATION_TEST_NATIVE_TEMPLATE\" \"$GENERATION_TEST_NATIVE_STATE\"\n"), 0700))
	require.NoError(t, client.Create(context.Background(), args))
	require.FileExists(t, marker)
	data, err := os.ReadFile(record)
	require.NoError(t, err)
	flags := strings.Fields(string(data))
	index := slices.Index(flags, "--scheduler-resource-generation="+args.ResourceGeneration)
	require.Greater(t, index, slices.Index(flags, "create"))
	require.Less(t, index, slices.Index(flags, args.ID))
}

func TestManagedNativeBirthRequiresBothOriginalChildRolesAndScope(t *testing.T) {
	for _, kind := range []string{"missing-protocol", "not-dispatched", "wrong-owner", "missing-sentry", "wrong-start", "wrong-role",
		"bad-hash", "missing-initializer", "missing-scope", "missing-gofer", "wrong-gofer-pid", "different-scope", "invented-gofer"} {
		t.Run(kind, func(t *testing.T) {
			client, args, _ := managedGenerationClient(t)
			var raw map[string]any
			require.NoError(t, json.Unmarshal(generationStateBytes(t, args.ID, args.ResourceGeneration, args.BundleDir), &raw))
			sandbox := raw["sandbox"].(map[string]any)
			birth := sandbox["processBirth"].(map[string]any)
			switch kind {
			case "missing-protocol":
				delete(raw, "processBirthVersion")
			case "not-dispatched":
				raw["runtimeDispatched"] = false
			case "wrong-owner":
				raw["resourceGeneration"] = "replacement"
			case "missing-sentry":
				delete(sandbox, "processBirth")
			case "wrong-start":
				birth["start_ticks"] = 0
			case "wrong-role":
				birth["role"] = "gofer"
			case "bad-hash":
				birth["executable_sha256"] = "unknown"
			case "missing-initializer":
				birth["initializer_pid"] = 0
			case "missing-scope":
				delete(birth, "scope")
			case "missing-gofer":
				raw["goferRequired"] = true
			case "wrong-gofer-pid":
				raw["goferRequired"], raw["goferPid"] = true, 456
				raw["goferBirth"] = controlledBirth(args.ID, args.ResourceGeneration, "gofer", 789)
			case "different-scope":
				raw["goferRequired"], raw["goferPid"] = true, 456
				gofer := controlledBirth(args.ID, args.ResourceGeneration, "gofer", 456)
				gofer["scope"].(map[string]any)["pid_namespace_inode"] = 99
				raw["goferBirth"] = gofer
			case "invented-gofer":
				raw["goferPid"] = 456
			}
			data, err := json.Marshal(raw)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
			_, err = client.loadStartState(args)
			require.Error(t, err)
		})
	}
	// A complete controlled pair is accepted as producer data, without
	// pretending that these fake PIDs were physically observed.
	client, args, _ := managedGenerationClient(t)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(generationStateBytes(t, args.ID, args.ResourceGeneration, args.BundleDir), &raw))
	raw["goferRequired"], raw["goferPid"] = true, 456
	raw["goferBirth"] = controlledBirth(args.ID, args.ResourceGeneration, "gofer", 456)
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	_, err = client.loadStartState(args)
	require.NoError(t, err)
}

func TestNativeConditionalDeleteNeverMasksMissingOrUnsupportedRuntime(t *testing.T) {
	for _, mode := range []string{"success", "missing", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			client, args, _ := managedGenerationClient(t)
			record := filepath.Join(t.TempDir(), "arguments")
			t.Setenv("GENERATION_DELETE_ARGUMENTS", record)
			body := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$GENERATION_DELETE_ARGUMENTS\"\n"
			if mode != "success" {
				body += "printf 'does not exist; unsupported flag\\n' >&2\nexit 1\n"
			}
			require.NoError(t, os.WriteFile(client.Binary, []byte(body), 0700))
			err := client.DeleteIfGeneration(context.Background(), args.ID, args.ResourceGeneration)
			if mode == "success" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "unconfirmed")
			}
			data, err := os.ReadFile(record)
			require.NoError(t, err)
			require.Equal(t, 1, strings.Count(string(data), "delete\n"))
			flags := strings.Fields(string(data))
			require.Contains(t, flags, "--expected-resource-generation="+args.ResourceGeneration)
			require.Equal(t, args.ID, flags[len(flags)-1])
		})
	}
}

func TestNativeConditionalDeleteCancellationAndInvalidIdentityDoNotInvokeCLI(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, client.DeleteIfGeneration(ctx, args.ID, args.ResourceGeneration), context.Canceled)
	require.Error(t, client.DeleteIfGeneration(context.Background(), args.ID, ""))
	require.Error(t, client.DeleteIfGeneration(context.Background(), "../replacement", args.ResourceGeneration))
	require.NoFileExists(t, marker)
}

type nativeDeletionClient struct {
	successfulRunscClient
	nativeCalls, legacyCalls int
	id, generation           string
	result                   error
}

func (c *nativeDeletionClient) DeleteIfGeneration(_ context.Context, id, generation string) error {
	c.nativeCalls++
	c.id, c.generation = id, generation
	return c.result
}
func (c *nativeDeletionClient) Delete(context.Context, string, bool) error {
	c.legacyCalls++
	return errors.New("unexpected legacy delete")
}

func TestRunscHandlerNativeDeleteCannotFallBackToLegacyClient(t *testing.T) {
	client := &nativeDeletionClient{result: errors.New("native result unknown")}
	handler := &Handler{runsc: client, sandboxRoot: t.TempDir()}
	require.ErrorContains(t, handler.DeleteRuntimeIfGeneration(context.Background(), "original", "generation-original"), "native result unknown")
	require.Equal(t, 1, client.nativeCalls)
	require.Zero(t, client.legacyCalls)
	require.Equal(t, "original", client.id)
	require.Equal(t, "generation-original", client.generation)
	handler.runsc = successfulRunscClient{}
	require.ErrorContains(t, handler.DeleteRuntimeIfGeneration(context.Background(), "original", "generation-original"), "cannot perform")
}
