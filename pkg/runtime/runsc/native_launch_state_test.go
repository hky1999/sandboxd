// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Controlled consumer data only, not an actual producer birth or process query.
func partialLaunchJSON(t *testing.T, id, generation string) map[string]any {
	t.Helper()
	return map[string]any{"id": id, "status": "creating", "resourceGeneration": generation,
		"processBirthVersion": 1, "processLaunchVersion": 1, "runtimeDispatched": true,
		"goferRequired": true, "goferPid": 456, "goferBirth": controlledBirth(id, generation, "gofer", 456),
		"goferLaunchState": nativeBirthPublished, "sentryLaunchState": nativeNotDispatched,
		"spec": map[string]any{"annotations": map[string]string{runtimeResourceGenerationAnnotation: generation}}}
}

func TestNativePartialLaunchRetirementReadDoesNotGrantControlAuthority(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	data, err := json.Marshal(partialLaunchJSON(t, args.ID, args.ResourceGeneration))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	require.NoError(t, client.VerifyRuntimeGeneration(context.Background(), args.ID, args.ResourceGeneration))
	require.Error(t, client.VerifyRuntimeGeneration(context.Background(), args.ID, "another-generation"))
	_, err = client.loadStartState(args)
	require.Error(t, err)
	require.NoFileExists(t, marker)
}

func TestNativePartialLaunchUnknownOrContradictorySourceIsRefused(t *testing.T) {
	for _, kind := range []string{"missing-version", "missing-stage", "unsupported", "dispatching-gofer", "dispatching-sentry", "missing-birth", "wrong-role", "wrong-pid", "contradictory-dispatch", "foreign-sandbox"} {
		t.Run(kind, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			raw := partialLaunchJSON(t, args.ID, args.ResourceGeneration)
			switch kind {
			case "missing-version":
				delete(raw, "processLaunchVersion")
			case "missing-stage":
				delete(raw, "sentryLaunchState")
			case "unsupported":
				raw["processLaunchVersion"] = 2
			case "dispatching-gofer":
				raw["goferLaunchState"] = nativeDispatching
			case "dispatching-sentry":
				raw["sentryLaunchState"] = nativeDispatching
			case "missing-birth":
				delete(raw, "goferBirth")
			case "wrong-role":
				raw["goferBirth"] = controlledBirth(args.ID, args.ResourceGeneration, "sentry", 456)
			case "wrong-pid":
				raw["goferPid"] = 789
			case "contradictory-dispatch":
				raw["runtimeDispatched"] = false
			case "foreign-sandbox":
				raw["sandbox"] = map[string]any{"id": "another-container"}
			}
			data, err := json.Marshal(raw)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
			require.Error(t, client.VerifyRuntimeGeneration(context.Background(), args.ID, args.ResourceGeneration))
			require.NoFileExists(t, marker)
		})
	}
}

func TestNativeCompleteControlBirthRequiresPublishedLaunchStages(t *testing.T) {
	client, args, _ := managedGenerationClient(t)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(generationStateBytes(t, args.ID, args.ResourceGeneration, args.BundleDir), &raw))
	raw["processLaunchVersion"], raw["sentryLaunchState"], raw["goferLaunchState"] = 1, nativeBirthPublished, nativeNotDispatched
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	_, err = client.loadStartState(args)
	require.NoError(t, err)
	raw["sentryLaunchState"] = nativeDispatching
	data, err = json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	_, err = client.loadStartState(args)
	require.Error(t, err)
}
