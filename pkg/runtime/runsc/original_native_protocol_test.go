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

func TestManagedCreateCannotAcceptGenerationAnnotationWithoutNativeBirthProtocol(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	legacy, marshalErr := json.Marshal(map[string]any{"id": args.ID, "status": "created", "bundleDir": args.BundleDir,
		"spec":    map[string]any{"annotations": runtimeGenerationAnnotations(args.ResourceGeneration)},
		"sandbox": map[string]any{"id": args.ID, "pid": 987654321, "controlSocketPath": "/original/control.sock"}})
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(os.Getenv("GENERATION_TEST_NATIVE_TEMPLATE"), legacy, 0600))
	err := client.Create(context.Background(), args)
	require.FileExists(t, marker, "the controlled command returned a legacy generation-only native state")
	require.Error(t, err, "a generation annotation alone cannot prove producer-captured process birth")
}
