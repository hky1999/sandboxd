// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// Reflection keeps this regression compilable on the original adapter. The
// assertions concern dispatching a command outside its configured cgroup,
// rather than the presence of the new field itself. No real cgroup is modified.
func setLaunchCgroupForRegression(args *StartArgs, path string) {
	field := reflect.ValueOf(args).Elem().FieldByName("CgroupPath")
	if field.IsValid() {
		field.SetString(path)
	}
}

func setLaunchBundleCgroup(t *testing.T, args StartArgs, group string) {
	t.Helper()
	path := filepath.Join(args.BundleDir, "config.json")
	data, err := json.Marshal(map[string]any{"annotations": runtimeGenerationAnnotations(args.ResourceGeneration),
		"linux": map[string]any{"cgroupsPath": group}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestManagedCreateMissingOriginalCgroupCannotDispatchOutsideIt(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	group := "/scheduler-nonexistent-original-" + filepath.Base(t.TempDir())
	setLaunchCgroupForRegression(&args, group)
	setLaunchBundleCgroup(t, args, group)
	require.Error(t, client.Create(context.Background(), args))
	require.NoFileExists(t, marker, "unavailable original cgroup must not fall back to a normal exec")
}

func TestManagedCreateRootOrTraversingCgroupCannotDispatch(t *testing.T) {
	for _, group := range []string{"/", "../foreign", "/original/../foreign", "/original//foreign"} {
		t.Run(group, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			setLaunchCgroupForRegression(&args, group)
			setLaunchBundleCgroup(t, args, group)
			require.Error(t, client.Create(context.Background(), args))
			require.NoFileExists(t, marker)
		})
	}
}

func TestManagedCreateBundleCannotRedirectOriginalLaunchCgroup(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	setLaunchCgroupForRegression(&args, "/scheduler-original")
	setLaunchBundleCgroup(t, args, "/scheduler-replacement")
	require.Error(t, client.Create(context.Background(), args))
	require.NoFileExists(t, marker, "bundle path mismatch must not become an unbound command")
}
