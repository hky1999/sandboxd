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

// Input-contract test only: no runtime command or physical cgroup operation.
// A matching linux.cgroupsPath must not authorize a different sandbox parent.
func TestManagedCreateRejectsIndependentSandboxCgroupParent(t *testing.T) {
	for _, parent := range []string{"/foreign-parent", "/owned/original", ""} {
		t.Run(parent, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			args.CgroupPath = "/owned/original"
			annotations := runtimeGenerationAnnotations(args.ResourceGeneration)
			annotations["dev.gvisor.spec.cgroup-parent"] = parent
			data, err := json.Marshal(map[string]any{"annotations": annotations, "linux": map[string]any{"cgroupsPath": args.CgroupPath}})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(args.BundleDir, "config.json"), data, 0600))
			require.Error(t, client.verifyManagedCreateInput(args), "separate sandbox parent must not silently replace the original launch boundary")
			require.NoFileExists(t, marker)
		})
	}
}

func TestManagedCreateAcceptsOriginalCgroupWithoutParentOverride(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	args.CgroupPath = "/owned/original"
	setLaunchBundleCgroup(t, args, args.CgroupPath)
	require.NoError(t, client.verifyManagedCreateInput(args))
	require.NoFileExists(t, marker)
}

func TestManagedCreateRejectsParentOverrideBeforeLaunchAndOutputChanges(t *testing.T) {
	for _, cgroupPath := range []string{"/owned/original", ""} {
		t.Run(cgroupPath, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			args.CgroupPath = cgroupPath
			annotations := runtimeGenerationAnnotations(args.ResourceGeneration)
			annotations["dev.gvisor.spec.cgroup-parent"] = "/foreign-parent"
			data, err := json.Marshal(map[string]any{"annotations": annotations, "linux": map[string]any{"cgroupsPath": args.CgroupPath}})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(args.BundleDir, "config.json"), data, 0600))
			args.UserStdout = filepath.Join(t.TempDir(), "original-output")
			originalOutput := []byte("original output must remain intact\n")
			require.NoError(t, os.WriteFile(args.UserStdout, originalOutput, 0600))
			client.openLaunchCgroup = func(string) (*os.File, *managedLaunchCgroup, error) {
				t.Fatal("parent override reached launch cgroup handling")
				return nil, nil, nil
			}
			require.ErrorContains(t, client.Create(context.Background(), args), "cannot override the original sandbox cgroup parent")
			require.NoFileExists(t, marker)
			require.NoFileExists(t, client.stateFilePath(args.ID))
			require.NoDirExists(t, filepath.Join(client.RootDir, managedLaunchDirectory))
			output, err := os.ReadFile(args.UserStdout)
			require.NoError(t, err)
			require.Equal(t, originalOutput, output)
		})
	}
}

func TestLegacyCreateRetainsIndependentCgroupParentInput(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	args.ResourceGeneration = ""
	args.CgroupPath = "/legacy/original"
	data, err := json.Marshal(map[string]any{"annotations": map[string]string{"dev.gvisor.spec.cgroup-parent": "/legacy/parent"}, "linux": map[string]any{"cgroupsPath": args.CgroupPath}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(args.BundleDir, "config.json"), data, 0600))
	client.openLaunchCgroup = func(string) (*os.File, *managedLaunchCgroup, error) {
		t.Fatal("legacy input reached managed launch cgroup handling")
		return nil, nil, nil
	}
	require.NoError(t, client.Create(context.Background(), args))
	require.FileExists(t, marker)
	require.NoDirExists(t, filepath.Join(client.RootDir, managedLaunchDirectory))
}
