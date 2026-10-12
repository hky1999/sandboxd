// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Controlled producer data and ordinary descriptor inheritance only. These
// tests do not observe a real cgroup, process birth or native runtime cleanup.
func cgroupRetirementJSON(t *testing.T, id, generation string) map[string]any {
	t.Helper()
	raw := partialLaunchJSON(t, id, generation)
	raw["goferPid"], raw["goferBirth"], raw["goferLaunchState"] = 0, nil, nativeDispatching
	raw["spec"].(map[string]any)["linux"] = map[string]any{"cgroupsPath": "/owned/original"}
	raw["launchCgroup"] = map[string]any{"version": 1, "path": "/owned/original", "device": 3, "inode": 9, "root_device": 3, "root_inode": 1, "parent_device": 3, "parent_inode": 5, "boot_id": "controlled-boot", "cgroup_namespace_device": 4, "cgroup_namespace_inode": 6, "mount_namespace_device": 4, "mount_namespace_inode": 7, "pid_namespace_device": 4, "pid_namespace_inode": 8}
	return raw
}

func TestNativeCgroupRetirementReadKeepsMissingBirthUnknownForControl(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	data, err := json.Marshal(cgroupRetirementJSON(t, args.ID, args.ResourceGeneration))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	state, err := client.loadNativeCgroupRetirementState(args.ID)
	require.NoError(t, err)
	require.Equal(t, nativeDispatching, state.GoferLaunchState)
	require.Nil(t, state.GoferBirth)
	require.Zero(t, state.GoferPID)
	require.Error(t, client.VerifyRuntimeGeneration(context.Background(), args.ID, args.ResourceGeneration))
	_, err = client.loadStartState(args)
	require.Error(t, err)
	require.NoFileExists(t, marker)
}

func TestNativeCgroupRetirementSourceRejectsChangedOriginalBindingAndDispatchFacts(t *testing.T) {
	for _, change := range []string{"group-version", "missing-parent", "root-device", "path", "missing-stage", "published-without-birth", "sentry-before-gofer", "status", "hooks", "independent-parent", "generation"} {
		t.Run(change, func(t *testing.T) {
			_, args, _ := managedGenerationClient(t)
			raw := cgroupRetirementJSON(t, args.ID, args.ResourceGeneration)
			group := raw["launchCgroup"].(map[string]any)
			switch change {
			case "group-version":
				group["version"] = 2
			case "missing-parent":
				delete(group, "parent_inode")
			case "root-device":
				group["root_device"] = 4
			case "path":
				group["path"] = "/owned/replacement"
			case "missing-stage":
				delete(raw, "sentryLaunchState")
			case "published-without-birth":
				raw["goferLaunchState"] = nativeBirthPublished
			case "sentry-before-gofer":
				raw["sentryLaunchState"] = nativeDispatching
			case "status":
				raw["status"] = "running"
			case "hooks":
				raw["spec"].(map[string]any)["hooks"] = map[string]any{"poststop": []any{map[string]any{"path": "/must-not-run"}}}
			case "independent-parent":
				raw["spec"].(map[string]any)["annotations"].(map[string]string)["dev.gvisor.spec.cgroup-parent"] = ""
			case "generation":
				raw["resourceGeneration"] = "replacement-generation"
			}
			data, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = decodeNativeCgroupRetirementState(data, args.ID)
			require.Error(t, err)
		})
	}
	client, args, _ := managedGenerationClient(t)
	data, err := json.Marshal(cgroupRetirementJSON(t, args.ID, args.ResourceGeneration))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), data, 0600))
	for _, change := range []string{"generation", "path", "device", "inode"} {
		original := OriginalCgroupIdentity{Path: "/owned/original", Device: 3, Inode: 9}
		generation := args.ResourceGeneration
		switch change {
		case "generation":
			generation = "different-generation"
		case "path":
			original.Path = "/owned/replacement"
		case "device":
			original.Device++
		case "inode":
			original.Inode++
		}
		err := client.VerifyRuntimeGenerationForCgroupRetirement(context.Background(), args.ID, generation, original)
		require.ErrorContains(t, err, "original generation lease")
	}
}

func TestNativeParentOfflineDeletePassesOriginalLeaseAndOneProofDescriptor(t *testing.T) {
	client, args, _ := managedGenerationClient(t)
	parent, err := os.Open(t.TempDir())
	require.NoError(t, err)
	defer parent.Close()
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(int(parent.Fd()), &stat))
	arguments, descriptor := filepath.Join(t.TempDir(), "arguments"), filepath.Join(t.TempDir(), "descriptor")
	t.Setenv("PARENT_PROOF_ARGUMENTS", arguments)
	t.Setenv("PARENT_PROOF_DESCRIPTOR", descriptor)
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PARENT_PROOF_ARGUMENTS\"\nstat -Lc '%d %i' /proc/self/fd/3 > \"$PARENT_PROOF_DESCRIPTOR\"\n"
	require.NoError(t, os.WriteFile(client.Binary, []byte(body), 0700))
	original := OriginalCgroupIdentity{Path: "/owned/original", Device: 3, Inode: 9}
	require.NoError(t, client.DeleteIfGenerationAfterCgroupParentOffline(context.Background(), args.ID, args.ResourceGeneration, parent, original))
	data, err := os.ReadFile(arguments)
	require.NoError(t, err)
	flags := strings.Fields(string(data))
	require.Contains(t, flags, "--scheduler-offline-cgroup-parent-fd=3")
	require.NotContains(t, flags, "--scheduler-offline-cgroup-fd=3")
	require.Contains(t, flags, "--scheduler-original-cgroup-path="+original.Path)
	require.Contains(t, flags, "--scheduler-original-cgroup-device=3")
	require.Contains(t, flags, "--scheduler-original-cgroup-inode=9")
	require.Contains(t, flags, "--expected-resource-generation="+args.ResourceGeneration)
	require.Equal(t, args.ID, flags[len(flags)-1])
	data, err = os.ReadFile(descriptor)
	require.NoError(t, err)
	require.Equal(t, strconv.FormatUint(stat.Dev, 10)+" "+strconv.FormatUint(stat.Ino, 10), strings.TrimSpace(string(data)))
}

func TestNativeParentOfflineDeleteInvalidOrUnsupportedInputHasNoFallback(t *testing.T) {
	client, args, marker := managedGenerationClient(t)
	parent, err := os.Open(t.TempDir())
	require.NoError(t, err)
	defer parent.Close()
	original := OriginalCgroupIdentity{Path: "/owned/original", Device: 3, Inode: 9}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, client.DeleteIfGenerationAfterCgroupParentOffline(ctx, args.ID, args.ResourceGeneration, parent, original), context.Canceled)
	require.Error(t, client.DeleteIfGenerationAfterCgroupParentOffline(context.Background(), args.ID, args.ResourceGeneration, nil, original))
	require.Error(t, client.DeleteIfGenerationAfterCgroupParentOffline(context.Background(), args.ID, args.ResourceGeneration, parent, OriginalCgroupIdentity{}))
	require.NoFileExists(t, marker)
	arguments := filepath.Join(t.TempDir(), "arguments")
	t.Setenv("PARENT_PROOF_ARGUMENTS", arguments)
	require.NoError(t, os.WriteFile(client.Binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$PARENT_PROOF_ARGUMENTS\"\nexit 1\n"), 0700))
	require.ErrorContains(t, client.DeleteIfGenerationAfterCgroupParentOffline(context.Background(), args.ID, args.ResourceGeneration, parent, original), "unconfirmed")
	data, err := os.ReadFile(arguments)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(data), "delete\n"))
	require.Contains(t, string(data), "--scheduler-offline-cgroup-parent-fd=3")
}
