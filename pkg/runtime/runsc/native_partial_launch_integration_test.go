// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The external ptrace wrapper stops the real producer after a successful
// directory fsync. It never writes native owner state. An observer outside the
// container cgroup audits the creator and all births before terminating the
// creator by its original pidfd. No partial state is synthesized here.
func TestRealNativePartialGoferBirthRetirementAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixture(t, false)
}

func TestRealNativeLaunchCgroupBindingBeforeChildBirthAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixture(t, true)
}

func TestRealNativeOfflineOriginalCgroupCleanupAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixtureWithOfflineCleanup(t, true, true)
}

func TestRealNativeOfflineOriginalParentAfterReopenAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixtureWithCgroupProof(t, true, true, true)
}

func TestRealNativeFirstGoferBirthUnpublishedAndOriginalCgroupCleanup(t *testing.T) {
	runNativePartialLaunchFixtureWithPublicationMode(t, true, true, true, true)
}

// Independent kernel observation, deliberately distinct from nativeRuntimeBirth.
// It never fills the missing producer record or grants ordinary control authority.
type nativeUnpublishedGoferObservation struct {
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArgumentsSHA256  string `json:"arguments_sha256"`
	CgroupSHA256     string `json:"cgroup_sha256"`
	ObservationOnly  bool   `json:"observation_only"`
}

func (o *nativeUnpublishedGoferObservation) verify(t *testing.T) {
	t.Helper()
	require.True(t, o.ObservationOnly)
	require.Positive(t, o.PID)
	root := filepath.Join("/proc", strconv.Itoa(o.PID))
	data, err := os.ReadFile(filepath.Join(root, "stat"))
	require.NoError(t, err)
	fields := strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])
	require.GreaterOrEqual(t, len(fields), 20)
	start, err := strconv.ParseUint(fields[19], 10, 64)
	require.NoError(t, err)
	require.Equal(t, o.StartTicks, start)
	for name, expected := range map[string]string{"exe": o.ExecutableSHA256, "cmdline": o.ArgumentsSHA256, "cgroup": o.CgroupSHA256} {
		require.Equal(t, expected, nativePhysicalSHA(t, filepath.Join(root, name)))
	}
}

func runNativePartialLaunchFixture(t *testing.T, bindCgroup bool) {
	runNativePartialLaunchFixtureWithOfflineCleanup(t, bindCgroup, false)
}

func runNativePartialLaunchFixtureWithOfflineCleanup(t *testing.T, bindCgroup, offlineCleanup bool) {
	runNativePartialLaunchFixtureWithCgroupProof(t, bindCgroup, offlineCleanup, false)
}

func runNativePartialLaunchFixtureWithCgroupProof(t *testing.T, bindCgroup, offlineCleanup, parentOffline bool) {
	runNativePartialLaunchFixtureWithPublicationMode(t, bindCgroup, offlineCleanup, parentOffline, false)
}

func runNativePartialLaunchFixtureWithPublicationMode(t *testing.T, bindCgroup, offlineCleanup, parentOffline, unpublished bool) {
	t.Helper()
	if os.Getenv("SANDBOXD_RUN_NATIVE_BIRTH_INTEGRATION") != "1" {
		t.Skip("requires an explicit isolated BareMetal1 partial native launch test")
	}
	if unpublished {
		require.True(t, bindCgroup && offlineCleanup && parentOffline)
		t.Setenv("NATIVE_STOP_BEFORE_FIRST_BIRTH_PUBLICATION", "1")
	}
	binary, binarySHA := os.Getenv("NATIVE_BIRTH_RUNSC_BINARY"), os.Getenv("NATIVE_BIRTH_RUNSC_SHA256")
	rootfs, rootfsSHA := os.Getenv("NATIVE_BIRTH_ROOTFS"), os.Getenv("NATIVE_BIRTH_ROOTFS_SHA256")
	tracer, tracerSHA := os.Getenv("NATIVE_BIRTH_CREATE_TRACER"), os.Getenv("NATIVE_BIRTH_CREATE_TRACER_SHA256")
	evidence := os.Getenv("NATIVE_BIRTH_EVIDENCE")
	for path, digest := range map[string]string{binary: binarySHA, rootfs: rootfsSHA, tracer: tracerSHA} {
		require.True(t, filepath.IsAbs(path) && nativeDigest(digest))
		require.Equal(t, digest, nativePhysicalSHA(t, path))
	}
	require.True(t, filepath.IsAbs(evidence))
	require.NoError(t, os.MkdirAll(evidence, 0700))
	save := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	wait := func(name string) {
		for {
			if _, err := os.Stat(filepath.Join(evidence, name)); err == nil {
				return
			}
			require.NoError(t, ctx.Err(), "original external observer did not finish %s", name)
			time.Sleep(10 * time.Millisecond)
		}
	}
	work := t.TempDir()
	root, filestore := filepath.Join(work, "runsc"), filepath.Join(work, "filestore")
	require.NoError(t, os.MkdirAll(root, 0700))
	require.NoError(t, os.MkdirAll(filestore, 0700))
	loader, err := runtimecore.NewBundleLoader("", filepath.Join(work, "bundles"))
	require.NoError(t, err)
	client := NewClientWithOptions(binary, root, Options{FilestoreDir: filestore, OverlayTmpfsSize: "64M", IgnoreCgroups: !bindCgroup})
	groups := make(map[string]string)
	originalGroupBindings := make(map[string]OriginalCgroupIdentity)
	closedGroups := make(map[string]bool)
	if bindCgroup {
		prefix := os.Getenv("NATIVE_LAUNCH_CGROUP_PARENT")
		parent, identity, err := openOriginalLaunchCgroup(prefix)
		require.NoError(t, err)
		defer parent.Close()
		// The outside observer supplies an original owned non-root parent.
		// The fixture never discovers or writes a different cgroup root.
		var expected struct {
			Device uint64 `json:"device"`
			Inode  uint64 `json:"inode"`
		}
		require.NoError(t, json.Unmarshal([]byte(os.Getenv("NATIVE_LAUNCH_CGROUP_PARENT_IDENTITY")), &expected))
		require.Equal(t, expected.Device, identity.Device)
		require.Equal(t, expected.Inode, identity.Inode)
		for _, id := range []string{"partial-peer", "partial-original"} {
			groups[id] = filepath.Join(prefix, "launch-"+id)
			require.NoError(t, os.Mkdir(filepath.Join("/sys/fs/cgroup", groups[id]), 0755))
			original, binding, err := openOriginalLaunchCgroup(groups[id])
			require.NoError(t, err)
			originalGroupBindings[id] = OriginalCgroupIdentity{Path: binding.Path, Device: binding.Device, Inode: binding.Inode}
			require.NoError(t, original.Close())
		}
		save("prepared-cgroup-original-bindings.json", originalGroupBindings)
	}
	makeArgs := func(id, generation string) StartArgs {
		export := filepath.Join(work, id+"-export")
		require.NoError(t, os.Mkdir(export, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(export, "marker"), []byte(id+"\n"), 0600))
		config := runtimecore.StartConfig{
			ID: id, ResourceGeneration: generation, Rootfs: rootfs, RootfsReadonly: true,
			DisableCgroup: true, Cwd: "/", Command: []string{"/bin/sh", "-c", "cat /home/marker; printf 'workload-ready\\n'; exec /bin/sleep 240"},
			Mounts: []*runtimeapi.Mount{{Type: "bind", Source: &runtimeapi.Mount_HostPath{HostPath: export}, Target: "/home", Options: []string{"ro", "rbind"}}},
		}
		config.CgroupPath = groups[id]
		config.DisableCgroup = !bindCgroup
		if bindCgroup {
			config.Resources = &runtimeapi.LinuxSandboxResources{}
		}
		bundle, _, err := loader.GenerateOci(runtimecore.OciLoadOptions{
			SandboxID: id, Config: config, UseGVisorRootfsImageAnnotations: true,
			CgroupPath:       config.CgroupPath,
			RootfsOverlayDir: filestore, RootfsOverlaySize: "64M", ManagedAnnotations: runtimeGenerationAnnotations(generation),
		})
		require.NoError(t, err)
		return StartArgs{ID: id, ResourceGeneration: generation, BundleDir: bundle, CgroupPath: config.CgroupPath, RootOverlay: RootFileOverlay(filestore, "64M"),
			UserStdout: filepath.Join(work, id+".stdout"), UserStderr: filepath.Join(work, id+".stderr")}
	}
	peerArgs := makeArgs("partial-peer", "generation-peer")
	peerTAP := newNativePhysicalTAP(t, 0)
	peerArgs.Network = peerTAP.network
	require.NoError(t, client.Create(ctx, peerArgs))
	peer, err := client.loadStartState(peerArgs)
	require.NoError(t, err)
	require.Equal(t, 1, peer.ProcessLaunchVersion)
	require.Equal(t, nativeBirthPublished, peer.SentryLaunchState)
	require.Equal(t, nativeBirthPublished, peer.GoferLaunchState)
	peerSentry, peerGofer := nativePhysicalPidfd(t, peer.Sandbox.ProcessBirth), nativePhysicalPidfd(t, peer.GoferBirth)
	shared := nativePhysicalNullNamespace(t, root)
	shared.verify(t, peer.GoferBirth)
	require.NoError(t, client.Start(ctx, peerArgs))
	for {
		output, err := os.ReadFile(peerArgs.UserStdout)
		require.NoError(t, err)
		if strings.Contains(string(output), peerArgs.ID+"\nworkload-ready\n") {
			break
		}
		require.NoError(t, ctx.Err())
		time.Sleep(10 * time.Millisecond)
	}
	peer, err = client.loadState(peerArgs.ID)
	require.NoError(t, err)
	save("partial-peer-birth.json", peer)
	partialArgs := makeArgs("partial-original", "generation-partial")
	tracedClient := *client
	tracedClient.Binary = tracer
	creation := make(chan error, 1)
	go func() { creation <- tracedClient.Create(ctx, partialArgs) }()
	for {
		if _, err := os.Stat(filepath.Join(evidence, "partial-create-paused.json")); err == nil {
			break
		}
		select {
		case err := <-creation:
			save("partial-create-failure.json", map[string]any{"error": fmt.Sprint(err), "stdout": readOutputSnippet(partialArgs.UserStdout), "stderr": readOutputSnippet(partialArgs.UserStderr)})
			t.Fatalf("actual producer did not reach original partial publication: %v", err)
		default:
		}
		require.NoError(t, ctx.Err())
		time.Sleep(10 * time.Millisecond)
	}
	var partial *containerState
	if unpublished {
		partial, err = client.loadNativeCgroupRetirementState(partialArgs.ID)
	} else {
		partial, err = client.loadNativeRetirementState(partialArgs.ID)
	}
	require.NoError(t, err)
	require.Empty(t, partial.Sandbox.ID)
	require.Equal(t, "creating", partial.Status)
	require.Equal(t, nativeNotDispatched, partial.SentryLaunchState)
	var partialGofer int
	var observed nativeUnpublishedGoferObservation
	verifyPartialGofer := func() { verifyNativePhysicalBirth(t, partial.GoferBirth) }
	if unpublished {
		require.Equal(t, nativeDispatching, partial.GoferLaunchState)
		require.Nil(t, partial.GoferBirth)
		require.Zero(t, partial.GoferPID)
		data, err := os.ReadFile(filepath.Join(evidence, "partial-create-paused.json"))
		require.NoError(t, err)
		var pause struct {
			Observation nativeUnpublishedGoferObservation `json:"unpublished_gofer_observation"`
			Missing     bool                              `json:"first_birth_publication_missing"`
		}
		require.NoError(t, json.Unmarshal(data, &pause))
		require.True(t, pause.Missing)
		observed = pause.Observation
		observed.verify(t)
		partialGofer, err = unix.PidfdOpen(observed.PID, 0)
		require.NoError(t, err)
		t.Cleanup(func() { unix.Close(partialGofer) })
		observed.verify(t)
		verifyPartialGofer = func() { observed.verify(t) }
	} else {
		require.Equal(t, nativeBirthPublished, partial.GoferLaunchState)
		partialGofer = nativePhysicalPidfd(t, partial.GoferBirth)
	}
	if bindCgroup {
		for id, group := range groups {
			data, err := os.ReadFile(filepath.Join(root, managedLaunchDirectory, id+".json"))
			require.NoError(t, err)
			var record managedLaunchRecord
			require.NoError(t, json.Unmarshal(data, &record))
			require.Equal(t, 1, record.Version)
			require.Equal(t, id, record.SandboxID)
			require.True(t, record.CloneIntoCgroup)
			require.Equal(t, "dispatching", record.Stage)
			require.Equal(t, group, record.Cgroup.Path)
			fd, actual, err := openOriginalLaunchCgroup(group)
			require.NoError(t, err)
			require.Equal(t, record.Cgroup, actual)
			state, err := client.loadNativeCgroupRetirementState(id)
			require.NoError(t, err)
			require.NotNil(t, state.LaunchCgroup)
			require.Equal(t, 1, state.LaunchCgroup.Version)
			require.Equal(t, actual, &state.LaunchCgroup.managedLaunchCgroup)
			save(id+"-producer-cgroup.json", state.LaunchCgroup)
			require.NoError(t, fd.Close())
			save(id+"-launch-intent.json", record)
		}
	}
	original, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	if unpublished {
		require.Error(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
		// The real creator still holds its lock. Inventory must report this
		// possible owner without waiting on CLI list or inventing a birth.
		inventoryCtx, cancelInventory := context.WithTimeout(ctx, 5*time.Second)
		inventory, inventoryErr := client.ListJSON(inventoryCtx)
		cancelInventory()
		require.NoError(t, inventoryErr)
		var possible []*runtimeListedState
		require.NoError(t, json.Unmarshal(inventory, &possible))
		require.Len(t, possible, 2)
		var creating *runtimeListedState
		for _, state := range possible {
			if state.ID == partialArgs.ID {
				creating = state
			}
		}
		require.NotNil(t, creating)
		require.Equal(t, "creating", creating.Status)
		require.Zero(t, creating.PID)
		require.Equal(t, partialArgs.ResourceGeneration, creating.Annotations[runtimeResourceGenerationAnnotation])
		current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
		require.NoError(t, err)
		require.Equal(t, original, current)
		save("unpublished-creating-inventory.json", map[string]any{"inventory_known": true, "possible_owners": possible, "original_birth_still_missing": true, "creator_lock_still_held": true, "original_formal_state_bytes_unchanged": true, "node_budget_tested": false})
	} else {
		require.NoError(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	}
	_, err = client.loadStartState(partialArgs)
	require.Error(t, err, "partial retirement source cannot authorize a control operation")
	save("partial-births-ready.json", map[string]any{"partial": partial, "peer": peer,
		"state_sha256": nativePhysicalSHA(t, client.stateFilePath(partialArgs.ID)), "control_source_refused": true, "unpublished_gofer_observation": observed, "first_birth_publication_missing": unpublished})
	wait("allow-partial-delete")
	select {
	case err := <-creation:
		require.Error(t, err, "creator termination cannot become a successful create reply")
		save("partial-create-outcome.json", map[string]any{"error": err.Error(), "creation_success_reply_received": false})
	case <-ctx.Done():
		t.Fatal("original terminated creator did not return its failed create outcome")
	}
	current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	require.Equal(t, original, current, "creator exit changed original partial owner bytes")
	require.Error(t, client.DeleteIfGeneration(ctx, partialArgs.ID, "generation-wrong"))
	current, err = os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	require.Equal(t, original, current)
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	save("partial-wrong-generation-refused.json", map[string]any{"original_state_bytes_unchanged": true, "peer": peer})
	if unpublished {
		require.Error(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
		// The native delete takes the original producer lock. Check its
		// missing-birth rejection only after the audited creator has exited,
		// not while deliberately holding that same lock in ptrace.
		negativeCtx, cancelNegative := context.WithTimeout(ctx, 5*time.Second)
		negativeErr := client.DeleteIfGeneration(negativeCtx, partialArgs.ID, partialArgs.ResourceGeneration)
		cancelNegative()
		require.Error(t, negativeErr)
		require.NotErrorIs(t, negativeErr, context.DeadlineExceeded, "semantic rejection must not borrow a lock timeout")
		current, err = os.ReadFile(client.stateFilePath(partialArgs.ID))
		require.NoError(t, err)
		require.Equal(t, original, current)
	} else {
		require.NoError(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	}
	if offlineCleanup {
		group, identity, err := openOriginalLaunchCgroup(groups[partialArgs.ID])
		require.NoError(t, err)
		defer group.Close()
		var parent *os.File
		if parentOffline {
			parent, _, err = openOriginalLaunchCgroup(filepath.Dir(groups[partialArgs.ID]))
			require.NoError(t, err)
			defer parent.Close()
			require.NoError(t, client.VerifyRuntimeGenerationForCgroupRetirement(ctx, partialArgs.ID, partialArgs.ResourceGeneration, originalGroupBindings[partialArgs.ID]))
			require.Error(t, client.DeleteIfGenerationAfterCgroupParentOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, parent, originalGroupBindings[partialArgs.ID]))
		}
		require.Error(t, client.DeleteIfGenerationAfterCgroupOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, group))
		current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
		require.NoError(t, err)
		require.Equal(t, original, current)
		save("original-online-cgroup-refused.json", map[string]any{"original_state_bytes_unchanged": true, "identity": identity})
		// 原创建进程退出后，gofer 可能已经退出。保留的原句柄能确认它，
		// 不要求原 PID 仍有 exe，也不查找同号的新进程取得退出证明。
		polls := []unix.PollFd{{Fd: int32(partialGofer), Events: unix.POLLIN}}
		count, err := unix.Poll(polls, 0)
		require.NoError(t, err)
		signalSent := count == 0
		if signalSent {
			verifyPartialGofer()
			require.NoError(t, unix.PidfdSendSignal(partialGofer, unix.SIGKILL, nil, 0))
		}
		verifyNativePhysicalExit(t, partialGofer)
		save("original-gofer-exit-before-group-removal.json", map[string]any{"original_pidfd_exit_confirmed": true, "additional_signal_sent": signalSent, "original_birth": partial.GoferBirth, "unpublished_observation": observed, "first_birth_publication_missing": unpublished})
		require.NoError(t, os.Remove(filepath.Join("/sys/fs/cgroup", groups[partialArgs.ID])))
		for _, name := range []string{"cgroup.procs", "cgroup.events"} {
			fd, err := unix.Openat(int(group.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err == nil {
				unix.Close(fd)
			}
			require.ErrorIs(t, err, unix.ENOENT)
		}
		save("original-offline-cgroup.json", map[string]any{"identity": identity, "original_empty_group_normally_removed": true, "original_control_entries_absent": true, "source": partial.LaunchCgroup})
		require.Error(t, client.DeleteIfGenerationAfterCgroupOffline(ctx, partialArgs.ID, "generation-wrong", group))
		current, err = os.ReadFile(client.stateFilePath(partialArgs.ID))
		require.NoError(t, err)
		require.Equal(t, original, current)
		if parentOffline {
			// Drop the original leaf handle before rebuilding the adapter. A
			// parent proof must not silently reuse or synthesize that handle.
			require.NoError(t, group.Close())
			reopened := NewClientWithOptions(client.Binary, client.RootDir, client.Options)
			binding := originalGroupBindings[partialArgs.ID]
			require.NoError(t, reopened.VerifyRuntimeGenerationForCgroupRetirement(ctx, partialArgs.ID, partialArgs.ResourceGeneration, binding))
			for _, change := range []string{"generation", "path", "device", "inode"} {
				changedBinding := binding
				generation := partialArgs.ResourceGeneration
				switch change {
				case "generation":
					generation = "generation-wrong"
				case "path":
					changedBinding.Path = groups[peerArgs.ID]
				case "device":
					changedBinding.Device++
				case "inode":
					changedBinding.Inode++
				}
				require.Error(t, reopened.DeleteIfGenerationAfterCgroupParentOffline(ctx, partialArgs.ID, generation, parent, changedBinding))
				current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
				require.NoError(t, err)
				require.Equal(t, original, current)
			}
			peerGroup, _, err := openOriginalLaunchCgroup(groups[peerArgs.ID])
			require.NoError(t, err)
			require.Error(t, reopened.DeleteIfGenerationAfterCgroupParentOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, peerGroup, binding))
			require.NoError(t, peerGroup.Close())
			replacementPath := filepath.Join("/sys/fs/cgroup", groups[partialArgs.ID])
			require.NoError(t, os.Mkdir(replacementPath, 0755))
			replacement, actual, err := openOriginalLaunchCgroup(groups[partialArgs.ID])
			require.NoError(t, err)
			require.NotEqual(t, binding.Inode, actual.Inode)
			controls := func() map[string]string {
				values := map[string]string{}
				for _, name := range []string{"cgroup.procs", "cgroup.events", "cgroup.freeze"} {
					data, err := os.ReadFile(filepath.Join(replacementPath, name))
					require.NoError(t, err)
					values[name] = string(data)
				}
				return values
			}
			before := controls()
			require.Error(t, reopened.DeleteIfGenerationAfterCgroupParentOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, parent, binding))
			require.Equal(t, before, controls())
			current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
			require.NoError(t, err)
			require.Equal(t, original, current)
			save("same-name-replacement-parent-proof-refused.json", map[string]any{"original": binding, "replacement": actual, "before": before, "after": controls(), "original_state_bytes_unchanged": true, "wrong_parent_descriptor_refused": true})
			require.NoError(t, replacement.Close())
			require.NoError(t, os.Remove(replacementPath))
			require.NoError(t, reopened.DeleteIfGenerationAfterCgroupParentOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, parent, binding))
			save("original-parent-offline-after-reopen.json", map[string]any{"original_directory_descriptor_closed": true, "new_adapter_from_original_state": true, "original_binding": binding, "online_source_refused": true, "wrong_generation_path_device_inode_refused": true, "native_parent_absence_cleanup_passed": true, "source": partial.LaunchCgroup, "node_budget_tested": false, "daemon_restart_tested": false, "first_birth_missing_tested": unpublished})
		} else {
			require.NoError(t, client.DeleteIfGenerationAfterCgroupOffline(ctx, partialArgs.ID, partialArgs.ResourceGeneration, group))
		}
		closedGroups[groups[partialArgs.ID]] = true
	} else {
		require.NoError(t, client.DeleteIfGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	}
	verifyNativePhysicalExit(t, partialGofer)
	require.NoFileExists(t, client.stateFilePath(partialArgs.ID))
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	shared.verify(t, peer.GoferBirth)
	running, err := client.loadState(peerArgs.ID)
	require.NoError(t, err)
	require.Equal(t, "running", running.Status)
	peerTAP.verify(t)
	save("partial-deleted-peer-live.json", map[string]any{"original_id": partialArgs.ID, "original_generation": partialArgs.ResourceGeneration,
		"original_gofer_exit_confirmed_by_independent_pidfd": true, "peer": running})
	require.NoError(t, client.DeleteIfGeneration(ctx, peerArgs.ID, peerArgs.ResourceGeneration))
	verifyNativePhysicalExit(t, peerSentry)
	verifyNativePhysicalExit(t, peerGofer)
	inventory, err := client.ListJSON(ctx)
	require.NoError(t, err)
	var final []any
	require.NoError(t, json.Unmarshal(inventory, &final))
	require.Empty(t, final)
	save("final-native-inventory.json", map[string]any{"inventory": final})
	save("shared-fixture-namespace-cleanup.json", shared.retireEmptyFixtureRoot(t))
	save("fixture-tap-cleanup.json", peerTAP.retire(t))
	if bindCgroup {
		for _, group := range groups {
			if closedGroups[group] {
				continue
			}
			path := filepath.Join("/sys/fs/cgroup", group)
			members, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
			require.NoError(t, err)
			require.Empty(t, strings.TrimSpace(string(members)))
			require.NoError(t, os.Remove(path))
		}
		save("launch-cgroup-fixture-cleanup.json", map[string]any{"groups": groups, "original_empty_groups_normally_removed": true,
			"scope": "This test's two original child cgroups only; no managed production cgroup cache or node budget settlement."})
	}
	save("partial-launch-summary.json", map[string]any{"producer_state_was_synthesized": false, "creator_terminated_by_external_original_pidfd": true,
		"three_original_birth_exits_confirmed": !unpublished, "three_original_process_exits_confirmed": true, "first_birth_publication_missing": unpublished, "peer_workload_started": true,
		"scope": "Actual gofer dispatch with published or explicitly unpublished first birth, externally audited creator termination and original cgroup-offline conditional retirement. Kernel observation never fills a missing birth. Complete daemon resources, deployment and node budget remain unverified."})
}
