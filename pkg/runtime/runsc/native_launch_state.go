// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	nativeNotDispatched  = "not_dispatched"
	nativeDispatching    = "dispatching"
	nativeBirthPublished = "birth_published"
)

// 原生生产端在派发前保存；没有这份记录不能使用离线分组清理入口。
type nativeLaunchCgroup struct {
	Version int `json:"version"`
	managedLaunchCgroup
	RootDevice        uint64 `json:"root_device"`
	RootInode         uint64 `json:"root_inode"`
	ParentDevice      uint64 `json:"parent_device"`
	ParentInode       uint64 `json:"parent_inode"`
	PIDNamespaceDev   uint64 `json:"pid_namespace_device"`
	PIDNamespaceInode uint64 `json:"pid_namespace_inode"`
}

func validateNativeLaunchStages(state *containerState, requireSentry bool) error {
	if state.ProcessLaunchVersion == 0 {
		if state.GoferLaunchState != "" || state.SentryLaunchState != "" {
			return errors.New("legacy native owner contains unsupported launch-stage facts")
		}
		return nil
	}
	if state.ProcessLaunchVersion != 1 {
		return errors.New("native process launch protocol is unsupported")
	}
	valid := func(stage string) bool {
		return stage == nativeNotDispatched || stage == nativeDispatching || stage == nativeBirthPublished
	}
	if !valid(state.GoferLaunchState) || !valid(state.SentryLaunchState) ||
		state.RuntimeDispatched != (state.GoferLaunchState != nativeNotDispatched || state.SentryLaunchState != nativeNotDispatched) ||
		state.GoferRequired != (state.GoferLaunchState != nativeNotDispatched) {
		return errors.New("native launch facts are missing or contradict dispatch ownership")
	}
	if state.GoferLaunchState == nativeDispatching || state.SentryLaunchState == nativeDispatching {
		return errors.New("native process dispatch lacks published birth; outcome remains unknown")
	}
	if requireSentry && state.SentryLaunchState != nativeBirthPublished {
		return errors.New("native control operation requires a published original sentry")
	}
	return nil
}

// Only the retirement verifier accepts producer-issued preparation or a
// published gofer with a provably undispatched Sentry. Control operations keep
// the existing complete state and birth requirements. This read authorizes no
// signal; generation-conditional native deletion still checks original pidfds.
func (c *Client) loadNativeRetirementState(id string) (*containerState, error) {
	return c.loadNativeOwnershipState(id, decodeNativeRetirementState)
}

func (c *Client) loadNativeCgroupRetirementState(id string) (*containerState, error) {
	return c.loadNativeOwnershipState(id, decodeNativeCgroupRetirementState)
}

func (c *Client) loadNativeOwnershipState(id string, decode func([]byte, string) (*containerState, error)) (*containerState, error) {
	if !runtimeInventoryID(id) {
		return nil, errors.New("native retirement container ID is invalid")
	}
	directory, original, err := openRuntimeIdentityDirectory(c.RootDir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	data, err := readPrivateRuntimeJSON(directory, filepath.Base(c.stateFilePath(id)))
	if err != nil {
		return nil, err
	}
	state, err := decode(data, id)
	if err != nil {
		return nil, err
	}
	if err := verifyRuntimeIdentityDirectory(c.RootDir, original); err != nil {
		return nil, err
	}
	return state, nil
}

// This read proves only the original producer's cgroup ownership. Unknown
// child dispatch can enter this route, but never the normal process verifier
// or control route. The generation lease must still authorize actual closure.
func (c *Client) VerifyRuntimeGenerationForCgroupRetirement(ctx context.Context, id, generation string, original OriginalCgroupIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !original.valid() || !runtimeInventoryID(generation) {
		return errors.New("original cgroup retirement binding is invalid")
	}
	state, err := c.loadNativeCgroupRetirementState(id)
	if err != nil {
		return err
	}
	b := state.LaunchCgroup
	if state.ResourceGeneration != generation || b.Path != original.Path || b.Device != original.Device || b.Inode != original.Inode {
		return errors.New("native cgroup producer differs from the original generation lease")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != b.BootID {
		return errors.New("native cgroup producer boot changed")
	}
	for _, entry := range []struct {
		path          string
		device, inode uint64
	}{
		{"/proc/thread-self/ns/cgroup", b.CgroupNamespaceDev, b.CgroupNamespaceInode},
		{"/proc/thread-self/ns/mnt", b.MountNamespaceDev, b.MountNamespaceInode},
		{"/proc/thread-self/ns/pid", b.PIDNamespaceDev, b.PIDNamespaceInode},
		{"/sys/fs/cgroup", b.RootDevice, b.RootInode},
	} {
		var stat unix.Stat_t
		if err := unix.Stat(entry.path, &stat); err != nil || stat.Dev != entry.device || stat.Ino != entry.inode {
			return errors.New("native cgroup producer observation scope changed")
		}
	}
	return ctx.Err()
}

func decodeNativeCgroupRetirementState(data []byte, id string) (*containerState, error) {
	var state containerState
	if err := json.Unmarshal(data, &state); err != nil || state.ID != id || state.ProcessBirthVersion != 1 || state.ProcessLaunchVersion != 1 ||
		!runtimeInventoryID(state.ResourceGeneration) || state.Spec.Annotations[runtimeResourceGenerationAnnotation] != state.ResourceGeneration {
		return nil, errors.New("native cgroup retirement owner is incomplete or different")
	}
	b := state.LaunchCgroup
	if b == nil || b.Version != 1 || !filepath.IsAbs(b.Path) || !validLaunchCgroupPath(b.Path) || state.Spec.Linux == nil || state.Spec.Linux.CgroupsPath != b.Path ||
		b.Device == 0 || b.Inode == 0 || b.RootDevice != b.Device || b.ParentDevice != b.Device || b.RootInode == 0 || b.ParentInode == 0 || b.Inode == b.RootInode || b.Inode == b.ParentInode ||
		b.BootID == "" || len(b.BootID) > 128 || b.CgroupNamespaceInode == 0 || b.MountNamespaceInode == 0 || b.PIDNamespaceInode == 0 {
		return nil, errors.New("native cgroup retirement lacks original directory and scope")
	}
	if _, overridden := state.Spec.Annotations["dev.gvisor.spec.cgroup-parent"]; overridden {
		return nil, errors.New("native cgroup retirement has an independent parent")
	}
	if h := state.Spec.Hooks; h != nil && len(h.Prestart)+len(h.CreateRuntime)+len(h.CreateContainer)+len(h.StartContainer)+len(h.Poststart)+len(h.Poststop) != 0 {
		return nil, errors.New("native cgroup retirement has external lifecycle hooks")
	}
	valid := func(stage string) bool {
		return stage == nativeNotDispatched || stage == nativeDispatching || stage == nativeBirthPublished
	}
	if !valid(state.GoferLaunchState) || !valid(state.SentryLaunchState) || state.RuntimeDispatched != (state.GoferLaunchState != nativeNotDispatched || state.SentryLaunchState != nativeNotDispatched) || state.GoferRequired != (state.GoferLaunchState != nativeNotDispatched) {
		return nil, errors.New("native cgroup retirement dispatch facts contradict ownership")
	}
	if state.GoferLaunchState == nativeBirthPublished {
		if err := state.GoferBirth.validate(id, state.ResourceGeneration, "gofer", state.GoferPID); err != nil {
			return nil, err
		}
	} else if state.GoferPID != 0 || state.GoferBirth != nil {
		return nil, errors.New("native unpublished gofer contains process facts")
	}
	if state.GoferRequired && state.GoferLaunchState != nativeBirthPublished && state.SentryLaunchState != nativeNotDispatched {
		return nil, errors.New("native sentry dispatched before required gofer publication")
	}
	if state.SentryLaunchState == nativeBirthPublished {
		return decodeNativeRetirementState(data, id)
	}
	if state.Status != "creating" || state.Sandbox.ID != "" || state.Sandbox.Pid != 0 || state.Sandbox.ProcessBirth != nil || state.Sandbox.ResourceGeneration != "" || state.Sandbox.ControlSocketPath != "" {
		return nil, errors.New("native unpublished sentry contains sandbox or lifecycle facts")
	}
	return &state, nil
}

func decodeNativeRetirementState(data []byte, id string) (*containerState, error) {
	var state containerState
	if err := json.Unmarshal(data, &state); err != nil || state.ID != id {
		return nil, errors.New("native retirement source is malformed or belongs to another container")
	}
	if state.Sandbox.ID != "" {
		complete, err := decodeNativeState(data, id)
		if err != nil {
			return nil, err
		}
		if err := validateNativeLaunchStages(complete, true); err != nil {
			return nil, err
		}
		return complete, nil
	}
	if state.ProcessBirthVersion != 1 || state.ProcessLaunchVersion != 1 || state.Status != "creating" ||
		!runtimeInventoryID(state.ResourceGeneration) || state.Spec.Annotations[runtimeResourceGenerationAnnotation] != state.ResourceGeneration ||
		state.Sandbox.Pid != 0 || state.Sandbox.ProcessBirth != nil || state.Sandbox.ResourceGeneration != "" || state.Sandbox.ControlSocketPath != "" ||
		state.SentryLaunchState != nativeNotDispatched {
		return nil, errors.New("native partial source is not an original undispatched sentry")
	}
	if err := validateNativeLaunchStages(&state, false); err != nil {
		return nil, err
	}
	if state.GoferRequired {
		if err := state.GoferBirth.validate(id, state.ResourceGeneration, "gofer", state.GoferPID); err != nil {
			return nil, err
		}
	} else if state.GoferBirth != nil || state.GoferPID != 0 {
		return nil, errors.New("native undispatched preparation contains process facts")
	}
	return &state, nil
}
