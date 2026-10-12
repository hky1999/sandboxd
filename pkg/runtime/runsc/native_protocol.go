// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// This is the independent consumer of the producer's schema. Validation of
// these fields is not a later observation of a live process; native deletion
// reacquires original kernel handles under its own state lock.
type nativeRuntimeBirth struct {
	Version          int    `json:"version"`
	ContainerID      string `json:"container_id"`
	Generation       string `json:"resource_generation"`
	Role             string `json:"role"`
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	InitializerPID   int    `json:"initializer_pid"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArgumentsSHA256  string `json:"arguments_sha256"`
	CgroupSHA256     string `json:"cgroup_sha256"`
	Scope            struct {
		BootID             string `json:"boot_id"`
		PIDNamespaceDevice uint64 `json:"pid_namespace_device"`
		PIDNamespaceInode  uint64 `json:"pid_namespace_inode"`
	} `json:"scope"`
}

func nativeDigest(value string) bool {
	bytes, err := hex.DecodeString(value)
	return err == nil && len(bytes) == 32 && value == strings.ToLower(value)
}

func (birth *nativeRuntimeBirth) validate(id, generation, role string, pid int) error {
	if birth == nil || birth.Version != 1 || birth.ContainerID != id || birth.Generation != generation ||
		birth.Role != role || birth.PID != pid || pid <= 0 || birth.StartTicks == 0 || birth.InitializerPID <= 0 ||
		birth.Scope.BootID == "" || birth.Scope.PIDNamespaceInode == 0 ||
		!nativeDigest(birth.ExecutableSHA256) || !nativeDigest(birth.ArgumentsSHA256) || !nativeDigest(birth.CgroupSHA256) {
		return errors.New("native runtime producer birth is missing or belongs to another execution")
	}
	return nil
}

func validateNativeRuntimeBirth(state *containerState, id, generation string) error {
	if state.ResourceGeneration != generation || state.ProcessBirthVersion != 1 || !state.RuntimeDispatched ||
		state.Sandbox.ResourceGeneration != generation {
		return errors.New("native runtime birth protocol is missing or differs")
	}
	if err := state.Sandbox.ProcessBirth.validate(id, generation, "sentry", state.Sandbox.Pid); err != nil {
		return err
	}
	if state.GoferRequired {
		if err := state.GoferBirth.validate(id, generation, "gofer", state.GoferPID); err != nil {
			return err
		}
		if state.GoferBirth.Scope != state.Sandbox.ProcessBirth.Scope {
			return errors.New("native runtime child observer scopes differ")
		}
	} else if state.GoferBirth != nil || state.GoferPID != 0 {
		return errors.New("native runtime no-gofer fact contradicts original ownership")
	}
	if err := validateNativeLaunchStages(state, true); err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteIfGeneration(ctx context.Context, id, generation string) error {
	return c.deleteWithOriginalCgroup(ctx, id, generation, nil)
}

// DeleteIfGenerationAfterCgroupOffline 把调用方持有的原目录句柄交给原生核验。
// 原生源码须在派发前记录同一分组，且核验其已离线；不使用兼容回退。
func (c *Client) DeleteIfGenerationAfterCgroupOffline(ctx context.Context, id, generation string, original *os.File) error {
	if original == nil {
		return errors.New("original offline cgroup descriptor is missing")
	}
	return c.deleteWithOriginalCgroup(ctx, id, generation, original)
}

// OriginalCgroupIdentity comes from the original generation lease, not from a
// later lookup of the same path or a replacement native state file.
type OriginalCgroupIdentity struct {
	Path   string
	Device uint64
	Inode  uint64
}

func (original OriginalCgroupIdentity) valid() bool {
	return filepath.IsAbs(original.Path) && validLaunchCgroupPath(original.Path) && original.Device != 0 && original.Inode != 0
}

// Parent proof is a separate restart protocol. The original path/device/inode
// must also be passed so a replacement producer record cannot borrow the same
// parent descriptor. Unsupported native flags remain unconfirmed.
func (c *Client) DeleteIfGenerationAfterCgroupParentOffline(ctx context.Context, id, generation string, parent *os.File, original OriginalCgroupIdentity) error {
	if parent == nil || !original.valid() {
		return errors.New("original offline parent or original lease identity is missing")
	}
	return c.deleteWithCgroupProof(ctx, id, generation, nil, parent, original)
}

func (c *Client) deleteWithOriginalCgroup(ctx context.Context, id, generation string, original *os.File) error {
	return c.deleteWithCgroupProof(ctx, id, generation, original, nil, OriginalCgroupIdentity{})
}

func (c *Client) deleteWithCgroupProof(ctx context.Context, id, generation string, original, parent *os.File, binding OriginalCgroupIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !runtimeInventoryID(id) || !runtimeInventoryID(generation) {
		return errors.New("original native runtime deletion identity is invalid")
	}
	args := append(c.globalArgs(), "delete", "--force", "--expected-resource-generation="+generation)
	if original != nil && parent != nil {
		return errors.New("original cgroup cleanup accepts exactly one proof descriptor")
	}
	if original != nil {
		args = append(args, "--scheduler-offline-cgroup-fd=3")
	} else if parent != nil {
		args = append(args, "--scheduler-offline-cgroup-parent-fd=3", "--scheduler-original-cgroup-path="+binding.Path,
			"--scheduler-original-cgroup-device="+strconv.FormatUint(binding.Device, 10), "--scheduler-original-cgroup-inode="+strconv.FormatUint(binding.Inode, 10))
	}
	args = append(args, id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	if original != nil {
		cmd.ExtraFiles = []*os.File{original}
	} else if parent != nil {
		cmd.ExtraFiles = []*os.File{parent}
	}
	var output boundedRuntimeOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("generation-conditional runsc deletion is unconfirmed: %w", err)
	}
	return nil
}
