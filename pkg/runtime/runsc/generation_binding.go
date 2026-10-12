// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const runtimeResourceGenerationAnnotation = "akernel.scheduler/resource-generation"

func (c *Client) VerifyRuntimeGeneration(ctx context.Context, id, generation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !runtimeInventoryID(generation) {
		return errors.New("original runtime resource generation is missing or invalid")
	}
	state, err := c.loadState(id)
	if err != nil {
		return err
	}
	if state.Spec.Annotations[runtimeResourceGenerationAnnotation] != generation {
		return errors.New("native runtime resource generation is missing or differs")
	}
	return ctx.Err()
}

// Applying the managed value last also clears caller-supplied generations for
// legacy input. Annotation equality is not process-birth or deletion proof.
func runtimeGenerationAnnotations(generation string) map[string]string {
	return map[string]string{runtimeResourceGenerationAnnotation: generation}
}

func readPrivateRuntimeJSON(directory *os.File, name string) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, errors.New("runtime identity input is not a filename")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after, current unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > runtimeStateBytes {
		return nil, errors.New("runtime identity input is not private bounded regular data")
	}
	data, err := io.ReadAll(io.LimitReader(f, runtimeStateBytes+1))
	if err != nil || len(data) > runtimeStateBytes {
		return nil, errors.New("runtime identity input is unreadable or exceeds its limit")
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if err := unix.Fstatat(int(directory.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameRuntimeInventoryStat(before, after) || !sameRuntimeInventoryStat(after, current) {
		return nil, errors.New("runtime identity input changed during observation")
	}
	if err := rejectRuntimeJSONDuplicates(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, err
	}
	return data, nil
}

func openRuntimeIdentityDirectory(path string) (*os.File, unix.Stat_t, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&0022 != 0 || stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, unix.Stat_t{}, errors.New("runtime identity directory is not privately owned")
	}
	return f, stat, nil
}

func verifyRuntimeIdentityDirectory(path string, original unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Lstat(path, &current); err != nil || current.Dev != original.Dev || current.Ino != original.Ino || current.Mode != original.Mode || current.Uid != original.Uid {
		return errors.New("runtime identity directory changed during observation")
	}
	return nil
}

func (c *Client) loadBoundedNativeState(id string) (*containerState, error) {
	if !runtimeInventoryID(id) {
		return nil, errors.New("runtime container ID is invalid")
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
	var state containerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, errors.New("native runtime control state is malformed")
	}
	if state.ID != id || state.Sandbox.ID != id || !knownRuntimeInventoryStatus(state.Status) || state.Sandbox.Pid < 0 || state.Sandbox.ControlSocketPath == "" {
		return nil, errors.New("native runtime control state belongs to another or incomplete physical identity")
	}
	if err := verifyRuntimeIdentityDirectory(c.RootDir, original); err != nil {
		return nil, err
	}
	return &state, nil
}

func (c *Client) loadStartState(args StartArgs) (*containerState, error) {
	state, err := c.loadState(args.ID)
	if err != nil || args.ResourceGeneration == "" {
		return state, err
	}
	if !runtimeInventoryID(args.ResourceGeneration) || state.Spec.Annotations[runtimeResourceGenerationAnnotation] != args.ResourceGeneration {
		return nil, errors.New("native runtime resource generation is missing or differs")
	}
	if state.BundleDir != args.BundleDir || state.Status != "created" || state.Sandbox.Pid <= 0 {
		return nil, errors.New("native runtime start source is not the original created bundle and active process reference")
	}
	return state, nil
}

func (c *Client) verifyManagedCreateInput(args StartArgs) error {
	if !runtimeInventoryID(args.ID) || !runtimeInventoryID(args.ResourceGeneration) {
		return errors.New("managed runtime container or resource generation is invalid")
	}
	if !filepath.IsAbs(args.BundleDir) || filepath.Clean(args.BundleDir) != args.BundleDir {
		return errors.New("managed runtime bundle is not an exact absolute directory")
	}
	if !filepath.IsAbs(c.RootDir) || filepath.Clean(c.RootDir) != c.RootDir {
		return errors.New("managed runtime root is not an exact absolute directory")
	}
	directory, original, err := openRuntimeIdentityDirectory(args.BundleDir)
	if err != nil {
		return fmt.Errorf("open managed runtime bundle: %w", err)
	}
	defer directory.Close()
	data, err := readPrivateRuntimeJSON(directory, "config.json")
	if err != nil {
		return fmt.Errorf("read managed runtime bundle: %w", err)
	}
	var spec struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(data, &spec); err != nil || spec.Annotations[runtimeResourceGenerationAnnotation] != args.ResourceGeneration {
		return errors.New("managed runtime bundle generation is missing or differs")
	}
	if err := verifyRuntimeIdentityDirectory(args.BundleDir, original); err != nil {
		return err
	}
	if _, err := os.Lstat(c.stateFilePath(args.ID)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("managed runtime already has state or its absence is unknown")
	}
	return nil
}
