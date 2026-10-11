// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonMountOperationBindsExistingOriginalWithoutRemount(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.isAliveFunc = nil
	d.setState(DaemonStateRunning)
	bindings := 0
	generation, err := d.MountWithPhysicalBinding(func(generation, target string) error {
		bindings++
		require.Equal(t, original.Generation, generation)
		require.Equal(t, original.Target, target)
		require.Equal(t, original, d.originalPhysicalIdentity())
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, original.Generation, generation)
	require.Equal(t, 1, bindings)
	require.Equal(t, original, d.originalPhysicalIdentity())
}

func TestDaemonMountOperationBindingFailureCannotReturnSuccessfulAcquisition(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.isAliveFunc = nil
	d.setState(DaemonStateRunning)
	generation, err := d.MountWithPhysicalBinding(func(string, string) error { return errors.New("durable caller binding failed") })
	require.Error(t, err)
	require.Empty(t, generation)
	require.Equal(t, original, d.originalPhysicalIdentity())
}

func TestDaemonMountOperationBindingFailurePreventsExecAndSurvivesReopen(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, os.MkdirAll(d.meta.DaemonDir, 0700))
	require.NoError(t, os.MkdirAll(d.meta.MountPoint, 0700))
	marker := filepath.Join(t.TempDir(), "must-not-execute")
	d.binPath = filepath.Join(t.TempDir(), "controlled-daemon")
	require.NoError(t, os.WriteFile(d.binPath, []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700))
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	timing, ctx := StartTimedOperation(context.Background(), "controlled-bind-before-exec", d.meta.ID)
	defer timing.End()
	var generation string
	err := d.initializeDaemonWithBinding(ctx, timing, func(g, target string) error {
		generation = g
		require.Equal(t, d.meta.MountPoint, target)
		require.Equal(t, "launching", d.originalPhysicalIdentity().Phase)
		return errors.New("operation journal cannot persist")
	})
	require.ErrorContains(t, err, "cannot persist")
	require.NotEmpty(t, generation)
	require.NoFileExists(t, marker, "the executable cannot run before durable binding")
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	require.Equal(t, generation, reopened.originalPhysicalIdentity().Generation)
	require.Equal(t, "launching", reopened.originalPhysicalIdentity().Phase)
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.Nil(t, reopened.originalPhysicalIdentity().Mount)
}
