// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonMountGenerationCapturedUnderOriginalLifecycle(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.isAliveFunc = nil
	d.setState(DaemonStateRunning)
	g, err := d.MountWithPhysicalGeneration()
	require.NoError(t, err)
	require.Equal(t, original.Generation, g)
	phase, err := d.InspectPhysicalGeneration(g)
	require.NoError(t, err)
	require.Equal(t, "running", phase)
	require.Equal(t, original, d.originalPhysicalIdentity())
}

func TestDaemonMountGenerationMismatchStopsBeforeObservation(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	attachTestPhysicalBirth(t, d)
	observations := 0
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		observations++
		return nil, fmt.Errorf("unexpected observation")
	}
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		observations++
		return nil, fmt.Errorf("unexpected observation")
	}
	_, err := d.InspectPhysicalGeneration(strings.Repeat("b", 64))
	require.Error(t, err)
	require.Zero(t, observations)
}

func TestDaemonMountGenerationCompletedQueryHasNoPhysicalEffects(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	observations := 0
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		observations++
		return nil, fmt.Errorf("unexpected observation")
	}
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		observations++
		return nil, fmt.Errorf("unexpected observation")
	}
	phase, err := d.InspectPhysicalGeneration(original.Generation)
	require.NoError(t, err)
	require.Equal(t, "released", phase)
	require.Zero(t, observations)
}

func TestDaemonMountGenerationOldReferenceCannotClearReplacement(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	attachTestPhysicalBirth(t, d)
	m := &manager{daemons: map[string]*Daemon{d.meta.ID: d}, recovered: map[string]bool{d.meta.ID: true}}
	require.Error(t, m.SetDaemonReferencedIfPhysicalGeneration(d.meta.ID, strings.Repeat("b", 64), false))
	require.True(t, m.recovered[d.meta.ID])
}

func TestDaemonMountGenerationLateAcquireCannotReopenRetiringReference(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	original.Phase = "releasing"
	require.NoError(t, d.publishPhysicalIdentity(original))
	m := &manager{daemons: map[string]*Daemon{d.meta.ID: d}, recovered: map[string]bool{d.meta.ID: false}}
	require.Error(t, m.SetDaemonReferencedIfPhysicalGeneration(d.meta.ID, original.Generation, true))
	require.False(t, m.recovered[d.meta.ID])
}
