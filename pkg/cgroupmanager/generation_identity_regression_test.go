// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/stretchr/testify/require"
)

// 普通受控接口回归，不操作实际分组、进程或资源控制文件。
type generationIdentityOps struct {
	cgroupOps
	value CgroupIdentity
	err   error
}

func (o *generationIdentityOps) identity(path string) (CgroupIdentity, error) {
	value := o.value
	value.Path = path
	return value, o.err
}

func TestGenerationReleaseRejectsChangedOrMissingOriginalDirectory(t *testing.T) {
	for _, change := range []string{"inode", "device", "missing"} {
		t.Run(change, func(t *testing.T) {
			m, old, _ := newGenerationLeaseFixture(t)
			ops := &generationIdentityOps{cgroupOps: old, value: CgroupIdentity{Device: 2, Inode: 1}}
			m.ops = ops
			path, err := m.AllocateForGeneration("generation-original")
			require.NoError(t, err)
			switch change {
			case "inode":
				ops.value.Inode++
			case "device":
				ops.value.Device++
			case "missing":
				ops.err = errors.New("original directory unavailable")
			}
			require.Error(t, m.RecycleForGeneration(path, "generation-original"))
			require.Empty(t, old.calls, "identity refusal must precede drain and reset")
			require.True(t, m.usingID.Has(path))
			require.Equal(t, "generation-original", m.leaseOwners[path])
			require.Empty(t, m.idleID.List())
		})
	}
}

func TestGenerationAllocationRetainsOwnerWhenOriginalIdentityCannotBeSaved(t *testing.T) {
	m, old, _ := newGenerationLeaseFixture(t)
	m.ops = &generationIdentityOps{cgroupOps: old, err: errors.New("identity read unavailable")}
	path, err := m.AllocateForGeneration("generation-original")
	require.Error(t, err)
	require.Equal(t, "/sandbox/lease", path)
	require.True(t, m.usingID.Has(path))
	require.Equal(t, "generation-original", m.leaseOwners[path])
	require.Empty(t, m.idleID.List())
	require.Empty(t, old.calls)
}

func TestGenerationOriginalDirectoryIdentitySurvivesLeaseReopen(t *testing.T) {
	m, old, db := newGenerationLeaseFixture(t)
	m.ops = &generationIdentityOps{cgroupOps: old, value: CgroupIdentity{Device: 2, Inode: 1}}
	path, err := m.AllocateForGeneration("generation-original")
	require.NoError(t, err)
	data, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	var state storedCgroupIDs
	require.NoError(t, json.Unmarshal(data, &state))
	reopened, current, _ := newGenerationLeaseFixture(t)
	reopened.idleID.Pop()
	for _, active := range state.Items {
		reopened.usingID.Set(active, struct{}{})
	}
	require.NoError(t, reopened.restoreGenerationLeases(state))
	reopened.ops = &generationIdentityOps{cgroupOps: current, value: CgroupIdentity{Device: 2, Inode: 9}}
	require.Error(t, reopened.RecycleForGeneration(path, "generation-original"))
	require.Empty(t, current.calls)
	require.True(t, reopened.usingID.Has(path))
	require.Equal(t, "generation-original", reopened.leaseOwners[path])
}

func TestGenerationLeaseRefusesChangedBootNamespaceAndMountRoot(t *testing.T) {
	for _, change := range []string{"boot", "cgroup-namespace", "mount-namespace", "pid-namespace", "mount-root"} {
		t.Run(change, func(t *testing.T) {
			m, old, _ := newGenerationLeaseFixture(t)
			scope, err := currentGenerationLeaseScope()
			require.NoError(t, err)
			m.readGenerationScope = func() (generationLeaseScope, error) { return scope, nil }
			path, err := m.AllocateForGeneration("generation-original")
			require.NoError(t, err)
			switch change {
			case "boot":
				scope.BootID = "replacement-boot"
			case "cgroup-namespace":
				scope.CgroupNamespaceInode++
			case "mount-namespace":
				scope.MountNamespaceInode++
			case "pid-namespace":
				scope.PIDNamespaceInode++
			case "mount-root":
				scope.MountRootInode++
			}
			require.Error(t, m.RecycleForGeneration(path, "generation-original"))
			require.Empty(t, old.calls)
			require.True(t, m.usingID.Has(path))
			require.Empty(t, m.idleID.List())
		})
	}
}

type generationReplacingAfterDrainOps struct {
	*generationIdentityOps
}

func (o *generationReplacingAfterDrainOps) kill(path string) error {
	if err := o.cgroupOps.kill(path); err != nil {
		return err
	}
	o.value.Inode++
	return nil
}

func TestGenerationLeaseChangeAfterDrainKeepsCapacityAndStopsReset(t *testing.T) {
	m, old, _ := newGenerationLeaseFixture(t)
	m.ops = &generationReplacingAfterDrainOps{generationIdentityOps: &generationIdentityOps{cgroupOps: old, value: CgroupIdentity{Device: 2, Inode: 1}}}
	path, err := m.AllocateForGeneration("generation-original")
	require.NoError(t, err)
	require.Error(t, m.RecycleForGeneration(path, "generation-original"))
	require.Equal(t, []string{"kill"}, old.calls)
	require.True(t, m.usingID.Has(path))
	require.Empty(t, m.idleID.List())
	require.Equal(t, 1, m.total)
}

func TestGenerationLeaseDoesNotAdoptDirectoryForLegacyOwnership(t *testing.T) {
	m, old, _ := newGenerationLeaseFixture(t)
	m.idleID.Pop()
	m.usingID.Set("/sandbox/lease", struct{}{})
	state := storedCgroupIDs{SchemaVersion: 2, Items: []string{"/sandbox/lease"}, LeaseOwners: map[string]string{"/sandbox/lease": "generation-legacy"}}
	require.NoError(t, m.restoreGenerationLeases(state))
	require.Error(t, m.RecycleForGeneration("/sandbox/lease", "generation-legacy"))
	require.Empty(t, old.calls)
	require.True(t, m.usingID.Has("/sandbox/lease"))
}
