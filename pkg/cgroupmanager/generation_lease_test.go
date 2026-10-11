// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

func TestCgroupReleaseReplaySurvivesLeaseReopen(t *testing.T) {
	m, _, db := newGenerationLeaseFixture(t)
	path, err := allocateGeneration(m, "original-generation")
	require.NoError(t, err)
	require.NoError(t, recycleGeneration(m, path, "original-generation"))
	_, err = allocateGeneration(m, "neighbor-generation")
	require.NoError(t, err)
	bytes, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	var state storedCgroupIDs
	require.NoError(t, json.Unmarshal(bytes, &state))
	reopened, ops, _ := newGenerationLeaseFixture(t)
	reopened.idleID.Pop()
	for _, active := range state.Items {
		reopened.usingID.Set(active, struct{}{})
	}
	require.NoError(t, reopened.restoreGenerationLeases(state))
	require.NoError(t, reopened.RecycleForGeneration(path, "original-generation"))
	require.Empty(t, ops.calls, "a persisted original completion must not drain the new owner after restart")
	require.True(t, reopened.usingID.Has(path))
	require.Equal(t, "neighbor-generation", reopened.leaseOwners[path])
}

func TestCgroupMissingOrChangedGenerationCannotRelease(t *testing.T) {
	m, ops, _ := newGenerationLeaseFixture(t)
	path, err := m.AllocateForGeneration("neighbor-generation")
	require.NoError(t, err)
	require.ErrorIs(t, m.RecycleForGeneration(path, "unknown-generation"), errord.ErrFailedPrecondition)
	require.ErrorIs(t, m.RecycleForGeneration("/sandbox/missing", "unknown-generation"), errord.ErrFailedPrecondition)
	_, err = m.AllocateForGeneration("neighbor-generation")
	require.ErrorIs(t, err, errord.ErrFailedPrecondition)
	require.Empty(t, ops.calls)
	require.True(t, m.usingID.Has(path))
	require.NoError(t, m.RecycleForGeneration(path, "neighbor-generation"))
	_, err = m.AllocateForGeneration("neighbor-generation")
	require.ErrorIs(t, err, errord.ErrFailedPrecondition)
}

func TestCgroupLeaseRestoreRejectsContradictoryState(t *testing.T) {
	for _, state := range []storedCgroupIDs{
		{SchemaVersion: 3},
		{SchemaVersion: 2, LeaseOwners: map[string]string{"/sandbox/missing": "generation"}},
		{SchemaVersion: 2, LeaseOwners: map[string]string{"/sandbox/lease": "generation"}, CompletedGenerations: map[string]string{"generation": "/sandbox/lease"}},
		{SchemaVersion: 2, CompletedGenerations: map[string]string{"generation": "/other-root/lease"}},
	} {
		m, ops, _ := newGenerationLeaseFixture(t)
		m.idleID.Pop()
		m.usingID.Set("/sandbox/lease", struct{}{})
		require.ErrorIs(t, m.restoreGenerationLeases(state), errord.ErrFailedPrecondition)
		require.Empty(t, ops.calls)
		require.True(t, m.usingID.Has("/sandbox/lease"))
	}
}

type generationLeases interface {
	AllocateForGeneration(string) (string, error)
	RecycleForGeneration(string, string) error
}

// The fallback executes the original behavior when capturing the regression.
// A separate assertion requires the generation-aware production interface.
func allocateGeneration(m *CgroupManager, generation string) (string, error) {
	if owned, ok := any(m).(generationLeases); ok {
		return owned.AllocateForGeneration(generation)
	}
	return m.Allocate()
}

func recycleGeneration(m *CgroupManager, path, generation string) error {
	if owned, ok := any(m).(generationLeases); ok {
		return owned.RecycleForGeneration(path, generation)
	}
	return m.Recycle(path)
}

type failingLeaseStore struct {
	store.DbStore
	failure error
}

func (s *failingLeaseStore) StoreRaw(key string, data []byte) error {
	if s.failure != nil {
		return s.failure
	}
	return s.DbStore.StoreRaw(key, data)
}

func newGenerationLeaseFixture(t *testing.T) (*CgroupManager, *fakeCgroupOps, *failingLeaseStore) {
	t.Helper()
	name := "/sandbox/lease"
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	db := &failingLeaseStore{DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "leases.db"))}
	m := &CgroupManager{rootName: "/sandbox", max: 1, cacheSize: 1,
		usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](),
		gcQueue: util.New(""), gcWake: make(chan struct{}, 1), ops: ops, oom: oom, total: 1, db: db}
	m.cgroups.Set(name, struct{}{})
	m.idleID.Push(name)
	require.NoError(t, oom.Add(name))
	return m, ops, db
}

func TestCgroupOldReleaseCannotMutateNewOwner(t *testing.T) {
	m, ops, _ := newGenerationLeaseFixture(t)
	path, err := allocateGeneration(m, "original-generation")
	require.NoError(t, err)
	require.NoError(t, recycleGeneration(m, path, "original-generation"))
	neighbor, err := allocateGeneration(m, "neighbor-generation")
	require.NoError(t, err)
	require.Equal(t, path, neighbor, "the test must exercise physical pool reuse")
	before := append([]string(nil), ops.calls...)
	require.NoError(t, recycleGeneration(m, path, "original-generation"))
	require.Equal(t, before, ops.calls, "original release replay must not drain the neighbor")
	require.True(t, m.usingID.Has(neighbor))
	require.Empty(t, m.idleID.List())
	require.Equal(t, 1, m.total)
	_, ok := any(m).(generationLeases)
	require.True(t, ok, "production handout and release require generation ownership")
}

func TestCgroupAllocationFailureRetainsUnconfirmedLease(t *testing.T) {
	m, _, db := newGenerationLeaseFixture(t)
	db.failure = errors.New("allocation journal unavailable")
	path, err := allocateGeneration(m, "original-generation")
	require.ErrorContains(t, err, "allocation journal unavailable")
	require.Equal(t, "/sandbox/lease", path, "return the original lease for owner reconciliation")
	require.True(t, m.usingID.Has(path))
	require.Empty(t, m.idleID.List())
}

func TestCgroupReleaseFailureCannotAdmitIdleLease(t *testing.T) {
	m, _, db := newGenerationLeaseFixture(t)
	path, err := allocateGeneration(m, "original-generation")
	require.NoError(t, err)
	db.failure = errors.New("release journal unavailable")
	require.ErrorContains(t, recycleGeneration(m, path, "original-generation"), "release journal unavailable")
	require.True(t, m.usingID.Has(path))
	require.Empty(t, m.idleID.List())
	db.failure = nil
	require.NoError(t, recycleGeneration(m, path, "original-generation"))
	require.False(t, m.usingID.Has(path))
	require.Equal(t, []string{path}, m.idleID.List())
}

func TestCgroupUnconditionalReleaseRefusesOwnedLease(t *testing.T) {
	m, ops, _ := newGenerationLeaseFixture(t)
	path, err := allocateGeneration(m, "original-generation")
	require.NoError(t, err)
	require.ErrorIs(t, m.Recycle(path), errord.ErrFailedPrecondition)
	require.Empty(t, ops.calls)
	require.True(t, m.usingID.Has(path))
}
