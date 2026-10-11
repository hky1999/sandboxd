// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package networkmanager

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestPooledReleaseReplaySurvivesLeaseReopen(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	path := filepath.Join(t.TempDir(), "network-leases.db")
	f.manager.db = store.NewStoreImp(path)
	f.manager.interfaces.Push(activeLeaseWithIfindex(t, 13))
	original, err := f.manager.Allocate()
	require.NoError(t, err)
	require.NoError(t, f.manager.Recycle(original))
	neighbor, err := f.manager.Allocate()
	require.NoError(t, err)

	reopened := newTapRecoveryFixture(t, convergedTap(t, 13))
	reopened.manager.db = store.NewStoreImp(path)
	bytes, err := reopened.manager.db.LoadRaw(config.BridgeIpBucket)
	require.NoError(t, err)
	var state storedInterfaceIDs
	require.NoError(t, json.Unmarshal(bytes, &state))
	require.NoError(t, validatePooledLeaseState(state))
	reopened.manager.completedPooledLeases = state.CompletedPooledLeases
	for _, active := range state.Items {
		reopened.manager.usingInterfaces.Set(active, struct{}{})
	}
	require.NoError(t, reopened.manager.load(sets.New[string]()))
	down := reopened.linkOps.setDownCount
	require.NoError(t, reopened.manager.Recycle(original))
	require.Equal(t, down, reopened.linkOps.setDownCount)
	require.True(t, reopened.manager.usingInterfaces.Has(neighbor))
	require.Empty(t, reopened.manager.interfaces.List())

	changed, err := NewNetResource(original)
	require.NoError(t, err)
	changed.Type = "altered-facts"
	require.ErrorIs(t, reopened.manager.Recycle(changed.ToString()), errord.ErrFailedPrecondition)
	require.Equal(t, down, reopened.linkOps.setDownCount)
}

func TestPooledLeaseJournalRejectsContradictoryFacts(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	f.manager.interfaces.Push(activeLeaseWithIfindex(t, 13))
	lease, err := f.manager.Allocate()
	require.NoError(t, err)
	resource, err := NewNetResource(lease)
	require.NoError(t, err)
	for _, state := range []storedInterfaceIDs{
		{SchemaVersion: 3},
		{Items: []string{lease}},
		{SchemaVersion: 2, Items: []string{lease, lease}},
		{SchemaVersion: 2, Items: []string{lease}, CompletedPooledLeases: map[string]string{resource.LeaseID: pooledLeaseFingerprint(lease)}},
		{SchemaVersion: 2, CompletedPooledLeases: map[string]string{resource.LeaseID: "not-a-fingerprint"}},
	} {
		require.ErrorIs(t, validatePooledLeaseState(state), errord.ErrFailedPrecondition)
	}
}

func TestPooledLeaseMissingReceiptCannotAuthorizeRelease(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	f.manager.db = store.NewMockStore()
	f.manager.interfaces.Push(activeLeaseWithIfindex(t, 13))
	lease, err := f.manager.Allocate()
	require.NoError(t, err)
	// Simulate lost ownership without fabricating a successful release.
	f.manager.usingInterfaces.Pop(lease)
	down := f.linkOps.setDownCount
	require.ErrorIs(t, f.manager.Recycle(lease), errord.ErrFailedPrecondition)
	require.Equal(t, down, f.linkOps.setDownCount)
	require.Empty(t, f.manager.interfaces.List())
}

func TestPooledLeaseRetryCannotMutateReassignedEndpoint(t *testing.T) {
	for _, operation := range []string{"recycle", "deactivate", "discard"} {
		t.Run(operation, func(t *testing.T) {
			f := newTapRecoveryFixture(t, convergedTap(t, 13))
			f.manager.db = store.NewMockStore()
			f.manager.interfaces.Push(activeLeaseWithIfindex(t, 13))
			original, err := f.manager.Allocate()
			require.NoError(t, err)
			require.NoError(t, f.manager.Recycle(original))
			neighbor, err := f.manager.Allocate()
			require.NoError(t, err)
			require.NotEqual(t, original, neighbor, "reusing an endpoint must create a distinct lease incarnation")
			up, down := f.linkOps.setUpCount, f.linkOps.setDownCount
			switch operation {
			case "recycle":
				err = f.manager.Recycle(original)
			case "deactivate":
				err = f.manager.Deactivate(original)
			case "discard":
				err = f.manager.Discard(original)
			}
			require.NoError(t, err)
			require.True(t, f.manager.usingInterfaces.Has(neighbor))
			require.Equal(t, up, f.linkOps.setUpCount)
			require.Equal(t, down, f.linkOps.setDownCount)
			using, idle := f.manager.Status()
			require.Equal(t, []string{neighbor}, using)
			require.Empty(t, idle)
			stored, err := f.manager.db.LoadRaw(config.BridgeIpBucket)
			require.NoError(t, err)
			var state storedInterfaceIDs
			require.NoError(t, json.Unmarshal(stored, &state))
			require.Equal(t, []string{neighbor}, state.Items)
		})
	}
}

func TestPooledRecycleFailureKeepsLeaseOutOfIdlePool(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	db := &flakyRawStore{MockStore: store.NewMockStore()}
	f.manager.db = db
	f.manager.interfaces.Push(activeLeaseWithIfindex(t, 13))
	lease, err := f.manager.Allocate()
	require.NoError(t, err)
	db.rawErr = errors.New("release journal unavailable")
	require.ErrorContains(t, f.manager.Recycle(lease), "release journal unavailable")
	using, idle := f.manager.Status()
	require.Equal(t, []string{lease}, using)
	require.Empty(t, idle, "a release must be durable before the endpoint can be reassigned")
	db.rawErr = nil
	require.NoError(t, f.manager.Recycle(lease))
	using, idle = f.manager.Status()
	require.Empty(t, using)
	require.Len(t, idle, 1)
	stored, err := db.LoadRaw(config.BridgeIpBucket)
	require.NoError(t, err)
	var state storedInterfaceIDs
	require.NoError(t, json.Unmarshal(stored, &state))
	require.Empty(t, state.Items)
}
