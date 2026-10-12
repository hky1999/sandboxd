// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package xpumanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type generationFailStore struct {
	store.DbStore
	writes, failWrite  int
	failRead           bool
	loseReadAfterWrite bool
}

func (s *generationFailStore) StoreRaw(key string, data []byte) error {
	s.writes++
	if s.writes == s.failWrite {
		return errors.New("device journal write unavailable")
	}
	if err := s.DbStore.StoreRaw(key, data); err != nil {
		return err
	}
	if s.loseReadAfterWrite {
		s.failRead = true
	}
	return nil
}
func (s *generationFailStore) LoadRaw(key string) ([]byte, error) {
	if s.failRead {
		return nil, errors.New("device journal read unavailable")
	}
	return s.DbStore.LoadRaw(key)
}

func ownedGenerationManager(t *testing.T, root string, db store.DbStore) *Manager {
	t.Helper()
	m := testManager(t)
	m.sandboxRoot = root
	require.NoError(t, m.initializeGenerationJournal(db))
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m
}
func generationFixture(t *testing.T) (*Manager, *generationFailStore) {
	t.Helper()
	root := t.TempDir()
	db := &generationFailStore{DbStore: store.NewStoreImp(filepath.Join(root, "devices.db"))}
	return ownedGenerationManager(t, filepath.Join(root, "containers"), db), db
}
func oneDevice() []*api.XpuAllocation {
	return []*api.XpuAllocation{{Type: "gpu", DeviceIds: []uint32{0}}}
}

func TestDeviceGenerationRetirementReplayPreservesSameIDReplacementAfterReopen(t *testing.T) {
	m, db := generationFixture(t)
	updates, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.NoError(t, err)
	var allocation leaseRecord
	require.NoError(t, json.Unmarshal([]byte(updates.Annotations[AllocationAnnotation]), &allocation))
	require.Equal(t, "original-generation", allocation.Generation)
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.NoError(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	_, err = m.AcquireForGeneration("sbox-original", "replacement-generation", oneDevice())
	require.NoError(t, err)
	root := m.sandboxRoot
	require.NoError(t, m.Close())
	m = ownedGenerationManager(t, root, db)
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.Equal(t, "sbox-original", m.leases["GPU-uuid-0"])
	require.Equal(t, "active", m.generationRecords["replacement-generation"].State)
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-original", "replacement-generation"))
	_, err = m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.Error(t, err, "late original acquire must remain fenced")
	_, err = m.AcquireForGeneration("sbox-neighbor", "neighbor-generation", oneDevice())
	require.ErrorContains(t, err, "already leased")
}

func TestDeviceGenerationMissingChangedAndUnconditionalRequestsCannotRelease(t *testing.T) {
	m, _ := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.NoError(t, err)
	require.Error(t, m.ReleaseIfGeneration("sbox-original", "unknown-generation"))
	require.Error(t, m.ReleaseIfGeneration("sbox-other", "original-generation"))
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-original", "unknown-generation"))
	m.Release("sbox-original")
	require.Equal(t, "sbox-original", m.leases["GPU-uuid-0"])
	_, err = m.AcquireForGeneration("sbox-original", "original-generation", []*api.XpuAllocation{{Type: "gpu", DeviceIds: []uint32{2}}})
	require.Error(t, err)
	_, err = m.AcquireForGeneration("sbox-original", "replacement-generation", nil)
	require.Error(t, err)
	_, err = m.Acquire("sbox-neighbor", oneDevice())
	require.Error(t, err)
}

func TestDeviceGenerationPartialAllocationWriteRetiresIntentWithoutLeasing(t *testing.T) {
	m, db := generationFixture(t)
	db.failWrite = db.writes + 2
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.ErrorContains(t, err, "write unavailable")
	require.Empty(t, m.leases)
	require.Equal(t, "intent", m.generationRecords["original-generation"].State)
	db.failWrite = 0
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.NoError(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	require.False(t, m.generationRecords["original-generation"].Allocated)
	_, err = m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.Error(t, err)
}

func TestDeviceGenerationReleaseWriteFailureKeepsOriginalLease(t *testing.T) {
	m, db := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.NoError(t, err)
	db.failWrite = db.writes + 1
	require.ErrorContains(t, m.ReleaseIfGeneration("sbox-original", "original-generation"), "write unavailable")
	require.Equal(t, "sbox-original", m.leases["GPU-uuid-0"])
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	db.failWrite = 0
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.Empty(t, m.leases)
}

func TestDeviceGenerationCommittedReleaseLostReadbackRecoversIndependentProof(t *testing.T) {
	m, db := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.NoError(t, err)
	db.loseReadAfterWrite = true
	require.ErrorContains(t, m.ReleaseIfGeneration("sbox-original", "original-generation"), "read unavailable")
	require.Equal(t, "sbox-original", m.leases["GPU-uuid-0"])
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	db.failRead, db.loseReadAfterWrite = false, false
	require.ErrorContains(t, m.ReleaseIfGeneration("sbox-original", "original-generation"), "unresolved")
	root := m.sandboxRoot
	require.NoError(t, m.Close())
	m = ownedGenerationManager(t, root, db)
	require.Empty(t, m.leases)
	require.NoError(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	_, err = m.AcquireForGeneration("sbox-neighbor", "neighbor-generation", oneDevice())
	require.NoError(t, err)
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.Equal(t, "sbox-neighbor", m.leases["GPU-uuid-0"])
}

func TestDeviceGenerationCPUOnlyOwnershipWorksWithoutGPUDiscovery(t *testing.T) {
	root := t.TempDir()
	db := store.NewStoreImp(filepath.Join(root, "devices.db"))
	m, err := NewWithStore("", filepath.Join(root, "containers"), db)
	require.NoError(t, err)
	defer m.Close()
	require.Empty(t, m.Resources())
	updates, err := m.AcquireForGeneration("sbox-cpu", "cpu-generation", nil)
	require.NoError(t, err)
	require.Nil(t, updates)
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-cpu", "cpu-generation"))
	require.NoError(t, m.ReleaseIfGeneration("sbox-cpu", "cpu-generation"))
	require.NoError(t, m.Close())
	m, err = NewWithStore("", filepath.Join(root, "containers"), db)
	require.NoError(t, err)
	defer m.Close()
	require.NoError(t, m.ConfirmReleasedForGeneration("sbox-cpu", "cpu-generation"))
}

func TestDeviceGenerationDuplicateOwnerAndReplacedJournalCannotMutate(t *testing.T) {
	m, db := generationFixture(t)
	other := testManager(t)
	other.sandboxRoot = m.sandboxRoot
	require.ErrorContains(t, other.initializeGenerationJournal(db), "already has an owner")
	path := m.generationOwner.path
	require.NoError(t, os.Rename(path, path+"-original"))
	require.NoError(t, os.Mkdir(path, 0700))
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", nil)
	require.ErrorContains(t, err, "directory changed")
	require.Empty(t, m.generationRecords)
}

func TestDeviceGenerationDamagedOrMissingJournalCannotProveEmptyOwnership(t *testing.T) {
	m, db := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", nil)
	require.NoError(t, err)
	require.NoError(t, db.DbStore.StoreRaw(generationLeaseBucket, []byte(`{"version":1,"records":{}}`)))
	require.Error(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.Error(t, m.ConfirmReleasedForGeneration("sbox-original", "original-generation"))
	root := m.sandboxRoot
	require.NoError(t, m.Close())
	other := testManager(t)
	other.sandboxRoot = root
	require.Error(t, other.initializeGenerationJournal(db))
}

func TestDeviceGenerationLegacyLeaseCannotBeBorrowedByNewGeneration(t *testing.T) {
	m, _ := generationFixture(t)
	m.leases["GPU-uuid-0"] = "sbox-original"
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", nil)
	require.ErrorContains(t, err, "legacy")
	require.Error(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	require.Equal(t, "sbox-original", m.leases["GPU-uuid-0"])
}

func TestDeviceGenerationStrictJournalRejectsDuplicateUnknownAndTrailingFields(t *testing.T) {
	m, db := generationFixture(t)
	raw, err := db.LoadRaw(generationLeaseBucket)
	require.NoError(t, err)
	for _, data := range [][]byte{
		append(append([]byte(nil), raw...), []byte(` {}`)...),
		append([]byte(`{"extra":1,`), raw[1:]...),
		append([]byte(`{"version":1,`), raw[1:]...),
	} {
		_, err := decodeGenerationState(data)
		require.Error(t, err)
	}
	_ = m
}

func TestDeviceGenerationLostInitializedRecordsCannotCreateFreshPool(t *testing.T) {
	m, db := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", oneDevice())
	require.NoError(t, err)
	root := m.sandboxRoot
	require.NoError(t, m.Close())
	// A different empty database is loss of the initialized namespace, not a
	// new node. Refuse bootstrap even when discovery reports idle devices.
	other := testManager(t)
	other.sandboxRoot = root
	require.ErrorContains(t, other.initializeGenerationJournal(store.NewMockStore()), "initialized original device journal is missing")
	// Losing both the data and initialization cannot erase namespace history.
	require.NoError(t, os.Remove(filepath.Join(filepath.Dir(root), "scheduler-xpu-leases", "initialization.json")))
	other = testManager(t)
	other.sandboxRoot = root
	require.ErrorContains(t, other.initializeGenerationJournal(store.NewMockStore()), "no original initialization")
	_ = db
}

func TestDeviceGenerationForeignJournalCannotBorrowOriginalCompletions(t *testing.T) {
	m, db := generationFixture(t)
	_, err := m.AcquireForGeneration("sbox-original", "original-generation", nil)
	require.NoError(t, err)
	require.NoError(t, m.ReleaseIfGeneration("sbox-original", "original-generation"))
	raw, err := db.LoadRaw(generationLeaseBucket)
	require.NoError(t, err)
	foreign, foreignDB := generationFixture(t)
	root := foreign.sandboxRoot
	require.NoError(t, foreign.Close())
	require.NoError(t, foreignDB.DbStore.StoreRaw(generationLeaseBucket, raw))
	other := testManager(t)
	other.sandboxRoot = root
	require.ErrorContains(t, other.initializeGenerationJournal(foreignDB), "another journal")
}

func TestDeviceGenerationFullJournalRefusesAllocationWithoutDiscardingHistory(t *testing.T) {
	m, db := generationFixture(t)
	records := make(map[string]generationLeaseRecord, generationLeaseLimit)
	for i := 0; i < generationLeaseLimit; i++ {
		generation := fmt.Sprintf("history-%d", i)
		records[generation] = generationLeaseRecord{Generation: generation, SandboxID: "sbox-history", Fingerprint: deviceSHA(nil), State: "released", Lease: leaseRecord{SandboxID: "sbox-history", Generation: generation}}
	}
	require.NoError(t, m.writeGenerationStateLocked(records))
	writes := db.writes
	digest := m.generationDigest
	_, err := m.AcquireForGeneration("sbox-new", "new-generation", nil)
	require.ErrorContains(t, err, "full")
	require.Equal(t, writes, db.writes)
	require.Equal(t, digest, m.generationDigest)
	require.Len(t, m.generationRecords, generationLeaseLimit)
}
