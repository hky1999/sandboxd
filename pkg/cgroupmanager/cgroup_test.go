// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"
	gotypes "github.com/gogo/protobuf/types"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKernelOps models the kernel cgroup tree in memory: create and delete
// move names in and out of the listing that restart recovery observes, and
// every control operation is recorded behind a mutex so concurrent manager
// activity can be asserted without data races. It replaces only the
// privileged cgroup filesystem accesses; no real kernel cgroup is touched.
type fakeKernelOps struct {
	mu        sync.Mutex
	existing  map[string]struct{}
	created   []string
	calls     []string
	killErr   error
	deleteErr error
	resetErr  error
}

func newFakeKernelOps(names ...string) *fakeKernelOps {
	existing := make(map[string]struct{}, len(names))
	for _, name := range names {
		existing[name] = struct{}{}
	}
	return &fakeKernelOps{existing: existing}
}

func (f *fakeKernelOps) record(call, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call+":"+name)
}

func (f *fakeKernelOps) countCalls(call, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, recorded := range f.calls {
		if recorded == call+":"+name {
			count++
		}
	}
	return count
}

func (f *fakeKernelOps) createdNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.created...)
}

func (f *fakeKernelOps) mode() cgroups.CGMode               { return cgroups.Unified }
func (f *fakeKernelOps) prepareRoot(string, int64) error    { return nil }
func (f *fakeKernelOps) stat(string) (Stats, error)         { return Stats{}, nil }
func (f *fakeKernelOps) newOOMWatcher() (oomWatcher, error) { return newFakeOOMWatcher(), nil }

func (f *fakeKernelOps) list(string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.existing))
	for name := range f.existing {
		names = append(names, name)
	}
	return names, nil
}

func (f *fakeKernelOps) create(name string, _ *specs.LinuxResources) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "create:"+name)
	f.created = append(f.created, name)
	f.existing[name] = struct{}{}
	return nil
}

func (f *fakeKernelOps) reset(name string) error {
	f.record("reset", name)
	return f.resetErr
}

func (f *fakeKernelOps) setPidsLimit(name string, _ int64) error {
	f.record("pids", name)
	return nil
}

func (f *fakeKernelOps) update(name string, _ *specs.LinuxResources) error {
	f.record("update", name)
	return nil
}

func (f *fakeKernelOps) kill(name string) error {
	f.record("kill", name)
	return f.killErr
}

func (f *fakeKernelOps) delete(name string) error {
	f.record("delete", name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.existing, name)
	return nil
}

// failingRawStore fails every StoreRaw without writing, modeling a store
// that is unavailable at handout time.
type failingRawStore struct {
	*store.MockStore
	err error
}

func (f *failingRawStore) StoreRaw(string, []byte) error { return f.err }

// writeThenErrRawStore persists the payload through the wrapped store and
// still returns err while err is set, modeling a StoreRaw whose transaction
// committed but whose return path reported failure. Clearing err restores
// normal delegation.
type writeThenErrRawStore struct {
	*store.MockStore
	err error
}

func (f *writeThenErrRawStore) StoreRaw(key string, data []byte) error {
	if err := f.MockStore.StoreRaw(key, data); err != nil {
		return err
	}
	return f.err
}

// gatedRawStore records every payload handed to StoreRaw in order and parks
// the first call until the test releases it. Recording before parking models
// a store that has taken its snapshot but has not written yet, which lets a
// test interleave a background flush with a handout store deterministically.
type gatedRawStore struct {
	mu      sync.Mutex
	inner   store.DbStore
	writes  []string
	entered chan struct{}
	release chan struct{}
}

func (g *gatedRawStore) StoreRaw(_ string, data []byte) error {
	g.mu.Lock()
	g.writes = append(g.writes, string(data))
	first := len(g.writes) == 1
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
	return g.inner.StoreRaw(config.CgroupBucket, data)
}

func (g *gatedRawStore) LoadRaw(key string) ([]byte, error) {
	return g.inner.LoadRaw(key)
}

func (g *gatedRawStore) Store(key string, data interface{}) error {
	return g.inner.Store(key, data)
}

func (g *gatedRawStore) Load(key string) (*gotypes.Any, error) {
	return g.inner.Load(key)
}

func (g *gatedRawStore) written() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.writes...)
}

type handoutResult struct {
	lease string
	err   error
}

func newLeaseTestManager(
	t *testing.T,
	db store.DbStore,
	ops cgroupOps,
	cacheSize, max int,
) *CgroupManager {
	t.Helper()
	manager, err := newCgroupManagerWithOps(
		db,
		config.ResourceConfig{CgroupCacheSize: cacheSize},
		max,
		"/sandbox",
		ops,
	)
	require.NoError(t, err)
	return manager
}

// crashManager stops the background workers without the final shutdown
// store, simulating a daemon that dies before keepStoring's next tick. The
// manager must not be shut down afterwards.
func crashManager(t *testing.T, c *CgroupManager) {
	t.Helper()
	close(c.stopCh)
	c.wg.Wait()
}

func loadStoredCgroupIDs(t *testing.T, db store.DbStore) map[string]struct{} {
	t.Helper()
	raw, err := db.LoadRaw(config.CgroupBucket)
	if errord.IsNotFound(err) {
		return map[string]struct{}{}
	}
	require.NoError(t, err)
	var stored storedCgroupIDs
	require.NoError(t, json.Unmarshal(raw, &stored))
	items := make(map[string]struct{}, len(stored.Items))
	for _, id := range stored.Items {
		items[id] = struct{}{}
	}
	return items
}

// TestAllocatePersistsIdleLeaseBeforeHandoffOnDisk pins the
// crash-consistency boundary on the idle path against a real on-disk bbolt
// store: the lease must already sit in the durable active set when Allocate
// returns, not only on keepStoring's next tick. A daemon dying between
// handoff and that tick otherwise recovers the leased cgroup as idle and
// cleanForReuse kills the processes of the sandbox that already started in
// it.
func TestAllocatePersistsIdleLeaseBeforeHandoffOnDisk(t *testing.T) {
	db := store.NewStoreImp(filepath.Join(t.TempDir(), "cgroup.db"))
	ops := newFakeKernelOps("/sandbox/aaa", "/sandbox/bbb")
	manager := newLeaseTestManager(t, db, ops, 2, 2)
	defer func() { require.NoError(t, manager.ShutDown()) }()

	lease, err := manager.Allocate()
	require.NoError(t, err)

	assert.True(t, manager.usingID.Has(lease))
	assert.Contains(t, loadStoredCgroupIDs(t, db), lease,
		"the idle-path lease must be durable before Allocate returns")
	assert.True(t, manager.storeDirty.Load(),
		"the pending mark stays set so keepStoring cannot drop a concurrent Recycle from the next flush")
}

// TestAllocatePersistsCreatedLeaseBeforeHandoff covers the same boundary on
// the cache-miss path, where the cgroup is created by the maintenance
// goroutine right before the handout.
func TestAllocatePersistsCreatedLeaseBeforeHandoff(t *testing.T) {
	db := store.NewMockStore()
	ops := newFakeKernelOps()
	manager := newLeaseTestManager(t, db, ops, 0, 4)
	defer func() { require.NoError(t, manager.ShutDown()) }()

	lease, err := manager.Allocate()
	require.NoError(t, err)

	assert.True(t, manager.cgroups.Has(lease))
	assert.Contains(t, loadStoredCgroupIDs(t, db), lease,
		"the created-path lease must be durable before Allocate returns")
}

// TestReopenAfterCrashKeepsConfirmedActiveLease is the restart half of the
// boundary and the regression for the kill window this change closes: after
// a crash right after the handout, reopening against the same store and the
// same cgroup tree must recover the persisted lease as active and must never
// clean it, while the sibling that was never leased is the one recovery
// cleans into the idle cache.
func TestReopenAfterCrashKeepsConfirmedActiveLease(t *testing.T) {
	db := store.NewStoreImp(filepath.Join(t.TempDir(), "cgroup.db"))
	ops := newFakeKernelOps("/sandbox/aaa", "/sandbox/bbb")
	manager := newLeaseTestManager(t, db, ops, 2, 2)

	lease, err := manager.Allocate()
	require.NoError(t, err)
	crashManager(t, manager)

	persisted := loadStoredCgroupIDs(t, db)
	require.Contains(t, persisted, lease,
		"without the synchronous handout store this record exists only after keepStoring's next tick")

	reopened := newLeaseTestManager(t, db, ops, 2, 2)
	defer func() { require.NoError(t, reopened.ShutDown()) }()

	using, idle := reopened.Status()
	assert.Contains(t, using, lease, "a persisted active lease must be recovered as active")
	assert.NotContains(t, idle, lease)

	sibling := "/sandbox/aaa"
	if lease == sibling {
		sibling = "/sandbox/bbb"
	}
	// Both siblings were cleaned once by the first manager's own recovery;
	// only the unpersisted one may be cleaned again by the reopen.
	assert.Equal(t, 2, ops.countCalls("kill", sibling),
		"the unpersisted sibling is cleaned into the idle cache on each recovery")
	assert.Equal(t, 2, ops.countCalls("reset", sibling))
	assert.Equal(t, 1, ops.countCalls("kill", lease),
		"recovery must never kill inside a recovered active lease beyond its pre-lease cleaning")
	assert.Equal(t, 1, ops.countCalls("reset", lease))
}

// TestAllocateFailsClosedWhenIdleLeaseCannotBeDurable is the failure half of
// the boundary: a StoreRaw failure must prevent the allocation. No lease is
// returned, and because Allocate applies no cgroup controls (Prepare only
// runs once the caller holds a confirmed lease), the popped cgroup is still
// exactly in its clean idle state and returns to the cache with total
// unchanged — reusable rather than leaked or double-handed.
func TestAllocateFailsClosedWhenIdleLeaseCannotBeDurable(t *testing.T) {
	db := &failingRawStore{MockStore: store.NewMockStore(), err: errors.New("bbolt unavailable")}
	ops := newFakeKernelOps("/sandbox/aaa")
	manager := newLeaseTestManager(t, db, ops, 1, 1)
	defer func() { _ = manager.ShutDown() }()
	// Construction recovery cleaned the seeded cgroup into the cache once;
	// the assertions below track new control operations from here on.
	killDuringRecovery := ops.countCalls("kill", "/sandbox/aaa")

	lease, err := manager.Allocate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "bbolt unavailable")
	assert.Empty(t, lease, "no lease may be returned when it cannot be made durable")

	using, idle := manager.Status()
	assert.Empty(t, using, "no lease may stay active when none was returned")
	assert.Equal(t, []string{"/sandbox/aaa"}, idle)
	assert.Equal(t, 1, manager.total, "total stays exact across the rolled-back handout")
	assert.Equal(t, killDuringRecovery, ops.countCalls("kill", "/sandbox/aaa"),
		"idle-path rollback needs no kernel convergence because the handout never touched controls")
	assert.True(t, manager.storeDirty.Load(),
		"the corrective flush stays pending for a possible write-then-error record")

	manager.db = store.NewMockStore()
	lease, err = manager.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "/sandbox/aaa", lease, "the rolled-back name is reusable once the store recovers")
	assert.Contains(t, loadStoredCgroupIDs(t, manager.db), lease)
}

// TestAllocateFailsClosedWhenCreatedLeaseCannotBeDurable covers rollback of
// a freshly created cgroup when the idle cache has no room: the cgroup is
// destroyed synchronously, the reservation is released, and the generated
// name returns to the pool.
func TestAllocateFailsClosedWhenCreatedLeaseCannotBeDurable(t *testing.T) {
	db := &failingRawStore{MockStore: store.NewMockStore(), err: errors.New("bbolt unavailable")}
	ops := newFakeKernelOps()
	manager := newLeaseTestManager(t, db, ops, 0, 4)
	defer func() { _ = manager.ShutDown() }()

	lease, err := manager.Allocate()
	require.Error(t, err)
	assert.Empty(t, lease)

	created := ops.createdNames()
	require.Len(t, created, 1)
	assert.Zero(t, manager.total, "the create reservation is released by the rollback")
	assert.Empty(t, manager.idleID.List())
	_, idle := manager.Status()
	assert.Empty(t, idle)
	assert.False(t, manager.cgroups.Has(created[0]))
	assert.Equal(t, 1, ops.countCalls("delete", created[0]),
		"a cache-full rollback destroys the never-handed-out cgroup")
	assert.Zero(t, manager.generator.Len(),
		"the destroyed cgroup's name is released for future creates")
}

// TestAllocateQuarantinesLeaseWhenRollbackDestroyFails covers the rollback
// branch that cannot be completed: when the synchronous destroy fails, the
// lease must stay active so the name stays quarantined and counted in the
// pool ceiling instead of being reused, queued for GC, or silently dropped.
func TestAllocateQuarantinesLeaseWhenRollbackDestroyFails(t *testing.T) {
	db := &failingRawStore{MockStore: store.NewMockStore(), err: errors.New("bbolt unavailable")}
	ops := newFakeKernelOps()
	ops.deleteErr = errors.New("device busy")
	manager := newLeaseTestManager(t, db, ops, 0, 1)
	defer func() { _ = manager.ShutDown() }()

	lease, err := manager.Allocate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "quarantined")
	assert.Empty(t, lease)

	using, _ := manager.Status()
	require.Len(t, using, 1)
	assert.Equal(t, 1, manager.total, "the quarantined lease stays counted in the pool ceiling")
	assert.True(t, manager.storeDirty.Load(),
		"the quarantined lease stays pending so the periodic store persists it as active")
	assert.Empty(t, manager.gcQueue.List(),
		"an unconfirmed destroy must not free the name through the GC queue either")

	_, err = manager.Allocate()
	assert.ErrorIs(t, err, errord.ErrResourceExhausted,
		"the quarantined name is not allocatable: the pool is at max with a lease nobody owns")
}

// TestWriteThenErrorHandoutRollbackIsCorrectedByFlush models a StoreRaw that
// committed its transaction but still returned an error: the handout fails
// closed and the cgroup rolls back to idle even though the persisted set may
// transiently still record the lease. storeDirty staying set is what makes
// the next keepStoring flush correct that record.
func TestWriteThenErrorHandoutRollbackIsCorrectedByFlush(t *testing.T) {
	db := &writeThenErrRawStore{
		MockStore: store.NewMockStore(),
		err:       errors.New("fsync failed after commit"),
	}
	ops := newFakeKernelOps("/sandbox/aaa")
	manager := newLeaseTestManager(t, db, ops, 1, 1)
	defer func() { _ = manager.ShutDown() }()

	lease, err := manager.Allocate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "fsync failed after commit")
	assert.Empty(t, lease)

	_, idle := manager.Status()
	assert.Equal(t, []string{"/sandbox/aaa"}, idle)
	assert.Contains(t, loadStoredCgroupIDs(t, db), "/sandbox/aaa",
		"write-then-error leaves the record on disk despite the returned error")

	require.True(t, manager.storeDirty.Load())
	db.err = nil
	require.NoError(t, manager.store(), "the pending corrective flush")
	assert.NotContains(t, loadStoredCgroupIDs(t, db), "/sandbox/aaa",
		"the corrective flush must drop the lease that was never handed out")
}

// TestBackgroundStoreSnapshotCannotOverwriteConfirmedLease pins the
// serialization between snapshots and writes: a keepStoring-style flush that
// snapshotted the active set before the handout and is parked mid-write must
// not be able to overwrite the lease the handout store confirmed afterwards.
func TestBackgroundStoreSnapshotCannotOverwriteConfirmedLease(t *testing.T) {
	inner := store.NewMockStore()
	db := &gatedRawStore{
		inner:   inner,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ops := newFakeKernelOps("/sandbox/aaa")
	manager := newLeaseTestManager(t, db, ops, 1, 1)
	defer func() { _ = manager.ShutDown() }()

	storeDone := make(chan error, 1)
	go func() { storeDone <- manager.store() }()
	<-db.entered

	handout := make(chan handoutResult, 1)
	go func() {
		lease, err := manager.Allocate()
		handout <- handoutResult{lease: lease, err: err}
	}()
	require.Eventually(t, func() bool { return manager.usingID.Has("/sandbox/aaa") },
		5*time.Second, time.Millisecond,
		"the handout marks the lease active before its store can proceed")

	close(db.release)
	require.NoError(t, <-storeDone)
	res := <-handout
	require.NoError(t, res.err)
	assert.Equal(t, "/sandbox/aaa", res.lease)

	writes := db.written()
	require.Len(t, writes, 2, "the background flush and the handout store both wrote")
	assert.NotContains(t, writes[0], "/sandbox/aaa",
		"the background flush carried the pre-handout snapshot")
	assert.Contains(t, writes[1], "/sandbox/aaa")
	assert.Contains(t, loadStoredCgroupIDs(t, inner), "/sandbox/aaa",
		"the newest active set, not the stale snapshot, is what survives on disk")
}

// TestShutdownWaitsForInFlightHandoutAndFailsClosedAfterwards covers the
// shutdown ordering: a handout that already entered the manager finishes its
// durable record first, the shutdown store is the last write and keeps the
// confirmed lease, and allocations that arrive afterwards fail closed.
func TestShutdownWaitsForInFlightHandoutAndFailsClosedAfterwards(t *testing.T) {
	inner := store.NewMockStore()
	db := &gatedRawStore{
		inner:   inner,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ops := newFakeKernelOps("/sandbox/aaa")
	manager := newLeaseTestManager(t, db, ops, 1, 1)

	handout := make(chan handoutResult, 1)
	go func() {
		lease, err := manager.Allocate()
		handout <- handoutResult{lease: lease, err: err}
	}()
	<-db.entered

	shutdown := make(chan error, 1)
	go func() { shutdown <- manager.ShutDown() }()
	select {
	case err := <-shutdown:
		t.Fatalf("shutdown must wait for the in-flight durable handoff, returned %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(db.release)
	res := <-handout
	require.NoError(t, res.err)
	assert.Equal(t, "/sandbox/aaa", res.lease)
	require.NoError(t, <-shutdown)

	assert.Contains(t, loadStoredCgroupIDs(t, inner), "/sandbox/aaa",
		"the shutdown store keeps the confirmed lease")
	_, err := manager.Allocate()
	assert.ErrorIs(t, err, errCgroupManagerStopped)
}

// TestShutdownCancelsQueuedCreationWait is the cancellation half of the
// shutdown ordering: stopCh must close promptly while an allocation is
// waiting for a queued or delayed creation — exactly as it did before
// durable handoffs existed — because a lifecycle lock held across that wait
// would let one allocation block shutdown cancellation for everyone. The
// waiting allocation then returns the stopped error once stopCh closes.
func TestShutdownCancelsQueuedCreationWait(t *testing.T) {
	// Bare manager with no maintenance goroutine: the request stays queued
	// and the allocation parks on its result, modeling a delayed creation.
	manager := &CgroupManager{
		max:        1,
		usingID:    cmap.New[struct{}](),
		idleID:     util.New[string](""),
		cgroups:    cmap.New[struct{}](),
		stopCh:     make(chan struct{}),
		createReqs: make(chan *createRequest, 1),
		oom:        newFakeOOMWatcher(),
	}

	allocated := make(chan struct{})
	go func() {
		_, _ = manager.Allocate()
		close(allocated)
	}()
	var req *createRequest
	select {
	case req = <-manager.createReqs:
	case <-time.After(5 * time.Second):
		t.Fatal("allocation never dispatched its create request")
	}

	shutdown := make(chan error, 1)
	go func() { shutdown <- manager.ShutDown() }()
	select {
	case <-manager.stopCh:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("ShutDown must close stopCh while Allocate awaits a delayed creation")
	}

	// The parked allocation cancels through stopCh without any fixture help.
	select {
	case <-allocated:
	case <-time.After(5 * time.Second):
		t.Fatal("allocation stuck after stopCh closed")
	}
	// Release the fixture channel so a later accidental read cannot block.
	req.result <- createResult{err: errors.New("release test creation")}
	require.NoError(t, <-shutdown)
	_, err := manager.Allocate()
	assert.ErrorIs(t, err, errCgroupManagerStopped)
}

// blockingDeleteOps wraps the in-memory kernel fake with a delete that
// signals entry, parks until released, and then fails — modeling a physical
// removal that is slow and ultimately unsuccessful.
type blockingDeleteOps struct {
	*fakeKernelOps
	entered chan struct{}
	release chan struct{}
}

func (o *blockingDeleteOps) delete(string) error {
	close(o.entered)
	<-o.release
	return errors.New("physical delete failed")
}

// failOnceRawStore fails the first StoreRaw and delegates every later call,
// so one allocation can be made to fail its durable handoff on demand.
type failOnceRawStore struct {
	store.DbStore
	calls atomic.Int32
}

func (f *failOnceRawStore) StoreRaw(key string, data []byte) error {
	if f.calls.Add(1) == 1 {
		return errors.New("first write fails")
	}
	return f.DbStore.StoreRaw(key, data)
}

// TestRollbackKeepsReservationUntilDeleteSucceeds pins the capacity bound of
// a failed rollback: the reservation is released only after the physical
// deletion succeeds, so while a rollback delete is still in flight — and
// even when it ultimately fails — a concurrent allocation must see the pool
// at its ceiling instead of consuming capacity that the failed delete then
// has to give back (which would push total past max and leave two active
// leases with only one slot). The failed delete quarantines the name while
// keeping the reservation it already holds.
func TestRollbackKeepsReservationUntilDeleteSucceeds(t *testing.T) {
	ops := &blockingDeleteOps{
		fakeKernelOps: newFakeKernelOps(),
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	manager := &CgroupManager{
		max:        1,
		cacheSize:  0,
		rootName:   "/sandbox",
		usingID:    cmap.New[struct{}](),
		idleID:     util.New[string](""),
		cgroups:    cmap.New[struct{}](),
		stopCh:     make(chan struct{}),
		createReqs: make(chan *createRequest, 2),
		gcQueue:    util.New[string](""),
		gcWake:     make(chan struct{}, 1),
		oom:        newFakeOOMWatcher(),
		ops:        ops,
		db: &failOnceRawStore{
			DbStore: store.NewStoreImp(filepath.Join(t.TempDir(), "leases.db")),
		},
	}

	type allocResult struct {
		lease string
		err   error
	}
	first := make(chan allocResult, 1)
	go func() {
		lease, err := manager.Allocate()
		first <- allocResult{lease, err}
	}()
	var req *createRequest
	select {
	case req = <-manager.createReqs:
	case <-time.After(5 * time.Second):
		t.Fatal("first allocation not dispatched")
	}
	manager.cgroups.Set("/sandbox/first", struct{}{})
	req.result <- createResult{id: "/sandbox/first"}

	select {
	case <-ops.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("rollback delete not reached")
	}

	// While the rollback delete is parked, the freed-looking slot must not
	// be allocatable: the reservation is still held. If a buggy release
	// already dispatched a create, serve it so the defect shows up as the
	// ceiling assertion below instead of a hang.
	second := make(chan allocResult, 1)
	go func() {
		lease, err := manager.Allocate()
		second <- allocResult{lease, err}
	}()
	select {
	case req = <-manager.createReqs:
		manager.cgroups.Set("/sandbox/second", struct{}{})
		req.result <- createResult{id: "/sandbox/second"}
		got := <-second
		assert.NoError(t, got.err)
		assert.Equal(t, "/sandbox/second", got.lease)
	case got := <-second:
		assert.ErrorIs(t, got.err, errord.ErrResourceExhausted,
			"capacity must stay reserved until the rollback delete outcome is known")
		assert.Empty(t, got.lease)
	case <-time.After(5 * time.Second):
		t.Fatal("second allocation blocked unexpectedly")
	}

	close(ops.release)
	got := <-first
	require.Error(t, got.err)
	assert.ErrorContains(t, got.err, "quarantined")
	assert.Empty(t, got.lease)

	assert.LessOrEqual(t, manager.total, manager.max,
		"a failed physical deletion must not push the pool past its ceiling after capacity reuse")
	assert.Equal(t, 1, manager.total,
		"the failed rollback keeps exactly its own reservation")
	assert.True(t, manager.usingID.Has("/sandbox/first"))
	assert.Empty(t, manager.idleID.List())
	assert.Empty(t, manager.gcQueue.List(),
		"an unconfirmed destroy must not free the name through the GC queue either")
}

// TestConcurrentAllocateRecycleStoreKeepsActiveSetExact exercises the
// Allocate/Recycle/store interleavings under the race detector: no name is
// ever handed out twice simultaneously, total stays equal to using + idle,
// and every lease still held when the daemon shuts down is durable, so a
// reopen recovers exactly those as active without cleaning them.
func TestConcurrentAllocateRecycleStoreKeepsActiveSetExact(t *testing.T) {
	const (
		seededIdle = 6
		workers    = 8
		iterations = 25
	)
	names := make([]string, 0, seededIdle)
	for i := range seededIdle {
		names = append(names, fmt.Sprintf("/sandbox/idle%d", i))
	}
	ops := newFakeKernelOps(names...)
	db := store.NewMockStore()
	manager := newLeaseTestManager(t, db, ops, seededIdle, seededIdle+workers)

	var violationsMu sync.Mutex
	var violations []string
	recordViolation := func(format string, args ...any) {
		violationsMu.Lock()
		defer violationsMu.Unlock()
		violations = append(violations, fmt.Sprintf(format, args...))
	}

	var outMu sync.Mutex
	out := make(map[string]bool)

	workersDone := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range iterations {
				lease, err := manager.Allocate()
				if err != nil {
					recordViolation("allocate: %v", err)
					continue
				}
				outMu.Lock()
				if out[lease] {
					recordViolation("double handout of %s", lease)
				}
				out[lease] = true
				outMu.Unlock()

				if i == iterations-1 {
					continue // keep the last lease held at shutdown
				}
				if err := manager.Recycle(lease); err != nil {
					recordViolation("recycle %s: %v", lease, err)
				}
				outMu.Lock()
				delete(out, lease)
				outMu.Unlock()
			}
		}()
	}
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		for {
			select {
			case <-workersDone:
				return
			default:
			}
			if err := manager.store(); err != nil {
				recordViolation("background store: %v", err)
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	wg.Wait()
	close(workersDone)
	<-flushDone
	assert.Empty(t, violations)

	outMu.Lock()
	held := make([]string, 0, len(out))
	for lease, isOut := range out {
		if isOut {
			held = append(held, lease)
		}
	}
	outMu.Unlock()
	assert.NotEmpty(t, held, "the workers keep their final leases across shutdown")

	using, idle := manager.Status()
	assert.Len(t, using, len(held))
	assert.Equal(t, manager.total, len(using)+len(idle),
		"total stays equal to using + idle once no create is in flight")
	for _, lease := range held {
		assert.Contains(t, using, lease)
	}

	require.NoError(t, manager.ShutDown())
	persisted := loadStoredCgroupIDs(t, db)
	for _, lease := range held {
		assert.Contains(t, persisted, lease,
			"every lease held across shutdown is durable after the final store")
	}

	killSnapshot := make(map[string]int, len(held))
	for _, lease := range held {
		killSnapshot[lease] = ops.countCalls("kill", lease)
	}
	reopened := newLeaseTestManager(t, db, ops, seededIdle, seededIdle+workers)
	defer func() { require.NoError(t, reopened.ShutDown()) }()

	reopenedUsing, _ := reopened.Status()
	assert.Len(t, reopenedUsing, len(held),
		"the reopen recovers exactly the durable active leases")
	for _, lease := range held {
		assert.Contains(t, reopenedUsing, lease)
		assert.Equal(t, killSnapshot[lease], ops.countCalls("kill", lease),
			"recovery must never clean a lease that was durable at shutdown")
	}
}
