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
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
)

type leaseTestStore struct {
	store.DbStore
	mu      sync.Mutex
	data    []byte
	err     error
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (s *leaseTestStore) StoreRaw(key string, data []byte) error {
	if key != config.CgroupBucket {
		return errors.New("unexpected bucket")
	}
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	err := s.err
	s.mu.Unlock()
	if first && s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]byte(nil), data...)
	return nil
}
func (s *leaseTestStore) IDs(t *testing.T) []string {
	t.Helper()
	s.mu.Lock()
	data := append([]byte(nil), s.data...)
	s.mu.Unlock()
	if len(data) == 0 {
		return nil
	}
	var snapshot storedCgroupIDs
	require.NoError(t, json.Unmarshal(data, &snapshot))
	return snapshot.Items
}
func leaseTestManager(db *leaseTestStore, cached bool) *CgroupManager {
	c := &CgroupManager{rootName: "/sandbox", max: 1, cacheSize: 1, usingID: cmap.New[struct{}](), idleID: util.New(""), cgroups: cmap.New[struct{}](), db: db, stopCh: make(chan struct{}), createReqs: make(chan *createRequest)}
	c.cgroups.Set("/sandbox/lease", struct{}{})
	if cached {
		c.total = 1
		c.idleID.Push("/sandbox/lease")
	}
	return c
}
func TestAllocatePersistsLeaseBeforeReturn(t *testing.T) {
	for _, cached := range []bool{true, false} {
		t.Run(map[bool]string{true: "cached", false: "created"}[cached], func(t *testing.T) {
			db := &leaseTestStore{}
			c := leaseTestManager(db, cached)
			if !cached {
				go func() { req := <-c.createReqs; req.result <- createResult{id: "/sandbox/lease"} }()
			}
			id, err := c.Allocate()
			require.NoError(t, err)
			require.Equal(t, "/sandbox/lease", id)
			require.Contains(t, db.IDs(t), id, "successful admission must survive a crash before the periodic writer")
		})
	}
}
func TestAllocateWaitsForDurableLeaseCommit(t *testing.T) {
	db := &leaseTestStore{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(db.release) }) }
	defer unblock()
	c := leaseTestManager(db, true)
	type answer struct {
		id  string
		err error
	}
	done := make(chan answer, 1)
	go func() { id, err := c.Allocate(); done <- answer{id, err} }()
	select {
	case <-db.entered:
	case <-done:
		t.Fatal("allocation returned before any ownership commit")
	case <-time.After(5 * time.Second):
		t.Fatal("allocation never attempted its commit")
	}
	select {
	case <-done:
		t.Fatal("allocation acknowledged a blocked ownership commit")
	default:
	}
	unblock()
	select {
	case a := <-done:
		require.NoError(t, a.err)
		require.Contains(t, db.IDs(t), a.id)
	case <-time.After(5 * time.Second):
		t.Fatal("committed allocation did not return")
	}
}
func TestAllocateStoreFailureDoesNotAdmitOrLoseCapacity(t *testing.T) {
	failure := errors.New("lease database unavailable")
	db := &leaseTestStore{err: failure}
	c := leaseTestManager(db, true)
	id, err := c.Allocate()
	require.ErrorIs(t, err, failure)
	require.Empty(t, id)
	require.Empty(t, c.usingID.Keys())
	require.Equal(t, []string{"/sandbox/lease"}, c.idleID.List())
	db.mu.Lock()
	db.err = nil
	db.mu.Unlock()
	id, err = c.Allocate()
	require.NoError(t, err)
	require.Contains(t, db.IDs(t), id)
}
func TestOlderStoreCannotOverwriteCommittedAllocation(t *testing.T) {
	db := &leaseTestStore{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(db.release) }) }
	defer unblock()
	c := leaseTestManager(db, true)
	oldDone := make(chan error, 1)
	go func() { oldDone <- c.store() }()
	select {
	case <-db.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old store did not reach its commit barrier")
	}
	type answer struct {
		id  string
		err error
	}
	allocated := make(chan answer, 1)
	go func() { id, err := c.Allocate(); allocated <- answer{id, err} }()
	require.Eventually(t, func() bool { return c.usingID.Has("/sandbox/lease") }, 5*time.Second, time.Millisecond)
	unblock()
	require.NoError(t, <-oldDone)
	select {
	case a := <-allocated:
		require.NoError(t, a.err)
		require.Contains(t, db.IDs(t), a.id, "an older periodic snapshot overwrote a successful admission")
	case <-time.After(5 * time.Second):
		t.Fatal("allocation did not finish")
	}
}
