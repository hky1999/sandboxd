// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

// All effects in these ordinary tests are controlled interfaces. No cgroup
// files, processes or signals are touched; physical acceptance is separate.
type closeTestDirectory struct {
	identity, parent CgroupIdentity
	absentNow        bool
	replaced         bool
	parentChanged    bool
	drainError       error
	removeError      error
	effects          []string
}

func (d *closeTestDirectory) parentIdentity() CgroupIdentity { return d.parent }
func (d *closeTestDirectory) verify() error {
	if d.replaced || d.parentChanged {
		return errors.New("original directory changed")
	}
	return nil
}
func (d *closeTestDirectory) absent() (bool, error) {
	if err := d.verify(); err != nil {
		return false, err
	}
	return d.absentNow, nil
}
func (d *closeTestDirectory) drain(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.effects = append(d.effects, "drain-original")
	return d.drainError
}
func (d *closeTestDirectory) remove() error {
	d.effects = append(d.effects, "remove-original")
	if d.removeError != nil {
		return d.removeError
	}
	d.absentNow = true
	return nil
}
func (d *closeTestDirectory) proof() (*ClosedGenerationCgroup, error) {
	return &ClosedGenerationCgroup{Identity: d.identity, ParentIdentity: d.parent}, nil
}
func (*closeTestDirectory) close() error { return nil }

type closeTestBackend struct {
	cgroupOps
	directory *closeTestDirectory
}

func (o *closeTestBackend) openGenerationDirectory(identity CgroupIdentity, _ generationLeaseScope, parent *CgroupIdentity, allowMissing bool) (generationDirectory, error) {
	d := o.directory
	if identity != d.identity || (parent != nil && *parent != d.parent) || d.replaced || d.parentChanged || (d.absentNow && !allowMissing) {
		return nil, errors.New("original directory cannot be pinned")
	}
	return d, nil
}

type closeFaultStore struct {
	store.DbStore
	writes         int
	failAt         int
	commitThenFail bool
}

func (s *closeFaultStore) StoreRaw(key string, data []byte) error {
	s.writes++
	if s.writes == s.failAt {
		if s.commitThenFail {
			if err := s.DbStore.StoreRaw(key, data); err != nil {
				return err
			}
		}
		return errors.New("injected close journal failure")
	}
	return s.DbStore.StoreRaw(key, data)
}

func newCloseFixture(t *testing.T) (*CgroupManager, *closeTestDirectory, *closeFaultStore, GenerationCgroupCloseRequest) {
	t.Helper()
	m, ops, db := newGenerationLeaseFixture(t)
	path, err := m.AllocateForGeneration("original-generation")
	require.NoError(t, err)
	d := &closeTestDirectory{identity: m.leaseIdentities[path], parent: CgroupIdentity{Path: "/sandbox", Device: 2, Inode: 40}}
	m.ops = &closeTestBackend{cgroupOps: ops, directory: d}
	s := &closeFaultStore{DbStore: db}
	m.db = s
	return m, d, s, GenerationCgroupCloseRequest{Path: path, Generation: "original-generation", OperationID: "close-original", Deadline: time.Now().Add(time.Minute).UTC()}
}

func reopenCloseFixture(t *testing.T, previous *CgroupManager, d *closeTestDirectory, db store.DbStore) *CgroupManager {
	t.Helper()
	data, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	var state storedCgroupIDs
	require.NoError(t, json.Unmarshal(data, &state))
	m, ops, _ := newGenerationLeaseFixture(t)
	m.idleID.Pop()
	for _, path := range state.Items {
		m.usingID.Set(path, struct{}{})
	}
	m.db = db
	m.ops = &closeTestBackend{cgroupOps: ops, directory: d}
	m.readGenerationScope = previous.readGenerationScope
	require.NoError(t, m.restoreGenerationLeases(state))
	return m
}

func TestGenerationCloseRetainsLeaseUntilSeparateResourceRelease(t *testing.T) {
	m, d, _, request := newCloseFixture(t)
	proof, err := m.CloseForGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, d.identity, proof.Identity)
	require.NoError(t, proof.Close())
	require.Equal(t, []string{"drain-original", "remove-original"}, d.effects)
	require.True(t, m.leaseClosures[request.Path].Closed)
	require.True(t, m.usingID.Has(request.Path))
	require.Equal(t, 1, m.total)
	require.Empty(t, m.idleID.List())
	require.NoError(t, m.RecycleForGeneration(request.Path, request.Generation))
	require.Equal(t, []string{"drain-original", "remove-original"}, d.effects)
	require.False(t, m.usingID.Has(request.Path))
	require.Equal(t, 0, m.total)
	require.Empty(t, m.idleID.List(), "a cgroup whose kill sequence changed must never enter the cached pool")
	require.False(t, m.cgroups.Has(request.Path))
	require.NoError(t, m.RecycleForGeneration(request.Path, request.Generation))
}

func TestGenerationCloseIntentFailurePreventsEffectsAndReuse(t *testing.T) {
	m, d, db, request := newCloseFixture(t)
	db.failAt = 1
	_, err := m.CloseForGeneration(context.Background(), request)
	require.ErrorContains(t, err, "injected close journal failure")
	require.Empty(t, d.effects)
	require.True(t, m.usingID.Has(request.Path))
	require.ErrorIs(t, m.RecycleForGeneration(request.Path, request.Generation), errord.ErrFailedPrecondition)
	require.Error(t, m.Prepare(request.Path, nil))
	require.Error(t, m.WriteFreeze(request.Path, false))
	require.Error(t, m.WriteMemoryLimits(request.Path, 1, 2))
	db.failAt = 0
	proof, err := m.CloseForGeneration(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
}

func TestGenerationCloseMissingCompletionRecoversFromOriginalParent(t *testing.T) {
	for _, uncertainCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-commit", true: "after-commit"}[uncertainCommit], func(t *testing.T) {
			m, d, db, request := newCloseFixture(t)
			db.failAt, db.commitThenFail = 2, uncertainCommit
			_, err := m.CloseForGeneration(context.Background(), request)
			require.Error(t, err)
			require.True(t, d.absentNow)
			require.False(t, m.leaseClosures[request.Path].Closed)
			require.True(t, m.usingID.Has(request.Path))
			require.Empty(t, m.idleID.List())
			before := append([]string(nil), d.effects...)
			db.failAt = 0
			reopened := reopenCloseFixture(t, m, d, db)
			proof, err := reopened.CloseForGeneration(context.Background(), request)
			require.NoError(t, err)
			require.NoError(t, proof.Close())
			require.Equal(t, before, d.effects, "restart recovery of original absence is read-only")
			require.True(t, reopened.usingID.Has(request.Path))
			require.NoError(t, reopened.RecycleForGeneration(request.Path, request.Generation))
			require.Equal(t, 0, reopened.total)
		})
	}
}

func TestGenerationCloseRefusesAlteredFingerprintAndOldGeneration(t *testing.T) {
	m, d, _, request := newCloseFixture(t)
	d.drainError = errors.New("drain stopped")
	_, err := m.CloseForGeneration(context.Background(), request)
	require.Error(t, err)
	before := append([]string(nil), d.effects...)
	for _, change := range []string{"operation", "deadline", "generation", "revision", "path"} {
		changed := request
		switch change {
		case "operation":
			changed.OperationID += "-replacement"
		case "deadline":
			changed.Deadline = changed.Deadline.Add(time.Second)
		case "generation":
			changed.Generation = "neighbor-generation"
		case "revision":
			changed.ExpectedRevision = 1
		case "path":
			changed.Path = "/sandbox/neighbor"
		}
		_, err := m.CloseForGeneration(context.Background(), changed)
		require.Error(t, err)
		require.Equal(t, before, d.effects)
	}
	require.True(t, m.usingID.Has(request.Path))
}

func TestGenerationCloseReopenRefusesReplacementAndParentChange(t *testing.T) {
	for _, change := range []string{"leaf", "parent", "boot"} {
		t.Run(change, func(t *testing.T) {
			m, d, db, request := newCloseFixture(t)
			d.removeError = errors.New("stop before original removal")
			_, err := m.CloseForGeneration(context.Background(), request)
			require.Error(t, err)
			reopened := reopenCloseFixture(t, m, d, db)
			switch change {
			case "leaf":
				d.replaced = true
			case "parent":
				d.parentChanged = true
			case "boot":
				scope := reopened.leaseScopes[request.Path]
				scope.BootID = "changed-boot"
				reopened.readGenerationScope = func() (generationLeaseScope, error) { return scope, nil }
			}
			before := append([]string(nil), d.effects...)
			_, err = reopened.CloseForGeneration(context.Background(), request)
			require.Error(t, err)
			require.Equal(t, before, d.effects)
			require.True(t, reopened.usingID.Has(request.Path))
			require.Empty(t, reopened.idleID.List())
		})
	}
}

func TestGenerationCloseDeadlineAndCancellationPreventNewEffects(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		m, d, _, request := newCloseFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		} else {
			request.Deadline = time.Now().Add(-time.Second)
		}
		_, err := m.CloseForGeneration(ctx, request)
		require.Error(t, err)
		cancel()
		require.Empty(t, d.effects)
		require.True(t, m.usingID.Has(request.Path))
	}
}

func TestGenerationCloseCompletionReplayIsReadOnlyAfterReopen(t *testing.T) {
	m, d, db, request := newCloseFixture(t)
	proof, err := m.CloseForGeneration(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
	before := append([]string(nil), d.effects...)
	reopened := reopenCloseFixture(t, m, d, db)
	proof, err = reopened.CloseForGeneration(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
	require.Equal(t, before, d.effects)
	db.failAt = db.writes + 1
	require.Error(t, reopened.RecycleForGeneration(request.Path, request.Generation))
	require.True(t, reopened.usingID.Has(request.Path))
	require.Empty(t, reopened.idleID.List())
	db.failAt = 0
	require.NoError(t, reopened.RecycleForGeneration(request.Path, request.Generation))
	require.Equal(t, before, d.effects)
}

func TestGenerationCloseJournalRejectsCorruptionAndLegacyAdoption(t *testing.T) {
	m, d, db, request := newCloseFixture(t)
	d.drainError = errors.New("keep intent")
	_, err := m.CloseForGeneration(context.Background(), request)
	require.Error(t, err)
	data, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	for _, change := range []string{"schema", "owner", "identity", "scope", "parent", "revision"} {
		var state storedCgroupIDs
		require.NoError(t, json.Unmarshal(data, &state))
		r := state.LeaseClosures[request.Path]
		switch change {
		case "schema":
			state.SchemaVersion = 4
		case "owner":
			r.Request.Generation = "foreign-generation"
		case "identity":
			r.Identity.Inode++
		case "scope":
			r.Scope.BootID = "foreign-boot"
		case "parent":
			r.Parent.Path = "/foreign"
		case "revision":
			r.Revision++
		}
		state.LeaseClosures[request.Path] = r
		require.ErrorIs(t, m.restoreGenerationLeases(state), errord.ErrFailedPrecondition)
	}
}

func TestGenerationCloseUnsupportedBackendNeverFallsBackToPathKill(t *testing.T) {
	m, ops, _ := newGenerationLeaseFixture(t)
	path, err := m.AllocateForGeneration("original-generation")
	require.NoError(t, err)
	_, err = m.CloseForGeneration(context.Background(), GenerationCgroupCloseRequest{Path: path, Generation: "original-generation", OperationID: "original-close", Deadline: time.Now().Add(time.Minute)})
	require.ErrorIs(t, err, errord.ErrFailedPrecondition)
	require.Empty(t, ops.calls)
	require.True(t, m.usingID.Has(path))
}
