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
	"github.com/stretchr/testify/require"
)

func nextCloseContinuation(original GenerationCgroupCloseRequest) GenerationCgroupCloseRequest {
	return GenerationCgroupCloseRequest{Path: original.Path, Generation: original.Generation, OperationID: "continue-original", ExpectedRevision: 1, Deadline: time.Now().Add(time.Minute).UTC()}
}

func TestGenerationCloseContinuationPersistsOriginalAndSurvivesReopen(t *testing.T) {
	m, d, db, original := newCloseFixture(t)
	// The daemon prepared this original request but crashed before manager
	// dispatch. Its expired deadline authorizes no effects on its own.
	original.Deadline = time.Now().Add(-time.Minute).UTC()
	continuation := nextCloseContinuation(original)
	d.drainError = errors.New("drain result unknown")
	_, err := m.ContinueCloseForGeneration(context.Background(), original, continuation)
	require.ErrorContains(t, err, "unknown")
	require.Equal(t, []string{"drain-original"}, d.effects)
	require.True(t, m.usingID.Has(original.Path))
	require.Equal(t, original, m.leaseClosures[original.Path].Request)
	require.Equal(t, uint64(2), m.leaseClosures[original.Path].Revision)
	_, err = m.CloseForGeneration(context.Background(), original)
	require.Error(t, err, "the expired original cannot replay a newer mutation")
	reopened := reopenCloseFixture(t, m, d, db)
	d.drainError = nil
	proof, err := reopened.ContinueCloseForGeneration(context.Background(), original, continuation)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
	require.True(t, reopened.usingID.Has(original.Path), "close is not full resource release")
	require.Equal(t, original, reopened.leaseClosures[original.Path].Request)
	before := append([]string(nil), d.effects...)
	proof, err = reopened.ContinueCloseForGeneration(context.Background(), original, continuation)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
	require.Equal(t, before, d.effects, "completed continuation replay is read-only")
	require.NoError(t, reopened.RecycleForGeneration(original.Path, original.Generation))
	require.Zero(t, reopened.total)
}

func TestGenerationCloseContinuationIntentSaveFailureCannotDispatch(t *testing.T) {
	for _, uncertainCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-commit", true: "after-commit"}[uncertainCommit], func(t *testing.T) {
			m, d, db, original := newCloseFixture(t)
			original.Deadline = time.Now().Add(-time.Minute).UTC()
			continuation := nextCloseContinuation(original)
			db.failAt, db.commitThenFail = 1, uncertainCommit
			_, err := m.ContinueCloseForGeneration(context.Background(), original, continuation)
			require.ErrorContains(t, err, "journal failure")
			require.Empty(t, d.effects)
			require.True(t, m.usingID.Has(original.Path))
			db.failAt = 0
			reopened := reopenCloseFixture(t, m, d, db)
			proof, err := reopened.ContinueCloseForGeneration(context.Background(), original, continuation)
			require.NoError(t, err)
			require.NoError(t, proof.Close())
			require.Equal(t, []string{"drain-original", "remove-original"}, d.effects)
			require.Equal(t, original, reopened.leaseClosures[original.Path].Request)
			require.Equal(t, []GenerationCgroupCloseRequest{continuation}, reopened.leaseClosures[original.Path].Continuations)
		})
	}
}

func TestGenerationCloseContinuationRejectsStaleIdentityRevisionAndFingerprint(t *testing.T) {
	for _, change := range []string{"live-deadline", "revision", "generation", "operation", "deadline", "replaced", "parent", "cancel"} {
		t.Run(change, func(t *testing.T) {
			m, d, _, original := newCloseFixture(t)
			if change != "live-deadline" {
				original.Deadline = time.Now().Add(-time.Minute).UTC()
			}
			continuation := nextCloseContinuation(original)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "revision":
				continuation.ExpectedRevision = 2
			case "generation":
				continuation.Generation = "neighbor-generation"
			case "operation":
				continuation.OperationID = original.OperationID
			case "deadline":
				continuation.Deadline = time.Now().Add(-time.Second)
			case "replaced":
				d.replaced = true
			case "parent":
				d.parentChanged = true
			case "cancel":
				cancel()
			}
			_, err := m.ContinueCloseForGeneration(ctx, original, continuation)
			require.Error(t, err)
			require.Empty(t, d.effects)
			require.True(t, m.usingID.Has(original.Path))
			require.Empty(t, m.leaseClosures, "invalid continuation must not create a new intent")
		})
	}
}

func TestGenerationCloseContinuationHistoryRejectsDowngradeAndMutation(t *testing.T) {
	m, d, db, original := newCloseFixture(t)
	original.Deadline = time.Now().Add(-time.Minute).UTC()
	continuation := nextCloseContinuation(original)
	d.drainError = errors.New("unknown")
	_, err := m.ContinueCloseForGeneration(context.Background(), original, continuation)
	require.Error(t, err)
	data, err := db.LoadRaw(config.CgroupBucket)
	require.NoError(t, err)
	for _, change := range []string{"schema", "revision", "operation", "deadline", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			var state storedCgroupIDs
			require.NoError(t, json.Unmarshal(data, &state))
			record := state.LeaseClosures[original.Path]
			switch change {
			case "schema":
				state.SchemaVersion = 5
			case "revision":
				record.Revision++
			case "operation":
				record.Continuations[0].OperationID = original.OperationID
			case "deadline":
				record.Continuations[0].Deadline = original.Deadline
			case "duplicate":
				record.Continuations = append(record.Continuations, record.Continuations[0])
				record.Revision++
			}
			state.LeaseClosures[original.Path] = record
			fresh, _, _ := newGenerationLeaseFixture(t)
			fresh.usingID.Set(original.Path, struct{}{})
			require.Error(t, fresh.restoreGenerationLeases(state))
		})
	}
}

func TestGenerationLeaseInspectionCannotChangeOriginalCloseHistory(t *testing.T) {
	m, d, _, original := newCloseFixture(t)
	original.Deadline = time.Now().Add(-time.Minute).UTC()
	continuation := nextCloseContinuation(original)
	d.drainError = errors.New("unknown")
	_, err := m.ContinueCloseForGeneration(context.Background(), original, continuation)
	require.Error(t, err)
	snapshot, err := m.InspectGenerationLease(original.Path, original.Generation)
	require.NoError(t, err)
	snapshot.CloseRequest.OperationID = "replacement"
	snapshot.Continuations[0].OperationID = "replacement"
	again, err := m.InspectGenerationLease(original.Path, original.Generation)
	require.NoError(t, err)
	require.Equal(t, original, *again.CloseRequest)
	require.Equal(t, []GenerationCgroupCloseRequest{continuation}, again.Continuations)
	_, err = m.InspectGenerationLease(original.Path, "neighbor-generation")
	require.Error(t, err)
}

func TestGenerationCloseNewContinuationSupersedesOnlyExpiredAttempt(t *testing.T) {
	m, d, _, original := newCloseFixture(t)
	original.Deadline = time.Now().Add(-time.Minute).UTC()
	first := nextCloseContinuation(original)
	first.Deadline = time.Now().Add(100 * time.Millisecond).UTC()
	d.drainError = errors.New("unknown")
	_, err := m.ContinueCloseForGeneration(context.Background(), original, first)
	require.Error(t, err)
	require.Len(t, m.leaseClosures[original.Path].Continuations, 1)
	<-time.After(time.Until(first.Deadline) + time.Millisecond)
	second := nextCloseContinuation(original)
	second.OperationID, second.ExpectedRevision = "second-continuation", 2
	d.drainError = nil
	proof, err := m.ContinueCloseForGeneration(context.Background(), original, second)
	require.NoError(t, err)
	require.NoError(t, proof.Close())
	require.Equal(t, uint64(3), m.leaseClosures[original.Path].Revision)
	require.Equal(t, original, m.leaseClosures[original.Path].Request)
	before := append([]string(nil), d.effects...)
	_, err = m.ContinueCloseForGeneration(context.Background(), original, first)
	require.Error(t, err)
	require.Equal(t, before, d.effects, "a superseded attempt cannot perform or borrow later completion")
}
