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

package checkpointstate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every waiter receives the same payload as a private copy: mutating the
// caller's input after completion and mutating one waiter's returned copy
// cannot change what any other waiter observes.
func TestCompleteWithResultDeliversCopiesToAllWaiters(t *testing.T) {
	c := NewCoordinator()
	attempt, execute, err := c.BeginRestore("sbox-result", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)

	const waiters = 4
	results := make(chan []byte, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			result, waitErr := attempt.WaitResult(context.Background())
			if waitErr != nil {
				t.Errorf("waiter: %v", waitErr)
			}
			results <- result
		}()
	}
	payload := []byte("restore-result")
	c.CompleteWithResult(attempt, payload, nil)
	// Caller-owned input mutation after publication must not leak.
	payload[0] = 'X'
	for i := 0; i < waiters; i++ {
		require.Equal(t, []byte("restore-result"), <-results)
	}
	first, err := attempt.WaitResult(context.Background())
	require.NoError(t, err)
	first[0] = 'X'
	second, err := attempt.WaitResult(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("restore-result"), second,
		"one waiter's output mutation must not reach later waiters")
}

// A failed completion publishes its error and never its payload; a cancelled
// wait returns the context error and no payload.
func TestWaitResultCarriesNoPayloadOnFailureOrCancellation(t *testing.T) {
	c := NewCoordinator()
	attempt, execute, err := c.BeginRestore("sbox-failed", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	boom := errors.New("boom")
	c.CompleteWithResult(attempt, []byte("never-published"), boom)
	result, waitErr := attempt.WaitResult(context.Background())
	require.ErrorIs(t, waitErr, boom)
	require.Nil(t, result)

	cancelled, execute, err := c.BeginRestore("sbox-cancelled", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, waitErr = cancelled.WaitResult(ctx)
	require.ErrorIs(t, waitErr, context.Canceled)
	require.Nil(t, result)
	c.Complete(cancelled, nil)
}

// Only the first completion of an attempt publishes: later, contradicting
// completions are ignored without republishing or panicking on done.
func TestOnlyFirstCompletionPublishesResult(t *testing.T) {
	c := NewCoordinator()
	attempt, execute, err := c.BeginRestore("sbox-double", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	c.CompleteWithResult(attempt, []byte("first"), nil)
	c.CompleteWithResult(attempt, []byte("second"), nil)
	c.Complete(attempt, errors.New("late"))
	result, waitErr := attempt.WaitResult(context.Background())
	require.NoError(t, waitErr)
	require.Equal(t, []byte("first"), result)
}

// A stale attempt's late completion can neither hijack the next attempt's
// payload nor release its physical lock keys.
func TestStaleCompletionDoesNotAffectNextAttempt(t *testing.T) {
	c := NewCoordinator()
	first, execute, err := c.BeginRestore("sbox-stale", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	c.CompleteWithResult(first, []byte("first"), nil)

	second, execute, err := c.BeginRestore("sbox-stale", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	c.CompleteWithResult(first, []byte("hijack"), nil)
	require.Error(t, c.BeginDelete("sbox-stale"),
		"the replacement attempt must still own the physical lock keys")

	c.CompleteWithResult(second, []byte("second"), nil)
	result, waitErr := second.WaitResult(context.Background())
	require.NoError(t, waitErr)
	require.Equal(t, []byte("second"), result)
	staleResult, staleErr := first.WaitResult(context.Background())
	require.NoError(t, staleErr)
	require.Equal(t, []byte("first"), staleResult)
}

// An attempt belongs to its coordinator: a foreign coordinator can complete
// nothing, and the owning completion still publishes afterwards.
func TestForeignCoordinatorCannotCompleteAttempt(t *testing.T) {
	owner := NewCoordinator()
	foreign := NewCoordinator()
	attempt, execute, err := owner.BeginRestore("sbox-foreign", "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	foreign.CompleteWithResult(attempt, []byte("foreign"), nil)
	foreign.Complete(attempt, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, waitErr := attempt.WaitResult(ctx)
	require.ErrorIs(t, waitErr, context.Canceled)
	require.Nil(t, result, "a foreign coordinator must not complete the attempt")

	owner.CompleteWithResult(attempt, []byte("owned"), nil)
	result, waitErr = attempt.WaitResult(context.Background())
	require.NoError(t, waitErr)
	require.Equal(t, []byte("owned"), result)
}

// The checkpoint path's nil-result Complete keeps working: success carries no
// payload, and errors still surface through both Wait and WaitResult.
func TestCheckpointCompleteStillWorks(t *testing.T) {
	c := NewCoordinator()
	attempt, execute, err := c.BeginCheckpoint(
		CheckpointKey{SandboxID: "sbox-legacy", CheckpointID: "artifact"}, "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	c.Complete(attempt, nil)
	require.NoError(t, attempt.Wait(context.Background()))
	result, waitErr := attempt.WaitResult(context.Background())
	require.NoError(t, waitErr)
	require.Nil(t, result)

	failed, execute, err := c.BeginCheckpoint(
		CheckpointKey{SandboxID: "sbox-legacy", CheckpointID: "artifact"}, "fingerprint")
	require.NoError(t, err)
	require.True(t, execute)
	checkpointErr := errors.New("checkpoint boom")
	c.Complete(failed, checkpointErr)
	require.ErrorIs(t, failed.Wait(context.Background()), checkpointErr)
	result, waitErr = failed.WaitResult(context.Background())
	require.ErrorIs(t, waitErr, checkpointErr)
	require.Nil(t, result)
}
