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

// Package checkpointstate coordinates only concurrent RPC execution. Durable
// checkpoint and sandbox facts live in checkpoint.Store and sandbox.Manager.
package checkpointstate

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CheckpointKey struct {
	SandboxID    string
	CheckpointID string
}

type Attempt struct {
	coordinator  *Coordinator
	operationKey string
	lockKeys     []string
	fingerprint  string
	done         chan struct{}
	err          error
	// result is the immutable payload of a successful completion. It is
	// copied into the attempt under the coordinator lock before done closes
	// and is never mutated afterwards, so no later writer — the completing
	// caller or a waiter holding a returned copy — can change what another
	// waiter observes.
	result []byte
}

func (a *Attempt) Wait(ctx context.Context) error {
	select {
	case <-a.done:
		return a.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitResult waits like Wait and, for a successful completion, returns a
// private copy of the published payload. Errors and cancellations carry no
// result; writes to the returned slice cannot affect other waiters.
func (a *Attempt) WaitResult(ctx context.Context) ([]byte, error) {
	if err := a.Wait(ctx); err != nil {
		return nil, err
	}
	if len(a.result) == 0 {
		return nil, nil
	}
	result := make([]byte, len(a.result))
	copy(result, a.result)
	return result, nil
}

type Coordinator struct {
	mu               sync.Mutex
	operations       map[string]*Attempt
	locks            map[string]*Attempt
	deleting         map[string]struct{}
	artifactReaders  map[string]uint64
	artifactDeleting map[string]bool
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		operations:       make(map[string]*Attempt),
		locks:            make(map[string]*Attempt),
		deleting:         make(map[string]struct{}),
		artifactReaders:  make(map[string]uint64),
		artifactDeleting: make(map[string]bool),
	}
}

func (c *Coordinator) BeginCheckpoint(
	key CheckpointKey,
	fingerprint string,
) (*Attempt, bool, error) {
	if key.SandboxID == "" || key.CheckpointID == "" {
		return nil, false, status.Error(codes.InvalidArgument,
			"checkpoint sandbox and artifact IDs are required")
	}
	return c.begin(
		"checkpoint:"+key.SandboxID,
		[]string{"sandbox:" + key.SandboxID, "artifact:" + key.CheckpointID},
		key.SandboxID,
		fingerprint,
	)
}

func (c *Coordinator) BeginRestore(
	targetSandboxID string,
	fingerprint string,
) (*Attempt, bool, error) {
	if targetSandboxID == "" {
		return nil, false, status.Error(codes.InvalidArgument,
			"restore target sandbox ID is required")
	}
	return c.begin(
		"restore:"+targetSandboxID,
		[]string{"sandbox:" + targetSandboxID},
		targetSandboxID,
		fingerprint,
	)
}

func (c *Coordinator) begin(
	operationKey string,
	lockKeys []string,
	sandboxID string,
	fingerprint string,
) (*Attempt, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.operations[operationKey]; existing != nil {
		if existing.fingerprint != fingerprint {
			return nil, false, status.Errorf(codes.FailedPrecondition,
				"sandbox %q already has a conflicting operation", sandboxID)
		}
		return existing, false, nil
	}
	if _, deleting := c.deleting[sandboxID]; deleting {
		return nil, false, status.Errorf(codes.FailedPrecondition,
			"sandbox %q is being deleted", sandboxID)
	}
	for _, key := range lockKeys {
		if c.artifactDeleting[key] {
			return nil, false, status.Error(codes.FailedPrecondition, "checkpoint artifact is being collected")
		}
		if owner := c.locks[key]; owner != nil {
			return nil, false, status.Errorf(codes.FailedPrecondition,
				"physical operation lock %q is already held", key)
		}
	}
	attempt := &Attempt{
		coordinator:  c,
		operationKey: operationKey,
		lockKeys:     append([]string(nil), lockKeys...),
		fingerprint:  fingerprint,
		done:         make(chan struct{}),
	}
	c.operations[operationKey] = attempt
	for _, key := range lockKeys {
		c.locks[key] = attempt
	}
	return attempt, true, nil
}

// Complete ends an attempt without a payload; checkpoint callers keep this
// nil-result form.
func (c *Coordinator) Complete(attempt *Attempt, err error) {
	c.CompleteWithResult(attempt, nil, err)
}

// CompleteWithResult ends an attempt and, on success, publishes result as the
// attempt's immutable payload: the bytes are copied before done closes and
// before the attempt's lock keys are released. Only the first completion of
// an attempt owned by this coordinator publishes anything — later, stale or
// foreign completions are ignored, and lock deletion is unchanged.
func (c *Coordinator) CompleteWithResult(attempt *Attempt, result []byte, err error) {
	if attempt == nil || attempt.coordinator != c {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operations[attempt.operationKey] != attempt {
		return
	}
	delete(c.operations, attempt.operationKey)
	for _, key := range attempt.lockKeys {
		if c.locks[key] == attempt {
			delete(c.locks, key)
		}
	}
	attempt.err = err
	if err == nil && len(result) > 0 {
		attempt.result = make([]byte, len(result))
		copy(attempt.result, result)
	}
	close(attempt.done)
}

func (c *Coordinator) BeginDelete(sandboxID string) error {
	if sandboxID == "" {
		return status.Error(codes.InvalidArgument, "sandbox ID is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, deleting := c.deleting[sandboxID]; deleting {
		return status.Errorf(codes.FailedPrecondition,
			"sandbox %q is already being deleted", sandboxID)
	}
	if c.locks["sandbox:"+sandboxID] != nil {
		return status.Errorf(codes.FailedPrecondition,
			"sandbox %q has an active physical operation", sandboxID)
	}
	c.deleting[sandboxID] = struct{}{}
	return nil
}

func (c *Coordinator) EndDelete(sandboxID string) {
	c.mu.Lock()
	delete(c.deleting, sandboxID)
	c.mu.Unlock()
}

// PinArtifact protects all manifest/image reads before the asynchronous restore
// attempt is registered. The attempt retains its own artifact lock after an RPC
// waiter disconnects; published restore metadata pins readers after completion.
func (c *Coordinator) PinArtifact(id string) (func(), error) {
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "checkpoint ID required")
	}
	key := "artifact:" + id
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.artifactDeleting[key] {
		return nil, status.Error(codes.FailedPrecondition, "artifact is being collected")
	}
	c.artifactReaders[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.artifactReaders[key]--
			if c.artifactReaders[key] == 0 {
				delete(c.artifactReaders, key)
			}
		})
	}, nil
}

// BeginRestoreArtifact keeps the original target-operation replay semantics and
// also excludes deletion throughout the background physical restore.
func (c *Coordinator) BeginRestoreArtifact(target, artifact, fingerprint string) (*Attempt, bool, error) {
	if target == "" || artifact == "" {
		return nil, false, status.Error(codes.InvalidArgument, "restore target and artifact required")
	}
	return c.begin("restore:"+target, []string{"sandbox:" + target, "artifact:" + artifact}, target, fingerprint)
}

// BeginArtifactDelete is a bounded refusal while any producer or reader owns
// the artifact. An old HTTP timeout or absence observation cannot bypass it.
func (c *Coordinator) BeginArtifactDelete(id string) (func(), error) {
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "checkpoint ID required")
	}
	key := "artifact:" + id
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.artifactDeleting[key] || c.artifactReaders[key] > 0 || c.locks[key] != nil {
		return nil, status.Error(codes.FailedPrecondition, "checkpoint producer or restore still owns artifact")
	}
	c.artifactDeleting[key] = true
	var once sync.Once
	return func() { once.Do(func() { c.mu.Lock(); delete(c.artifactDeleting, key); c.mu.Unlock() }) }, nil
}
