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

package langrtmanager

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
)

type cancellationMounter struct {
	mockMounter
	entered chan struct{}
	calls   atomic.Int32
}

func (m *cancellationMounter) Mount(ctx context.Context, cfg RootfsConfig) (string, []string, *imageconfig.Process, error) {
	if m.calls.Add(1) == 1 {
		close(m.entered)
		<-ctx.Done()
		return "", nil, nil, ctx.Err()
	}
	return m.mockMounter.Mount(ctx, cfg)
}

type observedWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestRootfsCanceledCreatorAllowsLiveWaiterRetry(t *testing.T) {
	m := &cancellationMounter{entered: make(chan struct{})}
	lm := NewLanguageRuntimeManager(m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := lm.AddLangRuntimeWithContext(ctx, newTestStartRequest("first", "/shared"), true)
		first <- err
	}()
	<-m.entered
	waiterCtx := &observedWaitContext{Context: context.Background(), entered: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		_, err := lm.AddLangRuntimeWithContext(waiterCtx, newTestStartRequest("second", "/shared"), true)
		second <- err
	}()
	select {
	case <-waiterCtx.entered:
	case <-time.After(time.Second):
		t.Fatal("waiter not waiting on shared rootfs")
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("live waiter did not retry canceled creation")
	}
	lr := lm.GetLangRuntime("second")
	if lr == nil {
		t.Fatal("live runtime missing")
	}
	lr.IncRef()
	lr.DecRef()
	if len(lm.List()) != 0 || len(lm.rootfsMap) != 0 {
		t.Fatal("rootfs references leaked")
	}
}

func TestRootfsWaiterCancellationDoesNotWaitForCreator(t *testing.T) {
	m := &cancellationMounter{entered: make(chan struct{})}
	lm := NewLanguageRuntimeManager(m)
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	first := make(chan error, 1)
	go func() {
		_, err := lm.AddLangRuntimeWithContext(ownerCtx, newTestStartRequest("first", "/shared"), true)
		first <- err
	}()
	<-m.entered
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiterCtx := &observedWaitContext{Context: ctx, entered: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		_, err := lm.AddLangRuntimeWithContext(waiterCtx, newTestStartRequest("second", "/shared"), true)
		second <- err
	}()
	select {
	case <-waiterCtx.entered:
	case <-time.After(time.Second):
		t.Fatal("waiter not waiting")
	}
	cancel()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}
	if ownerCtx.Err() != nil {
		t.Fatal("waiter canceled owner")
	}
	cancelOwner()
	<-first
	if len(lm.List()) != 0 || len(lm.rootfsMap) != 0 {
		t.Fatal("canceled rootfs retained")
	}
}
