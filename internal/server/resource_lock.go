// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
)

// physicalLocks serializes resource IO against create, delete and checkpoint
// for one sandbox ID. Waiters are cancellable; unused keys are removed.
type physicalLocks struct {
	mu   sync.Mutex
	keys map[string]*physicalLock
}

type physicalLock struct {
	refs  int
	token chan struct{}
}

func (l *physicalLocks) acquire(ctx context.Context, id string) (func(), error) {
	l.mu.Lock()
	if l.keys == nil {
		l.keys = make(map[string]*physicalLock)
	}
	entry := l.keys[id]
	if entry == nil {
		entry = &physicalLock{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		l.keys[id] = entry
	}
	entry.refs++
	l.mu.Unlock()
	releaseRef := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.keys, id)
		}
	}
	select {
	case <-ctx.Done():
		releaseRef()
		return nil, ctx.Err()
	case <-entry.token:
		var once sync.Once
		return func() { once.Do(func() { entry.token <- struct{}{}; releaseRef() }) }, nil
	}
}
