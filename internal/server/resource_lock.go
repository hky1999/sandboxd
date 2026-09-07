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

package server

import (
	"context"
	"sync"
)

// physicalLocks serializes resource IO against start, delete, and checkpoint
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
