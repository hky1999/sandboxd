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
	"fmt"
	"sync"
)

type LanguageRuntime struct {
	ID          string
	Readonly    bool
	Sandbox     string
	SeedInfo    *SeedInfo
	RootFS      *RootFS
	cleanupFunc func()

	mu        sync.Mutex
	refcnt    int64
	temporary bool
}

func (lr *LanguageRuntime) SetTemporary(temporary bool) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	lr.temporary = temporary
}

func (lr *LanguageRuntime) IncRef() {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	lr.refcnt += 1
}

func (lr *LanguageRuntime) DecRef() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if lr.refcnt <= 0 {
		return fmt.Errorf("language runtime reference is not owned")
	}
	if lr.temporary && lr.refcnt == 1 {
		if err := lr.RootFS.DecRef(); err != nil {
			return err
		}
		if lr.cleanupFunc != nil {
			lr.cleanupFunc()
		}
	}
	lr.refcnt--
	return nil
}
