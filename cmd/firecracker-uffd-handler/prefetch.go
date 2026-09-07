// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// runPrefetch stops scheduling on the first fetch error and joins every worker.
// It does not cancel the shared page source: foreground faults still need it.
// An already-running fetch must finish under its own I/O cancellation policy.
func runPrefetch(stop <-chan struct{}, total uint64, workers int, fetch func(uint64) error) (uint64, error) {
	select {
	case <-stop:
		return 0, context.Canceled
	default:
	}
	if total == 0 {
		return 0, nil
	}
	if workers <= 0 {
		return 0, fmt.Errorf("prefetch requires positive worker count")
	}
	queue := make(chan uint64)
	aborted := make(chan struct{})
	var stopOnce, errOnce sync.Once
	cancel := func() { stopOnce.Do(func() { close(aborted) }) }
	var firstErr error
	var completed atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					cancel()
					return
				case <-aborted:
					return
				case idx, ok := <-queue:
					if !ok {
						return
					}
					select {
					case <-stop:
						cancel()
						return
					case <-aborted:
						return
					default:
					}
					if err := fetch(idx); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("chunk %d: %w", idx, err) })
						cancel()
						return
					}
					completed.Add(1)
				}
			}
		}()
	}
dispatch:
	for idx := uint64(0); idx < total; idx++ {
		select {
		case <-stop:
			cancel()
			break dispatch
		case <-aborted:
			break dispatch
		case queue <- idx:
		}
	}
	close(queue)
	wg.Wait()
	if firstErr != nil {
		return completed.Load(), firstErr
	}
	select {
	case <-stop:
		return completed.Load(), context.Canceled
	default:
		return completed.Load(), nil
	}
}
