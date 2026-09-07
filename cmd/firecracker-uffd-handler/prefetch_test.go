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
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrefetchAllWorkersFail(t *testing.T) {
	sentinel := errors.New("store unavailable")
	done := make(chan error, 1)
	var calls atomic.Uint64
	go func() {
		n, err := runPrefetch(make(chan struct{}), 64, 4, func(uint64) error { calls.Add(1); return sentinel })
		if n != 0 {
			done <- errors.New("failed chunks counted as complete")
			return
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("producer stuck after workers failed")
	}
	if calls.Load() > 4 {
		t.Fatalf("continued scheduling failed walk: %d", calls.Load())
	}
}

func TestPrefetchJoinsActiveFetches(t *testing.T) {
	entered := make(chan uint64, 4)
	fail := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	sentinel := errors.New("first failure")
	go func() {
		_, err := runPrefetch(make(chan struct{}), 64, 4, func(idx uint64) error {
			entered <- idx
			if idx == 0 {
				<-fail
				return sentinel
			}
			<-release
			return nil
		})
		done <- err
	}()
	// Every worker is inside its callback before the first error is released.
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(fail)
			close(release)
			t.Fatal("workers did not start")
		}
	}
	close(fail)
	select {
	case <-done:
		close(release)
		t.Fatal("returned with active fetches")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not join after release")
	}
}

func TestPrefetchCompletionAndStop(t *testing.T) {
	counts := make([]atomic.Int32, 31)
	n, err := runPrefetch(make(chan struct{}), uint64(len(counts)), 4, func(i uint64) error { counts[i].Add(1); return nil })
	if err != nil || n != uint64(len(counts)) {
		t.Fatalf("%d %v", n, err)
	}
	for i := range counts {
		if counts[i].Load() != 1 {
			t.Fatalf("chunk %d count=%d", i, counts[i].Load())
		}
	}
	stop := make(chan struct{})
	close(stop)
	n, err = runPrefetch(stop, 31, 4, func(uint64) error { t.Error("fetch after stop"); return nil })
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("%d %v", n, err)
	}
	if n, err = runPrefetch(nil, 0, 0, nil); n != 0 || err != nil {
		t.Fatalf("empty walk %d %v", n, err)
	}
}
