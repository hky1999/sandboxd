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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/pelletier/go-toml"
)

func checkpointConcurrencyService(n int) *sandboxService {
	cfg := config.Config{}
	cfg.Firecracker.CheckpointConcurrency = n
	return &sandboxService{config: cfg}
}

func TestCheckpointConcurrencyBoundAndRelease(t *testing.T) {
	for _, n := range []int{0, 1, 2, 4, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			service := checkpointConcurrencyService(n)
			limit := n
			if limit == 0 {
				limit = 1
			}
			releases := make([]func(), 0, limit)
			defer func() {
				for _, release := range releases {
					release()
				}
			}()
			for i := 0; i < limit; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				release, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
				cancel()
				if err != nil {
					t.Fatalf("slot %d of %d: %v", i, limit, err)
				}
				releases = append(releases, release)
			}
			// Hold all accepted operations until a further operation has timed out.
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			release, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
			if release != nil {
				release()
				t.Fatal("operation admitted above configured bound")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("waiting operation: %v", err)
			}
			releases[0]()
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			next, err := service.acquireFirecrackerCheckpointMemorySlot(ctx2)
			if err != nil {
				t.Fatal(err)
			}
			// An old release must not steal the new owner's token or block.
			done := make(chan struct{})
			go func() { releases[0](); close(done) }()
			select {
			case <-done:
			case <-ctx2.Done():
				t.Fatal("release not idempotent")
			}
			next()
		})
	}
}

func TestCheckpointConcurrencyRejectsInvalidAndCancelled(t *testing.T) {
	for _, n := range []int{-1, 9, 1000000} {
		service := checkpointConcurrencyService(n)
		release, err := service.acquireFirecrackerCheckpointMemorySlot(context.Background())
		if err == nil || release != nil {
			t.Fatalf("invalid concurrency %d accepted", n)
		}
	}
	service := checkpointConcurrencyService(4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		release, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
		if release != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled: %v", err)
		}
	}
	// Failed wrapper preconditions must return their slots as well.
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := service.withTransientFirecrackerCheckpointMemory(ctx, config.RuntimeNameFirecracker, "sandbox", "", nil, nil, false, func() error { t.Error("invalid operation ran"); return nil })
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wrapper failed to release: %v", err)
		}
	}
}

func TestCheckpointConcurrencyParallelAdmission(t *testing.T) {
	service := checkpointConcurrencyService(4)
	entered := make(chan struct{}, 4)
	finish := make(chan struct{})
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer release()
			entered <- struct{}{}
			<-finish
		}()
	}
	count := 0
	for count < 4 {
		select {
		case <-entered:
			count++
		case err := <-errs:
			t.Errorf("admission: %v", err)
			count = 4
		case <-ctx.Done():
			t.Error("operations could not overlap")
			count = 4
		}
	}
	close(finish)
	wg.Wait()
}

func TestCheckpointConcurrencyTOMLPath(t *testing.T) {
	var cfg config.Config
	if err := toml.Unmarshal([]byte("[plugin.runtime.firecracker]\ncheckpoint_concurrency = 4\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	service := &sandboxService{config: cfg}
	releases := []func(){}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, err := service.acquireFirecrackerCheckpointMemorySlot(ctx)
		cancel()
		if err != nil {
			t.Fatalf("decoded configuration failed to admit slot %d: %v", i, err)
		}
		releases = append(releases, r)
	}
}
