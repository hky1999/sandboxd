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

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type startupInspectionHandler struct {
	svc.Handler
	list func(context.Context) ([]*svc.State, error)
}

func (h startupInspectionHandler) List(ctx context.Context) ([]*svc.State, error) {
	return h.list(ctx)
}

func startupInspectionManager(t *testing.T, health chan bool, list func(context.Context) ([]*svc.State, error)) *Manager {
	t.Helper()
	handlers := cmap.New[svc.Handler]()
	handlers.Set("runsc", startupInspectionHandler{list: list})
	manager, err := NewManager(t.TempDir(), handlers, health, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	return manager
}

func waitStartupInspection(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime inspection or manager shutdown did not complete")
	}
}

func TestManagerStartupInspectsImmediately(t *testing.T) {
	health := make(chan bool, 1)
	var calls atomic.Int32
	manager := startupInspectionManager(t, health, func(context.Context) ([]*svc.State, error) {
		calls.Add(1)
		return nil, nil
	})
	done := make(chan struct{})
	go func() {
		manager.Start()
		close(done)
	}()
	defer func() {
		manager.Stop()
		waitStartupInspection(t, done)
	}()
	select {
	case ready := <-health:
		if !ready || calls.Load() == 0 {
			t.Fatal("startup health was not backed by a successful runtime inspection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startup waits for the periodic housekeeping interval")
	}
}

func TestManagerStartupWaitsForInitialInspection(t *testing.T) {
	health := make(chan bool, 1)
	started, release := make(chan struct{}), make(chan struct{})
	manager := startupInspectionManager(t, health, func(ctx context.Context) ([]*svc.State, error) {
		close(started)
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	done := make(chan struct{})
	go func() {
		manager.Start()
		close(done)
	}()
	defer func() {
		manager.Stop()
		select {
		case <-release:
		default:
			close(release)
		}
		waitStartupInspection(t, done)
	}()
	waitStartupInspection(t, started)
	select {
	case <-health:
		t.Fatal("health was published before runtime inspection completed")
	default:
	}
	close(release)
	select {
	case ready := <-health:
		if !ready {
			t.Fatal("successful initial inspection did not report healthy")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initial runtime inspection result was not published")
	}
}

func TestHousekeepingFailedInspectionPreservesUnknownState(t *testing.T) {
	health := make(chan bool, 1)
	manager := startupInspectionManager(t, health, func(context.Context) ([]*svc.State, error) {
		return nil, errors.New("runtime inventory is unavailable")
	})
	path := filepath.Join(t.TempDir(), "unknown")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	manager.sandboxes.Set("unknown", &Sandbox{
		PATH:     path,
		Metadata: &runtime.SandboxMetadata{ID: "unknown", RuntimeHandler: "runsc"},
	})
	marker := filepath.Join(manager.recyclePath, "retained-until-inspected")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	manager.housekeeping()
	if <-health {
		t.Error("failed runtime inspection was reported healthy")
	}
	if !manager.sandboxes.Has("unknown") {
		t.Error("unknown sandbox was removed after failed runtime inspection")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
		t.Error("recycled state was removed before runtime inspection completed")
	}
}

func TestHousekeepingCanRecoverAfterInspectionFailure(t *testing.T) {
	health := make(chan bool, 1)
	failing := true
	manager := startupInspectionManager(t, health, func(context.Context) ([]*svc.State, error) {
		if failing {
			return nil, errors.New("runtime inventory is unavailable")
		}
		return nil, nil
	})
	manager.housekeeping()
	if <-health {
		t.Error("failed inspection was reported healthy")
	}
	failing = false
	manager.housekeeping()
	if !<-health {
		t.Error("later successful inspection did not restore health")
	}
}

func TestHousekeepingStopUnblocksHealthPublication(t *testing.T) {
	health := make(chan bool)
	inspected := make(chan struct{})
	manager := startupInspectionManager(t, health, func(context.Context) ([]*svc.State, error) {
		close(inspected)
		return nil, nil
	})
	done := make(chan struct{})
	go func() {
		manager.housekeeping()
		close(done)
	}()
	waitStartupInspection(t, inspected)
	manager.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("stopping the manager did not unblock its pending health publication")
		// Release the old implementation's sender so a failing regression
		// leaves no goroutine behind.
		select {
		case <-health:
		case <-time.After(2 * time.Second):
			t.Fatal("pending health sender could not be collected")
		}
		waitStartupInspection(t, done)
	}
}
