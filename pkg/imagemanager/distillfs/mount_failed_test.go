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

package distillfs

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestManager creates a minimal manager with pre-populated daemons for testing
// GC and daemon lookup behavior. It bypasses NewManager to avoid filesystem setup.
func newTestManager(daemons map[string]*Daemon) *manager {
	return &manager{
		ctx:     context.Background(),
		daemons: daemons,
	}
}

func newTestDaemon(t *testing.T, id string) *Daemon {
	t.Helper()
	d := &Daemon{
		ctx: context.Background(),
		meta: DaemonMeta{
			ID:         id,
			Name:       id,
			MountPoint: t.TempDir(),
		},
		config: &BackendConfig{},
	}
	d.setState(DaemonStateStopped)
	d.kickStop = NewStopper()
	return d
}

// --- Daemon-level mountFailed tests ---

func TestDaemon_MountFailure_DoesNotSetMountFailed(t *testing.T) {
	// When startDaemonProcess fails immediately (binary not found), the daemon
	// goes to Stopped state. mount() detects this and returns "failed to start"
	// WITHOUT setting mountFailed (that only happens on timeout).
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)
	mock.mockIsAlive = func() bool { return false }

	err := mock.Mount()
	if err == nil {
		t.Fatal("Mount() should fail without a real binary")
	}

	// mountFailed should NOT be set on immediate failure — only on timeout
	if mock.mountFailed.Load() {
		t.Error("mountFailed should NOT be set on immediate start failure (only on timeout)")
	}
}

func TestDaemon_MountFailed_FlagBehavior(t *testing.T) {
	// Test the flag semantics directly since the actual timeout path takes 60s.
	// The timeout case in mount() does: d.mountFailed.Store(true)
	// The mount() entry does: d.mountFailed.Store(false)
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Simulate: a prior mount timed out, setting mountFailed=true
	mock.mountFailed.Store(true)
	if !mock.mountFailed.Load() {
		t.Fatal("mountFailed should be true after Store(true)")
	}

	// New mount attempt should clear the flag at entry
	mock.setState(DaemonStateRunning)
	mock.mockIsAlive = func() bool { return true }

	err := mock.Mount()
	if err != nil {
		t.Fatalf("Mount() should succeed: %v", err)
	}
	if mock.mountFailed.Load() {
		t.Error("mount() should clear mountFailed at entry")
	}
}

func TestDaemon_Mount_ClearsMountFailed(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Pre-set mountFailed to true (simulating a prior timeout)
	mock.mountFailed.Store(true)

	// Set daemon to running so mount returns quickly via fast path
	mock.setState(DaemonStateRunning)
	mock.mockIsAlive = func() bool { return true }

	err := mock.Mount()
	if err != nil {
		t.Fatalf("Mount() on running daemon should succeed: %v", err)
	}

	if mock.mountFailed.Load() {
		t.Error("mountFailed should be cleared by a new mount attempt")
	}
}

func TestDaemon_UnmountForGC_ProceedsWhenMountFailed(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Daemon has a failed mount
	mock.mountFailed.Store(true)
	mock.setState(DaemonStateStopped)

	result := mock.unmountForGC()
	if !result {
		t.Error("unmountForGC() should return true when mountFailed is set")
	}
}

func TestDaemon_UnmountForGC_AbortsWhenMountFailedCleared(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// mountFailed is false (a new mount cleared it)
	mock.mountFailed.Store(false)
	mock.setState(DaemonStateRunning)

	result := mock.unmountForGC()
	if result {
		t.Error("unmountForGC() should return false when mountFailed is not set")
	}
}

// --- Manager-level GC tests ---

func TestGCDaemons_CleansUpFailedDaemon(t *testing.T) {
	d := newTestDaemon(t, "failed-1")
	d.mountFailed.Store(true)
	// IsAlive returns false (no real process), so GC won't call unmountForGC
	// but the re-check will still delete it.

	mgr := newTestManager(map[string]*Daemon{
		d.meta.ID: d,
	})

	mgr.gcDaemons()

	mgr.mu.RLock()
	_, exists := mgr.daemons[d.meta.ID]
	mgr.mu.RUnlock()

	if exists {
		t.Error("gcDaemons should have removed the failed daemon from the map")
	}
}

func TestGCDaemons_SkipsFailedDaemonWhenMountFailedCleared(t *testing.T) {
	d := newTestDaemon(t, "recovered-1")
	d.mountFailed.Store(true)

	mgr := newTestManager(map[string]*Daemon{
		d.meta.ID: d,
	})

	// Simulate: after GC collects the daemon but before cleanup,
	// a mount request clears mountFailed. We achieve this by clearing
	// the flag before calling gcDaemons - since the daemon is not alive,
	// GC won't call unmountForGC, but the re-check at cleanup sees false.
	//
	// More precisely: set isAliveFunc to clear mountFailed during the
	// "unmount alive failed daemons" loop, simulating a concurrent mount.
	d.isAliveFunc = func() bool {
		// Simulate a concurrent mount clearing the flag
		d.mountFailed.Store(false)
		return true
	}

	mgr.gcDaemons()

	mgr.mu.RLock()
	_, exists := mgr.daemons[d.meta.ID]
	mgr.mu.RUnlock()

	if !exists {
		t.Error("gcDaemons should NOT have removed the daemon because mountFailed was cleared")
	}
}

func TestGCDaemons_DoesNotAffectHealthyDaemons(t *testing.T) {
	healthy := newTestDaemon(t, "healthy-1")
	healthy.mountFailed.Store(false)
	healthy.updateExpired() // Not expired

	failed := newTestDaemon(t, "failed-1")
	failed.mountFailed.Store(true)

	mgr := newTestManager(map[string]*Daemon{
		healthy.meta.ID: healthy,
		failed.meta.ID:  failed,
	})

	mgr.gcDaemons()

	mgr.mu.RLock()
	_, healthyExists := mgr.daemons[healthy.meta.ID]
	_, failedExists := mgr.daemons[failed.meta.ID]
	mgr.mu.RUnlock()

	if !healthyExists {
		t.Error("gcDaemons should NOT remove healthy daemon")
	}
	if failedExists {
		t.Error("gcDaemons should remove failed daemon")
	}
}

func TestGCDaemons_RetainsAliveFailedWithUnknownPID(t *testing.T) {
	d := newTestDaemon(t, "alive-failed")
	d.mountFailed.Store(true)
	d.isAliveFunc = func() bool { return true }
	// Set up stopChan so unmountLocked doesn't panic
	d.stopChan = make(chan struct{})
	d.kickStop = NewStopper()

	// Close stopChan to simulate the watch goroutine exiting
	go func() {
		<-d.kickStop.Done()
		close(d.stopChan)
	}()

	mgr := newTestManager(map[string]*Daemon{
		d.meta.ID: d,
	})

	mgr.gcDaemons()

	mgr.mu.RLock()
	_, exists := mgr.daemons[d.meta.ID]
	mgr.mu.RUnlock()

	if !exists {
		t.Error("gcDaemons must retain an alive daemon whose original PID is unknown")
	}
	if !d.releasePending {
		t.Error("unresolved daemon release must remain pending")
	}
	if d.getState() == DaemonStateStopped {
		t.Error("failed unmount cannot publish Stopped")
	}
}

// --- Race protection tests (GetDaemon / CreateDaemon clear mountFailed) ---

func TestGetDaemon_ClearsMountFailed(t *testing.T) {
	d := newTestDaemon(t, "get-clear")
	d.mountFailed.Store(true)

	mgr := newTestManager(map[string]*Daemon{
		d.meta.ID: d,
	})

	got := mgr.GetDaemon("get-clear")
	if got == nil {
		t.Fatal("GetDaemon should return the daemon")
	}
	if d.mountFailed.Load() {
		t.Error("GetDaemon should clear mountFailed to protect against GC race")
	}
}

func TestGetDaemon_NonExistent_ReturnsNil(t *testing.T) {
	mgr := newTestManager(map[string]*Daemon{})

	got := mgr.GetDaemon("no-such-daemon")
	if got != nil {
		t.Error("GetDaemon should return nil for non-existent daemon")
	}
}

func TestCreateDaemon_ExistingDaemon_ClearsMountFailed(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{BackendType: "oss", Oss: &OssConfig{}}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)
	nydusConfig := BackendConfig{BackendType: "registry", Registry: &RegistryConfig{}}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)
	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	opts := &DaemonCreateOpt{ID: "existing-1", Name: "test"}
	if err := mgr.CreateDaemon(opts); err != nil {
		t.Fatalf("CreateDaemon() failed: %v", err)
	}

	// Simulate a prior mount timeout
	d := mgr.GetDaemon(opts.ID)
	d.mountFailed.Store(true)

	// CreateDaemon again on the existing daemon should clear mountFailed
	if err := mgr.CreateDaemon(opts); err != nil {
		t.Fatalf("CreateDaemon() second call failed: %v", err)
	}

	if d.mountFailed.Load() {
		t.Error("CreateDaemon on existing daemon should clear mountFailed")
	}
}

// --- Concurrency: simulate the exact race scenario ---

func TestGCDaemons_RaceWithGetDaemon(t *testing.T) {
	// Simulate: mount goroutine calls GetDaemon (clears mountFailed),
	// then GC runs. GC should NOT delete the daemon.
	d := newTestDaemon(t, "race-1")
	d.mountFailed.Store(true)

	mgr := newTestManager(map[string]*Daemon{
		d.meta.ID: d,
	})

	// Step 1: Mount goroutine retrieves daemon (like the API layer does)
	got := mgr.GetDaemon("race-1")
	if got == nil {
		t.Fatal("GetDaemon should return the daemon")
	}

	// Step 2: GC runs - should see mountFailed=false and skip cleanup
	mgr.gcDaemons()

	mgr.mu.RLock()
	_, exists := mgr.daemons[d.meta.ID]
	mgr.mu.RUnlock()

	if !exists {
		t.Error("GC should NOT delete daemon after GetDaemon cleared mountFailed")
	}
}

func TestGCDaemons_ConcurrentMountAndGC(t *testing.T) {
	// Run GC and Mount concurrently many times to detect races via -race flag.
	for i := 0; i < 50; i++ {
		d := newTestDaemon(t, "concurrent")
		d.mountFailed.Store(true)
		// Make daemon appear running so mount() returns via fast path
		d.setState(DaemonStateRunning)
		d.isAliveFunc = func() bool { return true }

		mgr := newTestManager(map[string]*Daemon{
			d.meta.ID: d,
		})

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			mgr.gcDaemons()
		}()

		go func() {
			defer wg.Done()
			// Simulate the API path: GetDaemon then Mount
			if got := mgr.GetDaemon("concurrent"); got != nil {
				_ = got.Mount()
			}
		}()

		wg.Wait()
	}
}

// --- Verify mount timeout behavior with mountFailed flag ---

func TestDaemon_RemountAfterFailure_ClearsFlag(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Simulate a prior mount timeout by setting the flag directly
	mock.mountFailed.Store(true)

	// Remount: daemon is now running (e.g., startDaemonProcess eventually succeeded)
	mock.setState(DaemonStateRunning)
	mock.mockIsAlive = func() bool { return true }

	err := mock.Mount()
	if err != nil {
		t.Fatalf("Mount() should succeed: %v", err)
	}
	if mock.mountFailed.Load() {
		t.Error("mountFailed should be false after successful remount")
	}
}

// --- Verify GC expiry-based pass still works alongside failed-daemon pass ---

func TestGCDaemons_ExpiryStillWorksWithFailedPass(t *testing.T) {
	expired := newTestDaemon(t, "expired-1")
	expired.expiredAt = time.Now().Add(-1 * time.Hour).UnixNano() // Already expired
	expired.isAliveFunc = func() bool { return false }

	failed := newTestDaemon(t, "failed-1")
	failed.mountFailed.Store(true)

	healthy := newTestDaemon(t, "healthy-1")
	healthy.updateExpired()
	healthy.isAliveFunc = func() bool { return true }

	mgr := newTestManager(map[string]*Daemon{
		expired.meta.ID: expired,
		failed.meta.ID:  failed,
		healthy.meta.ID: healthy,
	})

	// Set up daemon dirs for cleanupDaemonResources
	mgr.root = t.TempDir()

	mgr.gcDaemons()

	mgr.mu.RLock()
	_, expiredExists := mgr.daemons[expired.meta.ID]
	_, failedExists := mgr.daemons[failed.meta.ID]
	_, healthyExists := mgr.daemons[healthy.meta.ID]
	mgr.mu.RUnlock()

	if expiredExists {
		t.Error("expired daemon should be cleaned by expiry-based GC")
	}
	if failedExists {
		t.Error("failed daemon should be cleaned by failed-daemon pass")
	}
	if !healthyExists {
		t.Error("healthy daemon should remain")
	}
}

func TestGCDaemons_NoDaemonsNoPanic(t *testing.T) {
	mgr := newTestManager(map[string]*Daemon{})
	// Should not panic with empty daemon map
	mgr.gcDaemons()
}

func TestGCDaemons_AllHealthyNoDeletion(t *testing.T) {
	d1 := newTestDaemon(t, "healthy-1")
	d1.updateExpired()
	d1.isAliveFunc = func() bool { return true }

	d2 := newTestDaemon(t, "healthy-2")
	d2.updateExpired()
	d2.isAliveFunc = func() bool { return true }

	mgr := newTestManager(map[string]*Daemon{
		d1.meta.ID: d1,
		d2.meta.ID: d2,
	})

	mgr.gcDaemons()

	mgr.mu.RLock()
	count := len(mgr.daemons)
	mgr.mu.RUnlock()

	if count != 2 {
		t.Errorf("all healthy daemons should remain, got %d want 2", count)
	}
}

func TestGCDaemons_MultipleFailedDaemons(t *testing.T) {
	daemons := make(map[string]*Daemon)
	for i := 0; i < 5; i++ {
		id := filepath.Base(t.TempDir()) // unique id
		d := newTestDaemon(t, id)
		d.mountFailed.Store(true)
		daemons[id] = d
	}

	mgr := newTestManager(daemons)
	mgr.gcDaemons()

	mgr.mu.RLock()
	remaining := len(mgr.daemons)
	mgr.mu.RUnlock()

	if remaining != 0 {
		t.Errorf("all failed daemons should be cleaned, %d remain", remaining)
	}
}
