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

// Tests for the shutdown wake path: a poll blocked on the uffd descriptor
// must be interrupted by cancellation instead of sleeping out its timeout,
// the wake descriptor must stay usable across repeated shutdown attempts and
// closes without leaking writes into a recycled descriptor number, and the
// shutdown sequence must write the wake before any teardown that can block.

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPollUffdOrCancelWakesOnCancel is the core regression: the production
// wait (same helper the fault loop uses) must block for its full timeout
// when idle — no hidden busy loop — and return promptly once shutdown writes
// the wake descriptor, far ahead of the 500ms timeout it was given.
func TestPollUffdOrCancelWakesOnCancel(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	defer wake.close()

	// Control: with no wake and no uffd data the wait blocks for the whole
	// (shortened, test-only) timeout instead of spinning.
	start := time.Now()
	woke, ready, hungUp, err := pollUffdOrCancel(int(r.Fd()), wake, 60)
	if err != nil {
		t.Fatal(err)
	}
	if woke || ready || hungUp {
		t.Fatalf("idle wait reported activity: woke=%v ready=%v hungUp=%v", woke, ready, hungUp)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("idle wait returned after %v; poll is not blocking", elapsed)
	}

	// Wake while blocked: must return far ahead of the production timeout.
	go func() {
		time.Sleep(20 * time.Millisecond)
		wake.wake()
	}()
	start = time.Now()
	woke, _, _, err = pollUffdOrCancel(int(r.Fd()), wake, uffdPollTimeoutMs)
	if err != nil {
		t.Fatal(err)
	}
	if !woke {
		t.Fatal("wake did not surface as cancelWoke")
	}
	if elapsed := time.Since(start); elapsed > 450*time.Millisecond {
		t.Fatalf("wait slept %v after wake; cancellation did not interrupt the poll", elapsed)
	}

	// The helper drained the descriptor: an immediate follow-up wait on an
	// unclosed stop re-blocks instead of spinning on stale readability.
	woke, _, _, err = pollUffdOrCancel(int(r.Fd()), wake, 0)
	if err != nil {
		t.Fatal(err)
	}
	if woke {
		t.Fatal("wake descriptor still readable after the wait; helper does not drain")
	}
}

// TestPollUffdOrCancelReportsReadinessAndHangup pins the uffd-side semantics
// of the helper against a plain pipe: readable data reports ready, and a
// closed peer reports hangup, matching the old single-descriptor poll.
func TestPollUffdOrCancelReportsReadinessAndHangup(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	defer wake.close()

	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	woke, ready, hungUp, err := pollUffdOrCancel(int(r.Fd()), wake, 100)
	if err != nil {
		t.Fatal(err)
	}
	if woke || !ready {
		t.Fatalf("readable uffd data misreported: woke=%v ready=%v", woke, ready)
	}
	buf := make([]byte, 1)
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}
	w.Close()
	woke, ready, hungUp, err = pollUffdOrCancel(int(r.Fd()), wake, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !hungUp {
		t.Fatalf("closed peer not reported as hangup: woke=%v ready=%v hungUp=%v", woke, ready, hungUp)
	}
}

// TestCancelWakeRepeatedWakeDrain covers the descriptor itself: repeated wake
// calls (repeated shutdown attempts) keep it readable, drain clears readiness
// without disabling later wakes, and draining an idle descriptor is a no-op.
func TestCancelWakeRepeatedWakeDrain(t *testing.T) {
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	defer wake.close()
	readable := func() bool {
		fds := []unix.PollFd{wake.pollFd()}
		n, err := unix.Poll(fds, 0)
		if err != nil {
			t.Fatal(err)
		}
		return n == 1 && fds[0].Revents&unix.POLLIN != 0
	}
	if readable() {
		t.Fatal("fresh wake descriptor is readable")
	}
	wake.wake()
	if !readable() {
		t.Fatal("wake left the descriptor unreadable")
	}
	wake.wake() // Repeated shutdown: counter only grows.
	if !readable() {
		t.Fatal("second wake lost readiness")
	}
	wake.drain()
	if readable() {
		t.Fatal("drain left the descriptor readable")
	}
	wake.drain() // Draining an idle descriptor must not block or error.
	wake.wake()  // Usable again after a drain.
	if !readable() {
		t.Fatal("wake after drain left the descriptor unreadable")
	}
}

// TestCancelWakeCloseGuardsRecycledDescriptor: close latches before the
// descriptor number can be recycled, so a wake issued after close (shutdown
// racing exit) cannot write into whatever now owns the number, and a second
// close cannot close the recycled descriptor.
func TestCancelWakeCloseGuardsRecycledDescriptor(t *testing.T) {
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	fdNum := wake.fd
	wake.close()
	path := filepath.Join(t.TempDir(), "reused")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if int(f.Fd()) != fdNum {
		f.Close()
		t.Skipf("fd %d was not recycled (open got %d); cannot observe a stale write", fdNum, f.Fd())
	}
	defer f.Close()
	wake.wake()  // Must be a no-op on the recycled descriptor.
	wake.drain() // Same.
	wake.close() // Repeated close must not close f's descriptor.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("recycled descriptor received %d stale byte(s)", len(data))
	}
	if _, err := f.Write([]byte("ok")); err != nil {
		t.Fatalf("second close shut the recycled descriptor: %v", err)
	}
}

// blockingStopSource makes stopPersistence block until released, so the test
// can inspect the wake state while teardown is in flight.
type blockingStopSource struct {
	calls   chan struct{}
	release chan struct{}
}

func (b *blockingStopSource) stopPersistence() *chunkPersister {
	b.calls <- struct{}{}
	<-b.release
	return nil
}

// TestRunShutdownWakesBeforeTeardownBlocks pins the shutdown ordering: by the
// time the (potentially blocking) persistence stop has been entered, stop is
// already closed and the wake descriptor is already readable — so a poll
// blocked on the uffd exits before, not after, the blocking teardown.
func TestRunShutdownWakesBeforeTeardownBlocks(t *testing.T) {
	wake, err := newCancelWake()
	if err != nil {
		t.Fatal(err)
	}
	defer wake.close()
	stop := make(chan struct{})
	var once sync.Once
	src := &blockingStopSource{calls: make(chan struct{}, 1), release: make(chan struct{})}
	ctx, cancelSource := context.WithCancel(context.Background())
	defer cancelSource()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runShutdown(&once, stop, wake, cancelSource, src)
	}()
	select {
	case <-src.calls:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown never reached the persistence stop")
	}
	select {
	case <-stop:
	default:
		t.Fatal("stop not closed while teardown is in flight")
	}
	fds := []unix.PollFd{wake.pollFd()}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || fds[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("wake descriptor not readable while teardown blocks: n=%d revents=%d", n, fds[0].Revents)
	}
	close(src.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish after teardown released")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("source context was not canceled")
	}
	// Repeated shutdown must not re-enter teardown.
	runShutdown(&once, stop, wake, cancelSource, src)
	runShutdown(&once, stop, wake, cancelSource, src)
	select {
	case <-src.calls:
		t.Fatal("repeated shutdown re-entered teardown")
	default:
	}
}

// TestCancelWakeConcurrentWakeAndClose races repeated wakes and closes from
// several goroutines (as the VMM-EOF watcher racing loop exit can produce);
// every method must stay safe and the descriptor must end closed exactly once.
func TestCancelWakeConcurrentWakeAndClose(t *testing.T) {
	for i := 0; i < 64; i++ {
		wake, err := newCancelWake()
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wake.wake()
				wake.wake()
			}()
		}
		for g := 0; g < 2; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wake.drain()
				wake.close()
			}()
		}
		wg.Wait()
		wake.close() // Idempotent final close.
	}
}
