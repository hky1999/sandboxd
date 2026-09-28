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

package chunkcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/checkpointchunks"
)

// allocatedBytes (TEST helper): the real st_blocks*512 of a path, for
// asserting what the filesystem reports. Production code derives
// allocation from an already-obtained FileInfo (allocatedFrom).
func allocatedBytes(path string) int64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Blocks * 512
}

// acquireEvictLockBounded takes the node evict lock EX for the test,
// waiting out the manager's own startup capacity pass first (Open's
// initial-scan goroutine runs one EvictIfNeeded; flocking immediately
// after Open races it and fails with EWOULDBLOCK).
func acquireEvictLockBounded(t *testing.T, root string) *os.File {
	t.Helper()
	ext, err := os.OpenFile(filepath.Join(root, evictLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(int(ext.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return ext
		}
		if time.Now().After(deadline) {
			ext.Close()
			t.Fatalf("startup capacity pass still holds the evict lock after 5s: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func open(t *testing.T, root string, high, low int64) *Manager {
	t.Helper()
	m, err := Open(Config{Root: root, HighWatermark: high, LowWatermark: low})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

func mustFetch(t *testing.T, m *Manager, digest string, body []byte, missCalls *atomic.Int64) []byte {
	t.Helper()
	got, err := m.Fetch(context.Background(), digest, int64(len(body)), func(context.Context) ([]byte, error) {
		if missCalls != nil {
			missCalls.Add(1)
		}
		return body, nil
	})
	if err != nil {
		t.Fatalf("fetch %s: %v", digest[:12], err)
	}
	return got
}

func TestFetchMissThenHitWithoutSecondDownload(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	body := []byte("hello chunk cache")
	d := digestOf(body)
	var calls atomic.Int64
	got := mustFetch(t, m, d, body, &calls)
	if string(got) != string(body) {
		t.Fatalf("body mismatch")
	}
	if calls.Load() != 1 {
		t.Fatalf("miss called %d times on first fetch", calls.Load())
	}
	again := mustFetch(t, m, d, body, &calls)
	if string(again) != string(body) {
		t.Fatalf("hit body mismatch")
	}
	if calls.Load() != 1 {
		t.Fatalf("hit path re-downloaded (miss calls=%d)", calls.Load())
	}
	st := m.Status()
	if st.Hits != 1 || st.Misses != 1 || st.HitBytes != int64(len(body)) {
		t.Fatalf("status %+v", st)
	}
}

func TestFetchRejectsInvalidDigestAndLength(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	if _, err := m.Fetch(context.Background(), "nothex", 4, func(context.Context) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("invalid digest accepted")
	}
	body := []byte("abc")
	d := digestOf(body)
	if _, err := m.Fetch(context.Background(), d, 10, func(context.Context) ([]byte, error) { return body, nil }); err == nil {
		t.Fatal("length mismatch accepted")
	}
	if _, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		return []byte("xyz"), nil // digest mismatch
	}); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if _, err := os.Stat(m.chunkPath(d)); !os.IsNotExist(err) {
		t.Fatal("unverified body was cached")
	}
	if m.Status().DownloadErrors != 2 {
		t.Fatalf("download errors = %d", m.Status().DownloadErrors)
	}
}

func TestFetchDownloadFailureIsNotCachedAndRetries(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	body := []byte("retry me")
	d := digestOf(body)
	fail := true
	_, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		if fail {
			return nil, fmt.Errorf("store down")
		}
		return body, nil
	})
	if err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("want store error, got %v", err)
	}
	if _, serr := os.Stat(m.chunkPath(d)); !os.IsNotExist(serr) {
		t.Fatal("failed download left a cache file")
	}
	fail = false
	if got := mustFetch(t, m, d, body, nil); string(got) != string(body) {
		t.Fatal("retry body mismatch")
	}
}

// A truncated, sparse or otherwise wrong final file must never be served and
// is evicted in favor of a refetch (hole ≠ content).
func TestPoisonedEntryEvictedAndRefetched(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("real bytes")
	d := digestOf(body)
	// Sparse placeholder of the right LENGTH but zeros: digest check fails.
	path := m.chunkPath(d)
	os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(int64(len(body)))
	f.Close()
	var calls atomic.Int64
	got := mustFetch(t, m, d, body, &calls)
	if string(got) != string(body) || calls.Load() != 1 {
		t.Fatalf("poisoned entry served or not refetched: calls=%d", calls.Load())
	}
	if m.Status().PoisonedEvicted == 0 {
		t.Fatal("poisoned eviction not counted")
	}
}

func TestInProcessSingleflight(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i)
	}
	d := digestOf(body)
	var calls atomic.Int64
	var wg sync.WaitGroup
	results := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
				calls.Add(1)
				time.Sleep(150 * time.Millisecond)
				return body, nil
			})
			if err != nil {
				t.Errorf("fetch: %v", err)
				return
			}
			results[i] = got
		}(i)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("miss ran %d times, want 1", calls.Load())
	}
	for i, r := range results {
		if string(r) != string(body) {
			t.Fatalf("result %d mismatch", i)
		}
	}
}

// Two managers on one root (distinct inflight maps, distinct lock fds — the
// same flock protocol two processes use) must collapse a concurrent miss of
// one digest into a single download+verify+publish.
func TestTwoManagersSingleFetch(t *testing.T) {
	root := t.TempDir()
	a := open(t, root, 0, 0)
	b := open(t, root, 0, 0)
	body := []byte("shared digest bytes")
	d := digestOf(body)
	var calls atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]byte, 2)
	errs := make([]error, 2)
	for i, m := range []*Manager{a, b} {
		wg.Add(1)
		go func(i int, m *Manager) {
			defer wg.Done()
			<-start
			got, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
				calls.Add(1)
				time.Sleep(300 * time.Millisecond)
				return body, nil
			})
			results[i], errs[i] = got, err
		}(i, m)
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("download ran %d times across managers, want 1", calls.Load())
	}
	for i := range errs {
		if errs[i] != nil || string(results[i]) != string(body) {
			t.Fatalf("manager %d: err=%v body-match=%v", i, errs[i], string(results[i]) == string(body))
		}
	}
}

// The cross-process claim is held across the whole miss: a follower that
// finds the lock busy waits, then adopts the leader's verified publication
// without running its own miss.
func TestFollowerWaitsForCrossProcessLeaderAndNeverDownloads(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("leader bytes")
	d := digestOf(body)

	// Simulate another process mid-download: hold the digest lock ourselves.
	lock, err := os.OpenFile(m.lockPath(d), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	var followerMiss atomic.Int64
	done := make(chan error, 1)
	go func() {
		got, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
			followerMiss.Add(1)
			return body, nil
		})
		if err == nil && string(got) != string(body) {
			err = fmt.Errorf("follower body mismatch")
		}
		done <- err
	}()
	// While the leader "downloads", the follower must not run its miss.
	time.Sleep(200 * time.Millisecond)
	if followerMiss.Load() != 0 {
		t.Fatalf("follower downloaded while leader held the lock (%d calls)", followerMiss.Load())
	}
	// Leader publishes atomically and releases.
	if err := m.publish(d, body); err != nil {
		t.Fatal(err)
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	lock.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follower: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower never returned")
	}
	if followerMiss.Load() != 0 {
		t.Fatalf("follower ran its own miss (%d)", followerMiss.Load())
	}
}

// Real child process: while it holds a pin's flock, the evictor honors it;
// SIGKILL the child (a crash) and the kernel must release the lock so the
// pin becomes provably stale and removable.
func TestPinHonoredWhileHeldAndReleasedOnProcessDeath(t *testing.T) {
	if os.Getenv("GO_CHUNKCACHE_HELPER") != "" {
		return // child processes execute TestHelperProcess instead
	}
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("pinned chunk")
	d := digestOf(body)
	mustFetch(t, m, d, body, nil)

	pinPath := filepath.Join(root, pinsDir, "child.pin")

	ready := filepath.Join(root, "child-ready")
	childLog, err := os.Create(filepath.Join(root, "child.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer childLog.Close()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "pin-holder", pinPath, d, ready)
	cmd.Env = append(os.Environ(), "GO_CHUNKCACHE_HELPER=1")
	cmd.Stdout, cmd.Stderr = childLog, childLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			childLog.Sync()
			if raw, rerr := os.ReadFile(filepath.Join(root, "child.log")); rerr == nil {
				t.Logf("child log:\n%s", raw)
			}
			t.Fatalf("child never acquired the pin lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	protected, count, bytes, err := m.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := protected[d]; !ok || count != 1 || bytes != int64(len(body)) {
		t.Fatalf("live pin not honored: protected=%v count=%d bytes=%d", protected, count, bytes)
	}
	if _, err := os.Stat(pinPath); err != nil {
		t.Fatal("live pin file must survive the sweep")
	}

	// Crash the holder: the kernel drops its flock.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	protected, _, _, err = m.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) != 0 {
		t.Fatalf("pin leaked past process death: %v", protected)
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatal("stale pin file not removed")
	}
}

// TestHelperProcess is executed as a child by the tests above. It is not a
// test itself.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_CHUNKCACHE_HELPER") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "helper: started args=%v\n", os.Args)
	args := os.Args
	for i, a := range args {
		if a == "--" && len(args) > i+4 && args[i+1] == "pin-holder" {
			pinPath, digest, ready := args[i+2], args[i+3], args[i+4]
			// Build the pin exactly like Manager.Pin: flock the temp fd
			// BEFORE the rename, so the sweeper never observes an unlocked
			// live pin. A directly-written unlocked pin file would be
			// (correctly) removed as stale by a concurrent sweep.
			dir := filepath.Dir(pinPath)
			tmp, err := os.CreateTemp(dir, tmpPrefix)
			if err != nil {
				fmt.Fprintf(os.Stderr, "helper: temp: %v\n", err)
				os.Exit(3)
			}
			if _, err := tmp.WriteString(digest + "\n"); err != nil {
				fmt.Fprintf(os.Stderr, "helper: write: %v\n", err)
				os.Exit(3)
			}
			if err := syscall.Flock(int(tmp.Fd()), syscall.LOCK_EX); err != nil {
				fmt.Fprintf(os.Stderr, "helper: flock: %v\n", err)
				os.Exit(4)
			}
			if err := os.Rename(tmp.Name(), pinPath); err != nil {
				fmt.Fprintf(os.Stderr, "helper: rename: %v\n", err)
				os.Exit(4)
			}
			fmt.Fprintf(os.Stderr, "helper: pin published and locked\n")
			if err := os.WriteFile(ready, []byte("1"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "helper: ready: %v\n", err)
				os.Exit(5)
			}
			time.Sleep(60 * time.Second) // parent kills us
			os.Exit(0)
		}
	}
	fmt.Fprint(os.Stderr, "helper: no -- pin-holder args\n")
	os.Exit(2)
}

// Auto-eviction must trigger strictly AFTER the leader's atomic publication
// (not at miss entry): a download blocked mid-flight must neither evict
// anything (usage is honestly below-typed pre-publish) nor leave the cache
// above high once the publication lands — no external EvictIfNeeded call
// is made anywhere in this test.
func TestAutoEvictionFiresAfterPublication(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10) // 64KiB: allocated == logical on 4KiB-block filesystems
	m, err := Open(Config{Root: root, HighWatermark: 3 * chunkLen, LowWatermark: 2 * chunkLen, TouchEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	dA, bA := mk(1)
	dB, bB := mk(2)
	dC, bC := mk(3)
	dD, bD := mk(4)
	mustFetch(t, m, dA, bA, nil)
	time.Sleep(20 * time.Millisecond)
	mustFetch(t, m, dB, bB, nil)
	time.Sleep(20 * time.Millisecond)
	mustFetch(t, m, dC, bC, nil) // usage == high: nothing to evict yet

	// Fourth fetch whose download BLOCKS on a barrier: the leader sits
	// inside the miss closure with nothing published.
	entered := make(chan struct{})
	release := make(chan struct{})
	fetched := make(chan error, 1)
	go func() {
		body, err := m.Fetch(context.Background(), dD, chunkLen, func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			return bD, nil
		})
		if err == nil && string(body) != string(bD) {
			err = fmt.Errorf("blocked-fetch body mismatch")
		}
		fetched <- err
	}()
	<-entered
	// While the leader is mid-download: no publication happened, so no
	// eviction may run and no existing entry may be removed.
	time.Sleep(150 * time.Millisecond)
	if st := m.Status(); st.Evictions != 0 || st.LogicalBytes != 3*chunkLen {
		t.Fatalf("pre-publish state disturbed: %+v", st)
	}
	for _, d := range []string{dA, dB, dC} {
		if _, err := os.Stat(m.chunkPath(d)); err != nil {
			t.Fatalf("entry %s vanished during a blocked download", d[:12])
		}
	}
	close(release)
	if err := <-fetched; err != nil {
		t.Fatalf("blocked fetch: %v", err)
	}
	// The publication is now accounted; the auto-trigger alone must bring
	// usage from 4 chunks down to the low watermark (2), oldest first.
	if !waitEvictSettled(t, m, map[string]bool{
		m.chunkPath(dA): false,
		m.chunkPath(dB): false,
		m.chunkPath(dC): true,
		m.chunkPath(dD): true,
	}) {
		st := m.Status()
		t.Fatalf("auto-eviction never settled high->low: %+v", st)
	}
	if st := m.Status(); st.Evictions == 0 {
		t.Fatal("eviction counter did not move without an external call")
	}
}

// waitEvictSettled polls until the auto-eviction triggered by fetch misses
// has brought usage to the low watermark AND the expected files exist (or
// not). Production eviction is asynchronous; assertions must wait for it.
func waitEvictSettled(t *testing.T, m *Manager, want map[string]bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok := true
		for path, exist := range want {
			_, err := os.Stat(path)
			if (err == nil) != exist {
				ok = false
				break
			}
		}
		if ok && m.Status().AllocatedBytes <= m.cfg.LowWatermark {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Watermarks: eviction runs from above high down to low, in LRU order, and
// pinned entries are never selected. LRU order is established by real
// publish times (20ms apart, TouchEvery=1ms) — the merge in Rescan keeps the
// fresher in-process clock, so backdating mtimes must not be relied on.
func TestEvictionWatermarksLRUAndPins(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10) // 64KiB: allocated == logical on 4KiB-block filesystems
	// high 3 chunks, low 2 chunks: crossing high evicts exactly down to low.
	m, err := Open(Config{Root: root, HighWatermark: 3 * chunkLen, LowWatermark: 2 * chunkLen, TouchEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	dA, bA := mk(1)
	dB, bB := mk(2)
	dC, bC := mk(3)
	dD, bD := mk(4)
	mustFetch(t, m, dA, bA, nil)
	time.Sleep(20 * time.Millisecond)
	mustFetch(t, m, dB, bB, nil)
	time.Sleep(20 * time.Millisecond)
	mustFetch(t, m, dC, bC, nil)
	// A is pinned for its holder's lifetime: eviction must skip it.
	release, err := m.Pin("runtime-A", []string{dA})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	mustFetch(t, m, dD, bD, nil) // usage 4 chunks > high 3: auto-evict fires
	if !waitEvictSettled(t, m, map[string]bool{
		m.chunkPath(dA): true, // pinned survives
		m.chunkPath(dB): false,
		m.chunkPath(dC): false,
		m.chunkPath(dD): true, // newest survives
	}) {
		st := m.Status()
		t.Fatalf("eviction did not settle as expected: usage=%d pinned=%d %+v", st.LogicalBytes, st.PinnedEntries, st)
	}
	st := m.Status()
	if st.PinnedEntries != 1 || st.PinnedBytes != chunkLen {
		t.Fatalf("pin accounting wrong: %+v", st)
	}
	// After release, the entry becomes evictable again. A is now the oldest
	// live entry, D the second oldest: both must go before the fresh B/C.
	release()
	mustFetch(t, m, dB, bB, nil)
	mustFetch(t, m, dC, bC, nil) // back to 4 live chunks > high
	if !waitEvictSettled(t, m, map[string]bool{
		m.chunkPath(dA): false,
		m.chunkPath(dD): false,
		m.chunkPath(dB): true,
		m.chunkPath(dC): true,
	}) {
		st := m.Status()
		t.Fatalf("post-release eviction did not settle: usage=%d pinned=%d %+v", st.LogicalBytes, st.PinnedEntries, st)
	}
}

// Boundary encoding: eviction touches ONLY cache entries under Root — never
// sibling spool directories, never lock/pin/status files.
func TestEvictionNeverEscapesCacheRoot(t *testing.T) {
	root := t.TempDir()
	spool := filepath.Join(filepath.Dir(root), "spool-checkpoint-dirs") // sibling of the cache root
	os.MkdirAll(spool, 0o755)
	unique := filepath.Join(spool, "only-copy")
	os.WriteFile(unique, []byte("unique unpublished bytes"), 0o600)

	const chunkLen = int64(64 << 10)
	m := open(t, root, 2*chunkLen, chunkLen)
	for seed := byte(1); seed <= 4; seed++ {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		mustFetch(t, m, digestOf(body), body, nil)
	}
	if err := m.EvictIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(unique)
	if err != nil || string(got) != "unique unpublished bytes" {
		t.Fatalf("eviction escaped the cache root: %v %q", err, got)
	}
	for _, reserved := range []string{locksDir, pinsDir} {
		if fi, err := os.Stat(filepath.Join(root, reserved)); err != nil || !fi.IsDir() {
			t.Fatalf("reserved dir %s damaged: %v", reserved, err)
		}
	}
}

// Crash reconciliation: on restart the index is rebuilt from disk, abandoned
// temps are swept by age, stale (holderless) pins are removed, and a
// truncated final file self-heals through the poisoned path.
func TestRestartReconcilesIndexSweepsTempAndStalePin(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("surviving chunk")
	d := digestOf(body)
	mustFetch(t, m, d, body, nil)

	// Abandoned temp file, backdated beyond the sweep age.
	shard := filepath.Join(root, d[:2])
	tmp, _ := os.CreateTemp(shard, tmpPrefix)
	tmp.WriteString("partial")
	tmp.Close()
	old := time.Now().Add(-2 * staleTempAge)
	os.Chtimes(tmp.Name(), old, old)
	// Stale pin whose holder is long gone (no flock anywhere).
	stale := filepath.Join(root, pinsDir, "ghost.pin")
	os.WriteFile(stale, []byte(d+"\n"), 0o600)

	m2 := open(t, root, 0, 0)
	if err := m2.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := m2.Status()
	if st.Entries != 1 || st.LogicalBytes != int64(len(body)) {
		t.Fatalf("index rebuild wrong: %+v", st)
	}
	if _, err := os.Stat(tmp.Name()); !os.IsNotExist(err) {
		t.Fatal("stale temp not swept")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale pin not swept")
	}
	if _, err := os.Stat(m2.chunkPath(d)); err != nil {
		t.Fatal("valid entry lost in rebuild")
	}
	if st.AllocatedBytes < int64(len(body)) {
		t.Fatalf("allocated accounting implausible: %+v", st)
	}
	// Truncate the final file (crash before writeback): next fetch must
	// refuse to serve it and refetch instead.
	os.WriteFile(m2.chunkPath(d), body[:5], 0o600)
	if got := mustFetch(t, m2, d, body, nil); string(got) != string(body) {
		t.Fatal("truncated entry served")
	}
}

// Watermark decisions use ALLOCATED bytes: a body whose st_blocks*512
// exceeds its size (block rounding) must trip the watermark when the
// logical size alone would not.
func TestWatermarkUsesAllocatedNotLogical(t *testing.T) {
	root := t.TempDir()
	body := make([]byte, 768) // logical 768; allocated >= 1024 on any block size
	for i := range body {
		body[i] = byte(i)
	}
	d := digestOf(body)
	path := filepath.Join(root, d[:2], d)
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, body, 0o600)
	if allocatedBytes(path) < 1024 {
		t.Skipf("filesystem reports allocated=%d for 768B; rounding not observable", allocatedBytes(path))
	}
	// high=900: logical (768) stays under, allocated (>=1024) crosses.
	m, err := Open(Config{Root: root, HighWatermark: 900, LowWatermark: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	if err := m.EvictIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("allocated-based eviction did not run (logical=%d allocated=%d high=900)",
			int64(len(body)), allocatedBytes(path))
	}
	// The OPEN-time background scan may hold a pre-delete view; one more
	// authoritative rescan reconciles accounting with the disk truth.
	if err := m.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if st.LogicalBytes != 0 || st.AllocatedBytes != 0 {
		t.Fatalf("post-eviction accounting not zero: %+v", st)
	}
}

// Half-configured watermarks are rejected everywhere (F).
func TestValidWatermarksShapes(t *testing.T) {
	for _, tc := range []struct {
		high, low int64
		wantErr   bool
	}{
		{0, 0, false}, {10, 10, false}, {10, 5, false},
		{0, 5, true}, {5, 0, true}, {5, 10, true}, {-1, 0, true}, {0, -1, true},
	} {
		err := ValidWatermarks(tc.high, tc.low)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ValidWatermarks(%d,%d) = %v, wantErr=%v", tc.high, tc.low, err, tc.wantErr)
		}
	}
	if _, err := Open(Config{Root: t.TempDir(), HighWatermark: 5, LowWatermark: 0}); err == nil {
		t.Fatal("Open accepted high>0 with low=0")
	}
}

// Two simultaneously-live Managers interleaving publishes on one shared
// root must converge to <= low ALLOCATED with the pinned set preserved —
// including the interleaving where one manager's bytes land after the
// other's authoritative scan (B). Convergence is driven purely by the
// per-publish trigger (worker + coalescing signal + dirty re-check).
func TestTwoManagersConvergeCrossHighWithPins(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m1, err := Open(Config{Root: root, HighWatermark: 3 * chunkLen, LowWatermark: 2 * chunkLen, TouchEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m1.Close()
	m2, err := Open(Config{Root: root, HighWatermark: 3 * chunkLen, LowWatermark: 2 * chunkLen, TouchEvery: time.Millisecond, Logger: log.New(os.Stderr, "M2 ", log.Lmicroseconds)})
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	m1.cfg.Logger = log.New(os.Stderr, "M1 ", log.Lmicroseconds)
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	dD, bD := mk(4)
	release, err := m2.Pin("runtime-D", []string{dD})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	dA, bA := mk(1)
	dB, bB := mk(2)
	dC, bC := mk(3)
	// Interleave: m1 fills to exactly high, then m2's publish crosses it
	// AFTER m1's own pass has scanned (barrier: wait for quiescence between
	// the phases so the interleaving is the reviewed one).
	mustFetch(t, m1, dA, bA, nil)
	mustFetch(t, m1, dB, bB, nil)
	mustFetch(t, m1, dC, bC, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m1.Status().AllocatedBytes <= 3*chunkLen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mustFetch(t, m2, dD, bD, nil) // crosses high from the OTHER manager
	// Essential invariants only: the PINNED chunk survives and the shared
	// root converges to exactly the low watermark's worth of entries. WHICH
	// unpinned chunk survives is LRU tie-breaking among near-equal mtimes
	// and is deliberately not asserted.
	deadline = time.Now().Add(5 * time.Second)
	for {
		pinnedAlive := true
		if _, err := os.Stat(m1.chunkPath(dD)); err != nil {
			pinnedAlive = false
		}
		var alive int
		var unpinnedAllocated int64
		entries, _ := os.ReadDir(root)
		for _, shard := range entries {
			if !shard.IsDir() || !isShardName(shard.Name()) {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(root, shard.Name()))
			for _, f := range files {
				if !checkpointchunks.ValidDigest(f.Name()) {
					continue
				}
				alive++
				if f.Name() != dD {
					unpinnedAllocated += allocatedBytes(filepath.Join(root, shard.Name(), f.Name()))
				}
			}
		}
		// low = 2 chunks: pinned D plus at most one unpinned survivor; the
		// unpinned remainder stays within the low watermark.
		if pinnedAlive && alive <= 2 && unpinnedAllocated <= 2*chunkLen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no convergence: pinnedAlive=%v alive=%d unpinnedAllocated=%d", pinnedAlive, alive, unpinnedAllocated)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A busy node evict lock must DELAY, not drop, the capacity pass (B/P1
// interleaving): while an external holder keeps the lock, nothing is
// evicted; after release the pending pass converges.
func TestBusyEvictLockDelaysNotDrops(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m, err := Open(Config{Root: root, HighWatermark: 2 * chunkLen, LowWatermark: chunkLen})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	// External holder of the node-wide evict lock (another process mid-pass).
	ext := acquireEvictLockBounded(t, root)
	dA, bA := mk(1)
	dB, bB := mk(2)
	dC, bC := mk(3)
	mustFetch(t, m, dA, bA, nil)
	mustFetch(t, m, dB, bB, nil)
	mustFetch(t, m, dC, bC, nil) // crosses high while the lock is held
	time.Sleep(300 * time.Millisecond)
	for _, d := range []string{dA, dB, dC} {
		if _, err := os.Stat(m.chunkPath(d)); err != nil {
			t.Fatal("eviction ran while the node lock was held by someone else")
		}
	}
	syscall.Flock(int(ext.Fd()), syscall.LOCK_UN)
	ext.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var left int
		for _, d := range []string{dA, dB, dC} {
			if _, err := os.Stat(m.chunkPath(d)); err == nil {
				left++
			}
		}
		if left == 1 || time.Now().After(deadline) {
			if left != 1 {
				t.Fatalf("pending pass never converged after lock release (left=%d)", left)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Leader failure with multiple waiters (C): every waiter re-elects exactly
// once; no panic, no unlocked map write; with a persistent miss all three
// attempts fail; with the second attempt succeeding, everyone converges on
// verified bytes with exactly two downloads.
func TestLeaderFailureReElectionAllFail(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	body := []byte("doomed chunk")
	d := digestOf(body)
	var calls atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
				calls.Add(1)
				time.Sleep(80 * time.Millisecond)
				return nil, fmt.Errorf("store down")
			})
		}()
	}
	wg.Wait()
	if calls.Load() != 3 {
		t.Fatalf("miss ran %d times, want exactly one per goroutine (3)", calls.Load())
	}
}

func TestLeaderFailureReElectionRecovers(t *testing.T) {
	m := open(t, t.TempDir(), 0, 0)
	body := []byte("second try wins")
	d := digestOf(body)
	var calls atomic.Int64
	var wg sync.WaitGroup
	results := make([][]byte, 3)
	errs := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
				if calls.Add(1) == 1 {
					return nil, fmt.Errorf("first leader fails")
				}
				return body, nil
			})
			results[i], errs[i] = got, err
		}(i)
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("miss ran %d times, want 2 (failed leader + one re-election)", calls.Load())
	}
	// The FIRST leader legitimately surfaces its own error; both woken
	// waiters converge (one re-leads and succeeds, one adopts the cache).
	failures, successes := 0, 0
	for i := range errs {
		if errs[i] != nil {
			if !strings.Contains(errs[i].Error(), "first leader fails") {
				t.Fatalf("goroutine %d: unexpected error %v", i, errs[i])
			}
			failures++
			continue
		}
		if string(results[i]) != string(body) {
			t.Fatalf("goroutine %d: wrong body", i)
		}
		successes++
	}
	if failures != 1 || successes != 2 {
		t.Fatalf("failures=%d successes=%d, want 1/2", failures, successes)
	}
}

// Lifecycle endpoint: when EVERY chunk is pinned the root sits above high
// (soft cap, observed as pinned overage); releasing the pin with NO further
// fetches must still converge to low — the release itself re-triggers.
func TestPinReleaseConvergesWithoutNewFetches(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m, err := Open(Config{Root: root, HighWatermark: 2 * chunkLen, LowWatermark: chunkLen, TouchEvery: time.Millisecond,
		Logger: log.New(os.Stderr, "pinconv ", log.Lmicroseconds)})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	ds := make([]string, 3)
	bodies := make([][]byte, 3)
	for i := range ds {
		ds[i], bodies[i] = mk(byte(i + 1))
	}
	// The pin must exist BEFORE the crossing publication: pins created
	// after a pass has already evicted protect nothing retroactively.
	release, err := m.Pin("all", ds)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ds {
		mustFetch(t, m, ds[i], bodies[i], nil)
	}
	// All three pinned: passes run but evict nothing; overage is recorded.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().PinnedOverageBytes > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Status().PinnedOverageBytes <= 0 {
		t.Fatalf("pinned overage not observed: %+v", m.Status())
	}
	for _, d := range ds {
		if _, err := os.Stat(m.chunkPath(d)); err != nil {
			t.Fatalf("pinned chunk %s evicted", d[:12])
		}
	}
	release() // no further fetches: convergence must come from the release
	deadline = time.Now().Add(5 * time.Second)
	for {
		var left int
		for _, d := range ds {
			if _, err := os.Stat(m.chunkPath(d)); err == nil {
				left++
			}
		}
		if left == 1 || time.Now().After(deadline) {
			if left != 1 {
				t.Fatalf("release did not converge (left=%d, want 1 = low watermark)", left)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// P1-A: Close must stay bounded even when a FOREIGN process holds the node
// evict flock — cancel-first lifecycle, never an unbounded Wait.
func TestCloseBoundedUnderForeignEvictLock(t *testing.T) {
	root := t.TempDir()
	m, err := Open(Config{Root: root, HighWatermark: 1 << 20, LowWatermark: 1 << 19})
	if err != nil {
		t.Fatal(err)
	}
	ext := acquireEvictLockBounded(t, root)
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
		// bounded return: the foreign holder still owns the lock
	case <-time.After(35 * time.Second):
		t.Fatal("Close hung behind a foreign evict flock")
	}
	syscall.Flock(int(ext.Fd()), syscall.LOCK_UN)
	ext.Close()
}

// P1-C: two holders using the SAME pin label must not clobber each other —
// releasing one leaves the other's protection intact and visible.
func TestPinSameLabelTwoHolders(t *testing.T) {
	root := t.TempDir()
	a := open(t, root, 0, 0)
	b := open(t, root, 0, 0)
	body := []byte("doubly pinned")
	d := digestOf(body)
	relA, err := a.Pin("same-label", []string{d})
	if err != nil {
		t.Fatal(err)
	}
	relB, err := b.Pin("same-label", []string{d})
	if err != nil {
		t.Fatal(err)
	}
	relA()
	protected, count, _, err := b.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := protected[d]; !ok || count != 1 {
		t.Fatalf("releasing holder A removed holder B's protection: protected=%v count=%d", protected, count)
	}
	relB()
	protected, count, _, err = a.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) != 0 || count != 0 {
		t.Fatalf("pins leaked after both releases: %v", protected)
	}
}

// A: concurrent touch (hit path, mutates lastTouch under mu) while eviction
// builds and sorts candidates — the value-copy makes the unlocked sort safe.
func TestConcurrentTouchDuringEviction(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m, err := Open(Config{Root: root, HighWatermark: 2 * chunkLen, LowWatermark: chunkLen, TouchEvery: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	var ds []string
	var bodies [][]byte
	for i := 0; i < 6; i++ {
		d, b := mk(byte(i + 1))
		ds = append(ds, d)
		bodies = append(bodies, b)
		mustFetch(t, m, d, b, nil)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				for _, d := range ds {
					m.touch(d) // mutates lastTouch under m.mu
				}
			}
		}
	}()
	// Deterministic coverage of the unlocked sort: drive evictToLow
	// DIRECTLY (candidates guaranteed present — 6 chunks above the 2-chunk
	// low watermark) while the touch loop runs.
	for i := 0; i < 20; i++ {
		if err := m.evictToLow(context.Background()); err != nil {
			t.Fatalf("evictToLow failed: %v", err)
		}
		// Repopulate so every iteration actually sorts a candidate set.
		for j, d := range ds {
			if _, err := os.Stat(m.chunkPath(d)); err != nil {
				mustFetch(t, m, d, bodies[j], nil)
			}
		}
	}
	close(stop)
	wg.Wait()
}

// B: CONCURRENT same-label Pins must all get distinct files; releasing any
// subset never removes a remaining holder's protection.
func TestPinSameLabelConcurrentHolders(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("concurrent labels")
	d := digestOf(body)
	const N = 16
	start := make(chan struct{})
	releases := make([]func(), N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			releases[i], errs[i] = m.Pin("same", []string{d})
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("pin %d: %v", i, errs[i])
		}
	}
	// release the first half; the rest must remain protected
	for i := 0; i < N/2; i++ {
		releases[i]()
	}
	protected, count, _, err := m.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := protected[d]; !ok || count != N/2 {
		t.Fatalf("protection broken: present=%v count=%d want count=%d", ok, count, N/2)
	}
	for i := N / 2; i < N; i++ {
		releases[i]()
	}
	protected, count, _, err = m.protectedSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) != 0 || count != 0 {
		t.Fatalf("pins leaked: %v %d", protected, count)
	}
}

// D: an adversarially HUGE cached file must be read bounded, poisoned and
// refetched — never an unbounded allocation.
func TestHugeCacheFileReadBoundedAndPoisoned(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := []byte("tiny real chunk")
	d := digestOf(body)
	path := m.chunkPath(d)
	os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// 64 MiB of junk where a 15-byte chunk belongs.
	junk := make([]byte, 64<<20)
	f.Write(junk)
	f.Close()
	var calls atomic.Int64
	got := mustFetch(t, m, d, body, &calls)
	if string(got) != string(body) || calls.Load() != 1 {
		t.Fatalf("huge poisoned file not refetched: calls=%d", calls.Load())
	}
	if fi, serr := os.Stat(path); serr == nil && fi.Size() != int64(len(body)) {
		t.Fatalf("poisoned file not replaced: size=%d", fi.Size())
	}
	if m.Status().PoisonedEvicted == 0 {
		t.Fatal("poisoned eviction not counted")
	}
}

// E: ValidWatermarkMiB owns the MiB<<20 overflow bound; ValidWatermarks
// itself is units-agnostic (shape only).
func TestWatermarkOverflowBounds(t *testing.T) {
	const maxMiB = MaxWatermarkMiB // == MaxInt64>>20
	if err := ValidWatermarkMiB(maxMiB, maxMiB); err != nil {
		t.Fatalf("max representable MiB watermark rejected: %v", err)
	}
	if err := ValidWatermarkMiB(maxMiB, maxMiB-1); err != nil {
		t.Fatalf("bounded pair rejected: %v", err)
	}
	// One MiB past the bound is exactly the first value whose <<20 shift
	// would overflow int64.
	var over int64 = maxMiB + 1
	if err := ValidWatermarkMiB(over, over); err == nil {
		t.Fatal("overflowing MiB watermark accepted")
	}
	if ValidWatermarks(-1, 0) == nil || ValidWatermarks(0, -1) == nil {
		t.Fatal("negative accepted")
	}
}

// Flock classification: acquired/busy/retry/fatal map correctly.
func TestClassifyFlockErr(t *testing.T) {
	if got := classifyFlockErr(nil); got != flockAcquired {
		t.Fatalf("nil -> %v", got)
	}
	if got := classifyFlockErr(syscall.EWOULDBLOCK); got != flockBusy {
		t.Fatalf("EWOULDBLOCK -> %v", got)
	}
	if got := classifyFlockErr(syscall.EAGAIN); got != flockBusy {
		t.Fatalf("EAGAIN -> %v", got)
	}
	if got := classifyFlockErr(syscall.EINTR); got != flockRetry {
		t.Fatalf("EINTR -> %v", got)
	}
	if got := classifyFlockErr(syscall.EBADF); got != flockFatal {
		t.Fatalf("EBADF -> %v", got)
	}
	if got := classifyFlockErr(syscall.ENOLCK); got != flockFatal {
		t.Fatalf("ENOLCK -> %v", got)
	}
}

// Deterministic Pin-vs-evict interleave, direction 1: while an evict pass
// holds the node lock (simulated by the test holding it EX), a concurrent
// PinContext BLOCKS (has not returned); after the pass releases, the pin
// completes, and the following eviction spares the pinned chunk.
func TestPinBlocksDuringEvictPassThenProtected(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m, err := Open(Config{Root: root, HighWatermark: 2 * chunkLen, LowWatermark: chunkLen})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	body := make([]byte, chunkLen)
	for i := range body {
		body[i] = byte(0xC3)
	}
	d := digestOf(body)
	ext := acquireEvictLockBounded(t, root)
	type pinResult struct {
		release func()
		err     error
	}
	pinDone := make(chan pinResult, 1)
	go func() {
		rel, perr := m.PinContext(context.Background(), "mid-evict", []string{d})
		pinDone <- pinResult{release: rel, err: perr}
	}()
	select {
	case <-pinDone:
		t.Fatal("Pin returned while the evict pass held the node lock")
	case <-time.After(200 * time.Millisecond):
	}
	syscall.Flock(int(ext.Fd()), syscall.LOCK_UN)
	ext.Close()
	var res pinResult
	select {
	case res = <-pinDone:
		if res.err != nil {
			t.Fatalf("pin failed after pass release: %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pin never returned after pass release")
	}
	// Post-pin protocol: populate under the pin, evict, SPARED; release,
	// evict again, GONE. This is the "sweep deleted first, pin returned,
	// Fetch re-populates, pin holds" leg of the atomicity proof.
	var calls atomic.Int64
	mustFetch(t, m, d, body, &calls)
	for i := 0; i < 3; i++ {
		if err := m.EvictIfNeeded(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(m.chunkPath(d)); err != nil {
		t.Fatal("held pin did not spare its chunk from eviction")
	}
	res.release()
	// Push usage above high with fresh unpinned chunks; LRU must reclaim
	// the released (oldest) entry first.
	fresh := make([][]byte, 2)
	for i := range fresh {
		fresh[i] = make([]byte, chunkLen)
		for j := range fresh[i] {
			fresh[i][j] = byte(0xF0 + i)
		}
		mustFetch(t, m, digestOf(fresh[i]), fresh[i], nil)
	}
	if err := m.EvictIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(m.chunkPath(d)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("released pin's chunk never reclaimed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Direction 2, independent: pin FIRST, then sweep must spare it.
	release2, err := m.PinContext(context.Background(), "pin-first", []string{d})
	if err != nil {
		t.Fatal(err)
	}
	mustFetch(t, m, d, body, nil)
	for i := 0; i < 3; i++ {
		if err := m.EvictIfNeeded(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(m.chunkPath(d)); err != nil {
		t.Fatal("pre-existing pin did not spare its chunk")
	}
	release2()
}

// Domain binding: mismatch fails closed; concurrent first-binds of two
// different domains end with exactly one winner; binding onto a root that
// already holds chunks refuses.
func TestStoreDomainBinding(t *testing.T) {
	root := t.TempDir()
	a, err := Open(Config{Root: root, StoreDomain: "http://store-a"})
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := Open(Config{Root: root, StoreDomain: "http://store-b"}); err == nil {
		t.Fatal("different store domain accepted on a bound root")
	}
	again, err := Open(Config{Root: root, StoreDomain: "http://store-a"})
	if err != nil {
		t.Fatalf("same domain rejected: %v", err)
	}
	again.Close()
	// The persisted file must not contain the raw URL.
	raw, _ := os.ReadFile(filepath.Join(root, domainFileName))
	if strings.Contains(string(raw), "http://store-a") {
		t.Fatal("raw store URL persisted (must be a fingerprint only)")
	}

	fresh := t.TempDir()
	const N = 8
	start := make(chan struct{})
	wins := make(chan string, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		domain := "http://store-a"
		if i%2 == 1 {
			domain = "http://store-b"
		}
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			<-start
			m, err := Open(Config{Root: fresh, StoreDomain: domain})
			if err == nil {
				m.Close()
				wins <- domain
			}
		}(domain)
	}
	close(start)
	wg.Wait()
	close(wins)
	// Correct semantics: whichever domain won the O_EXCL create, ALL of
	// that domain's Opens succeed (they match the fingerprint) and ALL of
	// the OTHER domain's fail. No cross-domain leakage, no empty-file
	// races (the read retries until the fingerprint lands).
	var aWins, bWins int
	for w := range wins {
		if w == "http://store-a" {
			aWins++
		} else {
			bWins++
		}
	}
	if !((aWins == 4 && bWins == 0) || (aWins == 0 && bWins == 4)) {
		t.Fatalf("cross-domain leak: store-a wins=%d store-b wins=%d (want one domain's 4 all-win and the other 0)", aWins, bWins)
	}

	dirty := t.TempDir()
	d := digestOf([]byte("old provenance"))
	os.MkdirAll(filepath.Join(dirty, d[:2]), 0o755)
	os.WriteFile(filepath.Join(dirty, d[:2], d), []byte("old provenance"), 0o600)
	if _, err := Open(Config{Root: dirty, StoreDomain: "http://store-new"}); err == nil {
		t.Fatal("binding onto a root with existing chunks accepted")
	}

	// Corrupt/short markers must fail closed WITHOUT panicking.
	for _, content := range []string{"", "xy", strings.Repeat("z", 63), strings.Repeat("g", 65)} {
		corrupt := t.TempDir()
		os.WriteFile(filepath.Join(corrupt, domainFileName), []byte(content), 0o644)
		if _, err := Open(Config{Root: corrupt, StoreDomain: "http://store-a"}); err == nil {
			t.Fatalf("corrupt marker %q accepted", content)
		}
	}

	// Same-domain concurrent Opens: every one succeeds and every manager
	// closes cleanly.
	same := t.TempDir()
	var wg2 sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			m, err := Open(Config{Root: same, StoreDomain: "http://store-a"})
			if err != nil {
				errs <- err
				return
			}
			m.Close()
		}()
	}
	wg2.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("same-domain concurrent Open: %v", err)
	}
}

// countChunkEntries is fail-closed: an unreadable shard root surfaces as an
// Open error, not as "empty root" (which would adopt unknown bytes).
func TestCountChunkEntriesFailsClosed(t *testing.T) {
	root := t.TempDir()
	// A shard directory with mode 0000 makes ReadDir fail for it.
	shard := filepath.Join(root, "ab")
	if err := os.MkdirAll(shard, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(shard, 0o0000)
	defer os.Chmod(shard, 0o755) // cleanup even on failure
	if _, err := Open(Config{Root: root, StoreDomain: "http://store-x"}); err == nil {
		t.Fatal("Open succeeded despite an unreadable shard (fail-open)")
	} else if !strings.Contains(err.Error(), "cannot inspect root") {
		t.Fatalf("error is not the fail-closed inspection error: %v", err)
	}
}

// P1-A: a LIVE pin whose body carries anything but a strict 64-hex digest
// is corruption, and eviction must fail closed on it — never read the pin
// as "protects nothing" and delete unpinned chunks. (Red test for the old
// code, which silently skipped invalid lines and evicted anyway.)
func TestEvictionFailsClosedOnCorruptLivePin(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	m, err := Open(Config{Root: root, HighWatermark: 2 * chunkLen, LowWatermark: 1 * chunkLen, TouchEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	dA, bA := mk(1)
	dB, bB := mk(2)
	dC, bC := mk(3)
	// Hold a LIVE pin over A FIRST, then corrupt its body in place: flock
	// is advisory, so a direct append from this process goes through while
	// the exclusive holder keeps the pin "live". Every eviction pass — the
	// fetch-triggered background ones included — must now fail closed
	// before deleting anything.
	release, err := m.Pin("runtime-corrupt", []string{dA})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	pins, err := filepath.Glob(filepath.Join(root, pinsDir, "runtime-corrupt.*.pin"))
	if err != nil || len(pins) != 1 {
		t.Fatalf("pin files (%v, err %v)", pins, err)
	}
	pf, err := os.OpenFile(pins[0], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pf.WriteString("not-a-digest\n"); err != nil {
		pf.Close()
		t.Fatal(err)
	}
	pf.Close()
	mustFetch(t, m, dA, bA, nil)
	mustFetch(t, m, dB, bB, nil)
	mustFetch(t, m, dC, bC, nil) // 3 chunks > high 2: eviction runs and must fail
	// The capacity pass must return the corruption, not a quiet pass.
	if err := m.EvictIfNeeded(context.Background()); err == nil {
		t.Fatal("eviction accepted a corrupt live pin")
	} else if !strings.Contains(err.Error(), "corrupt pin") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fail-closed means NO deletes happened: everything survives.
	for _, d := range []string{dA, dB, dC} {
		if _, serr := os.Stat(m.chunkPath(d)); serr != nil {
			t.Fatalf("chunk %s deleted despite fail-closed: %v", d[:12], serr)
		}
	}
}

// P1-A: a pin entry that vanishes between listing and open is a benign
// race, not an error. A dangling symlink named *.pin deterministically
// produces ENOENT on open.
func TestProtectedSetToleratesVanishedPin(t *testing.T) {
	root := t.TempDir()
	m, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	if err := os.Symlink(filepath.Join(root, pinsDir, "never-existed.pin"),
		filepath.Join(root, pinsDir, "gone.123.1.pin")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.protectedSet(); err != nil {
		t.Fatalf("vanished pin treated as error: %v", err)
	}
}

// P1-B: a cancelled eviction pass is INCOMPLETE, not done — it must return
// context.Canceled, keep the not-yet-evicted chunks, and must not dress the
// remainder up as pinned overage in the status.
func TestEvictToLowCancelledReturnsCtxErr(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	// high above the working set so fetches never auto-trigger eviction;
	// evictToLow is exercised directly (it is the P1-B site).
	m, err := Open(Config{Root: root, HighWatermark: 10 * chunkLen, LowWatermark: 2 * chunkLen})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	mk := func(seed byte) (string, []byte) {
		body := make([]byte, chunkLen)
		for i := range body {
			body[i] = seed
		}
		return digestOf(body), body
	}
	var digests []string
	for i := byte(1); i <= 4; i++ {
		d, b := mk(i)
		digests = append(digests, d)
		mustFetch(t, m, d, b, nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The integration path surfaces the cancel (Rescan's ctx check) ...
	if err := m.EvictIfNeeded(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("EvictIfNeeded: want context.Canceled, got %v", err)
	}
	// ... and the eviction loop itself (in-package, under the same ctx)
	// must return the cancel instead of completing the pass.
	if err := m.evictToLow(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("evictToLow: want context.Canceled, got %v", err)
	}
	for _, d := range digests {
		if _, serr := os.Stat(m.chunkPath(d)); serr != nil {
			t.Fatalf("chunk %s deleted under a cancelled pass: %v", d[:12], serr)
		}
	}
	if st := m.Status(); st.PinnedOverageBytes != 0 {
		t.Fatalf("cancelled pass recorded pinned overage: %+v", st)
	}
}

// P1-C: Rescan fail-closed on shard-listing and stat errors — anything but
// a genuinely concurrent ENOENT must RETURN; a skipped shard would write an
// undercounted "trusted" status that watermark decisions then act on.
func TestRescanFailClosedOnReadErrors(t *testing.T) {
	root := t.TempDir()
	m, err := Open(Config{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}
	mustFetch(t, m, digestOf(body), body, nil)
	if err := m.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := m.Status().AllocatedBytes

	// Non-ENOENT shard listing error: returned, index untouched.
	origList := readShardEntries
	readShardEntries = func(string) ([]os.DirEntry, error) {
		return nil, fmt.Errorf("list shard: %w", fs.ErrPermission)
	}
	t.Cleanup(func() { readShardEntries = origList })
	err = m.Rescan(context.Background())
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("shard list error swallowed: %v", err)
	}
	if after := m.Status().AllocatedBytes; after != before {
		t.Fatalf("failed rescan changed accounting: %d -> %d", before, after)
	}

	// Genuinely concurrent shard disappearance: tolerated.
	readShardEntries = func(string) ([]os.DirEntry, error) {
		return nil, fs.ErrNotExist
	}
	if err := m.Rescan(context.Background()); err != nil {
		t.Fatalf("benign shard vanish treated as error: %v", err)
	}
	readShardEntries = origList

	// Non-ENOENT stat error on a data file: returned.
	origInfo := dirEntryInfo
	dirEntryInfo = func(os.DirEntry) (fs.FileInfo, error) {
		return nil, fmt.Errorf("stat entry: %w", fs.ErrPermission)
	}
	t.Cleanup(func() { dirEntryInfo = origInfo })
	err = m.Rescan(context.Background())
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("stat error swallowed: %v", err)
	}
	if after := m.Status().AllocatedBytes; after != before {
		t.Fatalf("failed rescan changed accounting: %d -> %d", before, after)
	}
}

// P1-A: the publish path's accounting stat is fail-closed per instance —
// a stat failure after a successful rename RETURNS the error and leaves
// the digest UNTRACKED (never indexed at allocated=0).
func TestPublishAccountingStatFailsClosed(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}
	d := digestOf(body)
	m.statAllocated = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	_, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) { return body, nil })
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("publish accounting failure swallowed: %v", err)
	}
	// The verified object exists on disk (publication itself succeeded);
	// only its accounting is untrusted.
	if _, serr := os.Stat(m.chunkPath(d)); serr != nil {
		t.Fatalf("published object missing: %v", serr)
	}
	if e, tracked := m.indexLookup(d); tracked {
		t.Fatalf("digest indexed despite accounting failure (allocated=%d)", e.allocated)
	}
}

// P1-3A: a verified warm read of an externally published, untracked
// object FAILS when its accounting stat fails — in EVERY configuration.
// The digest stays untracked, the index goes dirty, and the failure is
// observable in Status().LastEvictErr.
func TestAdoptAccountingStatFailsClosed(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	// Let the initial background scan finish FIRST, so the only adoption
	// path left for the externally-written file is the Fetch-time adopt.
	for i := 0; i < 500; i++ {
		if m.Status().IndexReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Status().IndexReady {
		t.Fatal("initial index scan never finished")
	}
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i & 0x7f)
	}
	d := digestOf(body)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(d)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(d), body, 0o600); err != nil {
		t.Fatal(err)
	}
	m.statAllocated = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if _, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		t.Fatal("miss called for a verified on-disk chunk")
		return nil, errors.New("unreachable")
	}); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("warm hit succeeded despite accounting failure: %v", err)
	}
	if e, tracked := m.indexLookup(d); tracked {
		t.Fatalf("digest indexed despite accounting failure (allocated=%d)", e.allocated)
	}
	m.mu.Lock()
	dirty := m.dirty
	m.mu.Unlock()
	if !dirty {
		t.Fatal("index not marked dirty after adopt accounting failure")
	}
	if st := m.Status(); st.LastEvictErr == "" {
		t.Fatal("adopt accounting failure not recorded in LastEvictErr")
	}
}

// P1-B: a non-ENOENT remove error during eviction propagates — accounting,
// objects and the status stay untouched; nothing is reported as a
// completed pass or as pinned overage.
func TestEvictRemoveErrorPropagates(t *testing.T) {
	root := t.TempDir()
	const chunkLen = int64(64 << 10)
	// high above the working set: no background pass interferes; the
	// eviction loop is exercised directly.
	m := open(t, root, 10*chunkLen, 2*chunkLen)
	var digests []string
	for i := byte(1); i <= 3; i++ {
		body := make([]byte, chunkLen)
		for j := range body {
			body[j] = i
		}
		d := digestOf(body)
		digests = append(digests, d)
		mustFetch(t, m, d, body, nil)
	}
	before := m.Status().AllocatedBytes
	m.removePath = func(string) error { return fmt.Errorf("unlink: %w", fs.ErrPermission) }
	err := m.evictToLow(context.Background())
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("remove failure swallowed: %v", err)
	}
	for _, d := range digests {
		if _, serr := os.Stat(m.chunkPath(d)); serr != nil {
			t.Fatalf("chunk %s deleted despite failed remove: %v", d[:12], serr)
		}
	}
	if after := m.Status().AllocatedBytes; after != before {
		t.Fatalf("accounting changed under failed eviction: %d -> %d", before, after)
	}
	if st := m.Status(); st.PinnedOverageBytes != 0 {
		t.Fatalf("failed eviction wrote pinned overage: %+v", st)
	}
}

// P1-3D: publish rename succeeded but accounting stat fails persistently —
// the FIRST Fetch errors, the SECOND Fetch also errors on the same
// untracked on-disk object WITHOUT re-running the miss callback (the
// "second request hits disk and succeeds" accounting bypass is closed),
// and after the stat recovers the THIRD read adopts properly with correct
// index accounting.
func TestFetchAccountingStatFailureFailsClosedAcrossRequests(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	// Let the initial background scan finish FIRST: a late scan would
	// legitimately adopt the renamed object (via real stat) and turn the
	// second request into a tracked hit, which is not what this test
	// exercises.
	for i := 0; i < 500; i++ {
		if m.Status().IndexReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Status().IndexReady {
		t.Fatal("initial index scan never finished")
	}
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}
	d := digestOf(body)
	statOK := true
	m.statAllocated = func(p string) (fs.FileInfo, error) {
		if statOK {
			return os.Stat(p)
		}
		return nil, fs.ErrPermission
	}
	var misses atomic.Int64
	statOK = false // accounting fails from the very first publish on
	// 1st: miss runs, rename lands, accounting fails -> error.
	_, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		misses.Add(1)
		return body, nil
	})
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("first fetch: want accounting error, got %v", err)
	}
	if misses.Load() != 1 {
		t.Fatalf("miss ran %d times", misses.Load())
	}
	if _, serr := os.Stat(m.chunkPath(d)); serr != nil {
		t.Fatalf("published object missing after failed accounting: %v", serr)
	}
	if e, tracked := m.indexLookup(d); tracked {
		t.Fatalf("indexed at allocated=%d despite failure", e.allocated)
	}
	if st := m.Status(); st.LastEvictErr == "" {
		t.Fatal("publish accounting failure not observable")
	}
	// 2nd: the disk hit reaches the same adoption gate and fails again —
	// no miss, no bypass.
	_, err = m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		misses.Add(1)
		return body, nil
	})
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("second fetch bypassed the accounting failure: %v", err)
	}
	if misses.Load() != 1 {
		t.Fatalf("miss re-ran on the accounting-failed object (%d)", misses.Load())
	}
	// 3rd: stat recovered -> adoption succeeds with correct accounting.
	statOK = true
	got, err := m.Fetch(context.Background(), d, int64(len(body)), func(context.Context) ([]byte, error) {
		t.Fatal("miss called for an on-disk verified object")
		return nil, errors.New("unreachable")
	})
	if err != nil {
		t.Fatalf("third fetch after recovery: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("third fetch served wrong bytes")
	}
	e, tracked := m.indexLookup(d)
	if !tracked || e.size != int64(len(body)) {
		t.Fatalf("adoption after recovery wrong: tracked=%v entry=%+v", tracked, e)
	}
	if want := allocatedBytes(m.chunkPath(d)); e.allocated != want {
		t.Fatalf("adopted allocated=%d, disk reports %d", e.allocated, want)
	}
}

// P1-3B: fetchLocked's post-lock double-check exit adopts a pre-existing
// untracked object; an injected stat failure fails that read too.
func TestFetchLockedDoubleCheckAdoptsPreexistingObject(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	for i := 0; i < 500; i++ {
		if m.Status().IndexReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Status().IndexReady {
		t.Fatal("initial index scan never finished")
	}
	noMiss := func(context.Context) ([]byte, error) {
		t.Fatal("miss called for an on-disk verified object")
		return nil, errors.New("unreachable")
	}
	// Success: untracked object on disk, lock uncontended.
	bodyA := make([]byte, 4096)
	for i := range bodyA {
		bodyA[i] = byte(0x5A ^ i)
	}
	dA := digestOf(bodyA)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(dA)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(dA), bodyA, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := m.fetchLocked(context.Background(), dA, int64(len(bodyA)), noMiss)
	if err != nil {
		t.Fatalf("double-check adopt: %v", err)
	}
	if !bytes.Equal(got, bodyA) {
		t.Fatal("double-check adopt served wrong bytes")
	}
	e, tracked := m.indexLookup(dA)
	if !tracked || e.allocated != allocatedBytes(m.chunkPath(dA)) {
		t.Fatalf("double-check adoption not accounted: tracked=%v entry=%+v", tracked, e)
	}
	// Failure injection on a second untracked object.
	bodyB := make([]byte, 4096)
	for i := range bodyB {
		bodyB[i] = byte(0xA5 ^ i)
	}
	dB := digestOf(bodyB)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(dB)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(dB), bodyB, 0o600); err != nil {
		t.Fatal(err)
	}
	m.statAllocated = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if _, err := m.fetchLocked(context.Background(), dB, int64(len(bodyB)), noMiss); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("double-check exit swallowed accounting failure: %v", err)
	}
	if _, tracked := m.indexLookup(dB); tracked {
		t.Fatal("double-check exit indexed despite accounting failure")
	}
}

// P1-3B: the flockBusy follower recheck adopts another process's
// publication as soon as the verified object is visible — bounded gate
// (the object exists before the follower starts), no sleep-based timing.
func TestFollowerRecheckAdoptsCrossProcessPublication(t *testing.T) {
	root := t.TempDir()
	m := open(t, root, 0, 0)
	for i := 0; i < 500; i++ {
		if m.Status().IndexReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Status().IndexReady {
		t.Fatal("initial index scan never finished")
	}
	noMiss := func(context.Context) ([]byte, error) {
		t.Fatal("miss called while a verified object was on disk")
		return nil, errors.New("unreachable")
	}
	runFollower := func(d string, length int64) error {
		// Hold the digest lock like a foreign leader process.
		lk, err := os.OpenFile(m.lockPath(d), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, ferr := m.fetchLocked(context.Background(), d, length, noMiss)
			done <- ferr
		}()
		// The follower is now in the busy branch; its recheck observes the
		// (already published) object and adopts without the lock.
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			_ = syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)
			lk.Close()
			t.Fatal("follower never adopted the published object")
			return nil
		}
	}
	bodyA := make([]byte, 4096)
	for i := range bodyA {
		bodyA[i] = byte(0x33 ^ i)
	}
	dA := digestOf(bodyA)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(dA)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(dA), bodyA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runFollower(dA, int64(len(bodyA))); err != nil {
		t.Fatalf("follower adopt: %v", err)
	}
	if e, tracked := m.indexLookup(dA); !tracked || e.allocated != allocatedBytes(m.chunkPath(dA)) {
		t.Fatalf("follower adoption not accounted: tracked=%v entry=%+v", tracked, e)
	}

	bodyB := make([]byte, 4096)
	for i := range bodyB {
		bodyB[i] = byte(0x66 ^ i)
	}
	dB := digestOf(bodyB)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(dB)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(dB), bodyB, 0o600); err != nil {
		t.Fatal(err)
	}
	m.statAllocated = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if err := runFollower(dB, int64(len(bodyB))); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("follower recheck swallowed accounting failure: %v", err)
	}
	if _, tracked := m.indexLookup(dB); tracked {
		t.Fatal("follower recheck indexed despite accounting failure")
	}
}

// P1-3C: with watermarks armed, adoption SUCCESS wakes the capacity worker
// (the authoritative pass evicts the oldest entry down to low — asserted
// by bounded polling on the outcome, not on internals), and adoption
// FAILURE is synchronously observable (LastEvictErr + dirty).
func TestAdoptionWakesCapacityWorker(t *testing.T) {
	const chunkLen = int64(64 << 10)
	root := t.TempDir()
	// high just under 2 chunks, low = 1 chunk: adopting the second chunk
	// pushes usage STRICTLY above high (an exact 2-chunk high would not
	// trigger — the pass evicts only above high).
	m := open(t, root, 2*chunkLen-512, chunkLen)
	for i := 0; i < 500; i++ {
		if m.Status().IndexReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Status().IndexReady {
		t.Fatal("initial index scan never finished")
	}
	body1 := make([]byte, chunkLen)
	for i := range body1 {
		body1[i] = 0x11
	}
	d1 := digestOf(body1)
	mustFetch(t, m, d1, body1, nil) // tracked, usage = 1 chunk <= high
	body2 := make([]byte, chunkLen)
	for i := range body2 {
		body2[i] = 0x22
	}
	d2 := digestOf(body2)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(d2)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(d2), body2, 0o600); err != nil {
		t.Fatal(err)
	}
	// Warm hit on the untracked object: adoption succeeds, wakes the
	// worker, and the node-wide pass evicts the OLDEST (d1) down to low.
	if _, err := m.Fetch(context.Background(), d2, chunkLen, func(context.Context) ([]byte, error) {
		t.Fatal("miss called for an on-disk verified object")
		return nil, errors.New("unreachable")
	}); err != nil {
		t.Fatalf("adoption fetch: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, gone := os.Stat(m.chunkPath(d1))
		_, kept := os.Stat(m.chunkPath(d2))
		if os.IsNotExist(gone) && kept == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("adoption did not wake the capacity worker: d1-present=%v d2-present=%v status=%+v", !os.IsNotExist(gone), kept == nil, m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// FAILURE leg: an untracked object whose stat fails errors the read,
	// records LastEvictErr and leaves the index dirty — synchronously.
	body3 := make([]byte, chunkLen)
	for i := range body3 {
		body3[i] = 0x33
	}
	d3 := digestOf(body3)
	if err := os.MkdirAll(filepath.Dir(m.chunkPath(d3)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.chunkPath(d3), body3, 0o600); err != nil {
		t.Fatal(err)
	}
	m.statAllocated = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if _, err := m.Fetch(context.Background(), d3, chunkLen, func(context.Context) ([]byte, error) {
		t.Fatal("miss called for an on-disk verified object")
		return nil, errors.New("unreachable")
	}); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("armed adoption failure swallowed: %v", err)
	}
	if st := m.Status(); st.LastEvictErr == "" {
		t.Fatal("armed adoption failure not recorded")
	}
	// The dirty flag itself is TRANSIENT by design: the same failure wakes
	// the capacity worker, whose pass clears it — asserting it after the
	// fact would race that pass. LastEvictErr above is the stable
	// observable.
}
