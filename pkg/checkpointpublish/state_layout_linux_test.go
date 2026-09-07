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

package checkpointpublish

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
	"golang.org/x/sys/unix"
)

func TestStateLayoutIdempotenceAndPublication(t *testing.T) {
	root, base := t.TempDir(), t.TempDir()
	layout, err := InitStateLayout(context.Background(), root, base)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(layout.Link)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	again, err := InitStateLayout(context.Background(), alias, base)
	if err != nil || *again != *layout {
		t.Fatalf("alias retry: %+v %v", again, err)
	}
	after, _ := os.Lstat(layout.Link)
	if !os.SameFile(before, after) {
		t.Fatal("retry replaced link inode")
	}
	source := fixtureCheckpoint(t)
	dir := filepath.Join(root, ".layout-owner")
	if err := os.Rename(source, dir); err != nil {
		t.Fatal(err)
	}
	local, err := chunkstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := acquirePublishClaim(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	// Canonical aliases must still find the same physical publish lock.
	if _, err := Run(context.Background(), filepath.Join(alias, ".layout-owner"), "test", local, "local"); !errors.Is(err, ErrPublishBusy) {
		claim.Close()
		t.Fatalf("claim bypass: %v", err)
	}
	claimInfo, _ := os.Stat(StatePath(dir) + ".lock")
	claim.Close()
	if _, err := Run(context.Background(), dir, "test", local, "local"); err != nil {
		t.Fatal(err)
	}
	state, err := Status(filepath.Join(alias, ".layout-owner"))
	if err != nil || state == nil || state.State != StatePublished {
		t.Fatalf("status: %+v %v", state, err)
	}
	physical := filepath.Join(layout.StateDirectory, ".layout-owner.json")
	one, err := os.Stat(physical)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := os.Stat(StatePath(dir))
	if !os.SameFile(one, two) {
		t.Fatal("state path diverged")
	}
	if _, err := InitStateLayout(context.Background(), root, base); err != nil {
		t.Fatal(err)
	}
	after, _ = os.Stat(StatePath(dir) + ".lock")
	if !os.SameFile(claimInfo, after) {
		t.Fatal("layout retry replaced publish lock")
	}
	// A missing root link must not expose pre-existing states automatically.
	if err := os.Remove(layout.Link); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(physical)
	if _, err := InitStateLayout(context.Background(), root, base); err == nil {
		t.Fatal("re-adopted states after root link disappeared")
	}
	current, _ := os.ReadFile(physical)
	if string(current) != string(saved) {
		t.Fatal("state changed after rejected adoption")
	}
}

func TestStateLayoutPreservesExistingAndRejectsConflicts(t *testing.T) {
	for _, kind := range []string{"empty-directory", "populated-directory", "different-link", "dangling-link"} {
		t.Run(kind, func(t *testing.T) {
			root, base := t.TempDir(), t.TempDir()
			link := filepath.Join(root, StateDirName)
			switch kind {
			case "empty-directory", "populated-directory":
				if err := os.Mkdir(link, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "populated-directory" {
					if err := os.WriteFile(filepath.Join(link, "sentinel"), []byte("preserve"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "different-link":
				if err := os.Symlink(t.TempDir(), link); err != nil {
					t.Fatal(err)
				}
			case "dangling-link":
				if err := os.Symlink(filepath.Join(base, "missing"), link); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(link)
			if _, err := InitStateLayout(context.Background(), root, base); err == nil {
				t.Fatal("accepted existing layout")
			}
			after, _ := os.Lstat(link)
			if !os.SameFile(before, after) {
				t.Fatal("existing entry changed")
			}
			if kind == "populated-directory" {
				b, err := os.ReadFile(filepath.Join(link, "sentinel"))
				if err != nil || string(b) != "preserve" {
					t.Fatal("existing state lost")
				}
			}
		})
	}
	root, base := t.TempDir(), t.TempDir()
	a, err := InitStateLayout(context.Background(), root, base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := InitStateLayout(context.Background(), t.TempDir(), base)
	if err != nil || a.StateDirectory == b.StateDirectory {
		t.Fatalf("root namespaces collide: %v", err)
	}
	if _, err := InitStateLayout(context.Background(), root, t.TempDir()); err == nil {
		t.Fatal("retargeted existing layout")
	}
	if _, err := InitStateLayout(context.Background(), root, root); err == nil {
		t.Fatal("allowed state base inside root")
	}
}

func TestStateLayoutPreparedRetryAndOwnerValidation(t *testing.T) {
	root, base := t.TempDir(), t.TempDir()
	layout, err := InitStateLayout(context.Background(), root, base)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the owned target was committed, before linking it.
	if err := os.Remove(layout.Link); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(base, ".state-layout-orphan")
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStateLayout(context.Background(), root, base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("removed an unrelated preparation directory")
	}
	ownerPath := filepath.Join(layout.StateDirectory, stateLayoutOwnerName)
	good, _ := os.ReadFile(ownerPath)
	for _, bad := range []string{"{", `{"version":1,"root":"/wrong"}`, `{"version":9}`} {
		if err := os.WriteFile(ownerPath, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := InitStateLayout(context.Background(), root, base); err == nil {
			t.Fatal("accepted corrupt owner")
		}
	}
	if err := os.Remove(ownerPath); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStateLayout(context.Background(), root, base); err == nil {
		t.Fatal("recreated missing owner")
	}
	if err := os.WriteFile(ownerPath, good, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStateLayout(context.Background(), root, base); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fresh := t.TempDir()
	if _, err := InitStateLayout(ctx, fresh, base); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	entries, _ := os.ReadDir(fresh)
	if len(entries) != 0 {
		t.Fatal("cancelled init changed root")
	}
}

func TestStateLayoutConcurrentInitialization(t *testing.T) {
	root, base := t.TempDir(), t.TempDir()
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := InitStateLayout(context.Background(), root, base); results <- err }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrStateLayoutBusy) {
			t.Fatal(err)
		}
	}
	if successes == 0 {
		t.Fatal("no initializer succeeded")
	}
	if _, err := InitStateLayout(context.Background(), root, base); err != nil {
		t.Fatal(err)
	}
}

func TestStateLayoutInitLockDeath(t *testing.T) {
	if path := os.Getenv("CN_LAYOUT_LOCK_CHILD"); path != "" {
		file, err := os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			os.Exit(3)
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
			os.Exit(4)
		}
		os.Stdout.WriteString("locked\n")
		time.Sleep(30 * time.Second)
		return
	}
	root, base := t.TempDir(), t.TempDir()
	layout, err := InitStateLayout(context.Background(), root, base)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := layout.StateDirectory + ".init.lock"
	before, _ := os.Stat(lockPath)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestStateLayoutInitLockDeath$")
	cmd.Env = append(os.Environ(), "CN_LAYOUT_LOCK_CHILD="+lockPath)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	})
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("child handshake: %q %v", line, err)
	}
	if _, err := InitStateLayout(context.Background(), root, base); !errors.Is(err, ErrStateLayoutBusy) {
		t.Fatalf("lock bypass: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child unexpectedly exited successfully")
	}
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("child was not killed by test")
	}
	if _, err := InitStateLayout(context.Background(), root, base); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(lockPath)
	if !os.SameFile(before, after) {
		t.Fatal("replaced initialization lock inode")
	}
}

func TestStateLayoutExternalMaterialize(t *testing.T) {
	source, store := stagingFixtureStore(t)
	root := t.TempDir()
	base, err := os.MkdirTemp("/dev/shm", "cn-state-layout-")
	if err != nil {
		t.Skipf("second FS unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	a, _ := os.Stat(root)
	b, _ := os.Stat(base)
	if a.Sys().(*syscall.Stat_t).Dev == b.Sys().(*syscall.Stat_t).Dev {
		t.Skip("second FS unavailable")
	}
	t.Logf("root device=%d state device=%d", a.Sys().(*syscall.Stat_t).Dev, b.Sys().(*syscall.Stat_t).Dev)
	layout, err := InitStateLayout(context.Background(), root, base)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "restored")
	if err := Materialize(context.Background(), target, filepath.Base(source), store); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, MaterializedMarker)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(layout.StateDirectory)
	if err != nil || len(entries) != 1 || entries[0].Name() != stateLayoutOwnerName {
		t.Fatalf("materialize wrote into state directory: %v %v", entries, err)
	}
}

func TestStateLayoutCompetingBases(t *testing.T) {
	root := t.TempDir()
	bases := []string{t.TempDir(), t.TempDir()}
	type result struct {
		layout *StateLayout
		err    error
	}
	start := make(chan struct{})
	done := make(chan result, 2)
	for _, base := range bases {
		go func(base string) {
			<-start
			l, e := InitStateLayout(context.Background(), root, base)
			done <- result{l, e}
		}(base)
	}
	close(start)
	var winner *StateLayout
	successes := 0
	for i := 0; i < 2; i++ {
		r := <-done
		if r.err == nil {
			winner = r.layout
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("got %d winning state bases", successes)
	}
	link, err := filepath.EvalSymlinks(filepath.Join(root, StateDirName))
	if err != nil || link != winner.StateDirectory {
		t.Fatalf("wrong winning link: %s %v", link, err)
	}
}

func TestStateLayoutPreparationDoesNotReplaceTarget(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "occupied")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(target)
	if err := prepareStateLayoutTarget(base, target, stateLayoutOwner{Version: 1, Root: "/test"}); err == nil {
		t.Fatal("replaced an existing target")
	}
	after, _ := os.Stat(target)
	if !os.SameFile(before, after) {
		t.Fatal("target inode changed")
	}
	entries, _ := os.ReadDir(base)
	if len(entries) != 1 || entries[0].Name() != "occupied" {
		t.Fatalf("preparation leaked: %v", entries)
	}
}
