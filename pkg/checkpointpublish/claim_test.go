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
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/chunkstore"
)

type claimGateStore struct {
	*chunkstore.Local
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (s *claimGateStore) Has(ctx context.Context, digest string) (bool, error) {
	s.calls.Add(1)
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
		return s.Local.Has(ctx, digest)
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func TestPublishClaimRejectsOverlapWithoutStateOrRequests(t *testing.T) {
	dir := fixtureCheckpoint(t)
	local, err := chunkstore.NewLocal(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &claimGateStore{Local: local, entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := RunWithOptions(ctx, dir, "owner", gate, "test", Options{Workers: 1}); done <- err }()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("owner never reached store")
	}
	before, err := os.ReadFile(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, alias} {
		_, err := Run(ctx, path, "contender", gate, "test")
		if !errors.Is(err, ErrPublishBusy) {
			t.Fatalf("overlap error=%v calls=%d", err, gate.calls.Load())
		}
	}
	after, err := os.ReadFile(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || !os.SameFile(st, current) || gate.calls.Load() != 1 {
		t.Fatal("contender changed state or issued requests")
	}
	// An unrelated checkpoint must remain publishable while the first is blocked.
	other := fixtureCheckpoint(t)
	if _, err := Run(ctx, other, "independent", local, "test"); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, dir, "retry", local, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestPublishClaimReleasedAfterProcessDeath(t *testing.T) {
	const childKey = "CN_PUBLISH_CLAIM_TEST_CHILD"
	if dir := os.Getenv(childKey); dir != "" {
		claim, err := acquirePublishClaim(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		defer claim.Close()
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("held"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublishClaimReleasedAfterProcessDeath$", "-test.count=1")
	cmd.Env = append(os.Environ(), childKey+"="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("child not ready")
		case <-tick.C:
		}
	}
	lockPath := StatePath(dir) + ".lock"
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if claim, err := acquirePublishClaim(context.Background(), dir); !errors.Is(err, ErrPublishBusy) {
		if claim != nil {
			claim.Close()
		}
		t.Fatalf("live child claim=%v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed child returned success")
	}
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected child exit: %v", cmd.ProcessState)
	}
	claim, err := acquirePublishClaim(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Close()
	after, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("lock inode replaced after owner death")
	}
}

func TestCanceledPublishDoesNotCreateClaimState(t *testing.T) {
	dir := fixtureCheckpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, dir, "canceled", nil, "test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(StatePath(dir))); !os.IsNotExist(err) {
		t.Fatalf("canceled request created metadata: %v", err)
	}
}
