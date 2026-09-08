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

package cgroupmanager

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewCgroupOpsSelectsDetectedMode(t *testing.T) {
	original := detectCgroupMode
	t.Cleanup(func() { detectCgroupMode = original })

	for _, test := range []struct {
		mode    cgroups.CGMode
		version int
		wantErr bool
	}{
		{mode: cgroups.Legacy, version: 1},
		{mode: cgroups.Hybrid, version: 1},
		{mode: cgroups.Unified, version: 2},
		{mode: cgroups.Unavailable, wantErr: true},
	} {
		detectCgroupMode = func() cgroups.CGMode { return test.mode }
		ops, err := newCgroupOps(0)
		if test.wantErr {
			assert.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, test.version, cgroupVersion(ops.mode()))
		assert.Equal(t, test.mode, ops.mode())
	}
}

func TestReadV2PidsCurrent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	value, tracked, err := readV2PidsCurrent(missing)
	require.NoError(t, err)
	assert.Zero(t, value)
	assert.False(t, tracked)

	filename := filepath.Join(t.TempDir(), "pids.current")
	require.NoError(t, os.WriteFile(filename, []byte("17\n"), 0644))
	value, tracked, err = readV2PidsCurrent(filename)
	require.NoError(t, err)
	assert.Equal(t, uint64(17), value)
	assert.True(t, tracked)

	require.NoError(t, os.WriteFile(filename, []byte("invalid\n"), 0644))
	_, tracked, err = readV2PidsCurrent(filename)
	assert.Error(t, err)
	assert.True(t, tracked)

	require.NoError(t, os.WriteFile(filename, []byte(strconv.FormatUint(^uint64(0), 10)), 0644))
	value, tracked, err = readV2PidsCurrent(filename)
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), value)
	assert.True(t, tracked)
}

func TestCgroupV2KillRejectsZeroPID(t *testing.T) {
	const helperEnv = "SANDBOXD_TEST_ZERO_PID_HELPER"
	if os.Getenv(helperEnv) != "1" {
		// The old implementation calls kill(0, SIGKILL). Run it only in a
		// dedicated process group so a regression cannot kill the test runner.
		cmd := exec.Command(os.Args[0], "-test.run=^TestCgroupV2KillRejectsZeroPID$")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "isolated cleanup helper failed: %s", output)
		return
	}
	group, err := syscall.Getpgid(0)
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), group, "unsafe to run outside an isolated process group")
	mountpoint := t.TempDir()
	name := "/sandbox/zero-pid"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(groupPath, "cgroup.procs"), []byte("0\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(groupPath, "pids.current"), []byte("1\n"), 0644))
	ops := &cgroupV2{mountpoint: mountpoint}
	require.ErrorContains(t, ops.kill(name), "unsafe cgroup PID")
}

func TestValidateCgroupProcessesRejectsUnsafePIDs(t *testing.T) {
	// Only validate here: a regression must not signal the test runner.
	for _, pid := range []uint64{1, uint64(os.Getpid()), math.MaxInt32 + 1, math.MaxUint64} {
		require.ErrorContains(t, validateCgroupProcesses([]uint64{pid}), "unsafe cgroup PID", "pid=%d", pid)
	}
}

func TestCgroupV2KillUsesExplicitSignals(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/test"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))

	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	drained := make(chan error, 1)
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	procsPath := filepath.Join(groupPath, "cgroup.procs")
	pidsCurrentPath := filepath.Join(groupPath, "pids.current")
	killPath := filepath.Join(groupPath, "cgroup.kill")
	require.NoError(t, os.WriteFile(
		procsPath,
		[]byte(strconv.Itoa(cmd.Process.Pid)),
		0644,
	))
	require.NoError(t, os.WriteFile(pidsCurrentPath, []byte("1\n"), 0644))
	require.NoError(t, os.WriteFile(killPath, []byte("untouched\n"), 0644))

	go func() {
		_ = cmd.Wait()
		err := os.WriteFile(procsPath, nil, 0644)
		// Real cgroup counters are read atomically. Replacing the fixture
		// avoids a truncate/write window that can expose an empty counter.
		pidsErr := os.WriteFile(pidsCurrentPath+".next", []byte("0\n"), 0644)
		if pidsErr == nil {
			pidsErr = os.Rename(pidsCurrentPath+".next", pidsCurrentPath)
		}
		if err == nil {
			err = pidsErr
		}
		drained <- err
	}()

	ops := &cgroupV2{mountpoint: mountpoint}
	require.NoError(t, ops.kill(name))
	require.NoError(t, <-drained)
	data, err := os.ReadFile(killPath)
	require.NoError(t, err)
	assert.Equal(t, "untouched\n", string(data))
}

func TestCgroupV2ExplicitKillDoesNotPoisonReusedGroup(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_CGROUP_INTEGRATION") != "1" {
		t.Skip("set SANDBOXD_RUN_CGROUP_INTEGRATION=1 to run")
	}
	if detectCgroupMode() != cgroups.Unified {
		t.Skip("requires cgroup v2")
	}

	ops := &cgroupV2{mountpoint: cgroupMountpoint}
	name := "/sandboxd-explicit-kill-test-" + strconv.Itoa(os.Getpid())
	require.NoError(t, ops.create(name, &specs.LinuxResources{}))
	t.Cleanup(func() {
		_ = ops.kill(name)
		_ = ops.delete(name)
	})

	groupFD, err := unix.Open(
		filepath.Join(cgroupMountpoint, name),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(groupFD) })

	sleeper := exec.Command("sleep", "30")
	sleeper.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    groupFD,
	}
	require.NoError(t, sleeper.Start())
	waited := make(chan error, 1)
	go func() { waited <- sleeper.Wait() }()

	require.NoError(t, ops.kill(name))
	waitErr := <-waited
	var exitErr *exec.ExitError
	require.ErrorAs(t, waitErr, &exitErr)
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	assert.Equal(t, syscall.SIGKILL, status.Signal())

	next := exec.Command("true")
	next.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    groupFD,
	}
	require.NoError(t, next.Run(), "reused cgroup killed the next process")
}

func TestSandboxResourcesConvertCoreControls(t *testing.T) {
	resource := &runtime.LinuxSandboxResources{
		CpuShares:          1024,
		CpuQuota:           50000,
		CpuPeriod:          100000,
		CpusetCpus:         "0-1",
		CpusetMems:         "0",
		MemoryLimitInBytes: 256 << 20,
	}
	linux := sandboxResources(resource)
	require.NotNil(t, linux.CPU)
	require.NotNil(t, linux.Memory)
	assert.Equal(t, resource.CpuShares, *linux.CPU.Shares)
	assert.Equal(t, resource.CpuQuota, *linux.CPU.Quota)
	assert.Equal(t, resource.CpuPeriod, *linux.CPU.Period)
	assert.Empty(t, linux.CPU.Cpus)
	assert.Empty(t, linux.CPU.Mems)
	assert.Equal(t, resource.MemoryLimitInBytes, *linux.Memory.Limit)

	v2 := cgroup2.ToResources(linux)
	require.NotNil(t, v2.CPU)
	require.NotNil(t, v2.CPU.Weight)
	assert.Equal(t, uint64(1+((1024-2)*9999)/262142), *v2.CPU.Weight)
	assert.Equal(t, "50000 100000", string(v2.CPU.Max))
	require.NotNil(t, v2.Memory)
	assert.Equal(t, resource.MemoryLimitInBytes, *v2.Memory.Max)
}

type fakeCgroupOps struct {
	calls            []string
	stats            Stats
	createdResources *specs.LinuxResources
	oom              *fakeOOMWatcher
	killErr          error
}

func (f *fakeCgroupOps) mode() cgroups.CGMode { return cgroups.Unified }
func (f *fakeCgroupOps) prepareRoot(string, int64) error {
	f.calls = append(f.calls, "prepare-root")
	return nil
}
func (f *fakeCgroupOps) list(string) ([]string, error) { return nil, nil }
func (f *fakeCgroupOps) create(_ string, resources *specs.LinuxResources) error {
	f.calls = append(f.calls, "create")
	f.createdResources = resources
	return nil
}
func (f *fakeCgroupOps) reset(string) error {
	f.calls = append(f.calls, "reset")
	return nil
}
func (f *fakeCgroupOps) setPidsLimit(string, int64) error {
	f.calls = append(f.calls, "pids")
	return nil
}
func (f *fakeCgroupOps) update(string, *specs.LinuxResources) error {
	f.calls = append(f.calls, "update")
	return nil
}
func (f *fakeCgroupOps) stat(string) (Stats, error) { return f.stats, nil }
func (f *fakeCgroupOps) readFreeze(string) (FreezeState, error) {
	f.calls = append(f.calls, "read-freeze")
	return FreezeState{}, nil
}
func (f *fakeCgroupOps) writeFreeze(string, bool) error {
	f.calls = append(f.calls, "write-freeze")
	return nil
}
func (f *fakeCgroupOps) writeMemoryLimits(string, uint64, uint64) error {
	f.calls = append(f.calls, "write-memory")
	return nil
}
func (f *fakeCgroupOps) identity(string) (CgroupIdentity, error) {
	return CgroupIdentity{Inode: 1, Device: 2}, nil
}
func (f *fakeCgroupOps) newOOMWatcher() (oomWatcher, error) {
	if f.oom == nil {
		f.oom = newFakeOOMWatcher()
	}
	return f.oom, nil
}
func (f *fakeCgroupOps) kill(string) error {
	f.calls = append(f.calls, "kill")
	return f.killErr
}
func (f *fakeCgroupOps) delete(string) error {
	f.calls = append(f.calls, "delete")
	return nil
}

type fakeOOMWatcher struct {
	mu       sync.Mutex
	flags    map[string]bool
	calls    []string
	closed   bool
	resetErr error
}

func newFakeOOMWatcher() *fakeOOMWatcher {
	return &fakeOOMWatcher{flags: make(map[string]bool)}
}

func (w *fakeOOMWatcher) Add(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "add:"+name)
	w.flags[name] = false
	return nil
}

func (w *fakeOOMWatcher) Remove(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "remove:"+name)
	delete(w.flags, name)
}

func (w *fakeOOMWatcher) Reset(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, "reset:"+name)
	if w.resetErr != nil {
		return w.resetErr
	}
	if _, ok := w.flags[name]; !ok {
		return errors.New("not registered")
	}
	w.flags[name] = false
	return nil
}

func (w *fakeOOMWatcher) OOMKilled(name string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	flag, ok := w.flags[name]
	if !ok {
		return false, errors.New("not registered")
	}
	return flag, nil
}

func (w *fakeOOMWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *fakeOOMWatcher) trigger(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flags[name] = true
}

func TestPrepareOnlyAppliesLeaseResources(t *testing.T) {
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	name := "/sandbox/lease"
	manager := &CgroupManager{
		rootName: "/sandbox",
		pidsMax:  64,
		usingID:  cmap.New[struct{}](),
		idleID:   util.New[string](""),
		cgroups:  cmap.New[struct{}](),
		ops:      ops,
		oom:      oom,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Prepare(name, &runtime.LinuxSandboxResources{
		CpuShares:          512,
		MemoryLimitInBytes: 128 << 20,
	}))
	assert.Equal(t, []string{"update"}, ops.calls)
	killed, err := manager.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed)
	oom.trigger(name)
	killed, err = manager.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)
}

func TestRecycleOnlyReturnsActiveOwnedCgroups(t *testing.T) {
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 1,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	name := "/sandbox/lease"
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle("/sandbox/not-active"))
	assert.Empty(t, manager.idleID.List())

	require.NoError(t, manager.Recycle(name))
	assert.Equal(t, []string{name}, manager.idleID.List())
	assert.Equal(t, []string{"kill", "reset"}, ops.calls)
	assert.Equal(t, []string{"add:" + name, "reset:" + name}, oom.calls)

	require.NoError(t, manager.Recycle(name))
	assert.Equal(t, []string{name}, manager.idleID.List(), "duplicate recycle must not duplicate a cache entry")
}

func TestRecycleDestroysCgroupWhenCleanupFails(t *testing.T) {
	name := "/sandbox/lease"
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom, killErr: assert.AnError}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 1,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle(name))
	assert.Empty(t, manager.idleID.List())
	assert.False(t, manager.cgroups.Has(name))
	assert.Equal(t, []string{name}, manager.gcQueue.List())
	assert.Zero(t, manager.total)
	assert.Equal(t, []string{"kill"}, ops.calls)
	assert.Equal(t, []string{"add:" + name, "remove:" + name}, oom.calls)
}

func TestRecycleDestroysCleanCgroupWhenCacheIsFull(t *testing.T) {
	name := "/sandbox/lease"
	oom := newFakeOOMWatcher()
	ops := &fakeCgroupOps{oom: oom}
	manager := &CgroupManager{
		rootName:  "/sandbox",
		cacheSize: 0,
		usingID:   cmap.New[struct{}](),
		idleID:    util.New[string](""),
		cgroups:   cmap.New[struct{}](),
		gcQueue:   util.New[string](""),
		gcWake:    make(chan struct{}, 1),
		ops:       ops,
		oom:       oom,
		total:     1,
	}
	manager.cgroups.Set(name, struct{}{})
	manager.usingID.Set(name, struct{}{})
	require.NoError(t, oom.Add(name))

	require.NoError(t, manager.Recycle(name))
	assert.Empty(t, manager.idleID.List())
	assert.Equal(t, []string{name}, manager.gcQueue.List())
	assert.Zero(t, manager.total)
	assert.Equal(t, []string{"kill", "reset"}, ops.calls)
	assert.Equal(
		t,
		[]string{"add:" + name, "reset:" + name, "remove:" + name},
		oom.calls,
	)
}

func TestDoCreateCarriesPidsLimitIntoOps(t *testing.T) {
	ops := &fakeCgroupOps{}
	oom := newFakeOOMWatcher()
	manager := &CgroupManager{
		pidsMax:   4096,
		cgroups:   cmap.New[struct{}](),
		generator: util.NewFixedLengthIDGenerator(12, nil, util.PrefixID("/sandbox/")),
		ops:       ops,
		oom:       oom,
	}

	id, err := manager.doCreate()
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Equal(t, []string{"create"}, ops.calls)
	assert.Contains(t, oom.calls, "add:"+id)
	if assert.NotNil(t, ops.createdResources) &&
		assert.NotNil(t, ops.createdResources.Pids) {
		assert.Equal(t, int64(4096), ops.createdResources.Pids.Limit)
	}
}

func TestCgroupResourcesDefaultsToUnlimitedPids(t *testing.T) {
	assert.Nil(t, (&CgroupManager{}).cgroupResources().Pids)
}

func TestV2ResetAndStats(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))

	writeTestFile(t, filepath.Join(groupPath, "cpu.weight"), "39")
	writeTestFile(t, filepath.Join(groupPath, "cpu.max"), "50000 100000")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "268435456")
	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "241591910")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.max"), "268435456")
	writeTestFile(t, filepath.Join(groupPath, "pids.max"), "1024")
	writeTestFile(t, filepath.Join(groupPath, "cpuset.cpus"), "0")
	writeTestFile(t, filepath.Join(groupPath, "cpuset.mems"), "0")

	ops := &cgroupV2{mountpoint: mountpoint}
	require.NoError(t, ops.reset(name))
	assertFileContents(t, filepath.Join(groupPath, "cpu.weight"), "100")
	assertFileContents(t, filepath.Join(groupPath, "cpu.max"), "max 100000")
	assertFileContents(t, filepath.Join(groupPath, "memory.max"), "max")
	assertFileContents(t, filepath.Join(groupPath, "memory.high"), "max")
	assertFileContents(t, filepath.Join(groupPath, "memory.swap.max"), "268435456")
	assertFileContents(t, filepath.Join(groupPath, "pids.max"), "1024")
	assertFileContents(t, filepath.Join(groupPath, "cpuset.cpus"), "0")
	assertFileContents(t, filepath.Join(groupPath, "cpuset.mems"), "0")

	writeTestFile(t, filepath.Join(groupPath, "cgroup.controllers"), "cpu memory")
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 123\nuser_usec 80\nsystem_usec 43\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.stat"), "anon 100\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.current"), "4096")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "8192")
	writeTestFile(t, filepath.Join(groupPath, "memory.peak"), "6144")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.current"), "0")
	writeTestFile(t, filepath.Join(groupPath, "memory.swap.max"), "max")
	writeTestFile(t, filepath.Join(groupPath, "memory.events"), "oom_kill 0\n")

	stats, err := ops.stat(name)
	require.NoError(t, err)
	assert.Equal(t, uint64(123000), stats.CPUUsageNanos)
	assert.Equal(t, uint64(80000), stats.CPUUserNanos)
	assert.Equal(t, uint64(43000), stats.CPUKernelNanos)
	assert.Equal(t, uint64(4096), stats.MemoryUsageBytes)
	assert.Equal(t, uint64(8192), stats.MemoryLimitBytes)
	assert.Equal(t, uint64(6144), stats.MemoryMaxUsageBytes)
	assert.True(t, stats.CPUUsageKnown)
	assert.True(t, stats.MemoryUsageKnown)
	assert.True(t, stats.MemoryLimitKnown)
	assert.True(t, stats.MemoryPeakKnown)
	assert.True(t, stats.CPULimitsKnown)
	assert.Equal(t, int64(-1), stats.CPUQuotaUsec)
	assert.Equal(t, uint64(100000), stats.CPUPeriodUsec)
	// The v2 backend names the absolute directory it read.
	assert.Equal(t, groupPath, stats.MemoryCgroupPath)
	writeTestFile(t, filepath.Join(groupPath, "cpu.max"), "50000 100000")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	assert.True(t, stats.CPULimitsKnown)
	assert.Equal(t, int64(50000), stats.CPUQuotaUsec)
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 123\nuser_usec 80\nsystem_usec 43\nnr_periods 9\nnr_throttled 2\nthrottled_usec 7\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.events"), "high 5\noom 1\noom_kill 1\n")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.True(t, stats.CPUPressureKnown)
	require.Equal(t, uint64(7000), stats.CPUThrottledNanos)
	require.True(t, stats.MemoryPressureKnown)
	require.Equal(t, uint64(5), stats.MemoryHighEvents)

}

// memory.high and the frozen state ride the same strict reads as the other
// counters, with "max" as the known-unlimited sentinel. The fixture carries
// the full shape containerd's stat walks, so the reads under test are the
// real ones.
func TestV2StatReadsMemoryHighAndFrozenState(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	for _, filename := range []string{
		"cgroup.controllers",
		"cpu.max",
		"cpu.stat",
		"cpu.weight",
		"cpuset.cpus",
		"cpuset.mems",
		"memory.current",
		"memory.events",
		"memory.high",
		"memory.max",
		"memory.peak",
		"memory.stat",
		"memory.swap.current",
		"memory.swap.max",
		"pids.max",
	} {
		writeTestFile(t, filepath.Join(groupPath, filename), "max")
	}
	writeTestFile(t, filepath.Join(groupPath, "cpu.max"), "50000 100000")
	writeTestFile(t, filepath.Join(groupPath, "cpu.stat"), "usage_usec 1\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.current"), "4096\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.events"), "high 0\noom 0\noom_kill 0\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.max"), "268435456")
	writeTestFile(t, filepath.Join(groupPath, "memory.peak"), "8192\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "214748160")
	ops := &cgroupV2{mountpoint: mountpoint, memoryHighRatio: 0.8}

	stats, err := ops.stat(name)
	require.NoError(t, err)
	require.True(t, stats.MemoryHighKnown)
	require.False(t, stats.MemoryHighUnlimited)
	assert.Equal(t, uint64(214748160), stats.MemoryHighBytes)
	assert.False(t, stats.FrozenKnown, "missing cgroup.events is unknown, not unfrozen")

	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 1\n")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.True(t, stats.FrozenKnown)
	assert.True(t, stats.Frozen)

	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 0\n")
	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "max")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	require.True(t, stats.FrozenKnown)
	assert.False(t, stats.Frozen)
	require.True(t, stats.MemoryHighKnown)
	assert.True(t, stats.MemoryHighUnlimited)

	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "junk")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	assert.False(t, stats.MemoryHighKnown)

	// The kernel only writes 0 or 1: any other frozen value is a malformed
	// source and must stay unknown, never an observed "unfrozen".
	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "214748160")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 2\n")
	stats, err = ops.stat(name)
	require.NoError(t, err)
	assert.False(t, stats.FrozenKnown, "frozen 2 is unknown, not unfrozen")
	freeze, err := ops.readFreeze(name)
	require.NoError(t, err)
	assert.False(t, freeze.EventsKnown, "readFreeze treats frozen 2 as unknown too")
	assert.False(t, freeze.Frozen)
}

// The freeze request/event bits and the ordered memory writes are the shrink
// primitives; identity binds the physical directory.
func TestV2FreezeAndOrderedMemoryWrites(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	ops := &cgroupV2{mountpoint: mountpoint}

	_, err := ops.readFreeze(name)
	require.NoError(t, err)
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 0\n")

	// A failed memory.max write leaves the already-written memory.high in
	// place: the two files have no atomic combined update. A directory in
	// place of the file fails the write for root and non-root alike.
	writeTestFile(t, filepath.Join(groupPath, "memory.high"), "214748160")
	require.NoError(t, os.Mkdir(filepath.Join(groupPath, "memory.max"), 0755))
	err = ops.writeMemoryLimits(name, 104857600, 536870912)
	require.ErrorContains(t, err, "memory.max")
	assertFileContents(t, filepath.Join(groupPath, "memory.high"), "104857600")

	require.NoError(t, os.RemoveAll(filepath.Join(groupPath, "memory.max")))
	require.NoError(t, ops.writeMemoryLimits(name, 104857600, 536870912))
	assertFileContents(t, filepath.Join(groupPath, "memory.high"), "104857600")
	assertFileContents(t, filepath.Join(groupPath, "memory.max"), "536870912")

	// An unreadable request bit is unknown, never an observed unfrozen one.
	writeTestFile(t, filepath.Join(groupPath, "cgroup.freeze"), "junk")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 0\n")
	freeze, err := ops.readFreeze(name)
	require.NoError(t, err)
	assert.False(t, freeze.RequestKnown)
	assert.True(t, freeze.EventsKnown)
	assert.False(t, freeze.Frozen)

	require.NoError(t, ops.writeFreeze(name, true))
	assertFileContents(t, filepath.Join(groupPath, "cgroup.freeze"), "1")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\nfrozen 1\n")
	freeze, err = ops.readFreeze(name)
	require.NoError(t, err)
	assert.True(t, freeze.RequestKnown)
	assert.True(t, freeze.RequestFrozen)
	assert.True(t, freeze.EventsKnown)
	assert.True(t, freeze.Frozen)

	identity, err := ops.identity(name)
	require.NoError(t, err)
	assert.Equal(t, name, identity.Path)
	assert.NotZero(t, identity.Inode)
}

func TestV2OOMWatcherUsesCgroupBaseline(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	memoryEvents := filepath.Join(groupPath, "memory.events")
	writeTestFile(t, memoryEvents, "low 0\nhigh 0\nmax 3\noom 3\noom_kill 3\n")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")

	watcher, err := newV2OOMWatcher(mountpoint)
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Add(name))
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")
	killed, err := watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed, "historical oom_kill count must not fire")

	watcher.eventsMu.Lock()
	writeTestFile(t, memoryEvents, "low 0\nhigh 0\nmax 4\noom 4\noom_kill 4\n")
	watcher.eventsMu.Unlock()
	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)

	require.NoError(t, watcher.Reset(name))
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 0\n")
	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.False(t, killed)
	watcher.Remove(name)
	_, err = watcher.OOMKilled(name)
	assert.Error(t, err)
}

func TestV2OOMWatcherWaitsForFinalMemoryEvent(t *testing.T) {
	mountpoint := t.TempDir()
	name := "/sandbox/lease"
	groupPath := filepath.Join(mountpoint, name)
	require.NoError(t, os.MkdirAll(groupPath, 0755))
	memoryEvents := filepath.Join(groupPath, "memory.events")
	writeTestFile(t, memoryEvents, "oom_kill 0\n")
	writeTestFile(t, filepath.Join(groupPath, "cgroup.events"), "populated 1\n")

	watcher, err := newV2OOMWatcher(mountpoint)
	require.NoError(t, err)
	defer watcher.Close()
	require.NoError(t, watcher.Add(name))

	writeDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		writeDone <- os.WriteFile(memoryEvents, []byte("oom_kill 1\n"), 0644)
	}()
	killed, err := watcher.OOMKilled(name)
	require.NoError(t, <-writeDone)
	require.NoError(t, err)
	assert.True(t, killed)
}

func TestV1OOMWatcherMultiplexesEventFDs(t *testing.T) {
	watcher, err := newV1OOMWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	for _, name := range []string{"/sandbox/a", "/sandbox/b"} {
		fd, fdErr := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
		require.NoError(t, fdErr)
		require.NoError(t, watcher.addFD(name, fd))
	}

	wakeEventFD(watcher.byName["/sandbox/b"].fd)
	require.Eventually(t, func() bool {
		killed, getErr := watcher.OOMKilled("/sandbox/b")
		return getErr == nil && killed
	}, 2*time.Second, 10*time.Millisecond)
	killed, err := watcher.OOMKilled("/sandbox/a")
	require.NoError(t, err)
	assert.False(t, killed)

	require.NoError(t, watcher.Reset("/sandbox/b"))
	killed, err = watcher.OOMKilled("/sandbox/b")
	require.NoError(t, err)
	assert.False(t, killed)
	watcher.Remove("/sandbox/b")
	_, err = watcher.OOMKilled("/sandbox/b")
	assert.Error(t, err)
}

func TestV1OOMKilledDrainsPendingEventFD(t *testing.T) {
	const name = "/sandbox/lease"
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	require.NoError(t, err)
	defer unix.Close(fd)

	entry := &v1OOMEntry{name: name, fd: fd}
	watcher := &v1OOMWatcher{
		byName: map[string]*v1OOMEntry{name: entry},
	}
	wakeEventFD(fd)

	killed, err := watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed)

	killed, err = watcher.OOMKilled(name)
	require.NoError(t, err)
	assert.True(t, killed, "OOM flag must remain set after the eventfd is drained")
}

func TestNewCgroupManagerRejectsNegativePidsMax(t *testing.T) {
	_, err := NewCgroupManager(nil, config.ResourceConfig{PidsMax: -1}, 1)
	assert.EqualError(t, err, "pids_max must be non-negative")
}

func TestNewCgroupManagerRejectsInvalidMemoryHighRatio(t *testing.T) {
	for _, ratio := range []float64{-0.1, 1.0, 1.5} {
		_, err := NewCgroupManager(
			nil,
			config.ResourceConfig{MemoryHighRatio: ratio},
			1,
		)
		assert.ErrorContains(
			t,
			err,
			"memory_high_ratio must be within [0, 1)",
			"ratio %.2f must be rejected",
			ratio,
		)
	}
}

func TestMemoryHighBytes(t *testing.T) {
	// The aligned expectation follows the host page size, as does the
	// implementation, instead of assuming 4 KiB pages.
	alignDown := func(value uint64) uint64 {
		page := uint64(os.Getpagesize())
		if value < page {
			return value
		}
		return value - value%page
	}
	for _, test := range []struct {
		limit uint64
		ratio float64
		want  uint64
	}{
		{limit: 0, ratio: 0.9, want: 0},
		{limit: 1 << 30, ratio: 0, want: 0},
		{limit: 1000, ratio: 0.5, want: 500},
		{limit: 1001, ratio: 0.5, want: 501},
		// Page-aligned DOWN once the value reaches a page: the soft limit
		// stays further below the hard limit and shrink margins compare
		// against the smaller budget. Sub-page ceilings keep the plain ceil.
		{limit: 1 << 30, ratio: 0.9, want: alignDown(966367642)},
		{limit: 100, ratio: 0.99, want: 99},
		{limit: 10, ratio: 0.999999, want: 9},
		{limit: 1, ratio: 0.9, want: 0},
	} {
		assert.Equal(
			t,
			test.want,
			MemoryHighBytes(test.limit, test.ratio),
			"limit=%d ratio=%.6f",
			test.limit,
			test.ratio,
		)
	}
}

func TestV2UpdateWritesMemoryHigh(t *testing.T) {
	const name = "/sandbox/lease"
	newFakeGroup := func(t *testing.T) (string, string) {
		mountpoint := t.TempDir()
		groupPath := filepath.Join(mountpoint, name)
		require.NoError(t, os.MkdirAll(groupPath, 0755))
		for _, filename := range []string{
			"cpu.weight",
			"cpu.max",
			"cpuset.cpus",
			"cpuset.mems",
			"memory.max",
			"memory.swap.max",
			"memory.high",
			"pids.max",
		} {
			writeTestFile(t, filepath.Join(groupPath, filename), "max")
		}
		return mountpoint, groupPath
	}
	limit := int64(1 << 30)
	resources := &specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &limit}}

	mountpoint, groupPath := newFakeGroup(t)
	ops := &cgroupV2{mountpoint: mountpoint, memoryHighRatio: 0.9}
	require.NoError(t, ops.update(name, resources))
	assertFileContents(t, filepath.Join(groupPath, "memory.max"), "1073741824")
	assertFileContents(t, filepath.Join(groupPath, "memory.high"),
		strconv.FormatUint(MemoryHighBytes(1<<30, 0.9), 10))

	mountpoint, groupPath = newFakeGroup(t)
	ops = &cgroupV2{mountpoint: mountpoint}
	require.NoError(t, ops.update(name, resources))
	assertFileContents(t, filepath.Join(groupPath, "memory.max"), "1073741824")
	assertFileContents(t, filepath.Join(groupPath, "memory.high"), "max")

	mountpoint, groupPath = newFakeGroup(t)
	ops = &cgroupV2{mountpoint: mountpoint, memoryHighRatio: 0.9}
	require.NoError(t, ops.update(name, &specs.LinuxResources{}))
	assertFileContents(t, filepath.Join(groupPath, "memory.high"), "max")
}

func writeTestFile(t *testing.T, name, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(name, []byte(contents), 0644))
}

func assertFileContents(t *testing.T, name, expected string) {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	assert.Equal(t, expected, string(data))
}

func TestReadCPUMaxDistinguishesUnknownUnlimitedAndFinite(t *testing.T) {
	for _, tc := range []struct {
		text   string
		quota  int64
		period uint64
		known  bool
	}{
		{"50000 100000", 50000, 100000, true}, {"125000 100000", 125000, 100000, true},
		{"max 100000", -1, 100000, true}, {"50000 0", 0, 0, false},
		{"bad 100000", 0, 0, false}, {"0 100000", 0, 0, false}, {"-1 100000", 0, 0, false},
		{"50000", 0, 0, false}, {"50000 100000 junk", 0, 0, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cpu.max")
			writeTestFile(t, path, tc.text)
			quota, period, known := readCPUMax(path)
			assert.Equal(t, tc.quota, quota)
			assert.Equal(t, tc.period, period)
			assert.Equal(t, tc.known, known)
		})
	}
	_, _, known := readCPUMax(filepath.Join(t.TempDir(), "missing"))
	assert.False(t, known)
}
