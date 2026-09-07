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

package firecracker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

// startRollbackHelperFixture maps an instance with a fresh identity record
// and no prior on-disk state, so a retained rollback must persist that
// identity itself.
func startRollbackHelperFixture(t *testing.T, sandboxID string) (*Handler, *firecrackerInstance) {
	t.Helper()
	bundlePath := t.TempDir()
	if err := os.Mkdir(filepath.Join(bundlePath, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{instances: make(map[string]*firecrackerInstance)}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:         sandboxID,
			BundlePath: bundlePath,
			Generation: "gen-" + sandboxID,
		},
		done: make(chan struct{}),
	}
	handler.instances[sandboxID] = instance
	return handler, instance
}

func TestStartRollbackConfirmsKernelExit(t *testing.T) {
	handler, instance := startRollbackHelperFixture(t, "rollback-helper-exit")
	startCheckpointPersistenceChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	original := errors.New("injected start failure")
	returned, retained := handler.rollbackStartedInstance(instance, original)
	if retained {
		t.Fatal("a live owned child with matching identity was retained")
	}
	if returned != original {
		t.Fatalf("confirmed rollback replaced the original failure: %v", returned)
	}
	if errors.Is(returned, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("confirmed rollback reported pending cleanup: %v", returned)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("rollback returned before the kernel exit notification")
	}
	if !instance.snapshot().Exited {
		t.Fatal("confirmed rollback left the instance unfinished")
	}
	handler.mu.RLock()
	_, mapped := handler.instances["rollback-helper-exit"]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("confirmed rollback left the instance mapped")
	}
}

func TestStartRollbackRetainsUnconfirmedExit(t *testing.T) {
	handler, instance := startRollbackHelperFixture(t, "rollback-helper-unknown")
	command := startCheckpointPersistenceChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	pid := instance.state.PID
	// Detach the recorded identity from the live owned child: the rollback
	// must neither signal the unrecognized process nor treat it as exited.
	handler.binary += "-unavailable"
	original := errors.New("injected start failure")
	returned, retained := handler.rollbackStartedInstance(instance, original)
	if !retained {
		t.Fatal("an unrecognized live child was treated as a confirmed exit")
	}
	if !errors.Is(returned, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("retained rollback lost the cleanup-pending sentinel: %v", returned)
	}
	if !errors.Is(returned, original) {
		t.Fatalf("retained rollback lost the original failure: %v", returned)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("unrecognized process was stopped")
	}
	if instance.snapshot().Exited {
		t.Fatal("unconfirmed exit finished the instance")
	}
	handler.mu.RLock()
	_, mapped := handler.instances["rollback-helper-unknown"]
	handler.mu.RUnlock()
	if !mapped {
		t.Fatal("unconfirmed exit unmapped the instance")
	}
	// The failure may precede the first ordinary persistence, yet the record
	// must still carry the incarnation identity for reconciliation.
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.ID != "rollback-helper-unknown" || disk.PID != pid ||
		disk.Generation != "gen-rollback-helper-unknown" || disk.Exited {
		t.Fatalf("retained identity record = %+v", disk)
	}
	// This fixture drives the rollback helper directly, so no waitCommand
	// monitor exists. Release the owned child through the pidfd pinned at
	// its spawn: the signal addresses exactly that process, and reaping it
	// here observes the kernel exit notification through the same gate.
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("retained child did not exit after the test released it")
	}
}

func TestStartRollbackRejectsInvalidRecordedPID(t *testing.T) {
	handler, instance := startRollbackHelperFixture(t, "rollback-helper-invalid")
	// A missing PID is an invalid record, not evidence of an exit; in
	// particular PID 1 must never be probed or signalled.
	instance.state.PID = 0
	returned, retained := handler.rollbackStartedInstance(instance, nil)
	if !retained {
		t.Fatal("an invalid recorded PID was treated as a confirmed exit")
	}
	if !errors.Is(returned, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("retained rollback lost the cleanup-pending sentinel: %v", returned)
	}
	handler.mu.RLock()
	_, mapped := handler.instances["rollback-helper-invalid"]
	handler.mu.RUnlock()
	if !mapped {
		t.Fatal("invalid record unmapped the instance")
	}
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Generation != "gen-rollback-helper-invalid" || disk.Exited {
		t.Fatalf("retained identity record = %+v", disk)
	}
}

// startRollbackVMMArgumentPIDs scans live process command lines for the VMM
// argument pair ("--id", sandboxID) and returns the matching PIDs, excluding
// the test process itself. Processes that exit while the scan runs are
// skipped, so only genuinely live VMM processes are reported. The scan backs
// assertions only: signalling authority never derives from argv matching.
func startRollbackVMMArgumentPIDs(t *testing.T, sandboxID string) []int {
	t.Helper()
	self := os.Getpid()
	matches := []int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		arguments := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		for index := 0; index+1 < len(arguments); index++ {
			if arguments[index] == "--id" && arguments[index+1] == sandboxID {
				matches = append(matches, pid)
				break
			}
		}
	}
	return matches
}

// TestMain recognizes the native Firecracker argument vector this package's
// full Start/Restore tests spawn their VMM stand-ins with: those children must
// behave like an idle VMM (alive until signalled) without going through the
// test flag parser, which would reject "--api-sock". Go test binaries never
// pass a five-argument vector of this exact shape, so the detection cannot
// misfire on a normal test run.
func TestMain(m *testing.M) {
	if len(os.Args) == 5 && os.Args[1] == "--api-sock" && os.Args[3] == "--id" {
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The rollback keys on native process identity (argv and /proc/PID/exe), not
// on VMM behavior: this test binary stands in for the VMM, so a fresh Start
// or Restore really spawns — and the rollback really stops — an owned child
// that stays alive until signalled. Actual VM lifecycle validation remains a
// separate acceptance requirement.
func startRollbackIdentifiedVMM(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skipf("mkfs.ext4 is unavailable: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	return binary
}

// startRollbackUnidentifiedVMM returns a binary path whose spawned process
// can never match its recorded identity: execve resolves the symlink, so the
// child's /proc/PID/exe names the target while the recorded binary stays the
// symlink path. The process stays alive and unrecognized — the exact shape of
// an exit that cannot be confirmed.
func startRollbackUnidentifiedVMM(t *testing.T) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "unidentified-vmm")
	if err := os.Symlink(startRollbackIdentifiedVMM(t), link); err != nil {
		t.Fatal(err)
	}
	return link
}

// startRollbackOciLoader stands in for the server-driven OCI generation: the
// rollback under test keys on the spawned process and its artifacts, not on
// OCI contents.
type startRollbackOciLoader struct {
	bundlePath string
	spec       *runtimecore.Spec
}

func (loader *startRollbackOciLoader) GenerateOci(runtimecore.OciLoadOptions) (string, *runtimecore.Spec, error) {
	return loader.bundlePath, loader.spec, nil
}

// startRollbackSandboxID derives a per-run sandbox ID so concurrent
// invocations of this test binary on one machine can never match each
// other's VMM children in the /proc observation scan above.
func startRollbackSandboxID(prefix string) string {
	return prefix + "-" + strconv.Itoa(os.Getpid())
}

// startRollbackHandler builds a Start-ready handler around a fake OCI loader
// and a cgroup path that does not exist, so every start fails at the cgroup
// attachment — after the VMM child was already spawned. The config carries a
// physical resource generation exactly as the server would.
func startRollbackHandler(t *testing.T, sandboxID, vmmBinary string) (*Handler, runtimecore.StartConfig, string) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), sandboxID)
	if err := os.MkdirAll(bundlePath, 0700); err != nil {
		t.Fatal(err)
	}
	// t.TempDir names embed the full test name and overflow Firecracker's
	// Unix socket path budget; keep the runtime root short.
	runtimeRoot, err := os.MkdirTemp("", "s0048")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeRoot) })
	handler := &Handler{
		binary:      vmmBinary,
		sandboxRoot: t.TempDir(),
		storageRoot: t.TempDir(),
		runtimeRoot: runtimeRoot,
		instances:   make(map[string]*firecrackerInstance),
		ociLoader: &startRollbackOciLoader{
			bundlePath: bundlePath,
			spec: &runtimecore.Spec{
				Root:    &runtimecore.Root{Path: fakeEROFSImage(t, "rootfs.erofs")},
				Process: &runtimecore.Process{Args: []string{"/bin/sh"}},
			},
		},
	}
	return handler, runtimecore.StartConfig{
		ID:                      sandboxID,
		CgroupPath:              "/akernel-0048-absent-cgroup",
		Network:                 firecrackerTestNetwork(),
		WritableLayerLimitBytes: firecrackerMinimumOverlay,
		ResourceGeneration:      "gen-" + sandboxID,
	}, bundlePath
}

// restoreRollbackHandler reuses the start fixture around a sealed v2
// checkpoint artifact so the Restore entry checks and instantiation run.
func restoreRollbackHandler(t *testing.T, sandboxID, vmmBinary string) (*Handler, runtimecore.StartConfig, string) {
	t.Helper()
	handler, config, bundlePath := startRollbackHandler(t, sandboxID, vmmBinary)
	checkpointDir := filepath.Join(t.TempDir(), "gen1")
	sealV2ArtifactFixture(t, checkpointDir)
	config.CheckpointDir = checkpointDir
	return handler, config, bundlePath
}

// prelaunchStdoutFailure returns a stdout path whose parent is the regular
// overlay file: output setup fails with ENOTDIR after every artifact
// directory exists but before the VMM is spawned.
func prelaunchStdoutFailure(handler *Handler, sandboxID string) string {
	return filepath.Join(handler.storageRoot, sandboxID, "overlay.ext4", "vmm.log")
}

func assertStartRollbackReleased(t *testing.T, handler *Handler, sandboxID, bundlePath string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(bundlePath, firecrackerArtifactsDir)); !os.IsNotExist(err) {
		t.Fatalf("state directory survived a confirmed rollback: %v", err)
	}
	if _, err := os.Stat(handler.runtimeDirectory(sandboxID)); !os.IsNotExist(err) {
		t.Fatalf("runtime directory survived a confirmed rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(handler.storageRoot, sandboxID)); !os.IsNotExist(err) {
		t.Fatalf("writable layer survived a confirmed rollback: %v", err)
	}
	handler.mu.RLock()
	_, mapped := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("instance stayed mapped after a confirmed rollback")
	}
}

func assertStartRollbackRetained(
	t *testing.T,
	handler *Handler,
	sandboxID, bundlePath string,
) firecrackerPersistedState {
	t.Helper()
	statePath := filepath.Join(bundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("persisted identity discarded on an unconfirmed exit: %v", err)
	}
	if _, err := os.Stat(handler.runtimeDirectory(sandboxID)); err != nil {
		t.Fatalf("runtime directory discarded on an unconfirmed exit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(handler.storageRoot, sandboxID)); err != nil {
		t.Fatalf("writable layer discarded on an unconfirmed exit: %v", err)
	}
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		t.Fatal("instance was unmapped on an unconfirmed exit")
	}
	if instance.snapshot().Exited {
		t.Fatal("unconfirmed exit finished the instance")
	}
	disk, err := readFirecrackerState(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return disk
}

// releaseStartRollbackRetained stops the retained instance's recorded child
// so the test leaves no orphan process behind. The instance itself stays
// mapped and its artifacts on disk: reconciling them belongs to the
// management-plane follow-up, not to this rollback step. The recorded PID is
// pinned through a pidfd before signalling, so the kill can never be
// redirected through PID recycling; the /proc scan afterwards only observes.
func releaseStartRollbackRetained(t *testing.T, handler *Handler, sandboxID string) {
	t.Helper()
	handler.mu.RLock()
	instance := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if instance == nil {
		return
	}
	state := instance.snapshot()
	if state.PID <= 1 {
		t.Fatalf("retained instance %s recorded invalid pid %d", sandboxID, state.PID)
	}
	fd, err := unix.PidfdOpen(state.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return // the recorded child is already gone
	}
	if err != nil {
		t.Fatalf("open pidfd for retained VMM pid %d: %v", state.PID, err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		t.Fatalf("signal retained VMM pid %d: %v", state.PID, err)
	}
	select {
	case <-instance.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("retained VMM pid %d did not exit after SIGKILL", state.PID)
	}
	if pids := startRollbackVMMArgumentPIDs(t, sandboxID); len(pids) != 0 {
		t.Fatalf("retained VMM still alive after SIGKILL: %v", pids)
	}
}

func TestFreshStartFailureRollbackConfirmsExit(t *testing.T) {
	handler, config, bundlePath := startRollbackHandler(
		t, startRollbackSandboxID("s0048fstart"), startRollbackIdentifiedVMM(t),
	)
	err := handler.Start(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "attach Firecracker to cgroup") {
		t.Fatalf("fresh Start failure = %v, want the cgroup attach failure", err)
	}
	if errors.Is(err, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("confirmed rollback reported pending cleanup: %v", err)
	}
	assertStartRollbackReleased(t, handler, config.ID, bundlePath)
	if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
		t.Fatalf("fresh Start left live VMM processes behind: %v", pids)
	}
}

func TestFreshStartFailureRollbackRetainsUnconfirmedExit(t *testing.T) {
	sandboxID := startRollbackSandboxID("s0048fkeep")
	handler, config, bundlePath := startRollbackHandler(
		t, sandboxID, startRollbackUnidentifiedVMM(t),
	)
	t.Cleanup(func() { releaseStartRollbackRetained(t, handler, sandboxID) })
	err := handler.Start(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "attach Firecracker to cgroup") {
		t.Fatalf("fresh Start failure = %v, want the cgroup attach failure", err)
	}
	if !errors.Is(err, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("unconfirmed rollback lost the cleanup-pending sentinel: %v", err)
	}
	disk := assertStartRollbackRetained(t, handler, sandboxID, bundlePath)
	if disk.ID != sandboxID || disk.Generation != "gen-"+sandboxID ||
		disk.PID <= 1 || disk.Exited {
		t.Fatalf("retained identity record = %+v", disk)
	}
	pids := startRollbackVMMArgumentPIDs(t, sandboxID)
	if len(pids) != 1 || pids[0] != disk.PID {
		t.Fatalf(
			"live unrecognized VMM processes for %s = %v, want exactly pid %d",
			sandboxID, pids, disk.PID,
		)
	}
}

func TestFreshStartPrelaunchFailureCleansArtifacts(t *testing.T) {
	handler, config, bundlePath := startRollbackHandler(
		t, startRollbackSandboxID("s0048fpre"), startRollbackIdentifiedVMM(t),
	)
	config.Stdout = prelaunchStdoutFailure(handler, config.ID)
	err := handler.Start(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("prelaunch Start failure = %v, want the stdout setup failure", err)
	}
	assertStartRollbackReleased(t, handler, config.ID, bundlePath)
	if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
		t.Fatalf("prelaunch failure spawned VMM processes: %v", pids)
	}
}

func TestRestoreFailureRollbackConfirmsExit(t *testing.T) {
	handler, config, bundlePath := restoreRollbackHandler(
		t, startRollbackSandboxID("s0048rstart"), startRollbackIdentifiedVMM(t),
	)
	err := handler.Restore(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "attach restored Firecracker to cgroup") {
		t.Fatalf("Restore failure = %v, want the cgroup attach failure", err)
	}
	if errors.Is(err, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("confirmed rollback reported pending cleanup: %v", err)
	}
	assertStartRollbackReleased(t, handler, config.ID, bundlePath)
	if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
		t.Fatalf("Restore left live VMM processes behind: %v", pids)
	}
}

func TestRestoreFailureRollbackRetainsUnconfirmedExit(t *testing.T) {
	sandboxID := startRollbackSandboxID("s0048rkeep")
	handler, config, bundlePath := restoreRollbackHandler(
		t, sandboxID, startRollbackUnidentifiedVMM(t),
	)
	t.Cleanup(func() { releaseStartRollbackRetained(t, handler, sandboxID) })
	err := handler.Restore(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "attach restored Firecracker to cgroup") {
		t.Fatalf("Restore failure = %v, want the cgroup attach failure", err)
	}
	if !errors.Is(err, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("unconfirmed rollback lost the cleanup-pending sentinel: %v", err)
	}
	disk := assertStartRollbackRetained(t, handler, sandboxID, bundlePath)
	if disk.ID != sandboxID || disk.Generation != "gen-"+sandboxID ||
		disk.PID <= 1 || disk.Exited {
		t.Fatalf("retained identity record = %+v", disk)
	}
	pids := startRollbackVMMArgumentPIDs(t, sandboxID)
	if len(pids) != 1 || pids[0] != disk.PID {
		t.Fatalf(
			"live unrecognized VMM processes for %s = %v, want exactly pid %d",
			sandboxID, pids, disk.PID,
		)
	}
}

func TestRestorePrelaunchFailureCleansArtifacts(t *testing.T) {
	handler, config, bundlePath := restoreRollbackHandler(
		t, startRollbackSandboxID("s0048rpre"), startRollbackIdentifiedVMM(t),
	)
	config.Stdout = prelaunchStdoutFailure(handler, config.ID)
	err := handler.Restore(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("prelaunch Restore failure = %v, want the stdout setup failure", err)
	}
	assertStartRollbackReleased(t, handler, config.ID, bundlePath)
	if pids := startRollbackVMMArgumentPIDs(t, config.ID); len(pids) != 0 {
		t.Fatalf("prelaunch failure spawned VMM processes: %v", pids)
	}
}
