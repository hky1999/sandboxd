package firecracker

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func checkpointPersistenceFixture(t *testing.T) (*Handler, *firecrackerInstance) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	instance := &firecrackerInstance{state: firecrackerPersistedState{ID: "persist-test", BundlePath: dir, Configured: true, MemoryMiB: 512, Vcpus: 2}, done: make(chan struct{})}
	return &Handler{}, instance
}

func TestCheckpointLineageOnlyDoesNotRewriteState(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "adopt"
		if lost {
			name = "invalidate"
		}
		t.Run(name, func(t *testing.T) {
			handler, instance := checkpointPersistenceFixture(t)
			instance.setBaseMemory("old-base", true)
			before := instance.snapshot()
			if err := handler.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(before.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if lost {
				instance.markBaseMemoryLineageLost()
			} else {
				instance.setBaseMemory("new-base", false)
			}
			if err := handler.persistCheckpointChanges(instance, before); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(info, after) {
				t.Fatal("lineage-only update replaced runtime state")
			}
			disk, err := readFirecrackerState(before.BundlePath)
			if err != nil {
				t.Fatal(err)
			}
			if disk != before {
				t.Fatalf("lineage-only update changed durable fields: %+v", disk)
			}
		})
	}
}

func TestCheckpointLifecycleChangesStillPersist(t *testing.T) {
	for _, field := range []string{"configured", "memory", "exit"} {
		t.Run(field, func(t *testing.T) {
			handler, instance := checkpointPersistenceFixture(t)
			before := instance.snapshot()
			if err := handler.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "configured":
				instance.mu.Lock()
				instance.state.Configured = false
				instance.mu.Unlock()
			case "memory":
				instance.setMemoryMiB(1024)
			case "exit":
				instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 17})
			}
			instance.markBaseMemoryLineageLost()
			if err := handler.persistCheckpointChanges(instance, before); err != nil {
				t.Fatal(err)
			}
			disk, err := readFirecrackerState(before.BundlePath)
			if err != nil {
				t.Fatal(err)
			}
			if disk != instance.snapshot() {
				t.Fatal("lifecycle change not persisted")
			}
		})
	}
}

// This owned child supplies native argv/exe identity, not KVM behavior. Actual
// checkpoint/restart/data validation is a separate VM acceptance requirement.
func startCheckpointPersistenceChild(t *testing.T, handler *Handler, instance *firecrackerInstance) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	handler.binary = binary
	instance.state.APIPath = filepath.Join(instance.state.BundlePath, "api.sock")
	instance.state.VsockPath = filepath.Join(instance.state.BundlePath, "absent-vsock.sock")
	command := handler.vmmCommand(instance.state.APIPath, instance.state.ID)
	command.Args = append([]string{binary, "-test.run=^TestVMMCommandProcessIdentity$", "--"}, command.Args[1:]...)
	command.Env = append(os.Environ(), "AKERNEL_VMM_COMMAND_CHILD=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child readiness %q: %v", line, err)
	}
	instance.state.PID = command.Process.Pid
	if !firecrackerProcessMatches(instance.state.PID, binary, instance.state.APIPath, instance.state.ID) {
		t.Fatal("child identity mismatch")
	}
	return command
}

func TestRecoveryDiscardsUnpersistedCheckpointLineage(t *testing.T) {
	handler, instance := checkpointPersistenceFixture(t)
	command := startCheckpointPersistenceChild(t, handler, instance)
	instance.setBaseMemory("deleted-older-base", true)
	before := instance.snapshot()
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	instance.setBaseMemory("new-live-base", false)
	if err := handler.persistCheckpointChanges(instance, before); err != nil {
		t.Fatal(err)
	}
	disk, err := readFirecrackerState(before.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.BaseMemoryPath != "deleted-older-base" {
		t.Fatal("fixture did not preserve stale disk lineage")
	}
	var recoveredInstances []*firecrackerInstance
	for i := 0; i < 2; i++ {
		recovered := handler.recoverState(disk)
		recoveredInstances = append(recoveredInstances, recovered)
		state, proof := recovered.checkpointStateAndProof()
		if state.Exited || !state.BaseMemoryLineageLost || state.BaseMemoryPath != "" || proof != nil {
			t.Fatalf("restart %d retained lineage: %+v", i, state)
		}
		kind, base, _, _, err := selectCheckpointTierWithProof(state, "", proof)
		if err != nil || kind != firecrackerSnapshotTypeFull || base != "" {
			t.Fatalf("restart %d did not force Full: %s %s %v", i, kind, base, err)
		}
		if _, _, _, _, err = selectCheckpointTierWithProof(state, firecrackerSnapshotTypeSoftDirty, proof); err == nil {
			t.Fatal("restart accepted explicit delta")
		}
		disk, err = readFirecrackerState(before.BundlePath)
		if err != nil {
			t.Fatal(err)
		}
		if !disk.BaseMemoryLineageLost || disk.BaseMemoryPath != "" {
			t.Fatal("recovery reset was not persisted")
		}
	}
	// The two recoveries create PID monitors in this test process. Suppress
	// their cleanup writes and wait for both to observe our owned child exit
	// before TemporaryDirectory removes the state directory.
	for _, recovered := range recoveredInstances {
		recovered.markDeleting()
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	for _, recovered := range recoveredInstances {
		select {
		case <-recovered.done:
		case <-time.After(time.Second):
			t.Fatal("recovered monitor did not observe child exit")
		}
	}
}

func TestCheckpointStopPersistsAlreadyFinishedSource(t *testing.T) {
	for _, running := range []bool{false, true} {
		name := "already-gone"
		if running {
			name = "owned-live-child"
		}
		t.Run(name, func(t *testing.T) {
			handler, instance := checkpointPersistenceFixture(t)
			if running {
				startCheckpointPersistenceChild(t, handler, instance)
			}
			before := instance.snapshot()
			if err := handler.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			instance.markBaseMemoryLineageLost()
			if err := handler.finishCheckpointedSandbox(instance, before, before.ID); err != nil {
				t.Fatal(err)
			}
			disk, err := readFirecrackerState(before.BundlePath)
			if err != nil {
				t.Fatal(err)
			}
			if !disk.Exited || disk.ExitedAt == "" || disk.ExitCode != 0 || !disk.BaseMemoryLineageLost {
				t.Fatalf("terminal state not durable: %+v", disk)
			}
			if running && firecrackerProcessMatches(before.PID, handler.binary, before.APIPath, before.ID) {
				t.Fatal("owned source survived stop")
			}
		})
	}
}
