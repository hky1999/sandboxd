package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These exercise the actual production launch flow with a child that dies
// before publishing a socket, without a VM, userfaultfd, or any shared
// daemon. The launch runs against a mapped instance with a persisted state
// file, exactly as Restore drives it; the assertions additionally pin the
// ownership contract (identity durable before the permit, retained after the
// failure).

// uffdLaunchFixture builds the handler/instance pair the production launch
// path persists through, plus a handler binary with the given script body.
func uffdLaunchFixture(t *testing.T, sandboxID, script string) (*Handler, *firecrackerInstance, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "uffd-handler")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(root, "bundle")
	if err := os.MkdirAll(filepath.Join(bundlePath, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{uffdHandlerBin: bin}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{ID: sandboxID, BundlePath: bundlePath},
		done:  make(chan struct{}),
	}
	return handler, instance, root
}

// assertUffdIdentityRecorded checks the durable ownership record the launch
// must leave behind once a gated child existed: full kernel identity while
// the launch is still pending the socket.
func assertUffdIdentityRecorded(t *testing.T, instance *firecrackerInstance, sockPath string) {
	t.Helper()
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	record := disk.Uffd
	if record.isZero() {
		t.Fatal("launch left no uffd ownership record")
	}
	if record.Version != firecrackerUffdRecordVersion ||
		record.Phase != firecrackerUffdPhasePending ||
		record.PID <= 1 || record.StartTime == 0 || record.BootID == "" ||
		record.Socket != sockPath {
		t.Fatalf("recorded uffd identity = %+v", record)
	}
	// The record must name the real child: its start time has to match the
	// live /proc value for the recorded PID.
	startTime, err := readFirecrackerProcessStartTime(record.PID)
	if os.IsNotExist(err) {
		// Early-exit handlers may already have been reaped; the durable
		// birth was captured before permit and must still be retained.
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if startTime != record.StartTime {
		t.Fatalf(
			"recorded start time %d does not match live %d for pid %d",
			record.StartTime, startTime, record.PID,
		)
	}
}

func TestLaunchUffdHandlerEarlyExit(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(
		t, "sbox-uffd-exit", "#!/bin/sh\nexit 23\n",
	)
	sockPath := filepath.Join(root, "absent.sock")
	start := time.Now()
	err := handler.launchUffdHandler(
		instance, "sbox-uffd-exit", sockPath, filepath.Join(root, "memory"), root,
	)
	if err == nil || !strings.Contains(err.Error(), "exited early") {
		t.Fatalf("expected early exit error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("early exit reported after %s, want it well before the 5s readiness deadline", elapsed)
	}
	assertUffdIdentityRecorded(t, instance, sockPath)
}

func TestLaunchUffdHandlerSignalExit(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(
		t, "sbox-uffd-signal", "#!/bin/sh\nkill -TERM $$\n",
	)
	sockPath := filepath.Join(root, "absent.sock")
	start := time.Now()
	err := handler.launchUffdHandler(
		instance, "sbox-uffd-signal", sockPath, filepath.Join(root, "memory"), root,
	)
	if err == nil || !strings.Contains(err.Error(), "exited early") {
		t.Fatalf("expected early exit error after signal, got %v", err)
	}
	// A signal death never registers as Exited(), so the retired
	// ProcessState poll missed it and burned the whole readiness window
	// before failing with "never appeared".
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("signal exit reported after %s, want the prompt exit branch", elapsed)
	}
	assertUffdIdentityRecorded(t, instance, sockPath)
}

func TestLaunchUffdHandlerFailureBeforeSpawnLeavesNoRecord(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(
		t, "sbox-uffd-absent", "#!/bin/sh\nexit 0\n",
	)
	// Point the handler at a path that cannot spawn: the failure precedes the
	// child, so no ownership record may survive it.
	handler.uffdHandlerBin = filepath.Join(root, "missing-handler")
	err := handler.launchUffdHandler(
		instance, "sbox-uffd-absent", filepath.Join(root, "absent.sock"),
		filepath.Join(root, "memory"), root,
	)
	if err == nil || !strings.Contains(err.Error(), "inspect uffd handler") {
		t.Fatalf("expected the pre-spawn inspection failure, got %v", err)
	}
	if !instance.snapshot().Uffd.isZero() {
		t.Fatalf("pre-spawn failure retained a record: %+v", instance.snapshot().Uffd)
	}
}
