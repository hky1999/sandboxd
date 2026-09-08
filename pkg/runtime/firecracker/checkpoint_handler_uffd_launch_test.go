package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These exercise the actual launch monitor with a child that dies before
// publishing a socket, without a VM, userfaultfd, or any shared daemon.

func TestLaunchUffdHandlerEarlyExit(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "exit-handler")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	h := &Handler{uffdHandlerBin: bin}
	start := time.Now()
	err := h.launchUffdHandler("sbox-uffd-exit", filepath.Join(root, "absent.sock"), filepath.Join(root, "memory"), root)
	if err == nil || !strings.Contains(err.Error(), "exited early") {
		t.Fatalf("expected early exit error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("early exit reported after %s, want it well before the 5s readiness deadline", elapsed)
	}
}

func TestLaunchUffdHandlerSignalExit(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "signal-handler")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nkill -TERM $$\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	h := &Handler{uffdHandlerBin: bin}
	start := time.Now()
	err := h.launchUffdHandler("sbox-uffd-signal", filepath.Join(root, "absent.sock"), filepath.Join(root, "memory"), root)
	if err == nil || !strings.Contains(err.Error(), "exited early") {
		t.Fatalf("expected early exit error after signal, got %v", err)
	}
	// A signal death never registers as Exited(), so the retired
	// ProcessState poll missed it and burned the whole readiness window
	// before failing with "never appeared".
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("signal exit reported after %s, want the prompt exit branch", elapsed)
	}
}
