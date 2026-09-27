package resourcemanager

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// writeLease writes a COMPLETE enabler lease: {case, ttl, armed_at,
// deadline=armed_at+ttl}.
func writeLease(t *testing.T, path, caseTag string, ttl time.Duration, backdate time.Duration) {
	t.Helper()
	armed := time.Now().Add(-backdate)
	cf := FaultControlFile{
		Case:           caseTag,
		TTLMs:          ttl.Milliseconds(),
		ArmedAtUnixMs:  armed.UnixMilli(),
		DeadlineUnixMs: armed.Add(ttl).UnixMilli(),
	}
	raw, err := json.Marshal(cf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Directed check 1 — TRIGGER.
func TestObservationFaultTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeLease(t, path, "ur-3", 45*time.Second, 0)
	tag, remaining, ok := f.Active()
	if !ok || tag != "ur-3" || remaining <= 0 || remaining > 45*time.Second {
		t.Fatalf("trigger failed: ok=%v tag=%q remaining=%v", ok, tag, remaining)
	}
}

// Directed check 2 — PERSISTENT ABSOLUTE EXPIRY: expired lease inert; stale
// armed_at inert; inconsistent lease inert.
func TestObservationFaultPersistentAbsoluteExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeLease(t, path, "ur-3", 1100*time.Millisecond, 0)
	if _, _, ok := f.Active(); !ok {
		t.Fatal("precondition: active")
	}
	time.Sleep(1300 * time.Millisecond)
	if _, _, ok := f.Active(); ok {
		t.Fatal("expired lease must be permanently inert (absolute deadline)")
	}
	// stale leftover: armed 20m ago, deadline still future
	cf := FaultControlFile{Case: "ur-4", TTLMs: (25 * time.Minute).Milliseconds(),
		ArmedAtUnixMs: time.Now().Add(-20 * time.Minute).UnixMilli(),
		DeadlineUnixMs: time.Now().Add(5 * time.Minute).UnixMilli()}
	raw, _ := json.Marshal(cf)
	_ = os.WriteFile(path, raw, 0o600)
	if _, _, ok := f.Active(); ok {
		t.Fatal("stale armed_at must be inert")
	}
	// inconsistent: deadline far beyond armed_at+ttl
	cf2 := FaultControlFile{Case: "ur-5", TTLMs: (30 * time.Second).Milliseconds(),
		ArmedAtUnixMs:  time.Now().UnixMilli(),
		DeadlineUnixMs: time.Now().Add(30 * time.Minute).UnixMilli()}
	raw2, _ := json.Marshal(cf2)
	_ = os.WriteFile(path, raw2, 0o600)
	if _, _, ok := f.Active(); ok {
		t.Fatal("inconsistent lease must be inert")
	}
}

// Directed check 3 — EXPLICIT RELEASE: removal releases; a different valid
// case is a NEW lease with its own tag.
func TestObservationFaultExplicitRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeLease(t, path, "ur-5", 60*time.Second, 0)
	if tag, _, ok := f.Active(); !ok || tag != "ur-5" {
		t.Fatal("precondition: armed ur-5")
	}
	writeLease(t, path, "ur-6", 60*time.Second, 0)
	tag, _, ok := f.Active()
	if !ok || tag != "ur-6" {
		t.Fatalf("case change = new lease: ok=%v tag=%q", ok, tag)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := f.Active(); ok {
		t.Fatal("file removal must release")
	}
}

// Directed check 4 — DEFAULT OFF / BOUNDED READ.
func TestObservationFaultDefaultOffAndBoundedRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fault.json")
	writeLease(t, path, "ur-7", 30*time.Second, 0)
	if _, _, ok := (&ObservationFault{Enabled: false, Path: path}).Active(); ok {
		t.Fatal("config gate closed must stay inactive")
	}
	var nilFault *ObservationFault
	if _, _, ok := nilFault.Active(); ok {
		t.Fatal("nil receiver must be inactive")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err == nil {
		if _, _, ok := (&ObservationFault{Enabled: true, Path: fifo}).Active(); ok {
			t.Fatal("FIFO control file must be refused")
		}
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, faultMaxFileSize+1), 0o600); err == nil {
		if _, _, ok := (&ObservationFault{Enabled: true, Path: big}).Active(); ok {
			t.Fatal("oversized control file must be refused")
		}
	}
}

// Directed check 5 — REAL wiring + REAL HTTP: production constructor,
// config applied BEFORE Start (as internal/server does), one keepalive
// connection (dial count == 1 asserted) observing 200 -> 503 -> 200
// (absolute expiry) -> 503 -> 200 (release); full bounded drain; timeouts.
func TestObservationFaultHTTPThroughRealModule(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "resource.sock")
	ctrl := filepath.Join(dir, "fault.json")
	mod, err := NewModule(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	mod.SetObservationFault(true, ctrl) // BEFORE Start, per internal/server
	if err := mod.Start(); err != nil {
		t.Fatal(err)
	}
	defer mod.Stop()

	var dials atomic.Int64
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				dials.Add(1)
				return net.Dial("unix", sock)
			},
		},
	}
	get := func() int {
		resp, err := client.Get("http://unix/resource")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return resp.StatusCode
	}

	mod.refreshOnce()
	if code := get(); code != http.StatusOK {
		t.Fatalf("pre-fault status = %d, want 200", code)
	}
	writeLease(t, ctrl, "ur-http", 1500*time.Millisecond, 0)
	waitFor := func(want int, budget time.Duration, what string) {
		deadline := time.Now().Add(budget)
		code := -1
		for time.Now().Before(deadline) {
			if code = get(); code == want {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: last status = %d, want %d", what, code, want)
	}
	waitFor(http.StatusServiceUnavailable, 10*time.Second, "fault-active")
	waitFor(http.StatusOK, 8*time.Second, "absolute expiry recovery")
	writeLease(t, ctrl, "ur-http-2", 30*time.Second, 0)
	waitFor(http.StatusServiceUnavailable, 8*time.Second, "second arm")
	if err := os.Remove(ctrl); err != nil {
		t.Fatal(err)
	}
	waitFor(http.StatusOK, 8*time.Second, "explicit release")
	if n := dials.Load(); n != 1 {
		t.Fatalf("keepalive violated: %d dial(s), want exactly 1", n)
	}
}
