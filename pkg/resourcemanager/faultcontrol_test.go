package resourcemanager

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeCtrl(t *testing.T, path string, cf any) {
	t.Helper()
	raw, err := json.Marshal(cf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Directed check 1 — TRIGGER: a gated, well-formed control file arms a
// lease for exactly the file's case with remaining in (0, TTL].
func TestObservationFaultTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeCtrl(t, path, FaultControlFile{Case: "ur-3", TTLMs: 45000})
	tag, remaining, ok := f.Active()
	if !ok || tag != "ur-3" || remaining <= 0 || remaining > 45*time.Second {
		t.Fatalf("trigger failed: ok=%v tag=%q remaining=%v", ok, tag, remaining)
	}
}

// Directed check 2 — NO SELF-ARMING WINDOW: out-of-bound TTL never arms
// (and never becomes valid later — the deadline is arm-time + clamped TTL,
// not a file-supplied absolute deadline); one-shot per case: after expiry
// the same file cannot re-arm.
func TestObservationFaultNoSelfArmAndOneShot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeCtrl(t, path, FaultControlFile{Case: "ur-3", TTLMs: int64((faultMaxTTL + time.Hour).Milliseconds())})
	if _, _, ok := f.Active(); ok {
		t.Fatal("TTL beyond the bound must never arm")
	}
	writeCtrl(t, path, FaultControlFile{Case: "ur-4", TTLMs: 1100})
	if _, _, ok := f.Active(); !ok {
		t.Fatal("valid TTL must arm")
	}
	// force expiry by backdating the lease deadline
	f.mu.Lock()
	f.lease.deadline = time.Now().Add(-time.Second)
	f.mu.Unlock()
	if _, _, ok := f.Active(); ok {
		t.Fatal("expired lease must auto-recover")
	}
	if _, _, ok := f.Active(); ok {
		t.Fatal("one-shot: the same still-present case must not re-arm")
	}
}

// Directed check 3 — EXPLICIT RELEASE: deleting the file (or changing the
// case) releases an armed lease immediately.
func TestObservationFaultExplicitRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fault.json")
	f := &ObservationFault{Enabled: true, Path: path}
	writeCtrl(t, path, FaultControlFile{Case: "ur-5", TTLMs: 60000})
	if _, _, ok := f.Active(); !ok {
		t.Fatal("precondition: armed")
	}
	writeCtrl(t, path, FaultControlFile{Case: "someone-else", TTLMs: 60000})
	if _, _, ok := f.Active(); ok {
		t.Fatal("case change must release")
	}
}

// Directed check 4 — DEFAULT OFF / BOUNDED READ: config gate closed stays
// inert; FIFO and oversized files are refused, not read unboundedly.
func TestObservationFaultDefaultOffAndBoundedRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fault.json")
	writeCtrl(t, path, FaultControlFile{Case: "ur-6", TTLMs: 30000})
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

// Directed check 5 — REAL config wiring + REAL HTTP over the unix socket,
// expiry and release observed on ONE keepalive connection. The Module is
// built through the production constructor path with the fault configured
// exactly as internal/server would (SetObservationFault from config).
func TestObservationFaultHTTPThroughRealModule(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "resource.sock")
	ctrl := filepath.Join(dir, "fault.json")
	mod, err := NewModule(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	// the same call internal/server makes from config.NodeResourceConfig
	mod.SetObservationFault(true, ctrl)
	if err := mod.Start(); err != nil {
		t.Fatal(err)
	}
	defer mod.Stop()

	client := &http.Client{Transport: unixTransport(sock)}

	get := func() (int, string) {
		resp, err := client.Get("http://unix/resource")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	// pre-fault: healthy module serves 200 (refresh once so Healthy() is true)
	mod.refreshOnce()
	if code, _ := get(); code != http.StatusOK {
		t.Fatalf("pre-fault status = %d, want 200", code)
	}
	// arm via the control file; the SAME keepalive connection now sees 503
	writeCtrl(t, ctrl, FaultControlFile{Case: "ur-http", TTLMs: 1200})
	deadline := time.Now().Add(10 * time.Second)
	code := 0
	for time.Now().Before(deadline) {
		code, _ = get()
		if code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("fault-active status = %d, want 503")
	}
	// expiry auto-recovery on the same connection (TTL 1.2s)
	deadline = time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		code, _ = get()
		if code == http.StatusOK {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Fatalf("post-expiry status = %d, want 200 (auto-recovery)", code)
	}
	// explicit release: new case arms, file removal releases, same connection
	writeCtrl(t, ctrl, FaultControlFile{Case: "ur-http-2", TTLMs: 30000})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ = get(); code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("second arm status = %d, want 503", code)
	}
	if err := os.Remove(ctrl); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ = get(); code == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Fatalf("post-release status = %d, want 200", code)
	}
}

func unixTransport(sock string) *http.Transport {
	dialer := func(network, addr string) (net.Conn, error) { return net.Dial("unix", sock) }
	return &http.Transport{Dial: dialer}
}
