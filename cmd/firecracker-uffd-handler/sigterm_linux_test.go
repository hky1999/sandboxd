// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// Tests for bounded graceful SIGTERM handling. The child scenarios execute
// the real main in a process this test owns and signal it only after its
// socket is published — the earliest point at which the signal notifier is
// guaranteed installed — in three states: before any connection is accepted,
// after a connection that never completes the handshake, and after a valid
// SCM_RIGHTS handshake with an idle pipe standing in for the uffd. Every
// state must end in a graceful joined exit, never a signal fatality or a
// deadlock. The in-process scenarios pin the connection and descriptor
// cleanup of the canceled or rejected handshake itself.

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// syncedBuffer collects child output while exec's copier goroutine writes it,
// so the test can wait for log lines before the child exits.
type syncedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncedBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncedBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runHandlerChildMain is the child half of the re-exec pattern from
// exit_join_linux_test.go: run the production main against the scenario's
// root directory and let the test binary exit normally afterwards.
func runHandlerChildMain(name, root string) {
	flag.CommandLine = flag.NewFlagSet(name, flag.ExitOnError)
	os.Args = []string{name, "-sock", filepath.Join(root, "uffd.sock"), "-backing", filepath.Join(root, "memory"), "-prefetch", "0", "-workers", "1"}
	main()
}

// newHandlerChildRoot prepares /tmp (short Unix socket paths) with the small
// dense backing file the local mode needs.
func newHandlerChildRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "uffd-sigterm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.WriteFile(filepath.Join(root, "memory"), bytes.Repeat([]byte{0x5a}, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

// startHandlerChild re-executes only the named test, which branches into
// runHandlerChildMain through its environment variable. The child belongs to
// this test alone; the cleanup kills it if the scenario failed to.
func startHandlerChild(t *testing.T, envVar, runPattern, root string) (*exec.Cmd, *syncedBuffer, chan error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run="+runPattern)
	cmd.Env = append(os.Environ(), envVar+"="+root)
	out := &syncedBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return cmd, out, done
}

// awaitHandlerChild bounds the graceful exit and falls back to killing the
// child so a deadlocked main fails the test instead of hanging it.
func awaitHandlerChild(t *testing.T, cmd *exec.Cmd, done chan error, grace time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(grace):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("handler child did not exit within %v", grace)
		return nil
	}
}

func waitHandlerSocketPublished(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("handler socket %s never published", sock)
}

func waitHandlerLog(t *testing.T, out *syncedBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("handler never logged %q: %s", want, out.String())
}

func assertSocketRemoved(t *testing.T, sock string) {
	t.Helper()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket %s not removed by deferred cleanup: %v", sock, err)
	}
}

// TestHandlerMainSigtermBeforeAcceptGraceful: termination while main blocks
// in Accept must close the listening socket, exit through the ordinary
// startup path (deferred cleanup runs), and not die from the signal.
func TestHandlerMainSigtermBeforeAcceptGraceful(t *testing.T) {
	const envVar = "AKERNEL_TEST_UFFD_SIGTERM_ACCEPT_ROOT"
	if root := os.Getenv(envVar); root != "" {
		runHandlerChildMain("uffd-sigterm-accept", root)
		return
	}
	root := newHandlerChildRoot(t)
	cmd, out, done := startHandlerChild(t, envVar, "^TestHandlerMainSigtermBeforeAcceptGraceful$", root)
	sock := filepath.Join(root, "uffd.sock")
	waitHandlerSocketPublished(t, sock)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := awaitHandlerChild(t, cmd, done, 5*time.Second); err != nil {
		t.Fatalf("handler child: %v\n%s", err, out.String())
	}
	if log := out.String(); !strings.Contains(log, "handler startup canceled") {
		t.Fatalf("startup cancellation not reported as ordinary exit: %s", log)
	}
	assertSocketRemoved(t, sock)
}

// TestHandlerMainSigtermDuringHandshakeGraceful: the VMM connected but never
// sent the handshake, leaving main blocked in ReadMsgUnix. Termination must
// close the accepted connection, unblock the read, and exit gracefully.
func TestHandlerMainSigtermDuringHandshakeGraceful(t *testing.T) {
	const envVar = "AKERNEL_TEST_UFFD_SIGTERM_READ_ROOT"
	if root := os.Getenv(envVar); root != "" {
		runHandlerChildMain("uffd-sigterm-read", root)
		return
	}
	root := newHandlerChildRoot(t)
	cmd, out, done := startHandlerChild(t, envVar, "^TestHandlerMainSigtermDuringHandshakeGraceful$", root)
	sock := filepath.Join(root, "uffd.sock")
	waitHandlerSocketPublished(t, sock)
	// Connected but silent: no handshake bytes, connection held open.
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := awaitHandlerChild(t, cmd, done, 5*time.Second); err != nil {
		t.Fatalf("handler child: %v\n%s", err, out.String())
	}
	if log := out.String(); !strings.Contains(log, "handler startup canceled") {
		t.Fatalf("startup cancellation not reported as ordinary exit: %s", log)
	}
	assertSocketRemoved(t, sock)
}

// TestHandlerMainSigtermAfterHandshakeGraceful: after a valid SCM_RIGHTS
// handshake, with the pipe-backed uffd idle and the VMM connection still
// open, termination must run the same shutdown path as the VMM EOF — the
// eventfd wake interrupts the uffd poll and every worker is joined.
func TestHandlerMainSigtermAfterHandshakeGraceful(t *testing.T) {
	const envVar = "AKERNEL_TEST_UFFD_SIGTERM_SERVE_ROOT"
	if root := os.Getenv(envVar); root != "" {
		runHandlerChildMain("uffd-sigterm-serve", root)
		return
	}
	root := newHandlerChildRoot(t)
	cmd, out, done := startHandlerChild(t, envVar, "^TestHandlerMainSigtermAfterHandshakeGraceful$", root)
	sock := filepath.Join(root, "uffd.sock")
	waitHandlerSocketPublished(t, sock)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	if _, _, err := conn.WriteMsgUnix([]byte("[]"), unix.UnixRights(pipe[0]), nil); err != nil {
		t.Fatal(err)
	}
	// Serving has started once the readiness line is logged; only then is
	// the signal guaranteed to exercise the serving shutdown path.
	waitHandlerLog(t, out, "handler ready:", 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := awaitHandlerChild(t, cmd, done, 5*time.Second); err != nil {
		t.Fatalf("handler child: %v\n%s", err, out.String())
	}
	log := out.String()
	if !strings.Contains(log, "termination signal received") {
		t.Fatalf("serving termination not reported: %s", log)
	}
	if !strings.Contains(log, "handler exiting, total faults served=0") {
		t.Fatalf("main exit not reached: %s", log)
	}
	assertSocketRemoved(t, sock)
}

// signalledListener reports a completed Accept so a test can cancel at a
// point where the handshake goroutine is deterministically past the accept
// and inside (or about to enter) the handshake read.
type signalledListener struct {
	net.Listener
	accepted chan struct{}
}

func (s *signalledListener) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err == nil {
		s.accepted <- struct{}{}
	}
	return c, err
}

type handshakeResult struct {
	regions []regionMapping
	fd      int
	conn    *net.UnixConn
	err     error
}

func recvHandshakeAsync(ctx context.Context, l net.Listener) <-chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		regions, fd, conn, err := recvHandshake(ctx, l)
		ch <- handshakeResult{regions: regions, fd: fd, conn: conn, err: err}
	}()
	return ch
}

// TestRecvHandshakeCancelUnblocksAccept: with no peer at all, cancellation
// must close the listening socket so a blocked Accept returns instead of
// waiting forever.
func TestRecvHandshakeCancelUnblocksAccept(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "uffd-hs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	l, err := net.Listen("unix", filepath.Join(root, "uffd.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := recvHandshakeAsync(ctx, l)
	// Give the goroutine a moment to reach the blocked Accept; the bound
	// below holds whichever way the race resolves.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case r := <-res:
		if r.err == nil || r.conn != nil {
			t.Fatalf("canceled accept returned %v, conn %v", r.err, r.conn)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not unblock Accept")
	}
}

// TestRecvHandshakeCancelDuringReadClosesConn: a connected but silent peer
// leaves the handshake read blocked; cancellation must close the accepted
// connection — observable as EOF on the peer side — and report the shutdown.
func TestRecvHandshakeCancelDuringReadClosesConn(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "uffd-hs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	l, err := net.Listen("unix", filepath.Join(root, "uffd.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	signalled := &signalledListener{Listener: l, accepted: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := recvHandshakeAsync(ctx, signalled)
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(root, "uffd.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case <-signalled.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake never accepted the connection")
	}
	cancel()
	select {
	case r := <-res:
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("want cancellation error, got %v", r.err)
		}
		if r.conn != nil {
			t.Fatal("canceled handshake handed out a live connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not unblock the handshake read")
	}
	// The accepted connection was closed, not merely abandoned: the peer
	// observes EOF instead of an open socket.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer did not observe the closed connection: %v", err)
	}
}

// peerSeesClosedHandshake runs one rejected-handshake exchange and verifies
// the outcome every rejection must share: an error, no connection handed
// out, and the accepted connection actually closed.
func peerSeesClosedHandshake(t *testing.T, payload []byte, rights []int, wantErr string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "uffd-hs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	sock := filepath.Join(root, "uffd.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	res := recvHandshakeAsync(context.Background(), l)
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var oob []byte
	if len(rights) > 0 {
		oob = unix.UnixRights(rights...)
	}
	if _, _, err := peer.WriteMsgUnix(payload, oob, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.err == nil || !strings.Contains(r.err.Error(), wantErr) {
			t.Fatalf("want error containing %q, got %v", wantErr, r.err)
		}
		if r.conn != nil {
			t.Fatalf("rejected handshake handed out a connection (%v)", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake never processed the payload")
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer did not observe the closed connection: %v", err)
	}
}

// TestRecvHandshakeDecodeErrorClosesConn: a malformed mapping table must
// close the accepted connection instead of leaving it for process exit.
func TestRecvHandshakeDecodeErrorClosesConn(t *testing.T) {
	peerSeesClosedHandshake(t, []byte("not-json"), nil, "decode mappings")
}

// TestRecvHandshakeNoFDErrorClosesConn: a handshake without an SCM_RIGHTS
// descriptor must close the accepted connection.
func TestRecvHandshakeNoFDErrorClosesConn(t *testing.T) {
	peerSeesClosedHandshake(t, []byte("[]"), nil, "no file descriptor")
}

// fdsForPath counts this process's descriptors pointing at path: the kernel
// duplicates SCM_RIGHTS payloads into the receiver, so a descriptor the
// handler failed to close stays visible as an extra entry.
func fdsForPath(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue // raced with a close
		}
		if target == path {
			n++
		}
	}
	return n
}

// TestRecvHandshakeSuccessKeepsConnOpenAndClosesExtraFDs: the one accepted
// outcome must be the opposite of the rejection paths — the connection is
// returned open (the VMM EOF watcher reads it) and descriptors beyond the
// uffd in the SCM_RIGHTS payload are closed, not leaked.
func TestRecvHandshakeSuccessKeepsConnOpenAndClosesExtraFDs(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "uffd-hs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	extraPath := filepath.Join(root, "extra")
	if err := os.WriteFile(extraPath, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	keep, err := os.Open(extraPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	extra, err := os.Open(extraPath)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	before := fdsForPath(t, extraPath) // this test's two handles

	sock := filepath.Join(root, "uffd.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	res := recvHandshakeAsync(context.Background(), l)
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	if _, _, err := peer.WriteMsgUnix([]byte("[]"), unix.UnixRights(pipe[0], int(extra.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	var r handshakeResult
	select {
	case r = <-res:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake never completed")
	}
	if r.err != nil {
		t.Fatalf("handshake: %v", r.err)
	}
	if r.conn == nil || r.fd < 0 {
		t.Fatalf("handshake returned conn=%v fd=%d", r.conn, r.fd)
	}
	defer r.conn.Close()
	defer unix.Close(r.fd)
	if got := fdsForPath(t, extraPath); got != before {
		t.Fatalf("extra descriptor handling changed open count: got %d, want %d", got, before)
	}
	// The connection is live from the handler side: a write must not fail,
	// and only closing it may surface EOF to the peer.
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatalf("write to a handshake-open connection failed: %v", err)
	}
	if err := r.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var inbound [1]byte
	if _, err := io.ReadFull(r.conn, inbound[:]); err != nil || inbound[0] != 'x' {
		t.Fatalf("handshake connection did not deliver payload: %v", err)
	}
	if err := r.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer did not observe the handler closing the connection: %v", err)
	}
}

func TestRecvHandshakeBadJSONClosesReceivedFD(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "uffd-rejected-fd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	before := fdsForPath(t, file.Name())
	peerSeesClosedHandshake(t, []byte("not-json"), []int{int(file.Fd())}, "decode mappings")
	if got := fdsForPath(t, file.Name()); got != before {
		t.Fatalf("rejected handshake leaked received FD: got %d want %d", got, before)
	}
}
