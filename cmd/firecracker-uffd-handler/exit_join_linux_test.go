package main

import (
	"bytes"
	"flag"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the real main in a child, with a pipe standing in only for the uffd.
// No pagefault is injected: closing the real Unix handshake connection must
// wake poll, stop background tasks and allow main to return.
func TestHandlerMainJoinsAfterHandshakeEOF(t *testing.T) {
	if root := os.Getenv("AKERNEL_TEST_UFFD_EXIT_ROOT"); root != "" {
		flag.CommandLine = flag.NewFlagSet("uffd-exit-child", flag.ExitOnError)
		os.Args = []string{"uffd-exit-child", "-sock", filepath.Join(root, "uffd.sock"), "-backing", filepath.Join(root, "memory"), "-prefetch", "0", "-workers", "1"}
		main()
		return
	}
	root, err := os.MkdirTemp("/tmp", "uffd-exit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.WriteFile(filepath.Join(root, "memory"), bytes.Repeat([]byte{0x5a}, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHandlerMainJoinsAfterHandshakeEOF$")
	cmd.Env = append(os.Environ(), "AKERNEL_TEST_UFFD_EXIT_ROOT="+root)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	var conn *net.UnixConn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(root, "uffd.sock"), Net: "unix"})
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatalf("handler child: %v\n%s", err, output.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler failed to join after handshake EOF")
	}
	if !strings.Contains(output.String(), "handler exiting, total faults served=0") {
		t.Fatalf("main exit not reached: %s", output.String())
	}
}
