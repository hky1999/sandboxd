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

package runsc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This opt-in kernel regression never creates a device in the caller's network
// namespace. The child must prove it entered a different namespace first.
func TestOpenTAPClearsInheritedChecksumOffload(t *testing.T) {
	const childEnv = "AKERNEL_RUNSC_TAP_OFFLOAD_CHILD"
	const parentEnv = "AKERNEL_RUNSC_TAP_OFFLOAD_PARENT_NETNS"
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(childEnv) == "1" {
		parentNS := os.Getenv(parentEnv)
		if parentNS == "" || currentNS == parentNS {
			t.Fatal("refusing TAP regression outside a new network namespace")
		}
		exerciseRawTAPChecksum(t)
		return
	}
	if os.Getenv("AKERNEL_RUNSC_TAP_INTEGRATION") != "1" {
		t.Skip("set AKERNEL_RUNSC_TAP_INTEGRATION=1 with unshare and CAP_NET_ADMIN")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, unshare, "--net", "--", os.Args[0],
		"-test.run=^TestOpenTAPClearsInheritedChecksumOffload$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", parentEnv+"="+currentNS)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated TAP regression failed: %v\n%s", err, output)
	}
	t.Logf("isolated TAP regression:\n%s", output)
}

func exerciseRawTAPChecksum(t *testing.T) {
	t.Helper()
	const name = "akcr-offload"
	const localIP = "172.31.250.1"
	const peerIP = "172.31.250.2"
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	warm, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer warm.Close()
	request, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatal(err)
	}
	request.SetUint16(uint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR))
	if err := unix.IoctlIfreq(int(warm.Fd()), unix.TUNSETIFF, request); err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetInt(int(warm.Fd()), unix.TUNSETPERSIST, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, ip, "link", "delete", "dev", name).CombinedOutput(); err != nil {
			t.Errorf("delete isolated test TAP: %v: %s", err, output)
		}
	})
	// Model a previous vnet-header consumer that accepts partial checksums.
	if err := unix.IoctlSetInt(int(warm.Fd()), unix.TUNSETOFFLOAD, unix.TUN_F_CSUM); err != nil {
		t.Fatal(err)
	}
	if err := warm.Close(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"addr", "add", localIP + "/24", "dev", name},
		{"link", "set", "dev", name, "up"},
		{"neigh", "replace", peerIP, "lladdr", "02:fc:ac:1f:fa:02", "nud", "permanent", "dev", name},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		output, err := exec.CommandContext(ctx, ip, args...).CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	tap, err := OpenTAP(*iface)
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}}
		connection, _ := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(peerIP, "50090"))
		if connection != nil {
			_ = connection.Close()
		}
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("test TCP dial did not stop after cancellation")
		}
	}()
	frame := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(tap.Fd()), Events: unix.POLLIN}}, 200)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if ready == 0 {
			continue
		}
		n, err := unix.Read(int(tap.Fd()), frame)
		if err == unix.EAGAIN {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n < 54 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
			continue
		}
		packet := frame[14:n]
		headerLength := int(packet[0]&0x0f) * 4
		length := int(binary.BigEndian.Uint16(packet[2:4]))
		if packet[0]>>4 != 4 || headerLength < 20 || length < headerLength+20 || length > len(packet) || packet[9] != 6 {
			continue
		}
		if !bytes.Equal(packet[12:16], net.ParseIP(localIP).To4()) || !bytes.Equal(packet[16:20], net.ParseIP(peerIP).To4()) {
			continue
		}
		tcp := packet[headerLength:length]
		if binary.BigEndian.Uint16(tcp[2:4]) != 50090 || tcp[13]&0x02 == 0 {
			continue
		}
		if tapInternetChecksum(packet[:headerLength]) != 0 {
			t.Fatal("test SYN has an invalid IPv4 header checksum")
		}
		pseudo := append([]byte{}, packet[12:20]...)
		pseudo = append(pseudo, 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
		pseudo = append(pseudo, tcp...)
		if remainder := tapInternetChecksum(pseudo); remainder != 0 {
			t.Fatalf("raw TAP delivered an incomplete TCP checksum: field=%#04x remainder=%#04x; vnet metadata is absent",
				binary.BigEndian.Uint16(tcp[16:18]), remainder)
		}
		t.Logf("raw TAP SYN carries a complete TCP checksum: field=%#04x, frame_bytes=%d", binary.BigEndian.Uint16(tcp[16:18]), n)
		return
	}
	t.Fatal("no matching host TCP SYN reached the isolated raw TAP")
}

func tapInternetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestTAPInternetChecksum(t *testing.T) {
	check := func(data []byte, want uint16) {
		t.Helper()
		if got := tapInternetChecksum(data); got != want {
			t.Fatal(fmt.Sprintf("checksum(%x)=%#04x, want %#04x", data, got, want))
		}
	}
	check(nil, 0xffff)
	check([]byte{0, 1}, 0xfffe)
	check([]byte{1}, 0xfeff)
	check([]byte{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7}, 0x220d)
}
