// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package runsc

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// This integration fixture only creates links in its caller's network namespace.
// Opt in from a task-owned, isolated container with /dev/net/tun and CAP_NET_ADMIN.
func TestOpenTAPClearsPersistentChecksumOffload(t *testing.T) {
	if os.Getenv("SANDBOXD_RUNSC_TAP_REUSE_TEST") != "1" {
		t.Skip("requires an isolated network namespace and explicit TAP test opt-in")
	}
	name := fmt.Sprintf("crtap%08x", uint32(time.Now().UnixNano()))
	openVnetQueue := func(exclusive bool) *os.File {
		t.Helper()
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "tap-reuse-fixture")
		t.Cleanup(func() { _ = file.Close() })
		request, err := unix.NewIfreq(name)
		if err != nil {
			t.Fatal(err)
		}
		flags := uint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
		if exclusive {
			flags |= unix.IFF_TUN_EXCL
		}
		request.SetUint16(flags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
			t.Fatalf("attach fixture TAP: %v", err)
		}
		return file
	}
	creator := openVnetQueue(true)
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Errorf("find owned TAP for cleanup: %v", err)
			return
		}
		if link.Attrs().Index != iface.Index {
			t.Error("owned TAP identity changed; refuse cleanup")
			return
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Errorf("delete owned TAP: %v", err)
		}
	})
	if err := unix.IoctlSetInt(int(creator.Fd()), unix.TUNSETPERSIST, 1); err != nil {
		t.Fatal(err)
	}
	enableChecksum := func(file *os.File) {
		t.Helper()
		if err := unix.IoctlSetInt(int(file.Fd()), unix.TUNSETOFFLOAD, unix.TUN_F_CSUM); err != nil {
			t.Fatalf("enable preceding vnet consumer offload: %v", err)
		}
	}
	checkChecksum := func(want bool) {
		t.Helper()
		got, err := tapTXChecksumForTest(name)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("persistent TAP TX checksum offload = %v, want %v", got, want)
		}
	}
	enableChecksum(creator)
	checkChecksum(true)
	if err := creator.Close(); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		func() {
			tap, err := OpenTAP(*iface)
			if err != nil {
				t.Fatal(err)
			}
			defer tap.Close()
			checkChecksum(false)
			request, err := unix.NewIfreq(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.IoctlIfreq(int(tap.Fd()), unix.TUNGETIFF, request); err != nil {
				t.Fatal(err)
			}
			if request.Uint16()&unix.IFF_VNET_HDR != 0 {
				t.Fatal("runsc queue still requires a vnet header")
			}
		}()
		next := openVnetQueue(false)
		enableChecksum(next)
		checkChecksum(true)
		if err := next.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func tapTXChecksumForTest(name string) (bool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	value := struct {
		Command uint32
		Data    uint32
	}{Command: 0x00000016} // ETHTOOL_GTXCSUM from linux/ethtool.h.
	request := struct {
		Name    [unix.IFNAMSIZ]byte
		Data    unsafe.Pointer
		Padding [24 - unsafe.Sizeof(uintptr(0))]byte
	}{Data: unsafe.Pointer(&value)}
	copy(request.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(&request)
	if errno != 0 {
		return false, errno
	}
	return value.Data != 0, nil
}
