// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These TAPs exist only in the dedicated test container's network namespace.
// Failure leaves them to that namespace's destruction; cleanup never adopts
// a same-name replacement or touches the original platform network.
type nativePhysicalTAP struct {
	name      string
	index     int
	mac       string
	namespace unix.Stat_t
	network   NetworkConfig
}

func newNativePhysicalTAP(t *testing.T, ordinal int) *nativePhysicalTAP {
	t.Helper()
	name := fmt.Sprintf("native%d", ordinal)
	_, err := netlink.LinkByName(name)
	var missing netlink.LinkNotFoundError
	require.True(t, errors.As(err, &missing), "the private TAP name is already present or its absence is unknown")
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.MTU = name, 1500
	link := &netlink.Tuntap{LinkAttrs: attrs, Mode: netlink.TUNTAP_MODE_TAP, Flags: netlink.TuntapFlag(unix.IFF_NO_PI)}
	require.NoError(t, netlink.LinkAdd(link))
	require.NoError(t, netlink.LinkSetUp(link))
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	var namespace unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/net", &namespace))
	return &nativePhysicalTAP{name: name, index: iface.Index, mac: iface.HardwareAddr.String(), namespace: namespace,
		network: NetworkConfig{Interface: iface, LinkAddress: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x01, byte(ordinal + 1)},
			IP: net.IPv4(172, 31, 123, byte(ordinal+2)), Mask: net.CIDRMask(24, 32), Gateway: net.IPv4(172, 31, 123, 1)}}
}

func (original *nativePhysicalTAP) verify(t *testing.T) netlink.Link {
	t.Helper()
	var namespace unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/net", &namespace))
	require.Equal(t, original.namespace.Dev, namespace.Dev)
	require.Equal(t, original.namespace.Ino, namespace.Ino)
	link, err := netlink.LinkByIndex(original.index)
	require.NoError(t, err)
	require.Equal(t, "tuntap", link.Type())
	require.Equal(t, original.name, link.Attrs().Name)
	require.Equal(t, original.mac, link.Attrs().HardwareAddr.String())
	require.Zero(t, link.Attrs().MasterIndex)
	return link
}

func (original *nativePhysicalTAP) evidence(t *testing.T) map[string]any {
	t.Helper()
	original.verify(t)
	return map[string]any{"name": original.name, "ifindex": original.index, "mac": original.mac,
		"network_namespace_device": original.namespace.Dev, "network_namespace_inode": original.namespace.Ino,
		"scope": "Private test-container TAP only; no original platform bridge, route or network modified."}
}

func (original *nativePhysicalTAP) retire(t *testing.T) map[string]any {
	t.Helper()
	record := original.evidence(t)
	require.NoError(t, netlink.LinkDel(original.verify(t)))
	_, err := netlink.LinkByIndex(original.index)
	var missing netlink.LinkNotFoundError
	require.True(t, errors.As(err, &missing), "the original private TAP deletion was not confirmed")
	record["original_tap_deletion_confirmed"] = true
	return record
}
