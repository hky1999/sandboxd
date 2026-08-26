package networkmanager

import (
	"errors"
	"net"
	"os"
	"testing"

	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/inclusionAI/sandboxd/internal/util"
)

// recoveryFixture models the P1 scenario from the PR review: a durable pooled
// TAP lease recorded with a stale ifindex, a host device recreated at a fresh
// ifindex, and everything else (bridge attach, host MAC) already converged.
type recoveryFixture struct {
	manager    *InterfaceManager
	linkOps    *fakeLinkOperations
	tapName    string
	staleLease string
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()

	ip := net.ParseIP("10.88.0.5").To4()
	require.NotNil(t, ip)
	mask := net.CIDRMask(16, 32)
	bridgeIP := net.ParseIP("10.88.0.1")
	tapName := util.IpToTap(ip.String())
	hostMAC, err := tapHostMAC(ip)
	require.NoError(t, err)
	guestMAC, err := tapGuestMAC(ip)
	require.NoError(t, err)

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName, Index: 42}}
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name:         tapName,
			Index:        13, // recreated: the lease still records 7
			MasterIndex:  42,
			HardwareAddr: hostMAC,
		},
		Mode: netlink.TUNTAP_MODE_TAP,
	}

	stale := &NetResource{
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeTap,
		GuestMAC:      guestMAC,
		Interface:     &net.Interface{Name: tapName, Index: 7},
		Ip:            ip,
		Mask:          mask,
		Gateway:       bridgeIP,
		Type:          "bridge",
	}
	staleLease := stale.ToString()

	// The fixture is converged apart from the ifindex: reaching a repair call
	// means the identity checks matched the wrong device, so fail loudly.
	linkOps := &fakeLinkOperations{
		link:         tap,
		setMasterErr: errors.New("unexpected bridge re-attach on converged fixture"),
		setMACErr:    errors.New("unexpected host MAC re-stamp on converged fixture"),
	}

	f := &recoveryFixture{
		tapName:    tapName,
		staleLease: staleLease,
		linkOps:    linkOps,
	}
	f.manager = &InterfaceManager{
		IpRange:    "10.88.0.1/16",
		BridgeIp:   bridgeIP,
		mask:       mask,
		bridgeLink: bridge,
		linkOps:    linkOps,
		listLinks: func() ([]net.Interface, error) {
			return []net.Interface{{Name: tapName, Index: 13}}, nil
		},
		listNetNS:       func() ([]os.DirEntry, error) { return nil, nil },
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
		idleIp:          util.New(""),
	}
	f.manager.usingInterfaces.Set(staleLease, struct{}{})
	return f
}

// refreshedLease returns the post-recovery durable key and verifies it only
// differs from the externally held string in bookkeeping fields.
func (f *recoveryFixture) refreshedLease(t *testing.T) string {
	t.Helper()
	keys := f.manager.usingInterfaces.Keys()
	require.Len(t, keys, 1, "exactly one active lease expected after recovery")
	assert.False(t, f.manager.usingInterfaces.Has(f.staleLease),
		"durable key must have been swapped away from the stale lease")
	refreshed, err := NewNetResource(keys[0])
	require.NoError(t, err)
	require.NotNil(t, refreshed.Interface)
	assert.Equal(t, f.tapName, refreshed.Interface.Name)
	assert.EqualValues(t, 13, refreshed.Interface.Index,
		"refreshed lease must carry the current ifindex")
	return keys[0]
}

// TestRecoveryIfindexDriftKeepsExternalLeaseReferenceWorking is the
// regression test requested in review: active ifindex drift, daemon restart
// (which renames the durable lease key), then sandbox deletion driving
// Deactivate and Release with the pre-restart annotation string. Before the
// immutable-identity resolution both operations silently succeeded without
// touching the TAP, leaking the lease, its IP, and its pool slot forever.
func TestRecoveryIfindexDriftKeepsExternalLeaseReferenceWorking(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.manager

	// Daemon restart: recovery repairs the stale ifindex and renames the
	// durable key.
	require.NoError(t, m.load(sets.New[string]()))
	f.refreshedLease(t)
	assert.Equal(t, 1, f.linkOps.setUpCount,
		"active-lease recovery must bring the TAP up")

	// Sandbox deletion step 1: Deactivate is called with the annotation
	// string persisted before the restart. It must actually disconnect the
	// TAP instead of no-op'ing on the renamed key.
	assert.NoError(t, m.Deactivate(f.staleLease))
	assert.Equal(t, 1, f.linkOps.setDownCount,
		"Deactivate must disconnect the TAP resolved by immutable identity")
	// The lease is retained (deactivated, not recycled).
	f.refreshedLease(t)

	// Sandbox deletion step 2: Release/Recycle must return the endpoint to
	// the idle pool under the same external reference.
	assert.NoError(t, m.Release(f.staleLease))
	assert.Equal(t, 2, f.linkOps.setDownCount,
		"Recycle must deactivate the TAP resolved by immutable identity")
	assert.Zero(t, m.usingInterfaces.Count(),
		"lease must leave the using set after Release")
	using, idle := m.Status()
	assert.Empty(t, using)
	require.Len(t, idle, 1)
	recycled, err := NewNetResource(idle[0])
	require.NoError(t, err)
	require.NotNil(t, recycled.Interface)
	assert.Equal(t, f.tapName, recycled.Interface.Name)
	assert.EqualValues(t, 13, recycled.Interface.Index,
		"idle queue must carry the refreshed lease, not the stale annotation string")
}

// TestResolveLeaseKeyRejectsForeignIdentity pins the resolution boundary: a
// miss that does not match any active lease by immutable identity stays a
// miss, so unrelated or malformed strings still take the no-op paths.
func TestResolveLeaseKeyRejectsForeignIdentity(t *testing.T) {
	f := newRecoveryFixture(t)
	m := f.manager

	require.NoError(t, m.load(sets.New[string]()))

	foreign := (&NetResource{
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeTap,
		Interface:     &net.Interface{Name: util.IpToTap("10.88.0.9"), Index: 99},
		Ip:            net.ParseIP("10.88.0.9"),
		Type:          "bridge",
	}).ToString()

	key, ok := m.resolveLeaseKey(foreign)
	assert.False(t, ok)
	assert.Empty(t, key)

	_, ok = m.resolveLeaseKey("not-json")
	assert.False(t, ok)

	// Unrelated strings keep the silent no-op semantics.
	assert.NoError(t, m.Deactivate(foreign))
	assert.Zero(t, f.linkOps.setDownCount)
	assert.Equal(t, 1, m.usingInterfaces.Count(),
		"the real lease must be untouched by a foreign Deactivate")
}
