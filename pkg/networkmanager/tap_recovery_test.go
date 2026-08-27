package networkmanager

import (
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

// tapRecoveryFixture builds a manager around one host TAP whose exact state
// the test controls, with every host mutation recorded by the fake link ops.
type tapRecoveryFixture struct {
	manager *InterfaceManager
	linkOps *fakeLinkOperations
	tapName string
}

func newTapRecoveryFixture(t *testing.T, tap *netlink.Tuntap) *tapRecoveryFixture {
	t.Helper()

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName, Index: 42}}
	linkOps := &fakeLinkOperations{link: tap}
	m := &InterfaceManager{
		IpRange:    "10.88.0.1/16",
		BridgeIp:   net.ParseIP("10.88.0.1"),
		mask:       net.CIDRMask(16, 32),
		bridgeLink: bridge,
		linkOps:    linkOps,
		listLinks: func() ([]net.Interface, error) {
			return []net.Interface{{Name: tap.Attrs().Name, Index: tap.Attrs().Index}}, nil
		},
		listNetNS:       func() ([]os.DirEntry, error) { return nil, nil },
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
		idleIp:          util.New(""),
	}
	return &tapRecoveryFixture{manager: m, linkOps: linkOps, tapName: tap.Attrs().Name}
}

func convergedTap(t *testing.T, ifindex int) *netlink.Tuntap {
	t.Helper()
	ip := net.ParseIP("10.88.0.5").To4()
	require.NotNil(t, ip)
	hostMAC, err := tapHostMAC(ip)
	require.NoError(t, err)
	return &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name:         util.IpToTap(ip.String()),
			Index:        ifindex,
			MasterIndex:  42,
			HardwareAddr: hostMAC,
		},
		Mode: netlink.TUNTAP_MODE_TAP,
	}
}

func activeLeaseWithIfindex(t *testing.T, ifindex int) string {
	t.Helper()
	ip := net.ParseIP("10.88.0.5").To4()
	guestMAC, err := tapGuestMAC(ip)
	require.NoError(t, err)
	stale := &NetResource{
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeTap,
		GuestMAC:      guestMAC,
		Interface:     &net.Interface{Name: util.IpToTap(ip.String()), Index: ifindex},
		Ip:            ip,
		Mask:          net.CIDRMask(16, 32),
		Gateway:       net.ParseIP("10.88.0.1"),
		Type:          "bridge",
	}
	return stale.ToString()
}

// TestRecoveryRejectsExternallyReplacedActiveTap pins the reviewer-requested
// boundary: sandboxd never recreates a leased TAP, so an ifindex mismatch on
// an ACTIVE lease means the device was replaced externally and the owning
// sandbox's networking is already broken (the guest holds the old device).
// Recovery must refuse to adopt the replacement instead of refreshing the
// lease record over a dead endpoint.
func TestRecoveryRejectsExternallyReplacedActiveTap(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	lease := activeLeaseWithIfindex(t, 7)
	f.manager.usingInterfaces.Set(lease, struct{}{})

	err := f.manager.load(sets.New[string]())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "was replaced externally")
	assert.Contains(t, err.Error(), "ifindex 13, durable lease records 7")

	// The durable lease is left untouched for the operator to resolve.
	assert.True(t, f.manager.usingInterfaces.Has(lease))
	assert.Zero(t, f.linkOps.setUpCount,
		"a replaced endpoint must not be adopted (no LinkSetUp)")
}

// TestRecoveryRepairsIdleOrphanMacAndBridgeDrift is the other half of the
// reviewer-requested pair: an orphan tap with no lease — e.g. left by a
// predecessor that died inside the createTapDevice window (random MAC, no
// bridge) — is adopted with its deterministic attributes repaired in place.
func TestRecoveryRepairsIdleOrphanMacAndBridgeDrift(t *testing.T) {
	tap := convergedTap(t, 13)
	tap.LinkAttrs.MasterIndex = 0 // detached
	tap.LinkAttrs.HardwareAddr = net.HardwareAddr{0x2a, 0x21, 0xc6, 0xf4, 0x97, 0xe0}
	f := newTapRecoveryFixture(t, tap)

	require.NoError(t, f.manager.load(sets.New[string]()))

	assert.Equal(t, 1, f.linkOps.setMasterCount, "bridge attach must be repaired")
	assert.Equal(t, 1, f.linkOps.setMACCount, "host MAC must be re-stamped")
	assert.Equal(t, 1, f.linkOps.setDownCount, "adopted idle tap must be set down")
	assert.Zero(t, f.linkOps.setUpCount)

	using, idle := f.manager.Status()
	assert.Empty(t, using)
	require.Len(t, idle, 1)
	adopted, err := NewNetResource(idle[0])
	require.NoError(t, err)
	require.NotNil(t, adopted.Interface)
	assert.Equal(t, f.tapName, adopted.Interface.Name)
}

// TestAllocationRefreshKeepsLeaseAndExternalStringConsistent covers the
// remaining ifindex-refresh path: a lease re-handed out by markUsing (no
// external consumer yet). The refreshed serialization is what gets stored
// AND what the caller persists as the sandbox annotation, so records and
// external holders can never diverge.
func TestAllocationRefreshKeepsLeaseAndExternalStringConsistent(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	// An idle lease whose device was externally recreated while idle (no
	// consumer); markUsing is the post-pop validation Allocate runs.
	stale := activeLeaseWithIfindex(t, 7)

	handedOut, err := f.manager.markUsing(stale)
	require.NoError(t, err)

	// The stored key IS the handed-out string (with current bookkeeping).
	assert.True(t, f.manager.usingInterfaces.Has(handedOut))
	refreshed, err := NewNetResource(handedOut)
	require.NoError(t, err)
	assert.EqualValues(t, 13, refreshed.Interface.Index)
	assert.NotEqual(t, stale, handedOut,
		"the refreshed serialization must replace the stale one everywhere")
	assert.Equal(t, 1, f.linkOps.setUpCount)

	// Sandbox deletion with that exact string recycles cleanly.
	assert.NoError(t, f.manager.Release(handedOut))
	using, idle := f.manager.Status()
	assert.Empty(t, using)
	assert.Len(t, idle, 1)
}

// TestResolveLeaseKeyRejectsForeignIdentity pins the resolution boundary: a
// miss that does not match any active lease by immutable identity stays a
// miss, so unrelated or malformed strings still take the no-op paths.
func TestResolveLeaseKeyRejectsForeignIdentity(t *testing.T) {
	f := newTapRecoveryFixture(t, convergedTap(t, 13))
	stored := activeLeaseWithIfindex(t, 13)
	f.manager.usingInterfaces.Set(stored, struct{}{})

	// Same immutable identity under an older serialization resolves.
	staleView := activeLeaseWithIfindex(t, 7)
	key, ok := f.manager.resolveLeaseKey(staleView)
	assert.True(t, ok)
	assert.Equal(t, stored, key)

	foreign := (&NetResource{
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeTap,
		Interface:     &net.Interface{Name: util.IpToTap("10.88.0.9"), Index: 99},
		Ip:            net.ParseIP("10.88.0.9"),
		Type:          "bridge",
	}).ToString()

	_, ok = f.manager.resolveLeaseKey(foreign)
	assert.False(t, ok)

	_, ok = f.manager.resolveLeaseKey("not-json")
	assert.False(t, ok)

	// Unrelated strings keep the silent no-op semantics.
	assert.NoError(t, f.manager.Deactivate(foreign))
	assert.Zero(t, f.linkOps.setDownCount)
	assert.Equal(t, 1, f.manager.usingInterfaces.Count(),
		"the real lease must be untouched by a foreign Deactivate")
}
