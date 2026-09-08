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

package networkacl

import (
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// newProtectedRestoreManager builds a model-level manager whose link lookups
// come from the injected ifindex table, so endpoint-identity verification runs
// without touching the kernel. Entries keep a nonzero ifindex: the protected
// path performs no kernel mutation, so nil BPF objects are never reached.
func newProtectedRestoreManager(
	entries map[string]persistedEntry,
	ifIndex map[string]int,
) *Manager {
	manager := &Manager{
		store:       store.NewMockStore(),
		entries:     entries,
		sourceIndex: make(map[string]string),
	}
	for sandboxID, entry := range entries {
		if !entry.Orphaned {
			manager.sourceIndex[entry.IP] = sandboxID
		}
	}
	manager.linkIndex = func(name string) (int, error) {
		if index, ok := ifIndex[name]; ok {
			return index, nil
		}
		return 0, &netlink.LinkNotFoundError{}
	}
	return manager
}

func pendingOwner(sandboxID string, ip net.IP, hostVeth string, ifIndex int) ProtectedBinding {
	return ProtectedBinding{
		Binding: Binding{SandboxID: sandboxID, IP: ip, HostVeth: hostVeth},
		IfIndex: ifIndex,
	}
}

func pendingEntry() persistedEntry {
	return persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-pend", IfIndex: 42, Generation: 3,
		Policy: Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}},
	}
}

func persistedEntries(t *testing.T, manager *Manager) map[string]persistedEntry {
	t.Helper()
	raw, err := manager.store.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	return state.Entries
}

// A retained failed start keeps its registered entry exactly as the kernel
// still enforces it: no re-apply, no generation bump, no orphan cleanup, and
// the DNS source index is rebuilt so the entry keeps authorizing as before.
func TestRestoreRetainsProtectedPendingEntry(t *testing.T) {
	entry := pendingEntry()
	manager := newProtectedRestoreManager(
		map[string]persistedEntry{"pend": entry},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, manager.persistLocked())

	require.NoError(t, manager.Restore(nil, map[string]ProtectedBinding{
		"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
	}))

	retained, exists := manager.entries["pend"]
	require.True(t, exists)
	assert.Equal(t, entry, retained, "protection must not rewrite the retained entry")
	assert.Equal(t, "pend", manager.sourceIndex[entry.IP])
	assert.Equal(t, entry, persistedEntries(t, manager)["pend"])
}

// A durable cleanup intent recorded on a protected entry means deletion was
// already authorized and possibly partially executed before the restart; how
// much kernel state survives is unknowable, so retention refuses it — the
// definite error defers to reconciliation instead of guessing either way.
func TestRestoreProtectedRefusesDurableCleanupIntent(t *testing.T) {
	entry := pendingEntry()
	entry.Orphaned = true
	manager := newProtectedRestoreManager(
		map[string]persistedEntry{"pend": entry},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, manager.persistLocked())
	before, err := manager.store.LoadRaw(stateStoreKey)
	require.NoError(t, err)

	err = manager.Restore(nil, map[string]ProtectedBinding{
		"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
	})
	require.ErrorContains(t, err, "durable cleanup intent")

	retained, exists := manager.entries["pend"]
	require.True(t, exists)
	assert.True(t, retained.Orphaned)
	assert.NotContains(t, manager.sourceIndex, entry.IP)
	after, err := manager.store.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

// The ambiguous crash state — metadata already recovered as an active sandbox
// while the start intent is still pending — must verify the two views agree
// and then keep the protected semantics: an active-path restore would bump the
// policy generation of the non-empty policy, protection leaves it untouched.
func TestRestoreProtectedActiveSameIDVerifiedNotOverwritten(t *testing.T) {
	entry := pendingEntry()
	manager := newProtectedRestoreManager(
		map[string]persistedEntry{"pend": entry},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, manager.persistLocked())

	active := map[string]Binding{
		"pend": {SandboxID: "pend", IP: net.ParseIP("10.88.0.2"), HostVeth: "acl-pend"},
	}
	require.NoError(t, manager.Restore(active, map[string]ProtectedBinding{
		"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
	}))

	retained, exists := manager.entries["pend"]
	require.True(t, exists)
	assert.Equal(t, entry, retained, "protection must not re-apply the same-ID entry")
	assert.Equal(t, "pend", manager.sourceIndex[entry.IP])

	manager = newProtectedRestoreManager(
		map[string]persistedEntry{"pend": entry},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, manager.persistLocked())
	err := manager.Restore(
		map[string]Binding{
			"pend": {SandboxID: "pend", IP: net.ParseIP("10.88.0.9"), HostVeth: "acl-other"},
		},
		map[string]ProtectedBinding{
			"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
		},
	)
	require.ErrorContains(t, err, "contradicts its pending start intent")
}

// A pending intent with network ownership but no ACL entry is missing key
// evidence (ACL was disabled or switched around the retained start), and a
// contradictory entry identity is never a takeover proof. Both fail before
// any destructive reconciliation — the ordinary orphan pass must not run.
func TestRestoreProtectedFailuresHappenBeforeOrphanCleanup(t *testing.T) {
	pending := func() *persistedEntry {
		entry := pendingEntry()
		return &entry
	}
	cases := []struct {
		name    string
		entry   *persistedEntry
		extra   map[string]persistedEntry
		active  map[string]Binding
		owner   ProtectedBinding
		ifIndex map[string]int
		message string
	}{
		{
			name:    "missing entry",
			entry:   nil,
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42},
			message: "has no managed network ACL state",
		},
		{
			name: "durable cleanup intent",
			entry: func() *persistedEntry {
				entry := pendingEntry()
				entry.Orphaned = true
				return &entry
			}(),
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42},
			message: "durable cleanup intent",
		},
		{
			name:  "active binding for another sandbox claims the lease",
			entry: pending(),
			active: map[string]Binding{
				"other": {SandboxID: "other", IP: net.ParseIP("10.88.0.2"), HostVeth: "acl-pend"},
			},
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42},
			message: "claims the network endpoint",
		},
		{
			name:    "ip mismatch",
			entry:   &persistedEntry{IP: "10.88.0.9", HostVeth: "acl-pend", IfIndex: 42},
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42},
			message: "contradicts its recorded network resource",
		},
		{
			name:    "host veth mismatch",
			entry:   &persistedEntry{IP: "10.88.0.2", HostVeth: "acl-other", IfIndex: 42},
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-other": 42},
			message: "contradicts its recorded network resource",
		},
		{
			name:    "recorded ifindex mismatch",
			entry:   &persistedEntry{IP: "10.88.0.2", HostVeth: "acl-pend", IfIndex: 40},
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42},
			message: "contradicts its recorded network resource",
		},
		{
			name:    "live endpoint missing",
			entry:   pending(),
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{},
			message: "find host endpoint acl-pend",
		},
		{
			name:    "live endpoint ifindex reused",
			entry:   pending(),
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 77},
			message: "a reused ifindex or renamed endpoint is not a takeover proof",
		},
		{
			name:  "another entry claims the ip",
			entry: pending(),
			extra: map[string]persistedEntry{
				"other": {IP: "10.88.0.2", HostVeth: "acl-other", IfIndex: 43},
			},
			owner:   pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			ifIndex: map[string]int{"acl-pend": 42, "acl-other": 43},
			message: "conflicts with the entry owned by other",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entries := map[string]persistedEntry{
				// A true orphan alongside the failing protected owner: a valid
				// reconciliation would clean it, so its survival proves no
				// destructive call ran.
				"orphan": {IP: "10.88.0.8", HostVeth: "acl-orphan", IfIndex: 0, Orphaned: false},
			}
			if testCase.entry != nil {
				entries["pend"] = *testCase.entry
			}
			for sandboxID, entry := range testCase.extra {
				entries[sandboxID] = entry
			}
			manager := newProtectedRestoreManager(entries, testCase.ifIndex)
			require.NoError(t, manager.persistLocked())
			before, err := manager.store.LoadRaw(stateStoreKey)
			require.NoError(t, err)

			err = manager.Restore(testCase.active, map[string]ProtectedBinding{"pend": testCase.owner})
			require.ErrorContains(t, err, testCase.message)

			assert.Contains(t, manager.entries, "orphan", "orphan cleanup must not run on failed verification")
			for sandboxID, entry := range entries {
				assert.Equal(t, entry, manager.entries[sandboxID], "%s must stay untouched", sandboxID)
			}
			after, err := manager.store.LoadRaw(stateStoreKey)
			require.NoError(t, err)
			assert.JSONEq(t, string(before), string(after), "no durable state may change on failed verification")
		})
	}
}

// Ownership claimed by a foreign entry — same IP, same host veth, or the same
// ifindex regardless of orphan marking — is a contradiction, because cleaning
// the other entry could destroy the protected endpoint's kernel state.
func TestRestoreProtectedCrossOwnershipFails(t *testing.T) {
	cases := []struct {
		name    string
		other   persistedEntry
		ifIndex map[string]int
	}{
		{
			name:    "same ip",
			other:   persistedEntry{IP: "10.88.0.2", HostVeth: "acl-other", IfIndex: 43},
			ifIndex: map[string]int{"acl-pend": 42, "acl-other": 43},
		},
		{
			name:    "same host veth",
			other:   persistedEntry{IP: "10.88.0.9", HostVeth: "acl-pend", IfIndex: 43},
			ifIndex: map[string]int{"acl-pend": 42},
		},
		{
			name:    "same ifindex on an orphaned entry",
			other:   persistedEntry{IP: "10.88.0.9", HostVeth: "acl-other", IfIndex: 42, Orphaned: true},
			ifIndex: map[string]int{"acl-pend": 42, "acl-other": 42},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			manager := newProtectedRestoreManager(
				map[string]persistedEntry{"pend": pendingEntry(), "other": testCase.other},
				testCase.ifIndex,
			)
			require.NoError(t, manager.persistLocked())

			err := manager.Restore(nil, map[string]ProtectedBinding{
				"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
			})
			require.ErrorContains(t, err, "conflicts with the entry owned by other")
		})
	}
}

// Ordinary semantics stay compatible beside protection: an active binding
// without protection is still resolved and re-owned, and a true orphan is
// still cleaned while a protected pending entry survives. The active apply
// path is kernel-bound (even an empty policy clears state at the live
// ifindex), so the active-control model test resolves its endpoint to ifindex
// zero — the recorded zero keeps the apply a no-op — and asserts the ownership
// accounting; kernel behavior stays covered by the tagged integration tests.
func TestRestoreActiveControlAndTrueOrphanUnchanged(t *testing.T) {
	activeManager := newProtectedRestoreManager(
		map[string]persistedEntry{
			"live": {IP: "10.88.0.3", HostVeth: "acl-live", IfIndex: 0, Orphaned: true},
			"pend": pendingEntry(),
		},
		map[string]int{"acl-live": 0, "acl-pend": 42},
	)
	require.NoError(t, activeManager.persistLocked())
	require.NoError(t, activeManager.Restore(
		map[string]Binding{
			"live": {SandboxID: "live", IP: net.ParseIP("10.88.0.3"), HostVeth: "acl-live"},
		},
		map[string]ProtectedBinding{
			"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
		},
	))
	resolved, exists := activeManager.entries["live"]
	require.True(t, exists)
	assert.False(t, resolved.Orphaned, "an ordinary active restore keeps re-owning the entry")
	assert.Equal(t, "live", activeManager.sourceIndex["10.88.0.3"])

	orphanManager := newProtectedRestoreManager(
		map[string]persistedEntry{
			"pend":   pendingEntry(),
			"orphan": {IP: "10.88.0.8", HostVeth: "acl-orphan", IfIndex: 0},
		},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, orphanManager.persistLocked())
	require.NoError(t, orphanManager.Restore(nil, map[string]ProtectedBinding{
		"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 42),
	}))
	assert.NotContains(t, orphanManager.entries, "orphan", "a true orphan must still be reconciled")
	assert.Equal(t, pendingEntry(), orphanManager.entries["pend"])
	stored := persistedEntries(t, orphanManager)
	assert.Contains(t, stored, "pend")
	assert.NotContains(t, stored, "orphan")
}

// A malformed protected owner (no ifindex recorded, no IPv4, no endpoint) is
// rejected like missing evidence rather than weakening the identity check.
func TestRestoreProtectedRejectsIncompleteOwner(t *testing.T) {
	manager := newProtectedRestoreManager(
		map[string]persistedEntry{"pend": pendingEntry()},
		map[string]int{"acl-pend": 42},
	)
	require.NoError(t, manager.persistLocked())

	err := manager.Restore(nil, map[string]ProtectedBinding{
		"pend": pendingOwner("pend", net.ParseIP("10.88.0.2"), "acl-pend", 0),
	})
	require.ErrorContains(t, err, "recorded ifindex")
	require.True(t, errors.Is(err, err))

	err = manager.Restore(nil, map[string]ProtectedBinding{
		"pend": pendingOwner("", net.ParseIP("10.88.0.2"), "acl-pend", 42),
	})
	require.ErrorContains(t, err, "requires a sandbox ID")
}
