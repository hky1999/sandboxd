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

package server

import (
	"context"
	"net"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingACLManager captures the recovery call so the full chain — durable
// intent record → binding reconstruction → ACL Restore — is observable without
// kernel ACL state.
type recordingACLManager struct {
	restoreActive    map[string]networkacl.Binding
	restoreProtected map[string]networkacl.ProtectedBinding
	restoreErr       error
}

func (m *recordingACLManager) Register(networkacl.Binding, networkacl.Policy) error { return nil }
func (m *recordingACLManager) Restore(
	active map[string]networkacl.Binding,
	protected map[string]networkacl.ProtectedBinding,
) error {
	m.restoreActive = active
	m.restoreProtected = protected
	return m.restoreErr
}
func (m *recordingACLManager) SetPolicy(string, networkacl.Policy) error { return nil }
func (m *recordingACLManager) Remove(string) error                       { return nil }
func (m *recordingACLManager) Close() error                              { return nil }

// A real Start that returns ErrStartCleanupPending leaves a retained intent
// whose durable network resource must reach the ACL restore as a protected
// owner — the exact call the real recovery in NewSandboxService makes. This
// is the composition the checker fixture's binding function alone cannot
// prove.
func TestRestoreNetworkACLPassesPendingIntentToProtectedRestore(t *testing.T) {
	handler := &intentRuntimeHandler{
		FakeRuntimeHandler: svc.NewFakeRuntimeHandler(),
		startErr:           svc.ErrStartCleanupPending,
	}
	root := t.TempDir()
	db := store.NewMockStore()
	s := newIntentTestServiceAtRoot(t, handler, root, db)
	const id = "sbox-pending-acl-owner"
	nr := &networkmanager.NetResource{
		Ip:        net.ParseIP("10.0.0.2"),
		Interface: &net.Interface{Name: "acl-pending-fake", Index: 4242},
	}
	s.allocateStartResourceFn = func(_, _, name string) (string, *networkmanager.NetResource, error) {
		if name == config.ResourceNameInterface {
			return nr.ToString(), nr, nil
		}
		return "", nil, nil
	}
	_, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.True(t, s.startIntents.Pending(id), "setup failed to retain the unknown start")

	// Daemon restart over the same durable state: the journal, the empty
	// metadata list, and the network lease record all come from disk.
	recovered := newIntentTestServiceAtRoot(t, handler, root, db)
	require.True(t, recovered.startIntents.Pending(id))
	recorder := &recordingACLManager{}
	recovered.aclMgr = recorder
	require.NoError(t, recovered.restoreNetworkACL())

	owner, ok := recorder.restoreProtected[id]
	require.True(t, ok, "the pending start's network ownership must be protected, not orphan-cleaned")
	assert.Equal(t, id, owner.SandboxID)
	assert.True(t, owner.IP.Equal(nr.Ip))
	assert.Equal(t, nr.Interface.Name, owner.HostVeth)
	assert.Equal(t, nr.Interface.Index, owner.IfIndex)
	binding, ok := recorder.restoreActive[id]
	require.True(t, ok, "the union bindings the fixture checks are the same map passed to Restore")
	assert.Equal(t, networkacl.Binding{
		SandboxID: id,
		IP:        nr.Ip,
		HostVeth:  nr.Interface.Name,
	}, binding)

	// A contradictory ownership record fails the restore instead of letting
	// any destructive reconciliation run.
	recorder.restoreErr = nil
	corrupt := newIntentTestServiceAtRoot(t, handler, root, db)
	corrupt.startIntents.mu.Lock()
	record := corrupt.startIntents.pending[id]
	record.Resources[config.ResourceNameInterface] = "{not a network resource"
	corrupt.startIntents.pending[id] = record
	corrupt.startIntents.mu.Unlock()
	corrupt.aclMgr = recorder
	require.Error(t, corrupt.restoreNetworkACL())
}

func intentRecordForACL(sandboxID string, mutate func(*startIntentRecord)) startIntentRecord {
	record := startIntentRecord{
		Version:    1,
		SandboxID:  sandboxID,
		Generation: "gen-acl-test",
		Runtime:    config.RuntimeNameRunsc,
		Phase:      startIntentPhaseRetained,
		Resources: map[string]string{
			config.ResourceNameInterface: (&networkmanager.NetResource{
				Ip:        net.ParseIP("10.88.0.2"),
				Interface: &net.Interface{Name: "acl-a", Index: 42},
			}).ToString(),
		},
		CreatedAt:      "2026-09-08T00:00:00Z",
		UpdatedAt:      "2026-09-08T00:00:00Z",
		RetainedReason: "runtime retained sandbox after failed start",
	}
	if mutate != nil {
		mutate(&record)
	}
	return record
}

func TestPendingACLOwnership(t *testing.T) {
	t.Run("retained start yields a protected owner with full endpoint identity", func(t *testing.T) {
		protected, err := pendingACLOwnership(
			[]startIntentRecord{intentRecordForACL("pend", nil)}, nil,
		)
		require.NoError(t, err)
		owner := protected["pend"]
		assert.True(t, owner.IP.Equal(net.ParseIP("10.88.0.2")))
		assert.Equal(t, "acl-a", owner.HostVeth)
		assert.Equal(t, 42, owner.IfIndex)
	})

	t.Run("runc intent owns no ACL state", func(t *testing.T) {
		protected, err := pendingACLOwnership([]startIntentRecord{
			intentRecordForACL("pend", func(record *startIntentRecord) {
				record.Runtime = config.RuntimeNameRunc
			}),
		}, nil)
		require.NoError(t, err)
		assert.NotContains(t, protected, "pend")
	})

	t.Run("missing network resource lease is a definite error", func(t *testing.T) {
		_, err := pendingACLOwnership([]startIntentRecord{
			intentRecordForACL("pend", func(record *startIntentRecord) {
				delete(record.Resources, config.ResourceNameInterface)
			}),
		}, nil)
		require.ErrorContains(t, err, "records no network resource lease")
	})

	t.Run("undecodable network resource is a definite error", func(t *testing.T) {
		_, err := pendingACLOwnership([]startIntentRecord{
			intentRecordForACL("pend", func(record *startIntentRecord) {
				record.Resources[config.ResourceNameInterface] = "{broken"
			}),
		}, nil)
		require.ErrorContains(t, err, "decode network resource")
	})

	t.Run("incomplete endpoint identity is a definite error", func(t *testing.T) {
		for name, resource := range map[string]*networkmanager.NetResource{
			"no interface": {Ip: net.ParseIP("10.88.0.2")},
			"no name": {Ip: net.ParseIP("10.88.0.2"),
				Interface: &net.Interface{Index: 42}},
			"no ifindex": {Ip: net.ParseIP("10.88.0.2"),
				Interface: &net.Interface{Name: "acl-a"}},
			"no ip": {Interface: &net.Interface{Name: "acl-a", Index: 42}},
			"non ipv4": {Ip: net.ParseIP("2001:db8::1"),
				Interface: &net.Interface{Name: "acl-a", Index: 42}},
		} {
			_, err := pendingACLOwnership([]startIntentRecord{
				intentRecordForACL("pend", func(record *startIntentRecord) {
					record.Resources[config.ResourceNameInterface] = resource.ToString()
				}),
			}, nil)
			assert.ErrorContains(t, err, "identity is incomplete", name)
		}
	})

	t.Run("same id active and pending must agree, and protection applies", func(t *testing.T) {
		active := map[string]networkacl.Binding{
			"pend": {SandboxID: "pend", IP: net.ParseIP("10.88.0.2"), HostVeth: "acl-a"},
		}
		protected, err := pendingACLOwnership(
			[]startIntentRecord{intentRecordForACL("pend", nil)}, active,
		)
		require.NoError(t, err)
		assert.Contains(t, protected, "pend")

		active = map[string]networkacl.Binding{
			"pend": {SandboxID: "pend", IP: net.ParseIP("10.88.0.9"), HostVeth: "acl-other"},
		}
		_, err = pendingACLOwnership(
			[]startIntentRecord{intentRecordForACL("pend", nil)}, active,
		)
		require.ErrorContains(t, err, "contradicts its pending start intent")
	})

	t.Run("two pending intents cannot claim one lease", func(t *testing.T) {
		_, err := pendingACLOwnership([]startIntentRecord{
			intentRecordForACL("pend-a", nil),
			intentRecordForACL("pend-b", nil),
		}, nil)
		require.ErrorContains(t, err, "both claim network endpoint")
	})
}
