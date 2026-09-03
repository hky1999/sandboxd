// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package networkacl

import (
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePolicyAndDNSMatching(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
		Rules: []*runtime.DNSRule{
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "GitHub.COM."},
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "*.github.com"},
		},
	}})
	require.NoError(t, err)
	assert.False(t, policy.AllowDNS("github.com."))
	assert.False(t, policy.AllowDNS("api.github.com."))
	assert.False(t, policy.AllowDNS("a.b.github.com."))
	assert.True(t, policy.AllowDNS("notgithub.com."))
}

func TestDNSDenyWins(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.DNSRule{
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Pattern: "*.example.com"},
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "blocked.example.com"},
		},
	}})
	require.NoError(t, err)
	assert.True(t, policy.AllowDNS("ok.example.com"))
	assert.False(t, policy.AllowDNS("blocked.example.com"))
	assert.False(t, policy.AllowDNS("example.com"))
}

func TestNormalizeDNSAllowsServiceDiscoveryOwnerNames(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.DNSRule{{
			Action:  runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Pattern: "_grpc._tcp.example.com",
		}},
	}})
	require.NoError(t, err)
	assert.True(t, policy.AllowDNS("_grpc._tcp.example.com."))
}

func TestDomainMatchingDoesNotTreatAQueryWildcardAsAPattern(t *testing.T) {
	assert.False(t, domainMatches("*.example.com", "example.com", false))
	assert.False(t, domainMatches("*.example.com", "example.com", true))
	assert.True(t, domainMatches("api.example.com.", "example.com", true))
}

func TestNormalizeTrafficPolicy(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.TrafficRule{{
			Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Direction: runtime.NetworkDirection_NETWORK_DIRECTION_BOTH,
			Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
			Peer:      &runtime.NetworkEndpoint{Address: "10.88.0.1", Port: 8080},
		}},
	}})
	require.NoError(t, err)
	require.Len(t, policy.Traffic.Rules, 1)
	assert.Equal(t, []uint8{directionIngress, directionEgress}, policy.Traffic.Rules[0].Directions)
	assert.Equal(t, uint8(6), policy.Traffic.Rules[0].Protocol)
}

func TestNormalizeStatefulSandboxPortWithAnyPeer(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Mode:          runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_STATEFUL,
		Rules: []*runtime.TrafficRule{{
			Action:      runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Direction:   runtime.NetworkDirection_NETWORK_DIRECTION_INGRESS,
			Protocol:    runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
			SandboxPort: 50090,
		}},
	}})
	require.NoError(t, err)
	require.Len(t, policy.Traffic.Rules, 1)
	assert.Equal(t, policyModeStateful, policy.Traffic.Mode)
	assert.True(t, policy.Traffic.Rules[0].PeerAny)
	assert.Equal(t, uint16(50090), policy.Traffic.Rules[0].SandboxPort)
}

func TestNormalizeTrafficPolicyV2(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{
		SchemaVersion: networkPolicySchemaV2,
		Traffic: &runtime.TrafficPolicy{
			IngressDefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			EgressDefaultAction:  runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
			Rules: []*runtime.TrafficRule{
				{
					Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
					Protocol:         runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
					Peer:             &runtime.NetworkEndpoint{Cidr: "192.0.2.129/24", PortRange: &runtime.PortRange{First: 443, Last: 445}},
					SandboxPortRange: &runtime.PortRange{First: 30000, Last: 30100}, Priority: 900,
				},
				{
					Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
					Protocol: runtime.NetworkProtocol_NETWORK_PROTOCOL_ANY,
					Peer:     &runtime.NetworkEndpoint{Domain: "*.BÜCHER.example."},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, policy.Traffic)
	assert.Equal(t, actionAllow, policy.Traffic.ActionFor(directionIngress))
	assert.Equal(t, actionDeny, policy.Traffic.ActionFor(directionEgress))
	assert.Equal(t, policyModeStateful, policy.Traffic.Mode)
	require.Len(t, policy.Traffic.Rules, 2)
	assert.Equal(t, [4]byte{192, 0, 2, 0}, policy.Traffic.Rules[0].PeerIP)
	assert.Equal(t, uint8(24), policy.Traffic.Rules[0].PeerPrefix)
	assert.Equal(t, uint16(443), policy.Traffic.Rules[0].PeerPortFirst)
	assert.Equal(t, uint16(445), policy.Traffic.Rules[0].PeerPortLast)
	assert.Equal(t, uint32(900), policy.Traffic.Rules[0].Priority)
	assert.Equal(t, "xn--bcher-kva.example", policy.Traffic.Rules[1].PeerDomain)
	assert.True(t, policy.Traffic.Rules[1].PeerWildcard)
	assert.Equal(t, defaultRulePriority, policy.Traffic.Rules[1].Priority)
	assert.True(t, policy.NeedsDNSProxy())
}

func TestNormalizeTrafficPolicyV2RejectsMixedAndUnsafeFields(t *testing.T) {
	tests := []struct {
		name string
		rule *runtime.TrafficRule
	}{
		{
			name: "legacy peer address",
			rule: &runtime.TrafficRule{
				Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol: runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
				Peer:     &runtime.NetworkEndpoint{Address: "192.0.2.1"},
			},
		},
		{
			name: "ingress domain",
			rule: &runtime.TrafficRule{
				Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_INGRESS,
				Protocol: runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
				Peer:     &runtime.NetworkEndpoint{Domain: "example.com"},
			},
		},
		{
			name: "invalid range",
			rule: &runtime.TrafficRule{
				Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol: runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
				Peer:     &runtime.NetworkEndpoint{Cidr: "192.0.2.0/24", PortRange: &runtime.PortRange{First: 100, Last: 99}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicy(&runtime.NetworkPolicy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &runtime.TrafficPolicy{
					IngressDefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
					EgressDefaultAction:  runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
					Rules:                []*runtime.TrafficRule{test.rule},
				},
			})
			require.Error(t, err)
		})
	}
}

func TestNormalizePolicyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		policy *runtime.NetworkPolicy
	}{
		{name: "unspecified default", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{}}},
		{name: "sandbox port with ICMP", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules: []*runtime.TrafficRule{{
				Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Direction: runtime.NetworkDirection_NETWORK_DIRECTION_INGRESS,
				Protocol: runtime.NetworkProtocol_NETWORK_PROTOCOL_ICMP, SandboxPort: 80,
			}},
		}}},
		{name: "IPv6", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules: []*runtime.TrafficRule{{
				Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
				Peer:      &runtime.NetworkEndpoint{Address: "2001:db8::1", Port: 443},
			}},
		}}},
		{name: "port with any", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules: []*runtime.TrafficRule{{
				Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_ANY,
				Peer:      &runtime.NetworkEndpoint{Address: "192.0.2.1", Port: 443},
			}},
		}}},
		{name: "arbitrary glob", policy: &runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules:         []*runtime.DNSRule{{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "api.*.example.com"}},
		}}},
		{name: "multiple trailing dots", policy: &runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules:         []*runtime.DNSRule{{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "example.com.."}},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicy(test.policy)
			require.Error(t, err)
		})
	}
}
