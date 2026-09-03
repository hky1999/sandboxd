// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingIPSet struct {
	commands [][]string
	failOne  func(args []string) bool
}

type memoryIPTables struct {
	chains  map[string][][]string
	failOne func(operation, chain string, rulespec []string) bool
}

func newMemoryIPTables() *memoryIPTables {
	return &memoryIPTables{chains: map[string][][]string{
		forwardChain: {},
		inputChain:   {},
		outputChain:  {},
	}}
}

func (m *memoryIPTables) shouldFail(operation, chain string, rulespec []string) error {
	if m.failOne == nil || !m.failOne(operation, chain, rulespec) {
		return nil
	}
	m.failOne = nil
	return errors.New("injected iptables failure")
}

func (m *memoryIPTables) Append(_, chain string, rulespec ...string) error {
	if err := m.shouldFail("append", chain, rulespec); err != nil {
		return err
	}
	if _, ok := m.chains[chain]; !ok {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	m.chains[chain] = append(m.chains[chain], append([]string(nil), rulespec...))
	return nil
}

func (m *memoryIPTables) Insert(_, chain string, pos int, rulespec ...string) error {
	if err := m.shouldFail("insert", chain, rulespec); err != nil {
		return err
	}
	rules, ok := m.chains[chain]
	if !ok {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	index := pos - 1
	if index < 0 || index > len(rules) {
		return fmt.Errorf("invalid insertion position %d", pos)
	}
	rule := append([]string(nil), rulespec...)
	rules = append(rules, nil)
	copy(rules[index+1:], rules[index:])
	rules[index] = rule
	m.chains[chain] = rules
	return nil
}

func (m *memoryIPTables) Delete(_ string, chain string, rulespec ...string) error {
	if err := m.shouldFail("delete", chain, rulespec); err != nil {
		return err
	}
	rules, ok := m.chains[chain]
	if !ok {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	for index, rule := range rules {
		if equalStringSlice(rule, rulespec) {
			m.chains[chain] = append(rules[:index], rules[index+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule does not exist in chain %s", chain)
}

func (m *memoryIPTables) DeleteIfExists(table, chain string, rulespec ...string) error {
	exists, err := m.Exists(table, chain, rulespec...)
	if err != nil || !exists {
		return err
	}
	return m.Delete(table, chain, rulespec...)
}

func (m *memoryIPTables) Exists(_ string, chain string, rulespec ...string) (bool, error) {
	rules, ok := m.chains[chain]
	if !ok {
		return false, fmt.Errorf("chain %s does not exist", chain)
	}
	for _, rule := range rules {
		if equalStringSlice(rule, rulespec) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memoryIPTables) ChainExists(_, chain string) (bool, error) {
	_, ok := m.chains[chain]
	return ok, nil
}

func (m *memoryIPTables) NewChain(_, chain string) error {
	if _, ok := m.chains[chain]; ok {
		return fmt.Errorf("chain %s already exists", chain)
	}
	m.chains[chain] = nil
	return nil
}

func (m *memoryIPTables) ClearChain(_, chain string) error {
	if err := m.shouldFail("clear", chain, nil); err != nil {
		return err
	}
	if _, ok := m.chains[chain]; !ok {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	m.chains[chain] = nil
	return nil
}

func (m *memoryIPTables) DeleteChain(_, chain string) error {
	if _, ok := m.chains[chain]; !ok {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	delete(m.chains, chain)
	return nil
}

func (m *memoryIPTables) List(_, chain string) ([]string, error) {
	rules, ok := m.chains[chain]
	if !ok {
		return nil, fmt.Errorf("chain %s does not exist", chain)
	}
	out := []string{"-N " + chain}
	for _, rule := range rules {
		out = append(out, "-A "+chain+" "+strings.Join(rule, " "))
	}
	return out, nil
}

func (m *memoryIPTables) ListChains(_ string) ([]string, error) {
	chains := make([]string, 0, len(m.chains))
	for chain := range m.chains {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	return chains, nil
}

func equalStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (m *memoryIPTables) target(t *testing.T, chain string) string {
	t.Helper()
	rules, ok := m.chains[chain]
	require.True(t, ok, "chain %s should exist", chain)
	require.NotEmpty(t, rules, "chain %s should contain a dispatcher", chain)
	require.Len(t, rules[0], 2)
	require.Equal(t, "-j", rules[0][0])
	return rules[0][1]
}

func (s *recordingIPSet) Run(args ...string) error {
	s.commands = append(s.commands, append([]string(nil), args...))
	if s.failOne != nil && s.failOne(args) {
		s.failOne = nil
		return errors.New("injected ipset failure")
	}
	return nil
}

func (s *recordingIPSet) Output(args ...string) (string, error) {
	s.commands = append(s.commands, append([]string(nil), args...))
	return "", nil
}

func TestIPTablesPrerequisiteProbeExercisesConnectionMarks(t *testing.T) {
	client := newMemoryIPTables()
	ipv6Client := newMemoryIPTables()
	ipset := &recordingIPSet{}
	var appended [][]string
	client.failOne = func(operation, chain string, rulespec []string) bool {
		if operation == "append" && chain == ipv4ProbeChain {
			appended = append(appended, append([]string(nil), rulespec...))
		}
		return false
	}
	backend := &iptablesBackend{
		client: client, ipv6Client: ipv6Client, ipset: ipset,
	}

	require.NoError(t, backend.validatePrerequisites())
	assert.Contains(t, appended, []string{
		"-m", "conntrack", "--ctstate", "NEW",
		"-j", "CONNMARK", "--set-xmark", "0xa5c10001/0xffff0001",
	})
	assert.Contains(t, appended, []string{
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "REPLY",
		"-m", "connmark", "--mark", "0xa5c10001/0xffff0001", "-j", "RETURN",
	})
	_, ipv4ProbeExists := client.chains[ipv4ProbeChain]
	_, ipv6ProbeExists := ipv6Client.chains[ipv6ProbeChain]
	assert.False(t, ipv4ProbeExists)
	assert.False(t, ipv6ProbeExists)
	assert.Empty(t, client.chains[forwardChain])
	assert.Empty(t, ipv6Client.chains[forwardChain])
	assert.Empty(t, client.chains[outputChain])
	assert.Empty(t, ipv6Client.chains[outputChain])
	assert.Equal(t, [][]string{
		{"destroy", ipsetProbeName},
		{"create", ipsetProbeName, "hash:ip", "family", "inet", "timeout", "1", "maxelem", "1"},
		{"destroy", ipsetProbeName},
	}, ipset.commands)
}

func TestEnsureDropBarrierRejectsConditionalDropAsCanonical(t *testing.T) {
	client := newMemoryIPTables()
	require.NoError(t, client.NewChain(filterTable, dropBarrierChain))
	require.NoError(t, client.Append(
		filterTable, dropBarrierChain, "-s", "192.0.2.1", "-j", "DROP",
	))
	backend := &iptablesBackend{client: client}

	require.NoError(t, backend.ensureDropBarrier())
	assert.Equal(t, []string{"-j", "DROP"}, client.chains[dropBarrierChain][0])
}

func TestIPTablesPrerequisiteProbeFailsClosedWithoutConnmark(t *testing.T) {
	client := newMemoryIPTables()
	client.failOne = func(operation, chain string, rulespec []string) bool {
		return operation == "append" && chain == ipv4ProbeChain &&
			strings.Contains(strings.Join(rulespec, " "), "-m connmark")
	}
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(), ipset: &recordingIPSet{},
	}

	err := backend.validatePrerequisites()
	require.ErrorContains(t, err, "requires the connmark match")
	_, probeExists := client.chains[ipv4ProbeChain]
	assert.False(t, probeExists)
}

func TestIPTablesPrerequisiteProbeFailsClosedWithoutBridgedOutput(t *testing.T) {
	client := newMemoryIPTables()
	client.failOne = func(operation, chain string, rulespec []string) bool {
		return operation == "insert" && chain == outputChain &&
			containsString(rulespec, "--physdev-is-bridged")
	}
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(), ipset: &recordingIPSet{},
	}

	err := backend.validatePrerequisites()
	require.ErrorContains(t, err, "requires IPv4 bridged OUTPUT matching")
	_, probeExists := client.chains[ipv4ProbeChain]
	assert.False(t, probeExists)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestIPTablesRulesAreStatefulAndDenyFirst(t *testing.T) {
	backend := &iptablesBackend{bridgeIP: net.ParseIP("10.88.0.1")}
	policy := Policy{
		DNS: &DNSPolicy{},
		Traffic: &TrafficPolicy{
			DefaultAction: actionDeny,
			Mode:          policyModeStateful,
			Rules: []TrafficRule{
				{
					Action: actionAllow, Directions: []uint8{directionIngress},
					Protocol: 6, PeerAny: true, SandboxPort: 50090,
				},
				{
					Action: actionDeny, Directions: []uint8{directionIngress},
					Protocol: 6, PeerIP: [4]byte{192, 0, 2, 10}, PeerPort: 32000,
					SandboxPort: 50090,
				},
			},
		},
	}
	rules := backend.compileRules(policy, directionIngress, 7)
	require.GreaterOrEqual(t, len(rules), 11)
	destinationMark := "0xa5c10002/0xffff0002"
	sourceMark := "0xa5c10001/0xffff0001"
	assert.Equal(t, []string{"-p", "tcp", "-s", "10.88.0.1", "--sport", "53", "-j", "RETURN"}, rules[0])
	assert.Equal(t, []string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"}, rules[4])
	assert.Equal(t, []string{
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"--ctdir", "ORIGINAL", "-m", "connmark", "--mark", destinationMark,
		"-j", "RETURN",
	}, rules[5])
	assert.Equal(t, []string{
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"--ctdir", "REPLY", "-m", "connmark", "--mark", sourceMark,
		"-j", "RETURN",
	}, rules[6])
	assert.Equal(t, []string{
		"-p", "tcp", "-s", "192.0.2.10", "--sport", "32000", "--dport", "50090", "-j", "DROP",
	}, rules[7])
	assert.Equal(t, []string{
		"-p", "tcp", "--dport", "50090", "-m", "conntrack", "--ctstate", "NEW",
		"-j", "CONNMARK", "--set-xmark", destinationMark,
	}, rules[8])
	assert.Equal(t, []string{"-p", "tcp", "--dport", "50090", "-j", "RETURN"}, rules[9])
	assert.Equal(t, []string{"-j", "DROP"}, rules[10])
}

func TestIPTablesConnectionMarkIsSharedAcrossManagedEndpoints(t *testing.T) {
	assert.Equal(t, uint32(0xa5c10000), aclConnectionMark)
	assert.Equal(t, uint32(0xffff0000), aclConnectionMarkMask)
	assert.Equal(t, "0xa5c10001/0xffff0001", aclConnectionMarkSpec(aclConnectionSourceBit))
	assert.Equal(t, "0xa5c10002/0xffff0002", aclConnectionMarkSpec(aclConnectionDestinationBit))
}

func TestIPTablesChainNamesFitKernelLimit(t *testing.T) {
	names := make([]string, 0, 4)
	egress, ingress, generationEgress, generationIngress := iptablesChainNames(
		net.ParseIP("255.255.255.255"), ^uint64(0),
	)
	names = append(names, egress, ingress, generationEgress, generationIngress)
	for _, name := range names {
		assert.LessOrEqual(t, len(name), 28, name)
	}
}

func TestIPTablesHooksCoverForwardedAndNodeLocalTraffic(t *testing.T) {
	hooks := aclIPTablesHooks(net.ParseIP("10.88.0.2"), "pv.0a580002", "egress", "ingress")
	assert.Equal(t, []iptablesHook{
		{chain: "FORWARD", rule: []string{
			"-s", "10.88.0.2", "-j", "egress",
		}},
		{chain: "FORWARD", rule: []string{
			"-m", "physdev", "--physdev-in", "pv.0a580002", "!", "-s", "10.88.0.2", "-j", "DROP",
		}},
		{chain: "INPUT", rule: []string{
			"-s", "10.88.0.2", "-j", "egress",
		}},
		{chain: "INPUT", rule: []string{
			"-m", "physdev", "--physdev-in", "pv.0a580002", "!", "-s", "10.88.0.2", "-j", "DROP",
		}},
		{chain: "FORWARD", rule: []string{
			"-d", "10.88.0.2", "-j", "ingress",
		}},
		{chain: "FORWARD", rule: []string{
			"-m", "physdev", "--physdev-out", "pv.0a580002", "!", "-d", "10.88.0.2", "-j", "DROP",
		}},
		{chain: "OUTPUT", rule: []string{
			"-d", "10.88.0.2", "-j", "ingress",
		}},
		{chain: "OUTPUT", rule: []string{
			"-m", "physdev", "--physdev-is-bridged", "--physdev-out", "pv.0a580002",
			"!", "-d", "10.88.0.2", "-j", "DROP",
		}},
	}, hooks)
}

func TestIP6TablesHooksDropTrafficOnTheSandboxBridgePort(t *testing.T) {
	hooks := aclIP6TablesHooks("pv.0a580002")
	assert.Equal(t, []iptablesHook{
		{chain: "FORWARD", rule: []string{
			"-m", "physdev", "--physdev-in", "pv.0a580002", "-j", "DROP",
		}},
		{chain: "INPUT", rule: []string{
			"-m", "physdev", "--physdev-in", "pv.0a580002", "-j", "DROP",
		}},
		{chain: "FORWARD", rule: []string{
			"-m", "physdev", "--physdev-out", "pv.0a580002", "-j", "DROP",
		}},
		{chain: "OUTPUT", rule: []string{
			"-m", "physdev", "--physdev-is-bridged", "--physdev-out", "pv.0a580002", "-j", "DROP",
		}},
	}, hooks)
}

func TestIPTablesV2PriorityCIDRPortRangesAndDomainSets(t *testing.T) {
	backend := &iptablesBackend{bridgeIP: net.ParseIP("10.88.0.1")}
	policy := Policy{
		SchemaVersion: networkPolicySchemaV2,
		Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionDeny,
			Mode:                 policyModeStateless,
			Rules: []TrafficRule{
				{
					Action: actionDeny, Directions: []uint8{directionEgress}, Protocol: 6,
					PeerIP: [4]byte{192, 0, 2, 99}, PeerPrefix: 32,
					PeerPortFirst: 443, PeerPortLast: 443, Priority: 100,
				},
				{
					Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
					PeerIP: [4]byte{192, 0, 2, 0}, PeerPrefix: 24,
					PeerPortFirst: 440, PeerPortLast: 450,
					SandboxPortFirst: 30000, SandboxPortLast: 30100, Priority: 200,
				},
				{
					Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
					PeerDomain: "example.com", PeerPortFirst: 443, PeerPortLast: 443,
					Priority: 150,
				},
			},
		},
	}
	rules := backend.compileRulesForSandbox(
		policy, directionEgress, 9, net.ParseIP("10.88.0.2"),
	)
	require.Len(t, rules, 8)
	assert.Equal(t, []string{
		"-p", "tcp", "-d", "10.88.0.1", "--dport", "53", "-j", "RETURN",
	}, rules[0])
	assert.Equal(t, []string{
		"-p", "tcp", "--dport", "53", "-j", "DROP",
	}, rules[1])
	assert.Equal(t, []string{
		"-p", "tcp", "-d", "192.0.2.0/24", "--dport", "440:450",
		"--sport", "30000:30100", "-j", "RETURN",
	}, rules[4])
	assert.Equal(t, []string{
		"-p", "tcp", "-m", "set", "--match-set",
		domainSetName(net.ParseIP("10.88.0.2"), 9, 2, false), "dst",
		"--dport", "443", "-j", "RETURN",
	}, rules[5])
	assert.Equal(t, []string{
		"-p", "tcp", "-d", "192.0.2.99", "--dport", "443", "-j", "DROP",
	}, rules[6])
	assert.Equal(t, []string{"-j", "DROP"}, rules[7])
	assert.LessOrEqual(t, len(domainSetName(net.ParseIP("255.255.255.255"), ^uint64(0), 255, false)), 31)
}

func TestChangedIPSetPeersDetectsOneRuleRemovedForSharedAddress(t *testing.T) {
	previous := persistedEntry{DomainGrants: []persistedDomainGrant{
		{IP: "192.0.2.10", RuleIndex: 1, ExpiresAt: 100},
		{IP: "192.0.2.10", RuleIndex: 2, ExpiresAt: 200},
	}}
	next := persistedEntry{DomainGrants: []persistedDomainGrant{
		{IP: "192.0.2.10", RuleIndex: 2, ExpiresAt: 200},
	}}

	assert.Equal(t, map[string]struct{}{"192.0.2.10": {}}, changedIPSetPeers(previous, next))
}

func TestConntrackFiltersMatchNATRewrittenSandboxFlows(t *testing.T) {
	sandboxIP := net.ParseIP("10.88.0.2")
	peerIP := net.ParseIP("192.0.2.10")
	publicIP := net.ParseIP("203.0.113.5")
	backendIP := net.ParseIP("198.51.100.7")
	assert.True(t, endpointTupleMatches(sandboxIP, sandboxIP, peerIP, backendIP, publicIP))
	assert.True(t, endpointTupleMatches(sandboxIP, peerIP, publicIP, sandboxIP, peerIP))
	assert.False(t, endpointTupleMatches(sandboxIP, peerIP, publicIP, backendIP, peerIP))

	peers := map[string]struct{}{peerIP.String(): {}}
	assert.True(t, domainPeerTupleMatches(sandboxIP, peers, sandboxIP, peerIP, backendIP))
	assert.False(t, domainPeerTupleMatches(sandboxIP, peers, peerIP, publicIP, sandboxIP))
	assert.False(t, domainPeerTupleMatches(sandboxIP, peers, sandboxIP, publicIP, backendIP))
}

func TestIPTablesStagesCompleteDomainSetBeforeActivation(t *testing.T) {
	recorder := &recordingIPSet{}
	backend := &iptablesBackend{ipset: recorder}
	entry := persistedEntry{
		IP: "10.88.0.2", Generation: 9,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
			Rules: []TrafficRule{{
				Action: actionDeny, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "blocked.example", Priority: 200,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "blocked.example", IP: "192.0.2.10",
			ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
		}},
	}

	require.NoError(t, backend.stageDomainGrants(entry))
	stable := domainSetName(net.ParseIP(entry.IP), entry.Generation, 0, false)
	temporary := domainSetName(net.ParseIP(entry.IP), entry.Generation, 0, true)
	require.Len(t, recorder.commands, 6)
	assert.Equal(t, []string{
		"create", stable, "hash:ip", "family", "inet", "timeout", "3600",
		"maxelem", "4096", "-exist",
	}, recorder.commands[0])
	assert.Equal(t, []string{"destroy", temporary}, recorder.commands[1])
	assert.Equal(t, "create", recorder.commands[2][0])
	assert.Equal(t, []string{"add", temporary, "192.0.2.10"}, recorder.commands[3][:3])
	assert.Equal(t, []string{"swap", temporary, stable}, recorder.commands[4])
	assert.Equal(t, []string{"destroy", temporary}, recorder.commands[5])
}

func TestIPTablesDomainPreparationFailureInstallsBarrierFirst(t *testing.T) {
	client := newMemoryIPTables()
	recorder := &recordingIPSet{}
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(),
		bridgeIP: net.ParseIP("10.88.0.1"), ipset: recorder,
		deleteConntrackForIP: func(net.IP) error { return nil },
	}
	require.NoError(t, backend.ensureDropBarrier())

	previous := persistedEntry{
		IP: "10.88.0.2", HostVeth: "pv.0a580002", Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
			Rules: []TrafficRule{{
				Action: actionDeny, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "blocked.example", Priority: 200,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "blocked.example", IP: "192.0.2.10",
			ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
		}},
	}
	require.NoError(t, backend.apply(persistedEntry{}, previous))
	stableEgress, stableIngress, _, _ := iptablesChainNames(
		net.ParseIP(previous.IP), previous.Generation,
	)

	next := previous
	next.DomainGrants = []persistedDomainGrant{{
		Question: "blocked.example", IP: "192.0.2.11",
		ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
	}}
	recorder.failOne = func(args []string) bool {
		return len(args) >= 2 && args[0] == "create" && strings.HasPrefix(args[1], "T")
	}
	require.Error(t, backend.applyDomainGrants(previous, next))
	assert.Equal(t, dropBarrierChain, client.target(t, stableEgress))
	assert.Equal(t, dropBarrierChain, client.target(t, stableIngress))
}

func TestIPTablesFirstActivationFailureStaysBlockedAndRetries(t *testing.T) {
	client := newMemoryIPTables()
	ipv6Client := newMemoryIPTables()
	backend := &iptablesBackend{
		client: client, ipv6Client: ipv6Client,
		bridgeIP: net.ParseIP("10.88.0.1"), ipset: &recordingIPSet{},
		deleteConntrackForIP: func(net.IP) error { return nil },
	}
	require.NoError(t, backend.ensureDropBarrier())

	next := persistedEntry{
		IP: "10.88.0.2", HostVeth: "pv.0a580002", Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionDeny,
			EgressDefaultAction:  actionDeny,
		}},
	}
	stableEgress, stableIngress, nextEgress, nextIngress := iptablesChainNames(
		net.ParseIP(next.IP), next.Generation,
	)
	client.failOne = func(operation, chain string, rulespec []string) bool {
		return operation == "insert" && chain == stableIngress &&
			equalStringSlice(rulespec, []string{"-j", nextIngress})
	}

	require.Error(t, backend.apply(persistedEntry{}, next))
	assert.Equal(t, dropBarrierChain, client.target(t, stableEgress))
	assert.Equal(t, dropBarrierChain, client.target(t, stableIngress))

	require.NoError(t, backend.apply(persistedEntry{}, next))
	assert.Equal(t, nextEgress, client.target(t, stableEgress))
	assert.Equal(t, nextIngress, client.target(t, stableIngress))
	assert.Equal(t, [][]string{{"-j", nextEgress}, {"-j", "RETURN"}}, client.chains[stableEgress])
	assert.Equal(t, [][]string{{"-j", nextIngress}, {"-j", "RETURN"}}, client.chains[stableIngress])
}

func TestIPTablesRollbackPreservesActiveGenerationAndRemovesTrailingTargets(t *testing.T) {
	client := newMemoryIPTables()
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(),
		bridgeIP: net.ParseIP("10.88.0.1"), ipset: &recordingIPSet{},
		deleteConntrackForIP: func(net.IP) error { return nil },
	}
	require.NoError(t, backend.ensureDropBarrier())

	old := persistedEntry{
		IP: "10.88.0.2", HostVeth: "pv.0a580002", Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
		}},
	}
	next := old
	next.Generation = 2
	next.Policy = Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
		IngressDefaultAction: actionDeny,
		EgressDefaultAction:  actionDeny,
	}}
	require.NoError(t, backend.apply(persistedEntry{}, old))
	stableEgress, stableIngress, oldEgress, oldIngress := iptablesChainNames(
		net.ParseIP(old.IP), old.Generation,
	)
	_, _, nextEgress, nextIngress := iptablesChainNames(net.ParseIP(next.IP), next.Generation)
	oldEgressRules := cloneRules(client.chains[oldEgress])
	oldIngressRules := cloneRules(client.chains[oldIngress])

	// Fail after the replacement target has been staged behind the drop barrier
	// but before that barrier is removed. The attempted generation must remain
	// unreachable until rollback repairs the complete transaction.
	client.failOne = func(operation, chain string, rulespec []string) bool {
		return operation == "delete" && chain == stableEgress &&
			equalStringSlice(rulespec, []string{"-j", dropBarrierChain})
	}
	require.Error(t, backend.apply(old, next))
	assert.Equal(t, dropBarrierChain, client.target(t, stableEgress))
	assert.Equal(t, dropBarrierChain, client.target(t, stableIngress))

	require.NoError(t, backend.rollback(old, next))
	assert.Equal(t, oldEgress, client.target(t, stableEgress))
	assert.Equal(t, oldIngress, client.target(t, stableIngress))
	assert.Equal(t, [][]string{{"-j", oldEgress}, {"-j", "RETURN"}}, client.chains[stableEgress])
	assert.Equal(t, [][]string{{"-j", oldIngress}, {"-j", "RETURN"}}, client.chains[stableIngress])
	assert.Equal(t, oldEgressRules, client.chains[oldEgress])
	assert.Equal(t, oldIngressRules, client.chains[oldIngress])
	_, nextEgressExists := client.chains[nextEgress]
	_, nextIngressExists := client.chains[nextIngress]
	assert.False(t, nextEgressExists)
	assert.False(t, nextIngressExists)
}

func TestIPTablesCleanupHookFailureRetainsBarrierAndRollbackRepairs(t *testing.T) {
	client := newMemoryIPTables()
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(),
		bridgeIP: net.ParseIP("10.88.0.1"), ipset: &recordingIPSet{},
		deleteConntrackForIP: func(net.IP) error { return nil },
	}
	require.NoError(t, backend.ensureDropBarrier())
	old := persistedEntry{
		IP: "10.88.0.2", HostVeth: "pv.0a580002", Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionDeny,
		}},
	}
	require.NoError(t, backend.apply(persistedEntry{}, old))
	stableEgress, stableIngress, oldEgress, oldIngress := iptablesChainNames(
		net.ParseIP(old.IP), old.Generation,
	)
	hooks := aclIPTablesHooks(net.ParseIP(old.IP), old.HostVeth, stableEgress, stableIngress)
	failedHook := hooks[len(hooks)-1]
	client.failOne = func(operation, chain string, rulespec []string) bool {
		return operation == "delete" && chain == failedHook.chain &&
			equalStringSlice(rulespec, failedHook.rule)
	}

	require.Error(t, backend.cleanup(old))
	assert.Equal(t, dropBarrierChain, client.target(t, stableEgress))
	assert.Equal(t, dropBarrierChain, client.target(t, stableIngress))
	for _, hook := range hooks {
		exists, err := client.Exists(filterTable, hook.chain, hook.rule...)
		require.NoError(t, err)
		assert.True(t, exists, "hook should be restored after cleanup failure")
	}

	require.NoError(t, backend.rollback(old, persistedEntry{}))
	assert.Equal(t, oldEgress, client.target(t, stableEgress))
	assert.Equal(t, oldIngress, client.target(t, stableIngress))
}

func TestIPTablesRetryBlocksEveryReachableNextGenerationBeforeRebuild(t *testing.T) {
	client := newMemoryIPTables()
	backend := &iptablesBackend{
		client: client, ipv6Client: newMemoryIPTables(),
		bridgeIP: net.ParseIP("10.88.0.1"), ipset: &recordingIPSet{},
		deleteConntrackForIP: func(net.IP) error { return nil },
	}
	require.NoError(t, backend.ensureDropBarrier())

	old := persistedEntry{
		IP: "10.88.0.2", HostVeth: "pv.0a580002", Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
		}},
	}
	next := old
	next.Generation = 2
	next.Policy = Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
		IngressDefaultAction: actionDeny,
		EgressDefaultAction:  actionDeny,
	}}
	require.NoError(t, backend.apply(persistedEntry{}, old))
	stableEgress, stableIngress, oldEgress, oldIngress := iptablesChainNames(
		net.ParseIP(old.IP), old.Generation,
	)
	_, _, nextEgress, nextIngress := iptablesChainNames(net.ParseIP(next.IP), next.Generation)

	// Model two possible residues of interrupted insert/delete transactions:
	// the next generation can be first, or it can be a trailing target reached
	// after the old generation returns an allowed packet.
	client.chains[nextEgress] = [][]string{{"-j", "DROP"}}
	client.chains[nextIngress] = [][]string{{"-j", "DROP"}}
	client.chains[stableEgress] = [][]string{
		{"-j", nextEgress}, {"-j", dropBarrierChain}, {"-j", "RETURN"},
	}
	client.chains[stableIngress] = [][]string{
		{"-j", oldIngress}, {"-j", nextIngress}, {"-j", "RETURN"},
	}
	unsafeClear := false
	client.failOne = func(operation, chain string, _ []string) bool {
		if operation != "clear" || (chain != nextEgress && chain != nextIngress) {
			return false
		}
		for _, stable := range []string{stableEgress, stableIngress} {
			for _, rule := range client.chains[stable] {
				if len(rule) == 2 && rule[0] == "-j" && rule[1] == chain {
					unsafeClear = true
					return true
				}
			}
		}
		return false
	}

	require.NoError(t, backend.apply(old, next))
	assert.False(t, unsafeClear)
	assert.Equal(t, nextEgress, client.target(t, stableEgress))
	assert.Equal(t, nextIngress, client.target(t, stableIngress))
	_, oldEgressExists := client.chains[oldEgress]
	assert.False(t, oldEgressExists)
}

func cloneRules(input [][]string) [][]string {
	output := make([][]string, len(input))
	for index, rule := range input {
		output[index] = append([]string(nil), rule...)
	}
	return output
}
