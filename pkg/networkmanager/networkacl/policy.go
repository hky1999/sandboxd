// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"fmt"
	"net"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"golang.org/x/net/idna"
)

const (
	actionAllow uint8 = 1
	actionDeny  uint8 = 2

	directionIngress uint8 = 1
	directionEgress  uint8 = 2

	policyModeStateless uint8 = 1
	policyModeStateful  uint8 = 2

	networkPolicySchemaV2 uint32 = 2
	defaultRulePriority   uint32 = 100
	maxTrafficRules              = 256
)

type Policy struct {
	SchemaVersion uint32         `json:"schema_version,omitempty"`
	Traffic       *TrafficPolicy `json:"traffic,omitempty"`
	DNS           *DNSPolicy     `json:"dns,omitempty"`
}

type TrafficPolicy struct {
	// DefaultAction is retained in persisted v1 policies. New enforcement uses
	// ActionFor so state written by an older daemon remains fail-closed.
	DefaultAction        uint8         `json:"default_action,omitempty"`
	IngressDefaultAction uint8         `json:"ingress_default_action"`
	EgressDefaultAction  uint8         `json:"egress_default_action"`
	Mode                 uint8         `json:"mode,omitempty"`
	Rules                []TrafficRule `json:"rules,omitempty"`
}

type TrafficRule struct {
	Action       uint8   `json:"action"`
	Directions   []uint8 `json:"directions"`
	Protocol     uint8   `json:"protocol"`
	PeerIP       [4]byte `json:"peer_ip"`
	PeerPrefix   uint8   `json:"peer_prefix,omitempty"`
	PeerAny      bool    `json:"peer_any,omitempty"`
	PeerDomain   string  `json:"peer_domain,omitempty"`
	PeerWildcard bool    `json:"peer_wildcard,omitempty"`
	// PeerPort and SandboxPort retain the persisted v1 representation.
	PeerPort         uint16 `json:"peer_port,omitempty"`
	SandboxPort      uint16 `json:"sandbox_port,omitempty"`
	PeerPortFirst    uint16 `json:"peer_port_first,omitempty"`
	PeerPortLast     uint16 `json:"peer_port_last,omitempty"`
	SandboxPortFirst uint16 `json:"sandbox_port_first,omitempty"`
	SandboxPortLast  uint16 `json:"sandbox_port_last,omitempty"`
	Priority         uint32 `json:"priority"`
}

type DNSPolicy struct {
	DefaultAction uint8     `json:"default_action"`
	Rules         []DNSRule `json:"rules,omitempty"`
}

type DNSRule struct {
	Action   uint8  `json:"action"`
	Name     string `json:"name"`
	Wildcard bool   `json:"wildcard"`
}

func NormalizePolicy(input *runtime.NetworkPolicy) (Policy, error) {
	var out Policy
	if input == nil {
		return out, nil
	}
	if input.SchemaVersion != 0 && input.SchemaVersion != networkPolicySchemaV2 {
		return Policy{}, fmt.Errorf("network policy schema version must be 2 or omitted for v1")
	}
	out.SchemaVersion = input.SchemaVersion
	if input.Traffic != nil {
		traffic, err := normalizeTraffic(input.Traffic, input.SchemaVersion)
		if err != nil {
			return Policy{}, err
		}
		out.Traffic = traffic
	}
	if input.Dns != nil {
		dns, err := normalizeDNS(input.Dns)
		if err != nil {
			return Policy{}, err
		}
		out.DNS = dns
	}
	return out, nil
}

func normalizeTraffic(input *runtime.TrafficPolicy, schemaVersion uint32) (*TrafficPolicy, error) {
	if len(input.Rules) > maxTrafficRules {
		return nil, fmt.Errorf("traffic policy has %d rules; maximum is %d", len(input.Rules), maxTrafficRules)
	}
	var ingressDefault, egressDefault uint8
	var err error
	if schemaVersion == networkPolicySchemaV2 {
		if input.DefaultAction != runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_UNSPECIFIED {
			return nil, fmt.Errorf("traffic default_action cannot be mixed with schema v2 defaults")
		}
		ingressDefault, err = normalizeAction(input.IngressDefaultAction)
		if err != nil {
			return nil, fmt.Errorf("traffic ingress default action: %w", err)
		}
		egressDefault, err = normalizeAction(input.EgressDefaultAction)
		if err != nil {
			return nil, fmt.Errorf("traffic egress default action: %w", err)
		}
	} else {
		if input.IngressDefaultAction != runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_UNSPECIFIED ||
			input.EgressDefaultAction != runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_UNSPECIFIED {
			return nil, fmt.Errorf("schema v2 traffic defaults require schema_version=2")
		}
		ingressDefault, err = normalizeAction(input.DefaultAction)
		if err != nil {
			return nil, fmt.Errorf("traffic default action: %w", err)
		}
		egressDefault = ingressDefault
	}
	mode, err := normalizePolicyMode(input.Mode, schemaVersion)
	if err != nil {
		return nil, fmt.Errorf("traffic policy mode: %w", err)
	}
	out := &TrafficPolicy{
		DefaultAction:        ingressDefault,
		IngressDefaultAction: ingressDefault,
		EgressDefaultAction:  egressDefault,
		Mode:                 mode,
		Rules:                make([]TrafficRule, 0, len(input.Rules)),
	}
	for index, inputRule := range input.Rules {
		rule, err := normalizeTrafficRule(inputRule, schemaVersion, index)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, rule)
	}
	return out, nil
}

func normalizeTrafficRule(input *runtime.TrafficRule, schemaVersion uint32, index int) (TrafficRule, error) {
	if input == nil {
		return TrafficRule{}, fmt.Errorf("traffic rule %d is nil", index)
	}
	action, err := normalizeAction(input.Action)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("traffic rule %d action: %w", index, err)
	}
	directions, err := normalizeDirection(input.Direction)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("traffic rule %d direction: %w", index, err)
	}
	protocol, err := normalizeProtocol(input.Protocol)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("traffic rule %d protocol: %w", index, err)
	}
	rule := TrafficRule{
		Action: action, Directions: directions, Protocol: protocol,
		PeerAny: true, Priority: defaultRulePriority,
	}
	if schemaVersion == networkPolicySchemaV2 {
		if input.SandboxPort != 0 {
			return TrafficRule{}, fmt.Errorf("traffic rule %d sandbox_port cannot be mixed with schema v2", index)
		}
		rule.SandboxPortFirst, rule.SandboxPortLast, err = normalizePortRange(input.SandboxPortRange)
		if err != nil {
			return TrafficRule{}, fmt.Errorf("traffic rule %d sandbox port range: %w", index, err)
		}
		if input.Priority != 0 {
			rule.Priority = input.Priority
		}
		if input.Peer != nil {
			if input.Peer.Address != "" || input.Peer.Port != 0 {
				return TrafficRule{}, fmt.Errorf("traffic rule %d v1 peer fields cannot be mixed with schema v2", index)
			}
			rule.PeerPortFirst, rule.PeerPortLast, err = normalizePortRange(input.Peer.PortRange)
			if err != nil {
				return TrafficRule{}, fmt.Errorf("traffic rule %d peer port range: %w", index, err)
			}
			cidr := strings.TrimSpace(input.Peer.Cidr)
			domain := strings.TrimSpace(input.Peer.Domain)
			if cidr != "" && domain != "" {
				return TrafficRule{}, fmt.Errorf("traffic rule %d peer cannot contain both CIDR and domain", index)
			}
			if cidr != "" {
				rule.PeerIP, rule.PeerPrefix, err = normalizeCIDR(cidr)
				if err != nil {
					return TrafficRule{}, fmt.Errorf("traffic rule %d peer CIDR: %w", index, err)
				}
				rule.PeerAny = false
			} else if domain != "" {
				if !containsDirection(directions, directionEgress) || containsDirection(directions, directionIngress) {
					return TrafficRule{}, fmt.Errorf("traffic rule %d domain peer is valid only for egress", index)
				}
				rule.PeerDomain, rule.PeerWildcard, err = normalizeDomainPattern(domain)
				if err != nil {
					return TrafficRule{}, fmt.Errorf("traffic rule %d peer domain: %w", index, err)
				}
				rule.PeerAny = false
			}
		}
	} else {
		if input.Priority != 0 || input.SandboxPortRange != nil {
			return TrafficRule{}, fmt.Errorf("traffic rule %d schema v2 fields require schema_version=2", index)
		}
		if input.SandboxPort > 65535 {
			return TrafficRule{}, fmt.Errorf("traffic rule %d sandbox port %d exceeds 65535", index, input.SandboxPort)
		}
		if input.SandboxPort != 0 {
			rule.SandboxPort = uint16(input.SandboxPort)
			rule.SandboxPortFirst = uint16(input.SandboxPort)
			rule.SandboxPortLast = uint16(input.SandboxPort)
		}
		if input.Peer != nil {
			if input.Peer.Cidr != "" || input.Peer.Domain != "" || input.Peer.PortRange != nil {
				return TrafficRule{}, fmt.Errorf("traffic rule %d schema v2 peer fields require schema_version=2", index)
			}
			parsed := net.ParseIP(strings.TrimSpace(input.Peer.Address))
			if parsed == nil || parsed.To4() == nil || strings.Contains(input.Peer.Address, ":") {
				return TrafficRule{}, fmt.Errorf("traffic rule %d peer address %q is not IPv4", index, input.Peer.Address)
			}
			if input.Peer.Port > 65535 {
				return TrafficRule{}, fmt.Errorf("traffic rule %d peer port %d exceeds 65535", index, input.Peer.Port)
			}
			copy(rule.PeerIP[:], parsed.To4())
			rule.PeerPrefix = 32
			rule.PeerAny = false
			if input.Peer.Port != 0 {
				rule.PeerPort = uint16(input.Peer.Port)
				rule.PeerPortFirst = uint16(input.Peer.Port)
				rule.PeerPortLast = uint16(input.Peer.Port)
			}
		}
	}
	if hasPortRange(rule) && protocol != 6 && protocol != 17 {
		return TrafficRule{}, fmt.Errorf("traffic rule %d uses ports with a non-TCP/UDP protocol", index)
	}
	return rule, nil
}

func normalizePortRange(input *runtime.PortRange) (uint16, uint16, error) {
	if input == nil {
		return 0, 0, nil
	}
	if input.First == 0 || input.First > 65535 || input.Last == 0 || input.Last > 65535 || input.First > input.Last {
		return 0, 0, fmt.Errorf("range must satisfy 1 <= first <= last <= 65535")
	}
	return uint16(input.First), uint16(input.Last), nil
}

func normalizeCIDR(value string) ([4]byte, uint8, error) {
	var out [4]byte
	trimmed := strings.TrimSpace(value)
	if !strings.Contains(trimmed, "/") {
		trimmed += "/32"
	}
	ip, network, err := net.ParseCIDR(trimmed)
	if err != nil || ip.To4() == nil || strings.Contains(trimmed, ":") {
		return out, 0, fmt.Errorf("%q is not an IPv4 address or CIDR", value)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return out, 0, fmt.Errorf("%q is not an IPv4 CIDR", value)
	}
	copy(out[:], network.IP.To4())
	return out, uint8(ones), nil
}

func hasPortRange(rule TrafficRule) bool {
	return rule.PeerPortFirst != 0 || rule.SandboxPortFirst != 0
}

func normalizePolicyMode(mode runtime.TrafficPolicyMode, schemaVersion uint32) (uint8, error) {
	switch mode {
	case runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_UNSPECIFIED:
		if schemaVersion == networkPolicySchemaV2 {
			return policyModeStateful, nil
		}
		return policyModeStateless, nil
	case runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_STATELESS:
		return policyModeStateless, nil
	case runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_STATEFUL:
		return policyModeStateful, nil
	default:
		return 0, fmt.Errorf("mode must be STATELESS or STATEFUL")
	}
}

func normalizeDNS(input *runtime.DNSPolicy) (*DNSPolicy, error) {
	defaultAction, err := normalizeAction(input.DefaultAction)
	if err != nil {
		return nil, fmt.Errorf("DNS default action: %w", err)
	}
	out := &DNSPolicy{DefaultAction: defaultAction, Rules: make([]DNSRule, 0, len(input.Rules))}
	for index, inputRule := range input.Rules {
		if inputRule == nil {
			return nil, fmt.Errorf("DNS rule %d is nil", index)
		}
		action, err := normalizeAction(inputRule.Action)
		if err != nil {
			return nil, fmt.Errorf("DNS rule %d action: %w", index, err)
		}
		name, wildcard, err := normalizeDomainPattern(inputRule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("DNS rule %d: %w", index, err)
		}
		out.Rules = append(out.Rules, DNSRule{Action: action, Name: name, Wildcard: wildcard})
	}
	return out, nil
}

func normalizeAction(action runtime.NetworkPolicyAction) (uint8, error) {
	switch action {
	case runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW:
		return actionAllow, nil
	case runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY:
		return actionDeny, nil
	default:
		return 0, fmt.Errorf("action must be ALLOW or DENY")
	}
}

func normalizeDirection(direction runtime.NetworkDirection) ([]uint8, error) {
	switch direction {
	case runtime.NetworkDirection_NETWORK_DIRECTION_INGRESS:
		return []uint8{directionIngress}, nil
	case runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS:
		return []uint8{directionEgress}, nil
	case runtime.NetworkDirection_NETWORK_DIRECTION_BOTH:
		return []uint8{directionIngress, directionEgress}, nil
	default:
		return nil, fmt.Errorf("direction must be INGRESS, EGRESS, or BOTH")
	}
}

func normalizeProtocol(protocol runtime.NetworkProtocol) (uint8, error) {
	switch protocol {
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_ANY:
		return 0, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP:
		return 6, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_UDP:
		return 17, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_ICMP:
		return 1, nil
	default:
		return 0, fmt.Errorf("protocol must be ANY, TCP, UDP, or ICMP")
	}
}

func normalizeDomainPattern(pattern string) (string, bool, error) {
	value := strings.ToLower(strings.TrimSpace(pattern))
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	normalized, err := normalizeDomainName(value)
	if err != nil {
		return "", false, fmt.Errorf("domain pattern %q is invalid", pattern)
	}
	return normalized, wildcard, nil
}

func normalizeDomainName(name string) (string, error) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if value == "" || strings.ContainsAny(value, "*?") {
		return "", fmt.Errorf("domain name %q is invalid", name)
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		// DNS-SD owner names use underscores even though they are not host
		// names. Preserve that established DNS-policy capability for ASCII
		// labels while traffic domains still normalize ordinary IDNs.
		ascii = value
		for _, char := range ascii {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') &&
				char != '-' && char != '_' && char != '.' {
				return "", fmt.Errorf("domain name %q is invalid", name)
			}
		}
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("domain name %q is invalid", name)
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain name %q is invalid", name)
		}
	}
	return strings.ToLower(ascii), nil
}

func domainMatches(name, pattern string, wildcard bool) bool {
	normalized, err := normalizeDomainName(name)
	if err != nil {
		return false
	}
	if wildcard {
		return len(normalized) > len(pattern) && strings.HasSuffix(normalized, "."+pattern)
	}
	return normalized == pattern
}

func (p Policy) Empty() bool {
	return p.Traffic == nil && p.DNS == nil
}

func (p Policy) NeedsDNSProxy() bool {
	if p.DNS != nil {
		return true
	}
	if p.Traffic == nil {
		return false
	}
	for _, rule := range p.Traffic.Rules {
		if rule.PeerDomain != "" {
			return true
		}
	}
	return false
}

func (p Policy) AllowDNS(name string) bool {
	if p.DNS == nil {
		return true
	}
	allowed := false
	for _, rule := range p.DNS.Rules {
		if !domainMatches(name, rule.Name, rule.Wildcard) {
			continue
		}
		if rule.Action == actionDeny {
			return false
		}
		allowed = true
	}
	if allowed {
		return true
	}
	return p.DNS.DefaultAction == actionAllow
}

func (p TrafficPolicy) ActionFor(direction uint8) uint8 {
	if direction == directionIngress {
		if p.IngressDefaultAction == 0 {
			return p.DefaultAction
		}
		return p.IngressDefaultAction
	}
	if p.EgressDefaultAction == 0 {
		return p.DefaultAction
	}
	return p.EgressDefaultAction
}

func (r TrafficRule) PeerPorts() (uint16, uint16) {
	if r.PeerPortFirst == 0 && r.PeerPort != 0 {
		return r.PeerPort, r.PeerPort
	}
	return r.PeerPortFirst, r.PeerPortLast
}

func (r TrafficRule) SandboxPorts() (uint16, uint16) {
	if r.SandboxPortFirst == 0 && r.SandboxPort != 0 {
		return r.SandboxPort, r.SandboxPort
	}
	return r.SandboxPortFirst, r.SandboxPortLast
}
